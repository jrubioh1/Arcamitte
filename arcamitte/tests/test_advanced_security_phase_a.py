from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from arcamitte.models import (
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
    get_or_create_user_profile,
)
from arcamitte.services import (
    upload_and_encrypt_document,
    dispatch_siem_event,
    rotate_master_keys,
)
from arcamitte.totp import (
    generate_qr_svg_data_uri,
    generate_scratch_codes,
    generate_totp_code,
    generate_totp_secret,
    get_totp_uri,
    hash_scratch_code,
    verify_totp_code,
)

User = get_user_model()


class TOTPCryptographicEngineTests(TestCase):
    """Pruebas del motor criptográfico RFC 6238 / RFC 4226 sin dependencias externas."""

    def test_rfc6238_official_appendix_b_vectors(self) -> None:
        """Verifica los vectores de prueba oficiales de la especificación RFC 6238 Apéndice B con HMAC-SHA256."""
        # Secreto oficial RFC para SHA-256: '12345678901234567890123456789012' (32 bytes ASCII)
        import base64

        rfc_secret_b32 = base64.b32encode(b"12345678901234567890123456789012").decode("ascii")

        # Vectores oficiales RFC 6238 Apéndice B (SHA-256, 8 dígitos)
        test_cases_8_digits = [
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
        ]
        for timestamp, expected_code in test_cases_8_digits:
            with self.subTest(timestamp=timestamp, digits=8):
                code = generate_totp_code(rfc_secret_b32, timestamp=timestamp, digits=8)
                self.assertEqual(code, expected_code)
                self.assertTrue(verify_totp_code(rfc_secret_b32, expected_code, timestamp=timestamp))

        # Vectores estándar de 6 dígitos (módulo 10^6)
        test_cases_6_digits = [
            (59, "119246"),
            (1111111109, "084774"),
            (1111111111, "062674"),
            (1234567890, "819424"),
            (2000000000, "698825"),
        ]
        for timestamp, expected_code in test_cases_6_digits:
            with self.subTest(timestamp=timestamp, digits=6):
                code = generate_totp_code(rfc_secret_b32, timestamp=timestamp, digits=6)
                self.assertEqual(code, expected_code)
                self.assertTrue(verify_totp_code(rfc_secret_b32, expected_code, timestamp=timestamp))

    def test_generate_and_verify_totp_code(self) -> None:
        """Comprueba generación de secretos y validación en tiempo constante con ventana de deriva."""
        secret = generate_totp_secret()
        self.assertGreaterEqual(len(secret), 32)

        # Código válido en el tiempo actual
        valid_code = generate_totp_code(secret)
        self.assertEqual(len(valid_code), 6)
        self.assertTrue(valid_code.isdigit())
        self.assertTrue(verify_totp_code(secret, valid_code))

        # Rechazo de código erróneo
        self.assertFalse(verify_totp_code(secret, "999999"))
        self.assertFalse(verify_totp_code(secret, "abcdef"))
        self.assertFalse(verify_totp_code(secret, ""))

    def test_scratch_codes_generation_and_consumption(self) -> None:
        """Verifica generación de códigos de rescate, almacenamiento en hash y consumo único."""
        plains, hashes = generate_scratch_codes(count=8)
        self.assertEqual(len(plains), 8)
        self.assertEqual(len(hashes), 8)

        # Cada código tiene formato XXXX-XXXX
        for p in plains:
            self.assertEqual(len(p), 9)
            self.assertEqual(p[4], "-")

        # El hash coincide
        self.assertEqual(hash_scratch_code(plains[0]), hashes[0])

        user = User.objects.create_user(
            username="rescatado", password="Corporate#Pass2026"
        )
        profile = get_or_create_user_profile(user)
        profile.enable_totp(secret=generate_totp_secret(), scratch_hashes=hashes)

        # Consumo correcto por primera vez
        consumed = profile.consume_scratch_code(plains[0])
        self.assertTrue(consumed)
        profile.refresh_from_db()
        self.assertEqual(len(profile.totp_scratch_codes), 7)

        # Intento de reutilización (debe fallar)
        reused = profile.consume_scratch_code(plains[0])
        self.assertFalse(reused)

    def test_totp_uri_and_qr_svg_generation(self) -> None:
        """Comprueba que la URI 'otpauth://' y el código QR SVG Data URI se construyen correctamente."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, username="operador1", issuer="Arcamitte")
        self.assertTrue(uri.startswith("otpauth://totp/Arcamitte%3Aoperador1?"))
        self.assertIn(f"secret={secret}", uri)
        self.assertIn("algorithm=SHA256", uri)

        qr_data_uri = generate_qr_svg_data_uri(uri)
        self.assertTrue(qr_data_uri.startswith("data:image/svg+xml"))


class TOTPAuthenticationViewsTests(TestCase):
    """Pruebas funcionales del flujo de autenticación 2FA en el Dashboard."""

    def setUp(self) -> None:
        self.client = Client()
        self.user = User.objects.create_user(
            username="analista_2fa",
            email="analista2fa@arcamitte.local",
            password="Corporate#Pass2026",
        )
        self.profile = get_or_create_user_profile(self.user)
        self.secret = generate_totp_secret()
        _, hashes = generate_scratch_codes(4)
        self.profile.enable_totp(secret=self.secret, scratch_hashes=hashes)
        self.login_url = reverse("dashboard:login")
        self.verify_url = reverse("dashboard:totp_verify")

    def test_login_requires_step2_when_totp_enabled(self) -> None:
        """Al validar contraseña de usuario con 2FA, se redirige a totp_verify sin autenticar sesión."""
        resp = self.client.post(
            self.login_url,
            {"username": "analista_2fa", "password": "Corporate#Pass2026"},
        )
        self.assertRedirects(resp, self.verify_url)

        # El usuario aún no está formalmente autenticado en request.user
        resp_home = self.client.get(reverse("dashboard:home"))
        expected_redirect = f"{self.login_url}?next={reverse('dashboard:home')}"
        self.assertRedirects(resp_home, expected_redirect)

    def test_totp_verify_with_valid_and_invalid_codes(self) -> None:
        """Verifica aceptación de código TOTP correcto y rechazo de códigos incorrectos."""
        # 1. Paso 1: Login inicial
        self.client.post(
            self.login_url,
            {"username": "analista_2fa", "password": "Corporate#Pass2026"},
        )

        # 2. Paso 2: Código inválido
        resp_bad = self.client.post(self.verify_url, {"code": "000000"})
        self.assertEqual(resp_bad.status_code, 400)
        self.assertContains(resp_bad, "inválido", status_code=400)

        # 3. Paso 2: Código válido
        valid_code = generate_totp_code(self.secret)
        resp_ok = self.client.post(self.verify_url, {"code": valid_code})
        self.assertRedirects(resp_ok, reverse("dashboard:home"))

        # Ahora el usuario sí tiene acceso autenticado al dashboard
        resp_dash = self.client.get(reverse("dashboard:home"))
        self.assertEqual(resp_dash.status_code, 200)

    @override_settings(ARCAMITTE_MFA_REQUIRED_FOR_STAFF=True)
    def test_mfa_required_for_staff_forces_initial_setup(self) -> None:
        """Si la política exige 2FA a staff, un administrador sin 2FA debe configurarlo en su primer acceso."""
        staff_user = User.objects.create_user(
            username="admin_sin_2fa",
            password="Corporate#Pass2026",
            is_staff=True,
        )
        profile = get_or_create_user_profile(staff_user)
        self.assertFalse(profile.is_totp_enabled)

        # Login paso 1
        resp = self.client.post(
            self.login_url,
            {"username": "admin_sin_2fa", "password": "Corporate#Pass2026"},
        )
        self.assertRedirects(resp, self.verify_url)

        # La pantalla de verificación detecta que debe configurarlo por primera vez
        resp_get = self.client.get(self.verify_url)
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, "Activación de 2FA Requerida")
        self.assertTrue(resp_get.context["must_setup_first"])

        # Confirmación de la activación inicial
        pending_secret = self.client.session.get("_totp_pending_secret")
        valid_code = generate_totp_code(pending_secret)
        resp_confirm = self.client.post(self.verify_url, {"code": valid_code})
        self.assertRedirects(resp_confirm, reverse("dashboard:totp_setup"))

        # El perfil ahora tiene 2FA activo en base de datos
        profile.refresh_from_db()
        self.assertTrue(profile.is_totp_enabled)

    def test_totp_setup_post_invalid_code_renders_error(self) -> None:
        """Verifica que el envío de un código TOTP incorrecto en setup no produce UnboundLocalError."""
        user_fresh = User.objects.create_user(
            username="fresh_user", email="fresh@test.es", password="Corporate#Pass2026"
        )
        self.client.force_login(user_fresh)
        setup_url = reverse("dashboard:totp_setup")
        # GET inicial para generar _totp_pending_secret
        resp_get = self.client.get(setup_url)
        self.assertEqual(resp_get.status_code, 200)

        # POST con código inválido
        resp_post = self.client.post(setup_url, {"code": "000000"})
        self.assertEqual(resp_post.status_code, 400)
        self.assertContains(resp_post, "incorrecto", status_code=400)


class SessionSecurityMiddlewareTests(TestCase):
    """Pruebas de Session Hijacking (IP Binding) y Sesión Concurrente Única (Single Session)."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            username="agente_seguro",
            email="agente@arcamitte.local",
            password="Corporate#Pass2026",
        )
        self.profile = get_or_create_user_profile(self.user)

    @override_settings(ARCAMITTE_SESSION_IP_BINDING=True)
    def test_session_hijacking_ip_discrepancy_terminates_session(self) -> None:
        """Si la IP de la solicitud difiere de la IP de la sesión inicial, la sesión se revoca inmediatamente."""
        client = Client(REMOTE_ADDR="198.51.100.10")
        client.login(username="agente_seguro", password="Corporate#Pass2026")

        # Fijar la IP inicial en la sesión
        session = client.session
        session["_arca_client_ip"] = "198.51.100.10"
        session.save()

        # Petición legítima desde la misma IP (200 OK)
        resp_ok = client.get(reverse("dashboard:home"), REMOTE_ADDR="198.51.100.10")
        self.assertEqual(resp_ok.status_code, 200)

        # Intento de uso de la cookie desde una IP distinta (Session Hijacking)
        resp_hijack = client.get(reverse("dashboard:home"), REMOTE_ADDR="203.0.113.88")
        # Redirige a login
        self.assertRedirects(resp_hijack, reverse("dashboard:login"))

        # Se ha registrado el evento de auditoría
        audit = DocumentAccessLog.objects.filter(
            action=DocumentAccessLog.Action.SECUESTRO_SESION_DETECTADO
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.ip_address, "203.0.113.88")

    @override_settings(ARCAMITTE_SINGLE_SESSION_PER_USER=True)
    def test_single_concurrent_session_revokes_older_session(self) -> None:
        """Al iniciar sesión desde un segundo cliente, la sesión del primer cliente es revocada."""
        client1 = Client(REMOTE_ADDR="192.168.1.10")
        client2 = Client(REMOTE_ADDR="192.168.1.20")

        # 1. Login en Cliente 1
        client1.post(
            reverse("dashboard:login"),
            {"username": "agente_seguro", "password": "Corporate#Pass2026"},
            REMOTE_ADDR="192.168.1.10",
        )
        self.profile.refresh_from_db()
        key1 = self.profile.current_session_key
        self.assertTrue(bool(key1))

        # Cliente 1 puede navegar
        self.assertEqual(
            client1.get(
                reverse("dashboard:home"), REMOTE_ADDR="192.168.1.10"
            ).status_code,
            200,
        )

        # 2. Login en Cliente 2 con la misma cuenta
        client2.post(
            reverse("dashboard:login"),
            {"username": "agente_seguro", "password": "Corporate#Pass2026"},
            REMOTE_ADDR="192.168.1.20",
        )
        self.profile.refresh_from_db()
        key2 = self.profile.current_session_key
        self.assertNotEqual(key1, key2)

        # 3. Cliente 1 intenta navegar de nuevo: su sesión debe ser revocada
        resp_terminated = client1.get(
            reverse("dashboard:home"), REMOTE_ADDR="192.168.1.10"
        )
        self.assertRedirects(resp_terminated, reverse("dashboard:login"))

        # Cliente 2 sigue activo y autorizado
        self.assertEqual(
            client2.get(
                reverse("dashboard:home"), REMOTE_ADDR="192.168.1.20"
            ).status_code,
            200,
        )


class MasterKeyRotationTests(TestCase):
    """Pruebas de rotación atómica de claves maestras (MultiFernet Keyring)."""

    def setUp(self) -> None:
        self.uo = OrganizationalUnit.objects.create(
            numeric_code=1001,
            name="Ciberseguridad",
            alias="CIBER",
            email="ciber@arcamitte.local",
        )
        self.user = User.objects.create_user(
            username="custodio", password="Corporate#Pass2026"
        )
        UserUOMembership.objects.create(
            user=self.user,
            uo=self.uo,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )
        self.doc = upload_and_encrypt_document(
            original_file=SimpleUploadedFile(
                "confidencial.pdf",
                b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF",
            ),
            allowed_emails=["dest@arcamitte.local"],
            burn_policy=EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
            origin_uo=self.uo,
            uploaded_by=self.user,
        )

    def test_rotate_master_keys_service_and_keyring_compatibility(self) -> None:
        """Comprueba que rotate_master_keys recifra las DEKs y que se descifran con el nuevo llavero."""
        old_dek = self.doc.encrypted_dek
        new_master_key = Fernet.generate_key().decode("utf-8")

        result = rotate_master_keys(
            new_primary_key=new_master_key,
            operator=self.user,
            client_ip="127.0.0.1",
        )
        self.assertEqual(result["status"], "success")
        self.assertGreaterEqual(result["rotated_documents"], 1)

        self.doc.refresh_from_db()
        # El DEK en base de datos ha sido modificado y recifrado
        self.assertNotEqual(self.doc.encrypted_dek, old_dek)

        # El nuevo DEK se descifra directamente con la nueva clave maestra
        fernet_new = Fernet(new_master_key.encode("utf-8"))
        dek_bytes = fernet_new.decrypt(self.doc.encrypted_dek.encode("utf-8"))
        fernet_dek = Fernet(dek_bytes)

        self.doc.encrypted_file.seek(0)
        decrypted = fernet_dek.decrypt(self.doc.encrypted_file.read())
        self.assertIn(b"%PDF-1.4", decrypted)

    def test_rotate_master_key_management_command(self) -> None:
        """Verifica la ejecución del comando de gestión 'rotate_master_key --generate'."""
        call_command("rotate_master_key", generate=True)
        # Comprobar que se ha registrado en auditoría
        audit = DocumentAccessLog.objects.filter(
            action=DocumentAccessLog.Action.ROTACION_CLAVE_MAESTRA
        ).first()
        self.assertIsNotNone(audit)
        self.assertIn("Rotación de clave maestra", audit.details)


class SIEMWebhookConnectorTests(TestCase):
    """Pruebas del conector asíncrono hacia SIEM / Webhooks externos."""

    @override_settings(
        ARCAMITTE_SIEM_WEBHOOK_URL="https://siem.arcamitte.local/api/alerts",
        ARCAMITTE_SIEM_WEBHOOK_TOKEN="secret-siem-bearer-token",
        ARCAMITTE_SIEM_WEBHOOK_EVENTS=["ip_ban", "user_lockout", "audit_export"],
    )
    @patch("urllib.request.urlopen")
    def test_dispatch_siem_event_sends_structured_json(
        self, mock_urlopen: MagicMock
    ) -> None:
        """Verifica que el conector SIEM formatea y envía el JSON estructurado con cabecera Bearer."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        dispatch_siem_event(
            event_type="ip_ban",
            details={"ip_address": "198.51.100.55", "reason": "Fuerza bruta"},
            actor="admin",
            ip="198.51.100.55",
        )

        import time

        time.sleep(0.3)  # Pequeño margen para el hilo del executor

        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(
            req.get_header("Authorization"), "Bearer secret-siem-bearer-token"
        )
        self.assertEqual(req.get_header("Content-type"), "application/json")

        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["event"], "IP_BAN")
        self.assertEqual(payload["actor"], "admin")
        self.assertEqual(payload["client_ip"], "198.51.100.55")
        self.assertEqual(payload["details"]["reason"], "Fuerza bruta")
