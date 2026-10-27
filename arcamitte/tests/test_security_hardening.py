from __future__ import annotations

import hashlib
import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from arcamitte.models import (
    AuditExportReceipt,
    BannedIP,
    DocumentAccessLog,
    OrganizationalUnit,
    UserUOMembership,
)
from arcamitte.services import (
    record_password_change,
    verify_audit_log_chain,
    verify_export_receipt,
)
from arcamitte.validators import (
    CorporatePasswordComplexityValidator,
    PasswordHistoryValidator,
    sanitize_csv_cell,
)

User = get_user_model()


class SecurityHardeningAndNonRepudiationTestCase(TestCase):
    """
    Batería exhaustiva de pruebas unitarias y de integración para las defensas de seguridad
    de Arcamitte: bloqueo de cuentas, baneo de IPs, notificaciones de seguridad,
    ciclo de vida de contraseñas, no repudio y mitigación de casos de abuso / adversarios.
    """

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._temp_media = tempfile.mkdtemp(prefix="arca_test_sec_")
        cls._media_override = override_settings(
            MEDIA_ROOT=cls._temp_media,
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
            ARCAMITTE_USER_MAX_FAILED_LOGINS=5,
            ARCAMITTE_USER_LOCKOUT_DURATION_MINUTES=30,
            ARCAMITTE_IP_BAN_FAILED_ATTEMPTS_THRESHOLD=10,
            ARCAMITTE_IP_BAN_WINDOW_MINUTES=10,
            ARCAMITTE_IP_BAN_DEFAULT_DURATION_HOURS=24,
            ARCAMITTE_PASSWORD_MIN_LENGTH=12,
            ARCAMITTE_PASSWORD_HISTORY_LIMIT=5,
            ARCAMITTE_PASSWORD_EXPIRATION_DAYS=90,
            ARCAMITTE_SECURITY_ALERTS_EMAIL="soc-alerts@arcamitte.local",
        )
        cls._media_override.enable()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._media_override.disable()
        shutil.rmtree(cls._temp_media, ignore_errors=True)
        super().tearDownClass()

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        mail.outbox.clear()

        # Superadministrador del sistema
        self.superadmin = User.objects.create_superuser(
            username="supersec",
            email="supersec@arcamitte.local",
            password="MasterSecretPassword123#@",
        )

        # Unidad Organizativa de pruebas
        self.uo = OrganizationalUnit.objects.create(
            numeric_code=2001,
            alias="CIBER",
            name="Ciberseguridad y Cumplimiento",
            email="ciber@arcamitte.local",
        )

        # Usuario operador estándar
        self.operator = User.objects.create_user(
            username="analista_sec",
            email="analista@arcamitte.local",
            password="CorporateSafePassword2026!#",
        )
        UserUOMembership.objects.create(
            user=self.operator,
            uo=self.uo,
            role=UserUOMembership.Role.OPERATOR,
        )

    # ==========================================================================
    # 1. BLOQUEO TEMPORAL DE USUARIOS Y NOTIFICACIONES
    # ==========================================================================

    def test_user_account_lockout_after_consecutive_failures(self) -> None:
        """
        Caso normal y abuso de fuerza bruta:
        Tras 5 intentos fallidos consecutivos de login, la cuenta debe quedar bloqueada.
        Incluso si el 6º intento introduce la contraseña correcta, el acceso debe denegarse
        y debe remitirse notificación de alerta por correo al usuario y al SOC.
        """
        login_url = reverse("dashboard:login")

        # 5 intentos con clave errónea
        for i in range(5):
            resp = self.client.post(
                login_url, {"username": "analista_sec", "password": "WrongPassword123!"}
            )
            self.assertEqual(resp.status_code, 200)

        self.operator.arcamitte_profile.refresh_from_db()
        profile = self.operator.arcamitte_profile
        self.assertTrue(profile.is_locked)
        self.assertEqual(profile.failed_login_attempts, 5)
        self.assertIsNotNone(profile.locked_until)

        # Se deben haber enviado 2 correos: al usuario y al buzón SOC
        self.assertGreaterEqual(len(mail.outbox), 2)
        user_emails = [m for m in mail.outbox if "analista@arcamitte.local" in m.to]
        self.assertEqual(len(user_emails), 1)
        self.assertIn("Aviso de bloqueo temporal", user_emails[0].subject)

        soc_emails = [m for m in mail.outbox if "soc-alerts@arcamitte.local" in m.to]
        self.assertEqual(len(soc_emails), 1)
        self.assertIn("bloqueada por fuerza bruta", soc_emails[0].subject)

        # 6º intento: el atacante/usuario prueba la contraseña correcta pero la cuenta está bloqueada
        resp_blocked = self.client.post(
            login_url,
            {"username": "analista_sec", "password": "CorporateSafePassword2026!#"},
        )
        self.assertEqual(resp_blocked.status_code, 429)
        self.assertContains(
            resp_blocked,
            "cuenta de usuario se encuentra temporalmente bloqueada",
            status_code=429,
        )

    def test_user_account_unlock_by_admin(self) -> None:
        """
        Prueba el flujo de desbloqueo manual de cuenta por un superadministrador.
        """
        profile = self.operator.arcamitte_profile
        profile.lock_account(minutes=30)
        self.assertTrue(profile.is_locked)

        # Superadmin inicia sesión y desbloquea
        self.client.force_login(self.superadmin)
        unlock_url = reverse("dashboard:user_unlock", args=[self.operator.id])
        resp = self.client.post(unlock_url, follow=True)
        self.assertEqual(resp.status_code, 200)

        profile.refresh_from_db()
        self.assertFalse(profile.is_locked)
        self.assertEqual(profile.failed_login_attempts, 0)
        self.assertIsNone(profile.locked_until)

    def test_unauthorized_user_unlock_abuse_blocked(self) -> None:
        """
        Caso de abuso: Un usuario no autorizado intenta desbloquear una cuenta
        ajena mediante POST directo a la vista de desbloqueo.
        """
        unauthorized_user = User.objects.create_user(
            username="rogue_user",
            email="rogue@external.local",
            password="SomeSecretPassword2026!#",
        )
        self.operator.arcamitte_profile.lock_account(minutes=30)

        self.client.force_login(unauthorized_user)
        unlock_url = reverse("dashboard:user_unlock", args=[self.operator.id])
        resp = self.client.post(unlock_url)
        self.assertEqual(resp.status_code, 403)

        self.operator.arcamitte_profile.refresh_from_db()
        self.assertTrue(self.operator.arcamitte_profile.is_locked)

    # ==========================================================================
    # 2. BANEO DE IPS Y MIDDLEWARE PERIMETRAL
    # ==========================================================================

    def test_ip_automatic_ban_on_attack_threshold(self) -> None:
        """
        Caso de abuso / ataque distribuido: Una IP acumula 10 fallos de login.
        El sistema debe incorporar la IP a BannedIP, enviar alerta SOC y el
        middleware IPBanMiddleware debe rechazar inmediatamente subsiguientes
        peticiones con HTTP 403 Forbidden.
        """
        attacker_ip = "198.51.100.99"
        login_url = reverse("dashboard:login")

        # 10 fallos desde la misma IP (probando usuarios aleatorios / credential stuffing)
        for i in range(10):
            resp = self.client.post(
                login_url,
                {"username": f"random_user_{i}", "password": "WrongPassword!"},
                REMOTE_ADDR=attacker_ip,
            )
            self.assertEqual(resp.status_code, 200)

        # Comprobar registro en BannedIP
        banned_entry = BannedIP.objects.filter(ip_address=attacker_ip).first()
        self.assertIsNotNone(banned_entry)
        self.assertTrue(banned_entry.is_currently_banned())

        # Siguiente petición desde esa IP debe ser interceptada por IPBanMiddleware con 403
        resp_banned = self.client.get(login_url, REMOTE_ADDR=attacker_ip)
        self.assertEqual(resp_banned.status_code, 403)
        self.assertIn(
            "Su dirección IP se encuentra bloqueada",
            resp_banned.content.decode("utf-8"),
        )

    def test_ip_manual_ban_and_unban_by_admin(self) -> None:
        """
        Prueba la gestión manual de lista negra de IPs desde el Dashboard
        (alta, bloqueo perimetral efectivo y revocación del baneo).
        """
        target_ip = "203.0.113.77"
        self.client.force_login(self.superadmin)

        # 1. Banear manualmente
        create_url = reverse("dashboard:ip_ban_create")
        resp = self.client.post(
            create_url,
            {
                "ip_address": target_ip,
                "reason": "Actividad sospechosa",
                "duration_hours": "12",
            },
            follow=True,
        )
        self.assertEqual(resp.status_code, 200)

        # Petición anónima desde esa IP -> 403
        anonymous_client = self.client_class()
        resp_blocked = anonymous_client.get(
            reverse("dashboard:login"), REMOTE_ADDR=target_ip
        )
        self.assertEqual(resp_blocked.status_code, 403)

        # 2. Desbanear
        banned_obj = BannedIP.objects.get(ip_address=target_ip)
        unban_url = reverse("dashboard:ip_ban_unban", args=[banned_obj.id])
        resp_unban = self.client.post(unban_url, follow=True)
        self.assertEqual(resp_unban.status_code, 200)

        # Acceso rehabilitado
        resp_allowed = anonymous_client.get(
            reverse("dashboard:login"), REMOTE_ADDR=target_ip
        )
        self.assertEqual(resp_allowed.status_code, 200)

    def test_ip_ban_unauthorized_access_abuse_blocked(self) -> None:
        """
        Caso de abuso: Un usuario regular sin permisos intenta banear o desbanear IPs.
        """
        self.client.force_login(self.operator)
        resp_list = self.client.get(reverse("dashboard:ip_ban_list"))
        self.assertEqual(resp_list.status_code, 403)

        resp_create = self.client.post(
            reverse("dashboard:ip_ban_create"),
            {"ip_address": "192.0.2.1", "reason": "Intento no autorizado"},
        )
        self.assertEqual(resp_create.status_code, 403)

    # ==========================================================================
    # 3. POLÍTICA DE CONTRASEÑAS (HISTORIAL Y COMPLEJIDAD)
    # ==========================================================================

    def test_password_history_validator_prevents_reuse_abuse(self) -> None:
        """
        Caso de abuso: Un usuario intenta rotar entre 2 contraseñas o reutilizar
        alguna de sus últimas 5 contraseñas previas.
        """
        user = User.objects.create_user(
            username="user_pwd_test",
            email="pwd@test.local",
            password="InitialPass1234#@",
        )
        validator = PasswordHistoryValidator(history_limit=5)

        # No puede ser idéntica a la actual
        with self.assertRaises(ValidationError) as ctx:
            validator.validate("InitialPass1234#@", user=user)
        self.assertIn(
            "no puede ser idéntica a su contraseña actual", str(ctx.exception)
        )

        # Registrar cambios sucesivos
        passwords = [
            "PasswordVersion01!#",
            "PasswordVersion02!#",
            "PasswordVersion03!#",
            "PasswordVersion04!#",
            "PasswordVersion05!#",
        ]
        for pwd in passwords:
            record_password_change(user, pwd)
            user.set_password(pwd)
            user.save()

        # Intento de reutilizar la versión 1 (debe fallar porque está en las últimas 5)
        with self.assertRaises(ValidationError) as ctx:
            validator.validate("PasswordVersion01!#", user=user)
        self.assertIn(
            "No puede reutilizar ninguna de sus últimas 5 contraseñas",
            str(ctx.exception),
        )

        # Tras un 6º cambio, la versión 1 ya no está en el historial de las últimas 5
        record_password_change(user, "PasswordVersion06!#")
        user.set_password("PasswordVersion06!#")
        user.save()

        # Ahora la versión 1 no debe provocar excepción en el validador de historial
        validator.validate("PasswordVersion01!#", user=user)

    def test_password_complexity_validator(self) -> None:
        """
        Valida que el validador de complejidad exija al menos 12 caracteres,
        mayúsculas, minúsculas, números y caracteres especiales.
        """
        validator = CorporatePasswordComplexityValidator(min_length=12)

        # Demasiado corta (< 12)
        with self.assertRaises(ValidationError):
            validator.validate("Short1!Aa")

        # Sin mayúscula
        with self.assertRaises(ValidationError):
            validator.validate("lowercase_only_123!#")

        # Sin dígito
        with self.assertRaises(ValidationError):
            validator.validate("NoDigitsHereSpecial!#")

        # Sin carácter especial
        with self.assertRaises(ValidationError):
            validator.validate("NoSpecialChars123456Aa")

        # Válida
        validator.validate("Arcamitte#2026!Demo")

    def test_password_expiration_forces_change_middleware(self) -> None:
        """
        Caducidad periódica: Si la contraseña tiene más de 90 días de antigüedad,
        el middleware debe forzar la redirección a la pantalla de cambio obligatorio.
        """
        profile = self.operator.arcamitte_profile
        profile.password_changed_at = timezone.now() - timezone.timedelta(days=95)
        profile.save()

        self.assertTrue(profile.is_password_expired)

        self.client.force_login(self.operator)
        resp = self.client.get(reverse("dashboard:document_list"))
        self.assertRedirects(resp, reverse("dashboard:password_change"))

    # ==========================================================================
    # 4. NO REPUDIO Y ENCADENAMIENTO CRIPTOGRÁFICO DE LOGS (HASH CHAINING)
    # ==========================================================================

    def test_audit_log_hash_chaining_integrity(self) -> None:
        """
        Verifica que cada nuevo registro de auditoría se encadene con el anterior
        mediante previous_hash y log_hash SHA-256 inalterable.
        """
        initial_check = verify_audit_log_chain()
        self.assertTrue(initial_check["is_valid"])

        log1 = DocumentAccessLog.objects.create(
            document=None,
            email="test1@arcamitte.local",
            action=DocumentAccessLog.Action.SOLICITUD_OTP,
            details="Petición de OTP 1",
            ip_address="192.168.1.10",
        )
        self.assertTrue(len(log1.log_hash) == 64)

        log2 = DocumentAccessLog.objects.create(
            document=None,
            email="test2@arcamitte.local",
            action=DocumentAccessLog.Action.OTP_ENVIADO,
            details="Petición de OTP 2",
            ip_address="192.168.1.11",
        )
        self.assertEqual(log2.previous_hash, log1.log_hash)

        chain_check = verify_audit_log_chain()
        self.assertTrue(chain_check["is_valid"])
        self.assertEqual(chain_check["head_hash"], log2.log_hash)

    def test_audit_log_chain_tamper_detection_abuse(self) -> None:
        """
        Caso de abuso / ataque de integridad: Un atacante manipula directamente
        en la base de datos un registro de auditoría.
        El validador verify_audit_log_chain debe detectar la corrupción de inmediato.
        """
        log = DocumentAccessLog.objects.create(
            document=None,
            email="legit@arcamitte.local",
            action=DocumentAccessLog.Action.SOLICITUD_OTP,
            details="Asiento legítimo original",
            ip_address="10.0.0.1",
        )

        # Simular ataque SQL directo alterando el texto del log
        DocumentAccessLog.objects.filter(id=log.id).update(
            details="Texto adulterado por atacante"
        )

        tamper_result = verify_audit_log_chain()
        self.assertFalse(tamper_result["is_valid"])
        self.assertEqual(tamper_result["corrupted_log_id"], log.id)
        self.assertIn("Manipulación de datos", tamper_result["error"])

    # ==========================================================================
    # 5. EXPORTACIÓN FORENSE CERTIFICADA Y MITIGACIÓN DE CSV INJECTION
    # ==========================================================================

    def test_certified_audit_export_and_verification(self) -> None:
        """
        Verifica el ciclo completo de exportación con garantía de no repudio:
        generación de CSV, cálculo SHA-256, recibo AuditExportReceipt y verificación.
        """
        self.client.force_login(self.superadmin)
        export_url = reverse("dashboard:audit_export")
        resp = self.client.post(
            export_url,
            {"reason": "Auditoría judicial formal ENS 2026"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "text/csv; charset=utf-8")

        receipt_id = resp["X-Arcamitte-Receipt-ID"]
        export_hash = resp["X-Arcamitte-Export-Hash"]
        csv_bytes = resp.content

        # Comprobar que el hash del contenido descargado coincide con export_hash
        self.assertEqual(hashlib.sha256(csv_bytes).hexdigest(), export_hash)

        # Comprobar existencia en AuditExportReceipt
        receipt = AuditExportReceipt.objects.get(receipt_id=receipt_id)
        self.assertEqual(receipt.export_hash, export_hash)
        self.assertEqual(receipt.reason, "Auditoría judicial formal ENS 2026")

        # Verificar mediante el servicio de comprobación de autenticidad
        verification = verify_export_receipt(receipt_id, file_bytes=csv_bytes)
        self.assertTrue(verification["found"])
        self.assertTrue(verification["is_valid"])
        self.assertTrue(verification["hash_match"])

    def test_certified_audit_export_tamper_detection_abuse(self) -> None:
        """
        Caso de abuso / falsedad documental: Un tercero altera un solo carácter
        del archivo CSV exportado.
        verify_export_receipt debe denunciar que el archivo ha sido manipulado.
        """
        self.client.force_login(self.superadmin)
        resp = self.client.post(
            reverse("dashboard:audit_export"), {"reason": "Test de alteración"}
        )
        receipt_id = resp["X-Arcamitte-Receipt-ID"]
        original_bytes = resp.content

        # Atacante modifica un byte del CSV
        tampered_bytes = original_bytes + b"\n# FILA FALSIFICADA INYECTADA"

        check = verify_export_receipt(receipt_id, file_bytes=tampered_bytes)
        self.assertTrue(check["found"])
        self.assertFalse(check["is_valid"])
        self.assertFalse(check["hash_match"])

    def test_csv_injection_mitigation_abuse(self) -> None:
        """
        Caso de abuso: CWE-1236 Formula Injection.
        Un documento o solicitud contiene fórmulas ejecutables de Excel (=CMD, +SUM, @IMPORT).
        El generador debe anteponer apóstrofo simple (') en cada celda peligrosa.
        """
        self.assertEqual(sanitize_csv_cell("=cmd|'/C calc'!A0"), "'=cmd|'/C calc'!A0")
        self.assertEqual(sanitize_csv_cell("+12345"), "'+12345")
        self.assertEqual(sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("-2+3"), "'-2+3")
        self.assertEqual(
            sanitize_csv_cell("Texto seguro normal"), "Texto seguro normal"
        )

    def test_audit_receipt_immutability_abuse(self) -> None:
        """
        Garantía de no repudio: Intentar eliminar un registro AuditExportReceipt
        debe arrojar PermissionDenied.
        """
        receipt = AuditExportReceipt.objects.create(
            receipt_id="ARCA-EXP-TEST-001",
            export_hash="a" * 64,
            exported_by=self.superadmin,
            records_count=10,
        )
        with self.assertRaises(PermissionDenied):
            receipt.delete()
