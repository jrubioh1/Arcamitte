from __future__ import annotations

import datetime

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from arcamitte.forms import UserManagementForm
from arcamitte.models import (
    APIToken,
    DocumentAccessLog,
    OrganizationalUnit,
    UserUOMembership,
    get_or_create_user_profile,
)
from arcamitte.services import (
    is_totp_required_for_user,
    upload_and_encrypt_document,
)

User = get_user_model()
TEST_FERNET_KEY = Fernet.generate_key().decode()

MINIMAL_VALID_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


@override_settings(ARCAMITTE_FERNET_KEY=TEST_FERNET_KEY)
class GovernanceAndTokenAuditTestCase(TestCase):
    """
    Suite de verificación integral para:
    - Auditoría y trazabilidad completa de API Tokens (creación, revocación y detalle).
    - Ventana dedicada de gestión de usuarios bloqueados (1-clic unlock y suspensión manual).
    - Panel de gobernanza de 2FA / TOTP y reseteo administrativo.
    - Cierre destructivo de asientos (Descargar y Clausurar).
    - Política corporativa estricta de usuarios (email obligatorio, unicidad case-insensitive, anti-colisión).
    - Desacoplamiento de roles y verificación de obligatoriedad de 2FA.
    """

    def setUp(self) -> None:
        self.client = Client()

        # Superusuario
        self.superuser = User.objects.create_superuser(
            username="master_super",
            email="super@arcamitte.local",
            password="MasterPassword#2026",
        )
        self.super_profile = get_or_create_user_profile(self.superuser)

        # UO de prueba
        self.uo = OrganizationalUnit.objects.create(
            numeric_code=8001,
            alias="GOV_TEST",
            name="Unidad de Gobernanza",
            email="gov@arcamitte.local",
        )

        # UO Admin (Role.ADMIN, is_staff=False)
        self.uo_admin = User.objects.create_user(
            username="uo_admin_user",
            email="admin_uo@arcamitte.local",
            password="AdminPassword#2026",
            is_staff=False,
            is_superuser=False,
        )
        UserUOMembership.objects.create(
            user=self.uo_admin,
            uo=self.uo,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )

        # Operador Estándar (Role.OPERATOR, is_staff=False)
        self.operator = User.objects.create_user(
            username="operator_std",
            email="operator@arcamitte.local",
            password="OperatorPassword#2026",
            is_staff=False,
            is_superuser=False,
        )
        UserUOMembership.objects.create(
            user=self.operator,
            uo=self.uo,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )
        self.operator_profile = get_or_create_user_profile(self.operator)

        # Staff de plataforma (is_staff=True, is_superuser=False)
        self.staff_user = User.objects.create_user(
            username="platform_staff",
            email="staff@arcamitte.local",
            password="StaffPassword#2026",
            is_staff=True,
            is_superuser=False,
        )

    # --------------------------------------------------------------------------
    # 1. API Token Creation, Revocation & Detail Audit
    # --------------------------------------------------------------------------
    def test_token_creation_and_revocation_audit_logging(self) -> None:
        """Verifica que la creación y revocación de API Tokens generen asientos en DocumentAccessLog."""
        self.client.force_login(self.superuser)

        # Creación de Token
        resp_create = self.client.post(
            reverse("dashboard:api_tokens"),
            {
                "name": "Microservicio_Facturacion",
                "scopes": [APIToken.Scope.DOCUMENTS_CREATE],
                "rate_limit": 120,
                "validity_days": 30,
            },
        )
        self.assertEqual(resp_create.status_code, 302)

        token = APIToken.objects.get(name="Microservicio_Facturacion")
        self.assertTrue(token.is_active)
        self.assertEqual(token.created_by, self.superuser)

        import json

        # Comprobar log de auditoría
        log_create = DocumentAccessLog.objects.filter(
            action=DocumentAccessLog.Action.TOKEN_API_CREADO
        ).first()
        self.assertIsNotNone(log_create)
        details_create = (
            json.loads(log_create.details)
            if isinstance(log_create.details, str)
            else log_create.details
        )
        self.assertEqual(details_create.get("token_id"), token.id)
        self.assertEqual(details_create.get("token_name"), "Microservicio_Facturacion")
        self.assertTrue(bool(log_create.log_hash))

        # Detalle del Token
        resp_detail = self.client.get(
            reverse("dashboard:api_token_detail", args=[token.id])
        )
        self.assertEqual(resp_detail.status_code, 200)
        self.assertContains(resp_detail, "Microservicio_Facturacion")
        self.assertContains(resp_detail, token.prefix)

        # Revocación de Token con motivo
        resp_revoke = self.client.post(
            reverse("dashboard:api_token_revoke", args=[token.id]),
            {"reason": "Rotación de credenciales anual"},
        )
        self.assertEqual(resp_revoke.status_code, 302)

        token.refresh_from_db()
        self.assertFalse(token.is_active)
        self.assertIsNotNone(token.revoked_at)
        self.assertEqual(token.revoked_by, self.superuser)
        self.assertEqual(token.revocation_reason, "Rotación de credenciales anual")

        # Comprobar log de auditoría de revocación
        log_revoke = DocumentAccessLog.objects.filter(
            action=DocumentAccessLog.Action.TOKEN_API_REVOCADO
        ).first()
        self.assertIsNotNone(log_revoke)
        details_revoke = (
            json.loads(log_revoke.details)
            if isinstance(log_revoke.details, str)
            else log_revoke.details
        )
        self.assertEqual(details_revoke.get("token_id"), token.id)
        self.assertEqual(details_revoke.get("reason"), "Rotación de credenciales anual")

    # --------------------------------------------------------------------------
    # 2. Locked & Suspended Users Management Panel
    # --------------------------------------------------------------------------
    def test_locked_users_panel_and_one_click_unlock(self) -> None:
        """Verifica que el panel de cuentas bloqueadas liste usuarios penalizados y permita desbloqueo 1-clic."""
        # Bloquear al operador fijando locked_until en el futuro
        self.operator_profile.locked_until = timezone.now() + datetime.timedelta(
            minutes=15
        )
        self.operator_profile.failed_login_attempts = 5
        self.operator_profile.save()

        self.client.force_login(self.superuser)
        resp = self.client.get(reverse("dashboard:locked_users"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "operator_std")
        self.assertContains(resp, "5")

        # Desbloqueo 1-clic
        resp_unlock = self.client.post(
            reverse("dashboard:user_unlock", args=[self.operator.id]),
            {"next": reverse("dashboard:locked_users")},
        )
        self.assertEqual(resp_unlock.status_code, 302)

        self.operator_profile.refresh_from_db()
        self.assertFalse(self.operator_profile.is_locked)
        self.assertEqual(self.operator_profile.failed_login_attempts, 0)
        self.assertIsNone(self.operator_profile.locked_until)

    def test_manual_user_suspension_with_mandatory_reason(self) -> None:
        """Verifica la suspensión administrativa forzosa de un usuario con motivo legal obligatorio."""
        self.client.force_login(self.superuser)

        # 1. Sin motivo -> Debe fallar y redirigir con error
        resp_no_reason = self.client.post(
            reverse("dashboard:user_suspend", args=[self.operator.id]),
            {"reason": ""},
        )
        self.assertEqual(resp_no_reason.status_code, 302)
        self.operator.refresh_from_db()
        self.assertTrue(self.operator.is_active)

        # 2. Auto-suspensión prohibida
        resp_self = self.client.post(
            reverse("dashboard:user_suspend", args=[self.superuser.id]),
            {"reason": "Auto suspensión"},
        )
        self.assertEqual(resp_self.status_code, 302)
        self.superuser.refresh_from_db()
        self.assertTrue(self.superuser.is_active)

        # 3. Suspensión legítima con motivo
        resp_suspend = self.client.post(
            reverse("dashboard:user_suspend", args=[self.operator.id]),
            {"reason": "Investigación interna de seguridad expediente SEC-2026-99"},
        )
        self.assertEqual(resp_suspend.status_code, 302)

        self.operator.refresh_from_db()
        self.operator_profile.refresh_from_db()
        self.assertFalse(self.operator.is_active)
        self.assertTrue(self.operator_profile.is_locked)

        # Verificar auditoría de suspensión
        log = DocumentAccessLog.objects.filter(
            action=DocumentAccessLog.Action.BLOQUEO_USUARIO,
            email=self.operator.email,
        ).first()
        self.assertIsNotNone(log)
        self.assertIn("SEC-2026-99", log.details)

    # --------------------------------------------------------------------------
    # 3. 2FA Governance & Enforcement Logic
    # --------------------------------------------------------------------------
    def test_2fa_enforcement_and_admin_reset(self) -> None:
        """Verifica la obligatoriedad estricta de 2FA por rol y reseteo administrativo."""
        # 1. Superusuario: 2FA obligatorio
        self.assertTrue(is_totp_required_for_user(self.superuser))

        # 2. Staff de plataforma: 2FA obligatorio
        self.assertTrue(is_totp_required_for_user(self.staff_user))

        # 3. Administrador de UO: 2FA obligatorio (incluso con is_staff=False)
        self.assertTrue(is_totp_required_for_user(self.uo_admin))

        # 4. Operador estándar: 2FA opcional por defecto
        self.assertFalse(is_totp_required_for_user(self.operator))

        # 5. Forzamiento individual por Superusuario
        self.client.force_login(self.superuser)

        # GET Panel de Gobernanza 2FA (Verifica que no ocurra NameError con UserProfile)
        resp_gov_get = self.client.get(reverse("dashboard:2fa_governance"))
        self.assertEqual(resp_gov_get.status_code, 200)
        self.assertContains(resp_gov_get, "Gobernanza de Segundo Factor (2FA)")

        resp_toggle = self.client.post(
            reverse("dashboard:2fa_governance"),
            {"user_id": self.operator.id},
        )
        self.assertEqual(resp_toggle.status_code, 302)

        self.operator.refresh_from_db()
        self.operator_profile = self.operator.arcamitte_profile
        self.assertTrue(self.operator_profile.is_mfa_enforced)
        # Ahora el operador tiene 2FA obligatorio
        self.assertTrue(is_totp_required_for_user(self.operator))

        # Simular activación previa de 2FA
        self.operator_profile.is_totp_enabled = True
        self.operator_profile.totp_secret = "JBSWY3DPEHPK3PXP"
        self.operator_profile.save()

        # Probar endpoint personal de configuración 2FA (sin UnboundLocalError en '_')
        self.client.force_login(self.operator)
        resp_totp_get = self.client.get(reverse("dashboard:totp_setup"))
        self.assertEqual(resp_totp_get.status_code, 200)

        # Probar POST regenerate_scratch sin confirmación válida
        resp_regen = self.client.post(
            reverse("dashboard:totp_setup"),
            {"action": "regenerate_scratch", "confirmation_code": "wrong_code"},
        )
        self.assertEqual(resp_regen.status_code, 302)

        # 6. Reseteo administrativo de 2FA (como superusuario)
        self.client.force_login(self.superuser)
        resp_reset = self.client.post(
            reverse("dashboard:user_reset_2fa", args=[self.operator.id]),
            {"reason": "Pérdida de móvil corporativo"},
        )
        self.assertEqual(resp_reset.status_code, 302)

        self.operator.refresh_from_db()
        self.operator_profile = self.operator.arcamitte_profile
        self.assertFalse(self.operator_profile.is_totp_enabled)
        self.assertEqual(self.operator_profile.totp_secret, "")

    # --------------------------------------------------------------------------
    # 4. Destructive Document Download & Closure (Consumo Destructivo)
    # --------------------------------------------------------------------------
    def test_document_download_and_burn_view(self) -> None:
        """Verifica que la descarga con clausura destruya físicamente el archivo y finalice el asiento."""
        uploaded = SimpleUploadedFile(
            "contrato_entrega.pdf",
            MINIMAL_VALID_PDF,
            content_type="application/pdf",
        )
        doc = upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails="destinatario@externo.es",
            uploaded_by=self.superuser,
            origin_uo=self.uo,
        )
        self.assertFalse(doc.is_consumed)
        self.assertTrue(bool(doc.encrypted_file))

        self.client.force_login(self.superuser)
        resp_burn = self.client.post(
            reverse("dashboard:document_download_and_burn", args=[doc.file_hash]),
            {"reason": "Entrega final al cliente con acta de recepción"},
        )
        self.assertEqual(resp_burn.status_code, 200)
        self.assertEqual(resp_burn["Content-Type"], "application/pdf")
        self.assertIn("attachment", resp_burn["Content-Disposition"])

        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)
        self.assertIsNotNone(doc.consumed_at)

        # Archivo físico eliminado
        self.assertFalse(bool(doc.encrypted_file))

        # Asiento en auditoría
        log = DocumentAccessLog.objects.filter(
            document=doc,
            action=DocumentAccessLog.Action.FINALIZACION_MANUAL,
        ).first()
        self.assertIsNotNone(log)
        self.assertIn("NIST SP 800-88", log.details)

    # --------------------------------------------------------------------------
    # 5. Strict Corporate User Form Validation
    # --------------------------------------------------------------------------
    def test_user_management_form_email_uniqueness_and_collision(self) -> None:
        """Verifica que UserManagementForm exija unicidad case-insensitive y prevenga colisiones username/email."""
        # 1. Email duplicado (case-insensitive)
        form_dup_email = UserManagementForm(
            data={
                "username": "nuevo_usuario",
                "email": "OPERATOR@ARCAMITTE.LOCAL",  # Ya existe en self.operator
                "first_name": "Nuevo",
                "last_name": "Usuario",
                "is_active": True,
            },
            is_superuser=True,
            current_user=self.superuser,
        )
        self.assertFalse(form_dup_email.is_valid())
        self.assertIn("email", form_dup_email.errors)
        self.assertIn("Ya existe otro usuario", str(form_dup_email.errors["email"]))

        # 2. Colisión: Email que coincide con el username de otra cuenta
        form_email_matches_user = UserManagementForm(
            data={
                "username": "nuevo_usuario_2",
                "email": "operator_std",  # Coincide con username de self.operator
                "first_name": "Nuevo",
                "last_name": "Usuario",
                "is_active": True,
            },
            is_superuser=True,
            current_user=self.superuser,
        )
        self.assertFalse(form_email_matches_user.is_valid())
        self.assertIn("email", form_email_matches_user.errors)

        # 3. Colisión: Username que coincide con el email de otra cuenta
        form_user_matches_email = UserManagementForm(
            data={
                "username": "operator@arcamitte.local",  # Coincide con email de self.operator
                "email": "otro_correo@empresa.com",
                "first_name": "Nuevo",
                "last_name": "Usuario",
                "is_active": True,
            },
            is_superuser=True,
            current_user=self.superuser,
        )
        self.assertFalse(form_user_matches_email.is_valid())
        self.assertIn("username", form_user_matches_email.errors)
