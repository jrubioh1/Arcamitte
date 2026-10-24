from datetime import timedelta
import hashlib
import os
import shutil
import tempfile
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from arcamitte.models import (
    AccessVerificationToken,
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
)
from arcamitte.services import (
    check_and_expire_document,
    consume_document_with_otp,
    process_expired_documents,
    request_document_access,
    terminate_document_manually,
    upload_and_encrypt_document,
)

User = get_user_model()
TEST_FERNET_KEY = Fernet.generate_key().decode()

MINIMAL_TEST_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


@override_settings(ARCAMITTE_FERNET_KEY=TEST_FERNET_KEY)
class ArcamitteViewsSecurityTestCase(TestCase):
    """
    Pruebas funcionales y de seguridad de controladores, vistas web GUI, API REST y Django Admin.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._temp_media = tempfile.mkdtemp()
        cls._media_override = override_settings(MEDIA_ROOT=cls._temp_media)
        cls._media_override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._media_override.disable()
        shutil.rmtree(cls._temp_media, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.test_content = MINIMAL_TEST_PDF
        self.expected_sha256 = hashlib.sha256(self.test_content).hexdigest().lower()
        self.allowed_email = "titular@empresa.com"

        self.superuser = User.objects.create_superuser(
            username="admin_super",
            email="admin@arcamitte.local",
            password="AdminPassword#2026",
        )
        self.staff_user = User.objects.create_user(
            username="staff_auditor",
            email="auditor@arcamitte.local",
            password="StaffPassword#2026",
            is_staff=True,
        )

        self.uo = OrganizationalUnit.objects.create(
            numeric_code=1001,
            alias="TEST_UO",
            name="Unidad de Pruebas",
            email="test_uo@arcamitte.local",
        )
        UserUOMembership.objects.create(
            user=self.staff_user,
            uo=self.uo,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )

        upload_file = SimpleUploadedFile("expediente_confidencial.pdf", self.test_content)
        self.document = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=[self.allowed_email],
            origin_uo=self.uo,
        )

    # --------------------------------------------------------------------------
    # 1. VISTA DE SOLICITUD (RequestAccessView - /arcamitte/solicitar/)
    # --------------------------------------------------------------------------
    def test_request_access_view_get_empty_and_prefilled(self):
        """GET /arcamitte/solicitar/ permite pre-rellenar ?hash=... por URL."""
        # 1. Sin parámetros
        resp1 = self.client.get(reverse("arcamitte:request-access"))
        self.assertEqual(resp1.status_code, 200)
        self.assertContains(resp1, "Hash SHA-256")
        self.assertNotContains(resp1, 'type="file"')  # Regla 1: Cero transporte de binario

        # 2. Con ?hash=
        resp2 = self.client.get(f"{reverse('arcamitte:request-access')}?hash={self.document.file_hash}")
        self.assertEqual(resp2.status_code, 200)
        self.assertContains(resp2, self.document.file_hash)

    def test_request_access_view_post_valid_redirects_and_sets_session(self):
        """POST con hash y correo autorizados almacena en sesión y redirige a canjear."""
        post_data = {
            "file_hash": self.document.file_hash,
            "email": self.allowed_email,
        }
        resp = self.client.post(reverse("arcamitte:request-access"), post_data)
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("arcamitte:redeem-otp"), resp.url)

        # Comprobar sesión
        session = self.client.session
        self.assertEqual(session.get("arcamitte_file_hash"), self.document.file_hash)
        self.assertEqual(session.get("arcamitte_email"), self.allowed_email)

    def test_request_access_view_post_invalid_hash(self):
        """POST con formato de hash inválido debe retornar 400 Bad Request."""
        post_data = {
            "file_hash": "z" * 64,
            "email": self.allowed_email,
        }
        resp = self.client.post(reverse("arcamitte:request-access"), post_data)
        self.assertEqual(resp.status_code, 400)
        self.assertContains(resp, "64 caracteres hexadecimales", status_code=400)

    @override_settings(ARCAMITTE_WEB_REQUEST_LIMIT_PER_MINUTE=3)
    def test_request_access_view_web_flood_rate_limiting(self):
        """Si una misma IP supera el límite por minuto en Web GUI, recibe HTTP 429 Too Many Requests."""
        cache.clear()
        post_data = {
            "file_hash": self.document.file_hash,
            "email": self.allowed_email,
        }
        for _ in range(3):
            resp = self.client.post(reverse("arcamitte:request-access"), post_data)
            self.assertEqual(resp.status_code, 302)

        resp_flood = self.client.post(reverse("arcamitte:request-access"), post_data)
        self.assertEqual(resp_flood.status_code, 429)
        self.assertContains(resp_flood, "límite de solicitudes", status_code=429)

    # --------------------------------------------------------------------------
    # 2. VISTA DE CANJE (RedeemOtpView - /arcamitte/canjear/)
    # --------------------------------------------------------------------------
    def test_redeem_otp_view_get_without_context_redirects(self):
        """Si el usuario entra a /canjear/ sin hash ni sesión, se le redirige a /solicitar/."""
        resp = self.client.get(reverse("arcamitte:redeem-otp"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("arcamitte:request-access"), resp.url)

    def test_redeem_otp_view_post_success_burn_after_read(self):
        """
        Canje exitoso con OTP válido:
        - Devuelve FileResponse con los bytes descifrados (as_attachment=True).
        - El archivo en disco es destruido (Burn-After-Read).
        """
        # Generar OTP solicitando acceso previamente
        request_document_access(self.document.file_hash, self.allowed_email)
        token = AccessVerificationToken.objects.get(document=self.document, email=self.allowed_email)

        physical_path = self.document.encrypted_file.path
        self.assertTrue(os.path.exists(physical_path))

        post_data = {
            "file_hash": self.document.file_hash,
            "email": self.allowed_email,
            "otp_code": token.otp_code,
        }
        resp = self.client.post(reverse("arcamitte:redeem-otp"), post_data)
        self.assertEqual(resp.status_code, 200)

        # Comprobar FileResponse y cabeceras de descarga
        self.assertEqual(resp["Content-Disposition"], 'attachment; filename="expediente_confidencial.pdf"')
        content = b"".join(resp.streaming_content) if resp.streaming else resp.content
        self.assertEqual(content, self.test_content)

        # Verificar destrucción física en disco
        self.assertFalse(os.path.exists(physical_path))

        # Registro en BD marcado como consumido
        self.document.refresh_from_db()
        self.assertTrue(self.document.is_consumed)
        self.assertEqual(self.document.consumed_by, self.allowed_email)

        # Privacidad y reseteo web estricto: verificar que el correo NO persiste en la sesión
        self.assertIsNone(self.client.session.get("arcamitte_verified_email"))

        # Al volver a /solicitar/, el formulario aparece completamente limpio
        resp_next = self.client.get(reverse("arcamitte:request-access"))
        self.assertEqual(resp_next.status_code, 200)
        self.assertNotContains(resp_next, f'value="{self.allowed_email}"')

    def test_redeem_otp_view_post_wrong_otp(self):
        """Código OTP incorrecto devuelve 400 y mensaje de error con intentos."""
        request_document_access(self.document.file_hash, self.allowed_email)

        post_data = {
            "file_hash": self.document.file_hash,
            "email": self.allowed_email,
            "otp_code": "000000",
        }
        resp = self.client.post(reverse("arcamitte:redeem-otp"), post_data)
        self.assertEqual(resp.status_code, 400)
        self.assertContains(resp, "Código de verificación incorrecto", status_code=400)

    # --------------------------------------------------------------------------
    # 3. PANEL DE ADMINISTRACIÓN (arcamitte/admin.py)
    # --------------------------------------------------------------------------
    def test_admin_change_form_no_password_fields(self):
        """El panel de administración no debe exhibir ningún campo de contraseña."""
        self.client.force_login(self.superuser)
        url = reverse("admin:arcamitte_encrypteddocument_change", args=[self.document.pk])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, 'name="password"')
        self.assertNotContains(resp, 'name="access_code"')
        self.assertNotContains(resp, 'name="encrypted_password"')

    def test_admin_audit_download_permission_denied_for_unauthorized_staff(self):
        """Un usuario staff sin permiso específico no puede realizar descargas de auditoría."""
        self.client.force_login(self.staff_user)
        audit_url = reverse("admin:arcamitte_encrypteddocument_audit_download", args=[self.document.pk])
        resp = self.client.get(audit_url)
        self.assertEqual(resp.status_code, 403)

    def test_admin_audit_download_success_for_authorized_staff(self):
        """El staff con permiso can_audit_download descarga la copia sin destruir el documento."""
        perm = Permission.objects.get(codename="can_audit_download")
        self.staff_user.user_permissions.add(perm)
        self.client.force_login(self.staff_user)

        physical_path = self.document.encrypted_file.path
        audit_url = reverse("admin:arcamitte_encrypteddocument_audit_download", args=[self.document.pk])
        resp = self.client.get(audit_url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("AUDIT_", resp["Content-Disposition"])
        content = b"".join(resp.streaming_content) if resp.streaming else resp.content
        self.assertEqual(content, self.test_content)

        # El archivo en disco NO debe haber sido destruido
        self.assertTrue(os.path.exists(physical_path))
        self.document.refresh_from_db()
        self.assertFalse(self.document.is_consumed)

        # Auditoría registrada
        self.assertTrue(
            DocumentAccessLog.objects.filter(
                document=self.document,
                action=DocumentAccessLog.Action.ADMIN_DESCARGA_PRESERVADA,
            ).exists()
        )

    # --------------------------------------------------------------------------
    # 4. ENDPOINTS API REST (DRF)
    # --------------------------------------------------------------------------
    def test_api_public_request_and_consume_flow(self):
        """Flujo completo vía API REST: request-access y consume con OTP."""
        # 1. Solicitar OTP
        api_req_url = reverse("arcamitte:api-public-request-access")
        resp1 = self.client.post(
            api_req_url,
            {"file_hash": self.document.file_hash, "email": self.allowed_email},
            content_type="application/json",
        )
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp1.json()["status"], "processed")

        # 2. Obtener OTP
        token = AccessVerificationToken.objects.get(document=self.document, email=self.allowed_email)

        # 3. Consumir vía API
        api_consume_url = reverse("arcamitte:api-public-consume")
        resp2 = self.client.post(
            api_consume_url,
            {
                "file_hash": self.document.file_hash,
                "email": self.allowed_email,
                "otp_code": token.otp_code,
            },
            content_type="application/json",
        )
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.content, self.test_content)

    def test_api_public_access_request_rate_limiting(self):
        """El endpoint REST aplica rate limiting (429) al superar el umbral de throttle."""
        from arcamitte.views import AccessRequestRateThrottle

        original_rate = AccessRequestRateThrottle.rate
        try:
            AccessRequestRateThrottle.rate = "2/minute"
            cache.clear()
            api_req_url = reverse("arcamitte:api-public-request-access")
            payload = {"file_hash": self.document.file_hash, "email": self.allowed_email}

            resp1 = self.client.post(api_req_url, payload, content_type="application/json")
            self.assertEqual(resp1.status_code, 200)

            resp2 = self.client.post(api_req_url, payload, content_type="application/json")
            self.assertEqual(resp2.status_code, 200)

            # La 3ª petición supera el límite de 2/minuto
            resp3 = self.client.post(api_req_url, payload, content_type="application/json")
            self.assertEqual(resp3.status_code, 429)
        finally:
            AccessRequestRateThrottle.rate = original_rate
            cache.clear()

    def test_admin_check_file_hash_view(self):
        """
        El endpoint AJAX de verificación previa de hash:
        - Para FIRST_ACCESS no retorna destinatarios pendientes (con que acceda uno finaliza).
        - Para ALL_RECIPIENTS retorna exclusivamente los destinatarios que faltan por descargar.
        """
        self.client.force_login(self.superuser)

        # 1. Documento con FIRST_ACCESS (por defecto)
        self.assertEqual(self.document.burn_policy, EncryptedDocument.BurnPolicy.FIRST_ACCESS)
        url = reverse("admin:arcamitte_encrypteddocument_check_hash") + f"?hash={self.document.file_hash}"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["exists"])
        self.assertFalse(data["is_consumed"])
        self.assertEqual(data["burn_policy"], EncryptedDocument.BurnPolicy.FIRST_ACCESS)
        # En FIRST_ACCESS NO debe haber lista de pendientes
        self.assertEqual(data["pending_recipients"], [])

        # 2. Documento con ALL_RECIPIENTS
        doc_all = upload_and_encrypt_document(
            original_file=SimpleUploadedFile("multi_recipient.pdf", MINIMAL_TEST_PDF + b"%extra_all"),
            allowed_emails=["user1@empresa.com", "user2@empresa.com"],
            burn_policy=EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
            origin_uo=self.uo,
        )
        url_all = reverse("admin:arcamitte_encrypteddocument_check_hash") + f"?hash={doc_all.file_hash}"
        resp_all = self.client.get(url_all)
        data_all = resp_all.json()
        self.assertTrue(data_all["exists"])
        self.assertEqual(data_all["burn_policy"], EncryptedDocument.BurnPolicy.ALL_RECIPIENTS)
        self.assertIn("user1@empresa.com", data_all["pending_recipients"])
        self.assertIn("user2@empresa.com", data_all["pending_recipients"])

        # Si user1 consume su copia en ALL_RECIPIENTS, solo user2 queda pendiente
        request_document_access(doc_all.file_hash, "user1@empresa.com")
        token = AccessVerificationToken.objects.filter(document=doc_all, email="user1@empresa.com", is_used=False).latest("created_at")
        consume_document_with_otp(doc_all.file_hash, "user1@empresa.com", token.otp_code)
        doc_all.refresh_from_db()
        self.assertFalse(doc_all.is_consumed)

        resp_partial = self.client.get(url_all)
        data_partial = resp_partial.json()
        self.assertNotIn("user1@empresa.com", data_partial["pending_recipients"])
        self.assertIn("user2@empresa.com", data_partial["pending_recipients"])

    def test_admin_delete_blocked_by_immutability(self):
        """
        Por principio de inmutabilidad y no repudio legal, el borrado de asientos
        desde Django Admin está estrictamente deshabilitado (has_delete_permission=False
        y EncryptedDocument.delete() lanza PermissionDenied, retornando 403 Forbidden).
        """
        self.client.force_login(self.superuser)
        request_document_access(self.document.file_hash, self.allowed_email)
        physical_path = self.document.encrypted_file.path
        self.assertTrue(os.path.exists(physical_path))

        delete_url = reverse("admin:arcamitte_encrypteddocument_delete", args=[self.document.pk])
        resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(resp.status_code, 403)

        # El documento, los tokens y los logs de auditoría continúan intactos
        self.assertTrue(EncryptedDocument.objects.filter(pk=self.document.pk).exists())
        self.assertEqual(AccessVerificationToken.objects.filter(document_id=self.document.pk).count(), 1)
        self.assertEqual(DocumentAccessLog.objects.filter(document_id=self.document.pk).count(), 1)
        self.assertTrue(os.path.exists(physical_path))

    def test_admin_terminate_document_view_shreds_file_and_creates_vicisitud(self):
        """
        La operación 'Finalizar Asiento' tritura físicamente el archivo cifrado en disco,
        marca el asiento como consumido, conserva el registro y levanta la vicisitud
        FINALIZACION_MANUAL en el log de auditoría.
        """
        self.client.force_login(self.superuser)
        request_document_access(self.document.file_hash, self.allowed_email)
        physical_path = self.document.encrypted_file.path
        self.assertTrue(os.path.exists(physical_path))

        terminate_url = reverse("admin:arcamitte_encrypteddocument_terminate", args=[self.document.pk])

        # 1. GET muestra la pantalla de confirmación con advertencia de irreversibilidad y motivo
        resp_get = self.client.get(terminate_url)
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, "Finalizar Asiento Documental")
        self.assertContains(resp_get, "destruido físicamente de disco")

        # 2. POST ejecuta la finalización con constancia de vicisitud
        resp_post = self.client.post(terminate_url, {"reason": "Trámite confidencial cerrado por acuerdo de partes"})
        self.assertEqual(resp_post.status_code, 302)

        # Verificar que el documento NO fue eliminado de BD (inmutabilidad del asiento)
        doc = EncryptedDocument.objects.get(pk=self.document.pk)
        self.assertTrue(doc.is_consumed)
        self.assertIn("Finalizado manualmente por", doc.consumed_by)
        self.assertIsNotNone(doc.consumed_at)

        # Verificar trituración física en disco
        self.assertFalse(os.path.exists(physical_path))

        # Verificar vicisitud en DocumentAccessLog
        log_vicisitud = DocumentAccessLog.objects.filter(
            document=doc, action=DocumentAccessLog.Action.FINALIZACION_MANUAL
        ).first()
        self.assertIsNotNone(log_vicisitud)
        self.assertIn("Trámite confidencial cerrado por acuerdo de partes", log_vicisitud.details)

    def test_admin_changelist_view_renders_correctly(self):
        """
        La vista de listado de EncryptedDocument en el Admin debe renderizar correctamente
        sin errores de formato (IndexError) para todas las políticas y estados (FIRST_ACCESS, ALL_RECIPIENTS y consumido).
        """
        self.client.force_login(self.superuser)

        # Crear un segundo documento con ALL_RECIPIENTS y consumo parcial
        second_file = SimpleUploadedFile("segundo_doc.pdf", b"%PDF-1.4\nsecond test content\n%%EOF\n")
        doc_all = upload_and_encrypt_document(
            second_file,
            allowed_emails=["u1@test.com", "u2@test.com"],
            burn_policy=EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
        )
        doc_all.consumed_recipients = ["u1@test.com"]
        doc_all.save()

        # Crear un tercer documento consumido para verificar badges y botones de documentos retirados
        third_file = SimpleUploadedFile("tercer_doc.pdf", b"%PDF-1.4\nthird test content\n%%EOF\n")
        doc_consumed = upload_and_encrypt_document(
            third_file,
            allowed_emails=["u3@test.com"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        )
        doc_consumed.is_consumed = True
        doc_consumed.consumed_by = "u3@test.com"
        doc_consumed.save()

        changelist_url = reverse("admin:arcamitte_encrypteddocument_changelist")
        resp = self.client.get(changelist_url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Descargado por 1/2 destinatarios")
        self.assertContains(resp, "1/2 descargados")
        self.assertContains(resp, "Plantilla")
        self.assertContains(resp, "Retirado")
        self.assertContains(resp, "Acciones")
        self.assertContains(resp, "field-actions_column")

        # Verificar también que el panel de auditoría en la vista de detalle de un documento consumido renderiza sin error
        change_consumed_url = reverse("admin:arcamitte_encrypteddocument_change", args=[doc_consumed.pk])
        resp_change = self.client.get(change_consumed_url)
        self.assertEqual(resp_change.status_code, 200)

    def test_admin_widgets_render_responsive_controls(self):
        """Verifica que EmailListAdminWidget y TargetUOWidget rendericen controles responsivos sin overflow."""
        from arcamitte.admin import EmailListAdminWidget, TargetUOWidget

        email_widget = EmailListAdminWidget()
        email_html = email_widget.render("allowed_emails", ["test@empresa.com", "otro@empresa.com"])
        self.assertIn("admin-email-row", email_html)
        self.assertIn("counter_badge", email_html)
        self.assertIn("destinatario", email_html)
        self.assertIn("max-width:520px", email_html)

        uo_widget = TargetUOWidget()
        uo_html = uo_widget.render("target_uo", None)
        self.assertIn("helper_box", uo_html)
        self.assertIn("grid-template-columns", uo_html)
        self.assertIn("btn_uo_members_all", uo_html)
        self.assertIn("specific_members_panel", uo_html)

    def test_admin_change_form_renders_corporate_email_template_and_allows_editing_description(self):
        """
        En el formulario de edición de EncryptedDocument en el Admin:
        - Se renderiza el panel de plantilla con textarea y botón de copiado.
        - Se permite modificar el campo de descripción y éste persiste al guardar.
        """
        self.client.force_login(self.superuser)
        change_url = reverse("admin:arcamitte_encrypteddocument_change", args=[self.document.pk])
        resp = self.client.get(change_url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Plantilla de Notificación por Correo Electrónico")
        self.assertContains(resp, "Copiar texto")
        self.assertContains(resp, self.document.file_hash)
        self.assertContains(resp, self.document.original_filename)

        # Modificar la descripción a través del POST
        log_count = self.document.access_logs.count()
        post_data = {
            "description": "Nueva descripción editada por el administrador",
            "allowed_emails": self.document.allowed_emails,
            "burn_policy": self.document.burn_policy,
            "access_logs-TOTAL_FORMS": str(log_count),
            "access_logs-INITIAL_FORMS": str(log_count),
            "access_logs-MIN_NUM_FORMS": "0",
            "access_logs-MAX_NUM_FORMS": "1000",
            "_save": "Guardar",
        }
        post_resp = self.client.post(change_url, post_data)
        self.assertEqual(post_resp.status_code, 302)

        self.document.refresh_from_db()
        self.assertEqual(self.document.description, "Nueva descripción editada por el administrador")

    def test_audit_log_view_only_user_cannot_delete(self):
        """Un usuario staff con permiso exclusivo de 'view' sobre registros de auditoría no puede eliminarlos."""
        view_only_user = User.objects.create_user(
            username="view_only_auditor",
            email="auditor_view@arcamitte.local",
            password="ViewPassword#2026",
            is_staff=True,
        )
        UserUOMembership.objects.create(
            user=view_only_user,
            uo=self.uo,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )
        perm = Permission.objects.get(codename="view_documentaccesslog")
        view_only_user.user_permissions.add(perm)

        # Crear un registro de auditoría
        request_document_access(self.document.file_hash, self.allowed_email)
        log = DocumentAccessLog.objects.first()
        self.assertIsNotNone(log)

        self.client.force_login(view_only_user)
        # 1. Changelist de logs debe cargar pero sin la acción de eliminación
        resp = self.client.get(reverse("admin:arcamitte_documentaccesslog_changelist"))
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "delete_selected")

        # 2. Intento de eliminación directa debe responder 403 Forbidden
        delete_url = reverse("admin:arcamitte_documentaccesslog_delete", args=[log.pk])
        del_resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(del_resp.status_code, 403)
        self.assertTrue(DocumentAccessLog.objects.filter(pk=log.pk).exists())

    def test_encrypted_document_view_only_user_does_not_see_delete_button_and_cannot_delete(self):
        """Un usuario con permiso exclusivo de lectura sobre EncryptedDocument no ve el botón de eliminar y recibe 403 si intenta borrar."""
        doc_viewer = User.objects.create_user(
            username="doc_viewer_user",
            email="doc_viewer@arcamitte.local",
            password="DocViewerPassword#2026",
            is_staff=True,
        )
        UserUOMembership.objects.create(
            user=doc_viewer,
            uo=self.uo,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )
        perm = Permission.objects.get(codename="view_encrypteddocument")
        doc_viewer.user_permissions.add(perm)

        self.client.force_login(doc_viewer)
        # 1. En el changelist no debe mostrarse el botón de papelera
        resp = self.client.get(reverse("admin:arcamitte_encrypteddocument_changelist"))
        self.assertEqual(resp.status_code, 200)
        delete_url = reverse("admin:arcamitte_encrypteddocument_delete", args=[self.document.pk])
        self.assertNotContains(resp, f'href="{delete_url}"')

        # 2. Intento de borrado directo responde 403 Forbidden
        del_resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(del_resp.status_code, 403)
        self.assertTrue(EncryptedDocument.objects.filter(pk=self.document.pk).exists())

    def test_encrypted_document_delete_blocked_if_user_lacks_permission_on_related_logs(self):
        """Si el usuario tiene permiso para borrar documentos pero no para sus registros relacionados, Django bloquea el borrado."""
        partial_deleter = User.objects.create_user(
            username="partial_deleter_user",
            email="partial@arcamitte.local",
            password="PartialPassword#2026",
            is_staff=True,
        )
        UserUOMembership.objects.create(
            user=partial_deleter,
            uo=self.uo,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )
        perm_delete_doc = Permission.objects.get(codename="delete_encrypteddocument")
        perm_view_doc = Permission.objects.get(codename="view_encrypteddocument")
        partial_deleter.user_permissions.add(perm_delete_doc, perm_view_doc)

        # Crear log asociado
        request_document_access(self.document.file_hash, self.allowed_email)
        self.assertTrue(DocumentAccessLog.objects.filter(document_id=self.document.pk).exists())

        self.client.force_login(partial_deleter)
        delete_url = reverse("admin:arcamitte_encrypteddocument_delete", args=[self.document.pk])
        # Django debe bloquear la eliminación con 403 porque no tiene delete_documentaccesslog ni delete_accessverificationtoken
        resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(resp.status_code, 403)
        self.assertTrue(EncryptedDocument.objects.filter(pk=self.document.pk).exists())

    def test_encrypted_document_delete_blocked_even_with_explicit_permissions(self):
        """
        Incluso si un usuario tiene permisos de borrado asignados en Django Auth,
        el borrado del asiento está estrictamente deshabilitado a nivel de ModelAdmin (has_delete_permission=False)
        y ORM (delete() lanza PermissionDenied), retornando 403 Forbidden.
        """
        doc_deleter = User.objects.create_user(
            username="doc_deleter_user",
            email="doc_deleter@arcamitte.local",
            password="DocDeleterPassword#2026",
            is_staff=True,
        )
        UserUOMembership.objects.create(
            user=doc_deleter,
            uo=self.uo,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )
        perm_delete_doc = Permission.objects.get(codename="delete_encrypteddocument")
        perm_view_doc = Permission.objects.get(codename="view_encrypteddocument")
        perm_delete_log = Permission.objects.get(codename="delete_documentaccesslog")
        perm_delete_tok = Permission.objects.get(codename="delete_accessverificationtoken")
        doc_deleter.user_permissions.add(perm_delete_doc, perm_view_doc, perm_delete_log, perm_delete_tok)

        request_document_access(self.document.file_hash, self.allowed_email)
        self.assertTrue(DocumentAccessLog.objects.filter(document_id=self.document.pk).exists())

        self.client.force_login(doc_deleter)
        delete_url = reverse("admin:arcamitte_encrypteddocument_delete", args=[self.document.pk])
        resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(resp.status_code, 403)
        self.assertTrue(EncryptedDocument.objects.filter(pk=self.document.pk).exists())
        self.assertEqual(DocumentAccessLog.objects.filter(document_id=self.document.pk).count(), 1)

    def test_orm_delete_blocked_by_immutability(self):
        """
        A nivel de modelo ORM, ni EncryptedDocument ni DocumentAccessLog permiten
        ser eliminados directamente mediante .delete(), lanzando PermissionDenied.
        Solo con force_hard_delete=True se permite en casos excepcionales de pruebas.
        """
        with self.assertRaises(PermissionDenied):
            self.document.delete()

        log = DocumentAccessLog.objects.create(
            document=self.document,
            email="audit@empresa.com",
            action=DocumentAccessLog.Action.SOLICITUD_OTP,
        )
        with self.assertRaises(PermissionDenied):
            log.delete()

        # Con force_hard_delete=True se permite la limpieza controlada
        log.delete(force_hard_delete=True)
        self.assertFalse(DocumentAccessLog.objects.filter(pk=log.pk).exists())

    def test_document_default_expiration_two_weeks(self):
        """
        Todo nuevo asiento documental cuenta por defecto con una caducidad de 2 semanas (14 días).
        """
        now = timezone.now()
        self.assertIsNotNone(self.document.expires_at)
        expected_expiry_min = now + timedelta(days=13)
        expected_expiry_max = now + timedelta(days=15)
        self.assertTrue(expected_expiry_min <= self.document.expires_at <= expected_expiry_max)
        self.assertFalse(self.document.is_expired())

    def test_expired_document_access_triggers_auto_closure_and_shredding(self):
        """
        Si un documento ha caducado (expires_at en el pasado) y un usuario solicita acceso,
        el sistema detecta el vencimiento, cierra el asiento, tritura el archivo y registra
        la vicisitud CADUCIDAD_AUTOMATICA.
        """
        physical_path = self.document.encrypted_file.path
        self.assertTrue(os.path.exists(physical_path))

        # Simular vencimiento de plazo
        self.document.expires_at = timezone.now() - timedelta(minutes=10)
        self.document.save(update_fields=["expires_at"])
        self.assertTrue(self.document.is_expired())

        # Intentar solicitar acceso público (redirige a canjear OTP con mensaje de estado)
        resp = self.client.post(
            reverse("arcamitte:request-access"),
            {"file_hash": self.document.file_hash, "email": self.allowed_email},
        )
        self.assertEqual(resp.status_code, 302)

        # Comprobar que el documento se cerró y el archivo se destruyó en disco
        self.document.refresh_from_db()
        self.assertTrue(self.document.is_consumed)
        self.assertIn("Caducidad automática", self.document.consumed_by)
        self.assertFalse(os.path.exists(physical_path))

        # Comprobar registro de vicisitud en auditoría
        expiry_log = DocumentAccessLog.objects.filter(
            document=self.document, action=DocumentAccessLog.Action.CADUCIDAD_AUTOMATICA
        ).first()
        self.assertIsNotNone(expiry_log)
        self.assertIn("vencido su plazo de disponibilidad", expiry_log.details)

        # Cualquier intento de consumo con OTP es rechazado
        success, _, _, msg = consume_document_with_otp(
            file_hash=self.document.file_hash,
            email=self.allowed_email,
            entered_otp="123456",
        )
        self.assertFalse(success)

    def test_i18n_language_switcher_and_page_translations(self):
        """
        Verifica que el cambio de idioma a inglés (en) y español (es) traduzca correctamente
        todos los textos, botones, etiquetas y avisos en las vistas públicas de solicitar y descargar.
        """
        # 1. Cambiar a inglés mediante set-language
        set_lang_url = reverse("arcamitte:set-language")
        resp_lang = self.client.get(f"{set_lang_url}?lang=en&next={reverse('arcamitte:request-access')}")
        self.assertEqual(resp_lang.status_code, 302)
        self.assertEqual(resp_lang.cookies["django_language"].value, "en")

        # 2. Vista solicitar en inglés
        req_url = reverse("arcamitte:request-access")
        resp_en = self.client.get(req_url)
        self.assertEqual(resp_en.status_code, 200)
        self.assertContains(resp_en, "Request Access")
        self.assertContains(resp_en, "Download Document")
        self.assertContains(resp_en, "Secure Document Download")
        self.assertContains(resp_en, "Request verification code")
        self.assertContains(resp_en, "Document Identifier (SHA-256 Hash)")
        self.assertContains(resp_en, "Email Address")

        # 3. Vista descargar en inglés
        redeem_url = reverse("arcamitte:redeem-otp") + f"?hash={self.document.file_hash}&email={self.allowed_email}"
        resp_redeem_en = self.client.get(redeem_url)
        self.assertEqual(resp_redeem_en.status_code, 200)
        self.assertContains(resp_redeem_en, "Document Verification and Download")
        self.assertContains(resp_redeem_en, "Verification Code (6 digits)")
        self.assertContains(resp_redeem_en, "Verify code and download document")
        self.assertContains(resp_redeem_en, "Security notices:")

        # 4. Cambiar a español mediante set-language
        resp_lang_es = self.client.get(f"{set_lang_url}?lang=es&next={reverse('arcamitte:request-access')}")
        self.assertEqual(resp_lang_es.status_code, 302)
        self.assertEqual(resp_lang_es.cookies["django_language"].value, "es")

        # 5. Vista solicitar en español
        resp_es = self.client.get(req_url)
        self.assertEqual(resp_es.status_code, 200)
        self.assertContains(resp_es, "Solicitar Acceso")
        self.assertContains(resp_es, "Descargar Documento")
        self.assertContains(resp_es, "Descarga Segura de Documentos")
        self.assertContains(resp_es, "Solicitar código de verificación")
        self.assertContains(resp_es, "Identificador del Documento (Hash SHA-256)")
        self.assertContains(resp_es, "Correo Electrónico")

        # 6. Vista descargar en español
        resp_redeem_es = self.client.get(redeem_url)
        self.assertEqual(resp_redeem_es.status_code, 200)
        self.assertContains(resp_redeem_es, "Verificación y Descarga de Documento")
        self.assertContains(resp_redeem_es, "Código de Verificación (6 dígitos)")
        self.assertContains(resp_redeem_es, "Verificar código y descargar documento")
        self.assertContains(resp_redeem_es, "Avisos de seguridad:")

    def test_close_expired_documents_management_command(self):
        """
        El comando de gestión 'close_expired_documents' busca asientos caducados y los cierra,
        respetando el flag --dry-run.
        """
        # Crear documento expirado con contenido y hash únicos
        expired_file = SimpleUploadedFile("expirado_unico.pdf", b"%PDF-1.4\nexpired unique content 2026\n%%EOF\n")
        doc_expired = upload_and_encrypt_document(
            expired_file,
            allowed_emails=["exp@test.com"],
            expires_at=timezone.now() - timedelta(days=1),
        )
        exp_path = doc_expired.encrypted_file.path
        self.assertTrue(os.path.exists(exp_path))

        # 1. Ejecutar con --dry-run: no debe modificar nada
        call_command("close_expired_documents", dry_run=True)
        doc_expired.refresh_from_db()
        self.assertFalse(doc_expired.is_consumed)
        self.assertTrue(os.path.exists(exp_path))

        # 2. Ejecutar normalmente: debe cerrar y triturar
        call_command("close_expired_documents")
        doc_expired.refresh_from_db()
        self.assertTrue(doc_expired.is_consumed)
        self.assertFalse(os.path.exists(exp_path))

        # Verificar vicisitud
        vic = DocumentAccessLog.objects.filter(
            document=doc_expired, action=DocumentAccessLog.Action.CADUCIDAD_AUTOMATICA
        ).exists()
        self.assertTrue(vic)

