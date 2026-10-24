from __future__ import annotations

import io
import shutil
import tempfile
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from arcamitte.models import (
    APIToken,
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
    default_document_expiry,
)
from arcamitte.services import upload_and_encrypt_document

User = get_user_model()


class DashboardTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._temp_media = tempfile.mkdtemp(prefix="arca_test_dash_")
        cls._media_override = override_settings(MEDIA_ROOT=cls._temp_media)
        cls._media_override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._media_override.disable()
        shutil.rmtree(cls._temp_media, ignore_errors=True)
        super().tearDownClass()

    def setUp(self) -> None:
        super().setUp()
        # Superuser
        self.admin_user = User.objects.create_superuser(
            username="superadmin",
            email="superadmin@arcamitte.local",
            password="StrongPassword123!",
        )

        # Regular operator user
        self.operator_user = User.objects.create_user(
            username="operador1",
            email="operador1@arcamitte.local",
            password="OperatorPassword123!",
        )

        # UOs
        self.uo_security = OrganizationalUnit.objects.create(
            numeric_code=1001,
            alias="SEGURIDAD",
            name="Departamento de Seguridad de la Información",
            email="seguridad@arcamitte.local",
            is_active=True,
        )
        self.uo_legal = OrganizationalUnit.objects.create(
            numeric_code=1002,
            alias="LEGAL",
            name="Asesoría Jurídica y Cumplimiento",
            email="legal@arcamitte.local",
            is_active=True,
        )

        # Operator membership in Security UO
        UserUOMembership.objects.create(
            user=self.operator_user,
            uo=self.uo_security,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        # Sample PDF file
        self.sample_pdf = SimpleUploadedFile(
            "contrato_confidencial.pdf",
            b"%PDF-1.4\n1 0 obj\n<< /Title (Confidential) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF",
            content_type="application/pdf",
        )

        # Pre-create a document in Security UO
        self.doc_sec = upload_and_encrypt_document(
            original_file=self.sample_pdf,
            allowed_emails=["auditor@empresa.com", "director@empresa.com"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            description="Documento de seguridad interna",
            origin_uo=self.uo_security,
            uploaded_by=self.operator_user,
        )

    def test_dashboard_login_page_renders(self) -> None:
        """Verifica que la página de login de Arcamitte se renderice correctamente."""
        response = self.client.get(reverse("dashboard:login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Arcamitte")
        self.assertContains(response, "csrfmiddlewaretoken")

    def test_dashboard_login_successful(self) -> None:
        """Verifica el inicio de sesión exitoso y la redirección al dashboard."""
        response = self.client.post(
            reverse("dashboard:login"),
            {
                "username": "superadmin",
                "password": "StrongPassword123!",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["user"].is_authenticated)
        self.assertContains(response, "Dashboard Criptográfico")

    def test_dashboard_home_requires_login(self) -> None:
        """Verifica que usuarios anónimos sean redirigidos al login."""
        response = self.client.get(reverse("dashboard:home"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("dashboard:login"), response.url)

    def test_dashboard_home_authenticated(self) -> None:
        """Verifica que el dashboard presente las métricas y enlaces principales."""
        self.client.force_login(self.admin_user)
        response = self.client.get(reverse("dashboard:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Total Asientos")
        self.assertContains(response, "Asientos Activos")
        self.assertContains(response, self.doc_sec.file_hash[:16])

    def test_dashboard_document_list_and_search(self) -> None:
        """Verifica el listado de documentos y la búsqueda por texto y estado."""
        self.client.force_login(self.admin_user)

        # Listado completo
        response = self.client.get(reverse("dashboard:document_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "contrato_confidencial.pdf")

        # Búsqueda por texto (éxito)
        response_found = self.client.get(reverse("dashboard:document_list") + "?q=contrato")
        self.assertContains(response_found, "contrato_confidencial.pdf")

        # Búsqueda por texto (sin resultados)
        response_empty = self.client.get(reverse("dashboard:document_list") + "?q=inexistente")
        self.assertContains(response_empty, "No se encontraron asientos")

        # Filtro por estado activo
        response_active = self.client.get(reverse("dashboard:document_list") + "?status=active")
        self.assertContains(response_active, "contrato_confidencial.pdf")

    def test_dashboard_document_upload_success(self) -> None:
        """Verifica el cifrado y registro de un nuevo documento desde el portal AdminKit."""
        self.client.force_login(self.admin_user)

        new_pdf = SimpleUploadedFile(
            "auditoria_q3.pdf",
            b"%PDF-1.4\nAuditoria confidencial\n%%EOF",
            content_type="application/pdf",
        )

        post_data = {
            "original_file": new_pdf,
            "origin_uo": self.uo_security.id,
            "target_uo": self.uo_legal.id,
            "allowed_emails": "interesado1@empresa.com, interesado2@empresa.com",
            "description": "Informe trimestral de auditoría para Asesoría Jurídica",
            "burn_policy": EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
            "expires_at": default_document_expiry().strftime("%Y-%m-%dT%H:%M"),
        }

        response = self.client.post(reverse("dashboard:document_upload"), post_data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Asiento cifrado con éxito")

        # Comprobar en base de datos
        created_doc = EncryptedDocument.objects.filter(original_filename="auditoria_q3.pdf").first()
        self.assertIsNotNone(created_doc)
        self.assertEqual(created_doc.origin_uo, self.uo_security)
        self.assertEqual(created_doc.target_uo, self.uo_legal)
        self.assertEqual(len(created_doc.allowed_emails), 2)
        self.assertEqual(created_doc.burn_policy, EncryptedDocument.BurnPolicy.ALL_RECIPIENTS)

    def test_dashboard_document_upload_validation_error(self) -> None:
        """Verifica que se muestren errores si faltan datos o el formato es inválido."""
        self.client.force_login(self.operator_user)

        # 1. Sin archivo y correo inválido
        bad_data = {
            "origin_uo": "",
            "allowed_emails": "email-invalido",
        }
        response = self.client.post(reverse("dashboard:document_upload"), bad_data)
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Debe seleccionar un archivo confidencial", status_code=400)

        # 2. Operador intenta emitir desde una UO donde no tiene membresía
        new_pdf = SimpleUploadedFile("doc.pdf", b"%PDF-1.4\nTest\n%%EOF", content_type="application/pdf")
        unauth_uo_data = {
            "original_file": new_pdf,
            "origin_uo": self.uo_legal.id,  # El operador solo pertenece a Seguridad
            "allowed_emails": "valido@empresa.com",
        }
        resp_unauth = self.client.post(reverse("dashboard:document_upload"), unauth_uo_data)
        self.assertEqual(resp_unauth.status_code, 400)
        self.assertContains(resp_unauth, "No tiene autorización operativa sobre la UO emisora seleccionada", status_code=400)

    def test_dashboard_document_upload_personal_seat(self) -> None:
        """Verifica que un documento sin UO emisora sea un asiento personal privado solo visible por su autor."""
        self.client.force_login(self.operator_user)

        personal_pdf = SimpleUploadedFile("asiento_personal.pdf", b"%PDF-1.4\nPersonal\n%%EOF", content_type="application/pdf")
        post_data = {
            "original_file": personal_pdf,
            "origin_uo": "",  # Sin UO -> Asiento Personal Privado
            "allowed_emails": "destinatario@externo.com",
            "description": "Asiento personal privado",
        }
        response = self.client.post(reverse("dashboard:document_upload"), post_data, follow=True)
        self.assertEqual(response.status_code, 200)

        created_doc = EncryptedDocument.objects.filter(original_filename="asiento_personal.pdf").first()
        self.assertIsNotNone(created_doc)
        self.assertIsNone(created_doc.origin_uo)
        self.assertEqual(created_doc.uploaded_by, self.operator_user)

        # El autor puede verlo en el listado y detalle
        resp_list = self.client.get(reverse("dashboard:document_list"))
        self.assertContains(resp_list, "asiento_personal.pdf")
        resp_detail = self.client.get(reverse("dashboard:document_detail", kwargs={"file_hash": created_doc.file_hash}))
        self.assertEqual(resp_detail.status_code, 200)

        # Otro usuario regular NO puede verlo
        other_user = User.objects.create_user(username="otro_operador", email="otro@empresa.com", password="Pass123!")
        UserUOMembership.objects.create(user=other_user, uo=self.uo_legal, role=UserUOMembership.Role.OPERATOR, is_active=True)
        self.client.force_login(other_user)

        resp_other_list = self.client.get(reverse("dashboard:document_list"))
        self.assertNotContains(resp_other_list, "asiento_personal.pdf")
        resp_other_detail = self.client.get(reverse("dashboard:document_detail", kwargs={"file_hash": created_doc.file_hash}))
        self.assertEqual(resp_other_detail.status_code, 403)

        # El superusuario SÍ puede verlo
        self.client.force_login(self.admin_user)
        resp_admin_list = self.client.get(reverse("dashboard:document_list"))
        self.assertContains(resp_admin_list, "asiento_personal.pdf")
        resp_admin_detail = self.client.get(reverse("dashboard:document_detail", kwargs={"file_hash": created_doc.file_hash}))
        self.assertEqual(resp_admin_detail.status_code, 200)

    def test_dashboard_document_upload_multiple_individual_emails(self) -> None:
        """Verifica que se reciban múltiples campos individuales de correo (POST getlist)."""
        self.client.force_login(self.admin_user)
        multi_pdf = SimpleUploadedFile("multi_email.pdf", b"%PDF-1.4\nMulti\n%%EOF", content_type="application/pdf")
        post_data = {
            "original_file": multi_pdf,
            "origin_uo": self.uo_security.id,
            "allowed_emails": ["primero@empresa.com", "segundo@empresa.com", "tercero@empresa.com"],
        }
        resp = self.client.post(reverse("dashboard:document_upload"), post_data, follow=True)
        self.assertEqual(resp.status_code, 200)
        doc = EncryptedDocument.objects.filter(original_filename="multi_email.pdf").first()
        self.assertIsNotNone(doc)
        self.assertEqual(set(doc.allowed_emails), {"primero@empresa.com", "segundo@empresa.com", "tercero@empresa.com"})

    def test_dashboard_uo_members_ajax(self) -> None:
        """Verifica que el endpoint AJAX retorne los miembros y buzón de una UO."""
        self.client.force_login(self.operator_user)
        resp = self.client.get(reverse("dashboard:uo_members_ajax", kwargs={"uo_id": self.uo_security.id}))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["uo_alias"], "SEGURIDAD")
        self.assertEqual(data["uo_email"], "seguridad@arcamitte.local")
        self.assertEqual(len(data["members"]), 1)
        self.assertEqual(data["members"][0]["username"], "operador1")
        self.assertEqual(data["members"][0]["email"], "operador1@arcamitte.local")

    def test_dashboard_document_detail_view(self) -> None:
        """Verifica la visualización de metadatos, estado de canje y trazas forenses."""
        self.client.force_login(self.admin_user)

        response = self.client.get(reverse("dashboard:document_detail", kwargs={"file_hash": self.doc_sec.file_hash}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.doc_sec.file_hash)
        self.assertContains(response, "auditor@empresa.com")
        self.assertContains(response, "director@empresa.com")
        self.assertContains(response, "Trazabilidad Forense")

    def test_dashboard_document_terminate_flow(self) -> None:
        """Verifica el flujo de clausura y destrucción física anticipada."""
        self.client.force_login(self.admin_user)

        # GET confirmación
        resp_get = self.client.get(reverse("dashboard:document_terminate", kwargs={"file_hash": self.doc_sec.file_hash}))
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, "Confirmación Obligatoria de Clausura")

        # POST sin justificación (error 400)
        resp_bad = self.client.post(reverse("dashboard:document_terminate", kwargs={"file_hash": self.doc_sec.file_hash}), {})
        self.assertEqual(resp_bad.status_code, 400)
        self.assertContains(resp_bad, "Debe proporcionar un motivo justificado", status_code=400)

        # POST con justificación válida
        resp_post = self.client.post(
            reverse("dashboard:document_terminate", kwargs={"file_hash": self.doc_sec.file_hash}),
            {"justification": "Revocación por término de expediente."},
            follow=True,
        )
        self.assertEqual(resp_post.status_code, 200)
        self.assertContains(resp_post, "Asiento terminado con éxito")

        # Comprobar estado en base de datos
        self.doc_sec.refresh_from_db()
        self.assertTrue(self.doc_sec.is_consumed)
        self.assertFalse(self.doc_sec.is_active)

    def test_dashboard_audit_logs_view(self) -> None:
        """Verifica la visualización y filtrado del log de auditoría."""
        self.client.force_login(self.admin_user)

        DocumentAccessLog.objects.create(
            document=self.doc_sec,
            email="auditor@empresa.com",
            action=DocumentAccessLog.Action.OTP_ENVIADO,
            details="Código de verificación enviado",
            ip_address="192.168.1.100",
        )

        response = self.client.get(reverse("dashboard:audit_logs"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Trazabilidad Forense")
        self.assertContains(response, "192.168.1.100")

        # Filtrar por acción OTP_ENVIADO
        resp_filter = self.client.get(reverse("dashboard:audit_logs") + f"?action={DocumentAccessLog.Action.OTP_ENVIADO}")
        self.assertEqual(resp_filter.status_code, 200)
        self.assertContains(resp_filter, "Código de verificación enviado")

    def test_dashboard_uo_list_view(self) -> None:
        """Verifica el directorio de Unidades Organizativas."""
        self.client.force_login(self.admin_user)

        response = self.client.get(reverse("dashboard:uo_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "1001")
        self.assertContains(response, "SEGURIDAD")
        self.assertContains(response, "1002")
        self.assertContains(response, "LEGAL")

    def test_dashboard_api_tokens_view_and_generation(self) -> None:
        """Verifica la emisión de API tokens M2M y la visualización única de la clave."""
        self.client.force_login(self.admin_user)

        # Listado inicial
        resp_list = self.client.get(reverse("dashboard:api_tokens"))
        self.assertEqual(resp_list.status_code, 200)

        # Generar nuevo token
        post_data = {
            "name": "Microservicio ERP Corporativo",
            "scopes": ["documents:create", "documents:read"],
            "rate_limit": 120,
            "validity_days": 180,
        }
        resp_create = self.client.post(reverse("dashboard:api_tokens"), post_data, follow=True)
        self.assertEqual(resp_create.status_code, 200)
        self.assertContains(resp_create, "fdec_live_")
        self.assertContains(resp_create, "Microservicio ERP Corporativo")

        token_obj = APIToken.objects.get(name="Microservicio ERP Corporativo")
        self.assertTrue(token_obj.is_active)

        # Revocar token
        resp_revoke = self.client.post(
            reverse("dashboard:api_token_revoke", kwargs={"token_id": token_obj.id}),
            follow=True,
        )
        self.assertEqual(resp_revoke.status_code, 200)
        token_obj.refresh_from_db()
        self.assertFalse(token_obj.is_active)

    def test_dashboard_departmental_isolation(self) -> None:
        """Verifica que un operador solo acceda a los documentos de sus UOs autorizadas."""
        # Crear documento en UO Legal
        doc_legal = upload_and_encrypt_document(
            original_file=SimpleUploadedFile("legal.pdf", b"%PDF-1.4\nLegal\n%%EOF", content_type="application/pdf"),
            allowed_emails=["abogado@empresa.com"],
            origin_uo=self.uo_legal,
            uploaded_by=self.admin_user,
        )

        # Loguear como operador de Seguridad (no tiene membresía en Legal)
        self.client.force_login(self.operator_user)

        # En listado no debe aparecer el documento de Legal
        resp_list = self.client.get(reverse("dashboard:document_list"))
        self.assertEqual(resp_list.status_code, 200)
        self.assertContains(resp_list, "contrato_confidencial.pdf")
        self.assertNotContains(resp_list, "legal.pdf")

        # Intentar acceder al detalle del documento de Legal debe devolver 403 Forbidden
        resp_detail = self.client.get(reverse("dashboard:document_detail", kwargs={"file_hash": doc_legal.file_hash}))
        self.assertEqual(resp_detail.status_code, 403)
