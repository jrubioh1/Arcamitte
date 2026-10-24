from __future__ import annotations

import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from arcamitte.models import (
    APIToken,
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
    default_document_expiry,
    get_or_create_user_profile,
)
from arcamitte.services import (
    upload_and_encrypt_document,
)

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
        """Verifica el inicio de sesión exitoso: superusuario al selector de modo y usuario regular al dashboard."""
        # 1. Login como Superusuario -> Debe redirigir al Selector de Modo
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
        self.assertContains(response, "Selección de Modo de Trabajo")
        self.assertContains(response, "Gobernanza y Administración")
        self.assertContains(response, "Operativa Documental")

        # 2. Login como Usuario Regular (Operador) -> Directo al Dashboard Operativo
        self.client.logout()
        resp_op = self.client.post(
            reverse("dashboard:login"),
            {
                "username": "operador1",
                "password": "OperatorPassword123!",
            },
            follow=True,
        )
        self.assertEqual(resp_op.status_code, 200)
        self.assertTrue(resp_op.context["user"].is_authenticated)
        self.assertContains(resp_op, "Dashboard Criptográfico")

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

        # Otro usuario regular NO puede verlo (incluso perteneciendo a la misma UO)
        same_uo_user = User.objects.create_user(username="colega_seguridad", email="colega@arcamitte.local", password="Pass123!")
        UserUOMembership.objects.create(user=same_uo_user, uo=self.uo_security, role=UserUOMembership.Role.OPERATOR, is_active=True)
        self.client.force_login(same_uo_user)

        resp_same_list = self.client.get(reverse("dashboard:document_list"))
        self.assertNotContains(resp_same_list, "asiento_personal.pdf")
        resp_same_detail = self.client.get(reverse("dashboard:document_detail", kwargs={"file_hash": created_doc.file_hash}))
        self.assertEqual(resp_same_detail.status_code, 403)

        # Otro usuario de otra UO tampoco
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

    def test_dashboard_user_without_any_uo_operates_standalone(self) -> None:
        """Verifica que un usuario activo sin UO asignada pueda operar en modo personal autónomo."""
        standalone_user = User.objects.create_user(
            username="sin_uo", email="sin_uo@empresa.com", password="Password123!"
        )
        self.client.force_login(standalone_user)

        # 1. Acceso a Home sin errores (0 documentos inicialmente)
        resp_home = self.client.get(reverse("dashboard:home"))
        self.assertEqual(resp_home.status_code, 200)
        self.assertEqual(resp_home.context["total_documents"], 0)

        # 2. Formulario de subida: disponible y contiene modal de confirmación
        resp_upload_page = self.client.get(reverse("dashboard:document_upload"))
        self.assertEqual(resp_upload_page.status_code, 200)
        self.assertEqual(len(resp_upload_page.context["available_origin_uos"]), 0)
        self.assertContains(resp_upload_page, "Ninguna (Asiento Personal Privado)")
        self.assertContains(resp_upload_page, "personalSeatConfirmModal")

        # 3. Subir documento personal
        pdf_file = SimpleUploadedFile("mi_asiento.pdf", b"%PDF-1.4\nStandalone\n%%EOF", content_type="application/pdf")
        post_data = {
            "original_file": pdf_file,
            "origin_uo": "",
            "allowed_emails": "cliente@externo.com",
            "description": "Asiento personal creado por usuario sin UO",
        }
        resp_post = self.client.post(reverse("dashboard:document_upload"), post_data, follow=True)
        self.assertEqual(resp_post.status_code, 200)

        doc = EncryptedDocument.objects.filter(original_filename="mi_asiento.pdf").first()
        self.assertIsNotNone(doc)
        self.assertIsNone(doc.origin_uo)
        self.assertEqual(doc.uploaded_by, standalone_user)

        # 4. Solo ve su propio documento en el listado
        resp_list = self.client.get(reverse("dashboard:document_list"))
        self.assertEqual(resp_list.status_code, 200)
        self.assertContains(resp_list, "mi_asiento.pdf")
        self.assertNotContains(resp_list, "contrato_confidencial.pdf")  # No ve el de Seguridad

        # 5. Puede ver el detalle de su documento
        resp_detail = self.client.get(reverse("dashboard:document_detail", kwargs={"file_hash": doc.file_hash}))
        self.assertEqual(resp_detail.status_code, 200)

        # 6. Intentar ver documento de otra UO devuelve 403
        resp_sec_detail = self.client.get(reverse("dashboard:document_detail", kwargs={"file_hash": self.doc_sec.file_hash}))
        self.assertEqual(resp_sec_detail.status_code, 403)

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

    def test_superuser_mode_selection_and_switch(self) -> None:
        """Verifica que el superusuario pueda seleccionar y conmutar entre Gobernanza y Operativa."""
        self.client.force_login(self.admin_user)

        # GET a selector de modo
        resp_get = self.client.get(reverse("dashboard:mode_selection"))
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, "Gobernanza y Administración")
        self.assertContains(resp_get, "Operativa Documental")

        # Conmutar a modo Operativo vía POST
        resp_post = self.client.post(reverse("dashboard:mode_selection"), {"mode": "operational"}, follow=True)
        self.assertEqual(resp_post.status_code, 200)
        self.assertEqual(self.client.session.get("dashboard_mode"), "operational")

        # En modo operativo, el sidebar oculta secciones complejas de gobernanza global
        self.assertNotContains(resp_post, "API Tokens (M2M)")
        self.assertContains(resp_post, "Modo Operativa")

        # Conmutar de vuelta a modo Gobernanza vía GET query param (?set=governance)
        resp_switch = self.client.get(
            reverse("dashboard:mode_selection") + "?set=governance",
            follow=True,
        )
        self.assertEqual(resp_switch.status_code, 200)
        self.assertEqual(self.client.session.get("dashboard_mode"), "governance")
        self.assertContains(resp_switch, "API Tokens (M2M)")
        self.assertContains(resp_switch, "Usuarios y Accesos")
        self.assertContains(resp_switch, "Modo Gobernanza")

    def test_regular_user_skips_mode_selection(self) -> None:
        """Verifica que un usuario regular no tenga acceso al selector de modo (403)."""
        self.client.force_login(self.operator_user)
        resp = self.client.get(reverse("dashboard:mode_selection"))
        self.assertEqual(resp.status_code, 403)

    def test_superuser_can_create_and_edit_any_uo(self) -> None:
        """Verifica que el superusuario pueda crear y editar cualquier UO."""
        self.client.force_login(self.admin_user)

        # Crear nueva UO
        create_data = {
            "numeric_code": 2001,
            "alias": "AUDITORIA",
            "name": "Departamento de Auditoría Interna",
            "email": "auditoria@arcamitte.local",
            "description": "Inspección y control",
            "is_active": True,
        }
        resp_create = self.client.post(reverse("dashboard:uo_create"), create_data, follow=True)
        self.assertEqual(resp_create.status_code, 200)
        self.assertTrue(OrganizationalUnit.objects.filter(alias="AUDITORIA").exists())

        # Editar UO
        uo_audit = OrganizationalUnit.objects.get(alias="AUDITORIA")
        edit_data = {
            "numeric_code": 2001,
            "alias": "AUDITORIA",
            "name": "Dirección General de Auditoría Interna",
            "email": "auditoria_gral@arcamitte.local",
            "description": "Actualizado por superadmin",
            "is_active": True,
        }
        resp_edit = self.client.post(reverse("dashboard:uo_edit", kwargs={"uo_id": uo_audit.id}), edit_data, follow=True)
        self.assertEqual(resp_edit.status_code, 200)
        uo_audit.refresh_from_db()
        self.assertEqual(uo_audit.name, "Dirección General de Auditoría Interna")

    def test_uo_admin_can_edit_own_uo_but_not_others(self) -> None:
        """Verifica que un Administrador de UO solo modifique su propia UO y no otras."""
        # Crear usuario Admin de Legal
        uo_admin = User.objects.create_user(
            username="admin_legal",
            email="admin_legal@arcamitte.local",
            password="AdminPassword123!",
        )
        UserUOMembership.objects.create(
            user=uo_admin,
            uo=self.uo_legal,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )

        self.client.force_login(uo_admin)

        # 1. Modificar su propia UO (Legal) -> Permitido
        edit_own = {
            "name": "Asesoría Jurídica y Regulatoria",
            "email": "legal_mod@arcamitte.local",
            "description": "Actualizado por admin UO",
        }
        resp_own = self.client.post(reverse("dashboard:uo_edit", kwargs={"uo_id": self.uo_legal.id}), edit_own, follow=True)
        self.assertEqual(resp_own.status_code, 200)
        self.uo_legal.refresh_from_db()
        self.assertEqual(self.uo_legal.name, "Asesoría Jurídica y Regulatoria")

        # 2. Intentar modificar otra UO (Seguridad) -> 403 Forbidden
        resp_other = self.client.get(reverse("dashboard:uo_edit", kwargs={"uo_id": self.uo_security.id}))
        self.assertEqual(resp_other.status_code, 403)

    def test_uo_admin_can_manage_members_in_own_uo(self) -> None:
        """Verifica que un Administrador de UO gestione miembros exclusivamente en su UO."""
        uo_admin = User.objects.create_user(
            username="admin_legal_2",
            email="admin_legal_2@arcamitte.local",
            password="AdminPassword123!",
        )
        UserUOMembership.objects.create(
            user=uo_admin,
            uo=self.uo_legal,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )

        new_user = User.objects.create_user(
            username="nuevo_abogado",
            email="abogado@arcamitte.local",
            password="PassWord123!",
        )

        self.client.force_login(uo_admin)

        # 1. Añadir miembro a UO Legal
        resp_add = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {"action": "add_member", "user_id": new_user.id, "role": UserUOMembership.Role.OPERATOR},
            follow=True,
        )
        self.assertEqual(resp_add.status_code, 200)
        m = UserUOMembership.objects.get(user=new_user, uo=self.uo_legal)
        self.assertEqual(m.role, UserUOMembership.Role.OPERATOR)

        # 2. Modificar rol a Auditor
        self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {"action": "update_role", "membership_id": m.id, "role": UserUOMembership.Role.AUDITOR},
            follow=True,
        )
        m.refresh_from_db()
        self.assertEqual(m.role, UserUOMembership.Role.AUDITOR)

        # 3. Desactivar membresía
        self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {"action": "toggle_active", "membership_id": m.id},
            follow=True,
        )
        m.refresh_from_db()
        self.assertFalse(m.is_active)

        # 4. Intentar gestionar miembros en otra UO (Seguridad) -> 403 Forbidden
        resp_sec = self.client.get(reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_security.id}))
        self.assertEqual(resp_sec.status_code, 403)

    def test_admin_reset_password_flow(self) -> None:
        """Verifica que el reseteo administrativo genere una clave temporal y exija cambio en primer acceso."""
        target_user = User.objects.create_user(
            username="usuario_reset",
            email="reset@arcamitte.local",
            password="InitialPassword123!",
        )

        self.client.force_login(self.admin_user)

        resp = self.client.post(
            reverse("dashboard:user_reset_password", kwargs={"user_id": target_user.id}),
            follow=True,
        )
        self.assertEqual(resp.status_code, 200)

        # Verificar que el perfil tiene must_change_password activo
        profile = get_or_create_user_profile(target_user)
        profile.refresh_from_db()
        self.assertTrue(profile.must_change_password)

    def test_mandatory_password_change_middleware(self) -> None:
        """Verifica que el middleware obligue a cambiar la contraseña a usuarios con clave temporal."""
        temp_user = User.objects.create_user(
            username="temp_user",
            email="temp@arcamitte.local",
            password="OldPassword123!",
        )
        profile = get_or_create_user_profile(temp_user)
        profile.must_change_password = True
        profile.save()

        # Loguear con el usuario
        self.client.force_login(temp_user)

        # Intentar acceder a home -> Debe redirigir a cambiar-password
        resp_home = self.client.get(reverse("dashboard:home"))
        self.assertEqual(resp_home.status_code, 302)
        self.assertEqual(resp_home.url, reverse("dashboard:password_change"))

        # Acceder a la pantalla de cambio de clave
        resp_form = self.client.get(reverse("dashboard:password_change"))
        self.assertEqual(resp_form.status_code, 200)
        self.assertContains(resp_form, "Primer acceso detectado")

        # Enviar actualización con contraseña válida
        resp_change = self.client.post(
            reverse("dashboard:password_change"),
            {
                "current_password": "OldPassword123!",
                "new_password": "NewCompl3xP@ssw0rd!2026",
                "confirm_password": "NewCompl3xP@ssw0rd!2026",
            },
            follow=True,
        )
        self.assertEqual(resp_change.status_code, 200)

        # Verificar que must_change_password es ahora False y accede al dashboard
        profile.refresh_from_db()
        temp_user.refresh_from_db()
        self.assertFalse(profile.must_change_password)
        self.assertTrue(temp_user.check_password("NewCompl3xP@ssw0rd!2026"))

    def test_forgot_password_self_service(self) -> None:
        """Verifica el flujo público de autoservicio '¿Olvidó su contraseña?'."""
        self.client.logout()

        # 1. GET a la pantalla
        resp_get = self.client.get(reverse("dashboard:password_reset_request"))
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, "Restablecer Contraseña")

        # 2. POST con email existente
        resp_post = self.client.post(
            reverse("dashboard:password_reset_request"),
            {"identity": self.operator_user.email},
            follow=True,
        )
        self.assertEqual(resp_post.status_code, 200)
        profile = get_or_create_user_profile(self.operator_user)
        profile.refresh_from_db()
        self.assertTrue(profile.must_change_password)

    def test_django_admin_links_completely_removed_from_ui(self) -> None:
        """Verifica que ningún enlace a Django Admin (/admin/) exista en la interfaz de usuario."""
        self.client.force_login(self.admin_user)

        # Cargar home en modo gobernanza
        resp_home = self.client.get(reverse("dashboard:home"))
        self.assertEqual(resp_home.status_code, 200)
        self.assertNotContains(resp_home, "href=\"/admin/\"")
        self.assertNotContains(resp_home, "href=\"/admin\"")
        self.assertNotContains(resp_home, "Django Admin Clásico")
        self.assertNotContains(resp_home, "Django Admin")

        # Cargar pantalla de login
        self.client.logout()
        resp_login = self.client.get(reverse("dashboard:login"))
        self.assertNotContains(resp_login, "/admin")

    def test_dashboard_full_i18n_translation_english_and_spanish(self) -> None:
        """Verifica que la interfaz se traduzca al 100% al cambiar a idioma inglés."""
        self.client.force_login(self.admin_user)

        # 1. Cambiar a inglés
        self.client.get(reverse("arcamitte:set-language") + "?lang=en&next=" + reverse("dashboard:home"))

        # 2. Cargar home en inglés
        resp_home = self.client.get(reverse("dashboard:home"))
        self.assertEqual(resp_home.status_code, 200)
        self.assertContains(resp_home, "Cryptographic Dashboard")
        self.assertContains(resp_home, "Encrypt Record")
        self.assertContains(resp_home, "Forensic Traceability")
        self.assertContains(resp_home, "Organizational Units")
        self.assertContains(resp_home, "Users and Access")

        # 3. Cargar selector de modo en inglés
        resp_mode = self.client.get(reverse("dashboard:mode_selection"))
        self.assertEqual(resp_mode.status_code, 200)
        self.assertContains(resp_mode, "Entry Mode Selection")
        self.assertContains(resp_mode, "Governance and Administration")
        self.assertContains(resp_mode, "Document Operations")

