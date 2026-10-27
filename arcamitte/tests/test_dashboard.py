from __future__ import annotations

import os
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
        # 1. Login como Superusuario -> Con 2FA obligatorio por diseño:
        # En el primer paso con credenciales primarias, se redirige a verificación TOTP
        resp_preauth = self.client.post(
            reverse("dashboard:login"),
            {
                "username": "superadmin",
                "password": "StrongPassword123!",
            },
        )
        self.assertEqual(resp_preauth.status_code, 302)
        self.assertIn(reverse("dashboard:totp_verify"), resp_preauth.url)

        # Configurar 2FA para superadmin y completar segundo factor
        from arcamitte.models import get_or_create_user_profile
        from arcamitte.totp import generate_totp_code

        profile = get_or_create_user_profile(self.admin_user)
        test_secret = "JBSWY3DPEHPK3PXP"
        profile.enable_totp(secret=test_secret, scratch_hashes=[])

        valid_totp = generate_totp_code(test_secret)
        response = self.client.post(
            reverse("dashboard:totp_verify"),
            {"code": valid_totp},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["user"].is_authenticated)
        self.assertContains(response, "Dashboard Criptográfico")
        self.assertContains(response, "Modo Gobernanza")
        self.assertContains(response, "Modo Operativa")
        self.assertNotContains(response, "Cambiar Modo de Inicio")

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
        response_found = self.client.get(
            reverse("dashboard:document_list") + "?q=contrato"
        )
        self.assertContains(response_found, "contrato_confidencial.pdf")

        # Búsqueda por texto (sin resultados)
        response_empty = self.client.get(
            reverse("dashboard:document_list") + "?q=inexistente"
        )
        self.assertContains(response_empty, "No se encontraron asientos")

        # Filtro por estado activo
        response_active = self.client.get(
            reverse("dashboard:document_list") + "?status=active"
        )
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

        response = self.client.post(
            reverse("dashboard:document_upload"), post_data, follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Asiento cifrado con éxito")

        # Comprobar en base de datos
        created_doc = EncryptedDocument.objects.filter(
            original_filename="auditoria_q3.pdf"
        ).first()
        self.assertIsNotNone(created_doc)
        self.assertEqual(created_doc.origin_uo, self.uo_security)
        self.assertEqual(created_doc.target_uo, self.uo_legal)
        self.assertEqual(len(created_doc.allowed_emails), 2)
        self.assertEqual(
            created_doc.burn_policy, EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
        )

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
        self.assertContains(
            response, "Debe seleccionar un archivo confidencial", status_code=400
        )

        # 2. Operador intenta emitir desde una UO donde no tiene membresía
        new_pdf = SimpleUploadedFile(
            "doc.pdf", b"%PDF-1.4\nTest\n%%EOF", content_type="application/pdf"
        )
        unauth_uo_data = {
            "original_file": new_pdf,
            "origin_uo": self.uo_legal.id,  # El operador solo pertenece a Seguridad
            "allowed_emails": "valido@empresa.com",
        }
        resp_unauth = self.client.post(
            reverse("dashboard:document_upload"), unauth_uo_data
        )
        self.assertEqual(resp_unauth.status_code, 400)
        self.assertContains(
            resp_unauth,
            "No tiene autorización operativa sobre la UO emisora seleccionada",
            status_code=400,
        )

    def test_dashboard_auditor_can_upload_documents(self) -> None:
        """Verifica que un usuario con rol de Auditor en una UO pueda cifrar y emitir documentos de su UO."""
        auditor_user = User.objects.create_user(
            username="auditor_emisor",
            email="auditor_emisor@arcamitte.local",
            password="AuditorPass123!",
        )
        UserUOMembership.objects.create(
            user=auditor_user,
            uo=self.uo_security,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )

        self.client.force_login(auditor_user)

        pdf_file = SimpleUploadedFile(
            "auditoria_fiscal.pdf",
            b"%PDF-1.4\nInforme Auditoria Fiscal 2026\n%%EOF",
            content_type="application/pdf",
        )
        post_data = {
            "original_file": pdf_file,
            "origin_uo": self.uo_security.id,
            "allowed_emails": "fiscalia@hacienda.gob.es",
            "description": "Documento subido por el auditor de la UO",
            "burn_policy": EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        }
        resp = self.client.post(
            reverse("dashboard:document_upload"), post_data, follow=True
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Asiento cifrado con éxito")

        doc = EncryptedDocument.objects.filter(
            original_filename="auditoria_fiscal.pdf"
        ).first()
        self.assertIsNotNone(doc)
        self.assertEqual(doc.origin_uo, self.uo_security)
        self.assertEqual(doc.uploaded_by, auditor_user)

    def test_dashboard_document_upload_personal_seat(self) -> None:
        """Verifica que un documento sin UO emisora sea un asiento personal privado solo visible por su autor."""
        self.client.force_login(self.operator_user)

        personal_pdf = SimpleUploadedFile(
            "asiento_personal.pdf",
            b"%PDF-1.4\nPersonal\n%%EOF",
            content_type="application/pdf",
        )
        post_data = {
            "original_file": personal_pdf,
            "origin_uo": "",  # Sin UO -> Asiento Personal Privado
            "allowed_emails": "destinatario@externo.com",
            "description": "Asiento personal privado",
        }
        response = self.client.post(
            reverse("dashboard:document_upload"), post_data, follow=True
        )
        self.assertEqual(response.status_code, 200)

        created_doc = EncryptedDocument.objects.filter(
            original_filename="asiento_personal.pdf"
        ).first()
        self.assertIsNotNone(created_doc)
        self.assertIsNone(created_doc.origin_uo)
        self.assertEqual(created_doc.uploaded_by, self.operator_user)

        # El autor puede verlo en el listado y detalle
        resp_list = self.client.get(reverse("dashboard:document_list"))
        self.assertContains(resp_list, "asiento_personal.pdf")
        resp_detail = self.client.get(
            reverse(
                "dashboard:document_detail", kwargs={"file_hash": created_doc.file_hash}
            )
        )
        self.assertEqual(resp_detail.status_code, 200)

        # Otro usuario regular NO puede verlo (incluso perteneciendo a la misma UO)
        same_uo_user = User.objects.create_user(
            username="colega_seguridad",
            email="colega@arcamitte.local",
            password="Pass123!",
        )
        UserUOMembership.objects.create(
            user=same_uo_user,
            uo=self.uo_security,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )
        self.client.force_login(same_uo_user)

        resp_same_list = self.client.get(reverse("dashboard:document_list"))
        self.assertNotContains(resp_same_list, "asiento_personal.pdf")
        resp_same_detail = self.client.get(
            reverse(
                "dashboard:document_detail", kwargs={"file_hash": created_doc.file_hash}
            )
        )
        self.assertEqual(resp_same_detail.status_code, 403)

        # Otro usuario de otra UO tampoco
        other_user = User.objects.create_user(
            username="otro_operador", email="otro@empresa.com", password="Pass123!"
        )
        UserUOMembership.objects.create(
            user=other_user,
            uo=self.uo_legal,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )
        self.client.force_login(other_user)

        resp_other_list = self.client.get(reverse("dashboard:document_list"))
        self.assertNotContains(resp_other_list, "asiento_personal.pdf")
        resp_other_detail = self.client.get(
            reverse(
                "dashboard:document_detail", kwargs={"file_hash": created_doc.file_hash}
            )
        )
        self.assertEqual(resp_other_detail.status_code, 403)

        # El superusuario SÍ puede verlo
        self.client.force_login(self.admin_user)
        resp_admin_list = self.client.get(reverse("dashboard:document_list"))
        self.assertContains(resp_admin_list, "asiento_personal.pdf")
        resp_admin_detail = self.client.get(
            reverse(
                "dashboard:document_detail", kwargs={"file_hash": created_doc.file_hash}
            )
        )
        self.assertEqual(resp_admin_detail.status_code, 200)

    def test_dashboard_document_upload_duplicate_hash_reactivates_seat_and_preserves_logs(
        self,
    ) -> None:
        """
        Verifica que al subir un archivo con un hash SHA-256 ya existente en el sistema:
        1. No se lance ValidationError ni error 500.
        2. Se reactive automáticamente el asiento, re-cifrando en disco y actualizando destinatarios.
        3. Se preserve íntegramente todo el historial previo en DocumentAccessLog.
        4. Se registre la nueva vicisitud de reactivación en la auditoría.
        """
        self.client.force_login(self.operator_user)

        sample_pdf_bytes = b"%PDF-1.4\nContenido Unico Reutilizable 2026\n%%EOF"
        first_pdf = SimpleUploadedFile(
            "expediente_reapertura.pdf",
            sample_pdf_bytes,
            content_type="application/pdf",
        )

        # 1. Primera subida
        post_data_1 = {
            "original_file": first_pdf,
            "origin_uo": self.uo_security.id,
            "target_uo": self.uo_legal.id,
            "allowed_emails": "destinatario_antiguo@empresa.com",
            "description": "Primera remesa del expediente",
            "burn_policy": EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        }
        resp1 = self.client.post(
            reverse("dashboard:document_upload"), post_data_1, follow=True
        )
        self.assertEqual(resp1.status_code, 200)
        self.assertContains(resp1, "Asiento cifrado con éxito")

        doc = EncryptedDocument.objects.get(
            original_filename="expediente_reapertura.pdf"
        )
        initial_pk = doc.pk
        initial_hash = doc.file_hash

        # Simular que el documento fue consumido y tiene registros de auditoría previos
        doc.is_consumed = True
        doc.consumed_by = "consumidor@empresa.com"
        doc.consumed_at = timezone.now()
        doc.save()

        DocumentAccessLog.objects.create(
            document=doc,
            email="consumidor@empresa.com",
            action=DocumentAccessLog.Action.DESCIFRADO_EXITOSO_BURN,
            origin_uo=doc.origin_uo,
            target_uo=doc.target_uo,
            ip_address="192.168.1.10",
            details="Primer canje exitoso antes del cierre",
        )
        prev_logs_count = DocumentAccessLog.objects.filter(document=doc).count()
        self.assertGreaterEqual(prev_logs_count, 1)

        # 2. Segunda subida con el mismo archivo exacto (mismo hash SHA-256) y nuevos destinatarios
        second_pdf = SimpleUploadedFile(
            "expediente_reapertura.pdf",
            sample_pdf_bytes,
            content_type="application/pdf",
        )
        post_data_2 = {
            "original_file": second_pdf,
            "origin_uo": self.uo_security.id,
            "target_uo": self.uo_legal.id,
            "allowed_emails": "nuevo_destinatario_1@empresa.com, nuevo_destinatario_2@empresa.com",
            "description": "Segunda remesa reactivada del expediente",
            "burn_policy": EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
        }
        resp2 = self.client.post(
            reverse("dashboard:document_upload"), post_data_2, follow=True
        )
        self.assertEqual(resp2.status_code, 200)

        # Verificar mensaje informativo de reactivación
        self.assertContains(resp2, "Asiento existente reactivado con éxito")

        # Verificar que el documento reactivado mantiene el mismo PK y hash
        doc.refresh_from_db()
        self.assertEqual(doc.pk, initial_pk)
        self.assertEqual(doc.file_hash, initial_hash)

        # El asiento vuelve a estar activo y disponible
        self.assertFalse(doc.is_consumed)
        self.assertIsNone(doc.consumed_by)
        self.assertIsNone(doc.consumed_at)

        # Los destinatarios han sido actualizados
        self.assertEqual(
            doc.allowed_emails,
            ["nuevo_destinatario_1@empresa.com", "nuevo_destinatario_2@empresa.com"],
        )
        self.assertEqual(doc.description, "Segunda remesa reactivada del expediente")

        # El historial anterior de auditoría sigue intacto + nueva vicisitud de reactivación
        current_logs = DocumentAccessLog.objects.filter(document=doc)
        self.assertGreater(current_logs.count(), prev_logs_count)
        self.assertTrue(
            current_logs.filter(
                action=DocumentAccessLog.Action.DESCIFRADO_EXITOSO_BURN
            ).exists()
        )
        self.assertTrue(
            current_logs.filter(
                action=DocumentAccessLog.Action.REACTIVACION_DOCUMENTO
            ).exists()
        )

    def test_dashboard_document_upload_duplicate_hash_denied_for_other_uo(self) -> None:
        """
        Verifica que si un usuario de una UO distinta intenta reactivar un documento
        perteneciente a otra UO, se rechace con ValidationError defensivo (status 400).
        """
        # Usuario de UO Legal
        legal_user = User.objects.create_user(
            username="operador_legal_hijack",
            email="legal_hijack@arcamitte.local",
            password="Password123!",
        )
        UserUOMembership.objects.create(
            user=legal_user,
            uo=self.uo_legal,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        self.client.force_login(legal_user)

        # Intentar subir el mismo contenido de doc_sec (que pertenece a Seguridad)
        hijack_file = SimpleUploadedFile(
            "expediente_sec.pdf",
            b"%PDF-1.4\n1 0 obj\n<< /Title (Confidential) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF",
            content_type="application/pdf",
        )
        post_data = {
            "original_file": hijack_file,
            "origin_uo": self.uo_legal.id,
            "allowed_emails": "atacante@externo.com",
            "description": "Intento de reactivacion cruzada no autorizada",
        }
        resp = self.client.post(reverse("dashboard:document_upload"), post_data)
        self.assertEqual(resp.status_code, 400)
        self.assertContains(
            resp, "pertenece a otra Unidad Organizativa", status_code=400
        )

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
        pdf_file = SimpleUploadedFile(
            "mi_asiento.pdf",
            b"%PDF-1.4\nStandalone\n%%EOF",
            content_type="application/pdf",
        )
        post_data = {
            "original_file": pdf_file,
            "origin_uo": "",
            "allowed_emails": "cliente@externo.com",
            "description": "Asiento personal creado por usuario sin UO",
        }
        resp_post = self.client.post(
            reverse("dashboard:document_upload"), post_data, follow=True
        )
        self.assertEqual(resp_post.status_code, 200)

        doc = EncryptedDocument.objects.filter(
            original_filename="mi_asiento.pdf"
        ).first()
        self.assertIsNotNone(doc)
        self.assertIsNone(doc.origin_uo)
        self.assertEqual(doc.uploaded_by, standalone_user)

        # 4. Solo ve su propio documento en el listado
        resp_list = self.client.get(reverse("dashboard:document_list"))
        self.assertEqual(resp_list.status_code, 200)
        self.assertContains(resp_list, "mi_asiento.pdf")
        self.assertNotContains(
            resp_list, "contrato_confidencial.pdf"
        )  # No ve el de Seguridad

        # 5. Puede ver el detalle de su documento
        resp_detail = self.client.get(
            reverse("dashboard:document_detail", kwargs={"file_hash": doc.file_hash})
        )
        self.assertEqual(resp_detail.status_code, 200)

        # 6. Intentar ver documento de otra UO devuelve 403
        resp_sec_detail = self.client.get(
            reverse(
                "dashboard:document_detail",
                kwargs={"file_hash": self.doc_sec.file_hash},
            )
        )
        self.assertEqual(resp_sec_detail.status_code, 403)

    def test_dashboard_document_upload_multiple_individual_emails(self) -> None:
        """Verifica que se reciban múltiples campos individuales de correo (POST getlist)."""
        self.client.force_login(self.admin_user)
        multi_pdf = SimpleUploadedFile(
            "multi_email.pdf", b"%PDF-1.4\nMulti\n%%EOF", content_type="application/pdf"
        )
        post_data = {
            "original_file": multi_pdf,
            "origin_uo": self.uo_security.id,
            "allowed_emails": [
                "primero@empresa.com",
                "segundo@empresa.com",
                "tercero@empresa.com",
            ],
        }
        resp = self.client.post(
            reverse("dashboard:document_upload"), post_data, follow=True
        )
        self.assertEqual(resp.status_code, 200)
        doc = EncryptedDocument.objects.filter(
            original_filename="multi_email.pdf"
        ).first()
        self.assertIsNotNone(doc)
        self.assertEqual(
            set(doc.allowed_emails),
            {"primero@empresa.com", "segundo@empresa.com", "tercero@empresa.com"},
        )

    def test_dashboard_uo_members_ajax(self) -> None:
        """Verifica que el endpoint AJAX retorne los miembros y buzón de una UO."""
        self.client.force_login(self.operator_user)
        resp = self.client.get(
            reverse("dashboard:uo_members_ajax", kwargs={"uo_id": self.uo_security.id})
        )
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

        # Configurar un destinatario consumido como lista de cadenas (formato oficial de modelo)
        self.doc_sec.consumed_recipients = ["auditor@empresa.com"]
        self.doc_sec.save(update_fields=["consumed_recipients"])

        response = self.client.get(
            reverse(
                "dashboard:document_detail",
                kwargs={"file_hash": self.doc_sec.file_hash},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.doc_sec.file_hash)
        self.assertContains(response, "auditor@empresa.com")
        self.assertContains(response, "director@empresa.com")
        self.assertContains(response, "Canjeado")
        self.assertContains(response, "Pendiente")
        self.assertContains(response, "Trazabilidad Forense")

    def test_dashboard_document_terminate_flow(self) -> None:
        """Verifica el flujo de clausura y destrucción física anticipada."""
        self.client.force_login(self.admin_user)

        # GET confirmación
        resp_get = self.client.get(
            reverse(
                "dashboard:document_terminate",
                kwargs={"file_hash": self.doc_sec.file_hash},
            )
        )
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, "Confirmación Obligatoria de Clausura")

        # POST sin justificación (error 400)
        resp_bad = self.client.post(
            reverse(
                "dashboard:document_terminate",
                kwargs={"file_hash": self.doc_sec.file_hash},
            ),
            {},
        )
        self.assertEqual(resp_bad.status_code, 400)
        self.assertContains(
            resp_bad, "Debe proporcionar un motivo justificado", status_code=400
        )

        # POST con justificación válida
        resp_post = self.client.post(
            reverse(
                "dashboard:document_terminate",
                kwargs={"file_hash": self.doc_sec.file_hash},
            ),
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
        resp_filter = self.client.get(
            reverse("dashboard:audit_logs")
            + f"?action={DocumentAccessLog.Action.OTP_ENVIADO}"
        )
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
        resp_create = self.client.post(
            reverse("dashboard:api_tokens"), post_data, follow=True
        )
        self.assertEqual(resp_create.status_code, 200)
        self.assertContains(resp_create, "arca_live_")
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
            original_file=SimpleUploadedFile(
                "legal.pdf", b"%PDF-1.4\nLegal\n%%EOF", content_type="application/pdf"
            ),
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
        resp_detail = self.client.get(
            reverse(
                "dashboard:document_detail", kwargs={"file_hash": doc_legal.file_hash}
            )
        )
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
        resp_post = self.client.post(
            reverse("dashboard:mode_selection"), {"mode": "operational"}, follow=True
        )
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
        resp_create = self.client.post(
            reverse("dashboard:uo_create"), create_data, follow=True
        )
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
        resp_edit = self.client.post(
            reverse("dashboard:uo_edit", kwargs={"uo_id": uo_audit.id}),
            edit_data,
            follow=True,
        )
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
        resp_own = self.client.post(
            reverse("dashboard:uo_edit", kwargs={"uo_id": self.uo_legal.id}),
            edit_own,
            follow=True,
        )
        self.assertEqual(resp_own.status_code, 200)
        self.uo_legal.refresh_from_db()
        self.assertEqual(self.uo_legal.name, "Asesoría Jurídica y Regulatoria")

        # 2. Intentar modificar otra UO (Seguridad) -> 403 Forbidden
        resp_other = self.client.get(
            reverse("dashboard:uo_edit", kwargs={"uo_id": self.uo_security.id})
        )
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
            {
                "action": "add_member",
                "user_id": new_user.id,
                "role": UserUOMembership.Role.OPERATOR,
            },
            follow=True,
        )
        self.assertEqual(resp_add.status_code, 200)
        m = UserUOMembership.objects.get(user=new_user, uo=self.uo_legal)
        self.assertEqual(m.role, UserUOMembership.Role.OPERATOR)

        # 2. Modificar rol a Auditor
        self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {
                "action": "update_role",
                "membership_id": m.id,
                "role": UserUOMembership.Role.AUDITOR,
            },
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
        resp_sec = self.client.get(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_security.id})
        )
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
            reverse(
                "dashboard:user_reset_password", kwargs={"user_id": target_user.id}
            ),
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
        self.assertNotContains(resp_home, 'href="/admin/"')
        self.assertNotContains(resp_home, 'href="/admin"')
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
        self.client.get(
            reverse("arcamitte:set-language")
            + "?lang=en&next="
            + reverse("dashboard:home")
        )

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

    def test_self_demotion_and_lockout_protection_in_user_management_form(self) -> None:
        """Verifica que un administrador/superusuario no pueda auto-bloquearse ni auto-degradarse."""
        from arcamitte.forms import UserManagementForm

        # 1. Enviar payload malicioso intentando auto-desactivar y auto-degradar la propia cuenta
        # Las salvaguardas de UserManagementForm deben desestimar la manipulación y preservar los privilegios
        form_self = UserManagementForm(
            data={
                "username": self.admin_user.username,
                "email": self.admin_user.email,
                "first_name": "Admin",
                "last_name": "Test",
                "is_active": False,
                "is_staff": False,
                "is_superuser": False,
            },
            instance=self.admin_user,
            is_superuser=True,
            current_user=self.admin_user,
        )
        self.assertTrue(form_self.is_valid(), form_self.errors)
        self.assertTrue(form_self.cleaned_data["is_active"])
        self.assertTrue(form_self.cleaned_data["is_staff"])
        self.assertTrue(form_self.cleaned_data["is_superuser"])
        self.assertTrue(form_self.cleaned_data["is_global_admin"])

        saved_user = form_self.save()
        self.assertTrue(saved_user.is_active)
        self.assertTrue(saved_user.arcamitte_profile.is_global_admin)
        self.assertFalse(saved_user.is_superuser)
        self.assertFalse(saved_user.is_staff)

        # 2. Intentar degradar al único superusuario activo del sistema por un tercero -> ValidationError
        # Aseguramos que solo existe un superusuario activo
        from arcamitte.models import UserProfile
        UserProfile.objects.filter(is_global_admin=True).exclude(user_id=self.admin_user.pk).update(is_global_admin=False)
        User.objects.filter(is_superuser=True).exclude(pk=self.admin_user.pk).delete()
        other_operator = User.objects.create_user(
            username="gestor_externo",
            email="gestor@arcamitte.local",
            password="Password123!",
            is_staff=True,
        )

        form_last_super = UserManagementForm(
            data={
                "username": self.admin_user.username,
                "email": self.admin_user.email,
                "first_name": "Admin",
                "last_name": "Test",
                "is_active": True,
                "is_staff": True,
                "is_superuser": False,
            },
            instance=self.admin_user,
            is_superuser=True,
            current_user=other_operator,  # No es él mismo
        )
        self.assertFalse(form_last_super.is_valid())
        self.assertIn("is_global_admin", form_last_super.errors)
        self.assertIn("único superusuario", str(form_last_super.errors["is_global_admin"]))

        # 3. Asignar rol de Administrador Global a nuevo candidato
        new_target = User.objects.create_user(
            username="nuevo_candidato",
            email="candidato@arcamitte.local",
            password="Password123!",
        )
        form_promote = UserManagementForm(
            data={
                "username": new_target.username,
                "email": new_target.email,
                "first_name": "Nuevo",
                "last_name": "Candidato",
                "is_active": True,
                "is_staff": False,
                "is_superuser": True,
            },
            instance=new_target,
            is_superuser=True,
            current_user=self.admin_user,
        )
        self.assertTrue(form_promote.is_valid(), form_promote.errors)
        saved_promoted = form_promote.save()
        self.assertTrue(saved_promoted.arcamitte_profile.is_global_admin)
        self.assertFalse(saved_promoted.is_superuser)
        self.assertFalse(saved_promoted.is_staff)

    def test_uo_admin_self_protection_in_uo_members(self) -> None:
        """Verifica que un Administrador de UO no pueda auto-degradarse, auto-desactivarse ni auto-expulsarse."""
        uo_admin = User.objects.create_user(
            username="admin_propio",
            email="admin_propio@arcamitte.local",
            password="AdminPassword123!",
        )
        m = UserUOMembership.objects.create(
            user=uo_admin,
            uo=self.uo_legal,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )

        self.client.force_login(uo_admin)

        # 1. Intentar auto-degradar su rol de ADMIN a OPERATOR -> Denegado con mensaje de error
        resp_demote = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {
                "action": "update_role",
                "membership_id": m.id,
                "role": UserUOMembership.Role.OPERATOR,
            },
            follow=True,
        )
        self.assertEqual(resp_demote.status_code, 200)
        m.refresh_from_db()
        self.assertEqual(
            m.role, UserUOMembership.Role.ADMIN
        )  # Debe seguir siendo ADMIN
        self.assertContains(
            resp_demote, "no puede revocar sus propios privilegios de administrador"
        )

        # 2. Intentar auto-desactivar su membresía -> Denegado con mensaje de error
        resp_toggle = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {"action": "toggle_active", "membership_id": m.id},
            follow=True,
        )
        self.assertEqual(resp_toggle.status_code, 200)
        m.refresh_from_db()
        self.assertTrue(m.is_active)  # Debe seguir activo
        self.assertContains(resp_toggle, "no puede desactivar su propia membresía")

        # 3. Intentar auto-expulsarse de la UO -> Denegado con mensaje de error
        resp_remove = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {"action": "remove_member", "membership_id": m.id},
            follow=True,
        )
        self.assertEqual(resp_remove.status_code, 200)
        self.assertTrue(
            UserUOMembership.objects.filter(pk=m.pk).exists()
        )  # Debe seguir existiendo
        self.assertContains(
            resp_remove, "no puede auto-expulsarse de esta Unidad Organizativa"
        )

    def test_user_form_renders_clear_descriptions_and_protection(self) -> None:
        """Verifica que el formulario de edición de usuario distinga claramente is_staff de is_superuser y alerte de auto-edición."""
        self.client.force_login(self.admin_user)

        # Cargar edición de la propia cuenta del superusuario
        resp_self = self.client.get(
            reverse("dashboard:user_edit", kwargs={"user_id": self.admin_user.id})
        )
        self.assertEqual(resp_self.status_code, 200)
        self.assertContains(resp_self, "Editando su propia cuenta")
        self.assertContains(resp_self, "Administrador Global de Seguridad")
        self.assertContains(resp_self, "Control Total / Soberano")
        # Verificar que no se muestran tecnicismos de código como (is_staff) o (is_superuser) en el texto
        self.assertNotContains(resp_self, "(is_staff)")
        self.assertNotContains(resp_self, "(is_superuser)")

        # Verificar z-index del navbar y menú desplegable
        self.assertContains(resp_self, 'style="z-index: 1060;')

    def test_hierarchical_authority_level_enforcement(self) -> None:
        """Verifica que nadie pueda otorgar un nivel superior al suyo ni administrar a un superusuario."""
        from arcamitte.forms import UserManagementForm

        # Crear un administrador de UO (is_staff=True, is_superuser=False)
        uo_admin = User.objects.create_user(
            username="admin_departamental",
            email="admin_dep@arcamitte.local",
            password="AdminPassword123!",
            is_staff=True,
        )
        UserUOMembership.objects.create(
            user=uo_admin,
            uo=self.uo_legal,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )
        # Añadir al superusuario también a la UO legal
        m_super = UserUOMembership.objects.create(
            user=self.admin_user,
            uo=self.uo_legal,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )

        # 1. Un no-superusuario no puede enviar is_superuser=True ni is_staff=True en UserManagementForm
        form_unauth = UserManagementForm(
            data={
                "username": "intento_super",
                "email": "intento@arcamitte.local",
                "first_name": "Intento",
                "last_name": "Hack",
                "is_active": True,
                "is_staff": True,
                "is_superuser": True,
            },
            is_superuser=False,
            current_user=uo_admin,
        )
        self.assertFalse(form_unauth.is_valid())
        self.assertIn(
            "Solo un superusuario global puede conceder privilegios",
            str(form_unauth.errors),
        )

        self.client.force_login(uo_admin)

        # 2. Un no-superusuario NO puede editar a un superusuario global -> 403 Forbidden
        resp_edit_super = self.client.get(
            reverse("dashboard:user_edit", kwargs={"user_id": self.admin_user.id})
        )
        self.assertEqual(resp_edit_super.status_code, 403)

        # 3. Un no-superusuario NO puede resetear la contraseña de un superusuario -> 403 Forbidden
        resp_reset_super = self.client.post(
            reverse(
                "dashboard:user_reset_password", kwargs={"user_id": self.admin_user.id}
            )
        )
        self.assertEqual(resp_reset_super.status_code, 403)

        # 4. En UO Members: Un no-superusuario NO puede degradar el rol de un superusuario
        resp_demote = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {
                "action": "update_role",
                "membership_id": m_super.id,
                "role": UserUOMembership.Role.OPERATOR,
            },
            follow=True,
        )
        self.assertEqual(resp_demote.status_code, 200)
        m_super.refresh_from_db()
        self.assertEqual(m_super.role, UserUOMembership.Role.ADMIN)
        self.assertContains(
            resp_demote,
            "No tiene privilegios suficientes para modificar el rol de un superusuario",
        )

        # 5. En UO Members: Un no-superusuario NO puede desactivar la membresía de un superusuario
        resp_toggle = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {"action": "toggle_active", "membership_id": m_super.id},
            follow=True,
        )
        self.assertEqual(resp_toggle.status_code, 200)
        m_super.refresh_from_db()
        self.assertTrue(m_super.is_active)
        self.assertContains(
            resp_toggle,
            "No tiene privilegios suficientes para modificar el estado de un superusuario",
        )

        # 6. En UO Members: Un no-superusuario NO puede desvincular a un superusuario
        resp_remove = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {"action": "remove_member", "membership_id": m_super.id},
            follow=True,
        )
        self.assertEqual(resp_remove.status_code, 200)
        self.assertTrue(UserUOMembership.objects.filter(pk=m_super.pk).exists())
        self.assertContains(
            resp_remove,
            "No tiene privilegios suficientes para desvincular a un superusuario",
        )

    def test_uo_members_search_bar_and_json_data(self) -> None:
        """Verifica que la vista de miembros de UO proporcione la barra de búsqueda interactiva y el JSON para filtro."""
        self.client.force_login(self.admin_user)

        # Crear un usuario disponible con nombre y apellidos
        User.objects.create_user(
            username="doctor_house",
            first_name="Gregory",
            last_name="House",
            email="house@princeton.edu",
            password="Password123!",
        )

        resp = self.client.get(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id})
        )
        self.assertEqual(resp.status_code, 200)

        # Verificar presencia de la barra de búsqueda y campos en HTML
        self.assertContains(resp, "member_search_input")
        self.assertContains(resp, "available-users-json")
        self.assertContains(resp, "doctor_house")
        self.assertContains(resp, "Gregory")
        self.assertContains(resp, "House")
        self.assertContains(resp, "house@princeton.edu")

    def test_uo_exclusivity_rule_and_occupied_members_detection(self) -> None:
        """
        Verifica que:
        1. Los usuarios asignados activamente a otra UO se identifiquen como ocupados en el JSON.
        2. No se permita vincular a un usuario ocupado a otra UO si no ha sido desvinculado previamente.
        3. Tras ser desvinculado por su UO o superusuario, quede libre y pueda ser asignado a la nueva UO.
        """
        # Crear usuario asignado a SEGURIDAD
        worker = User.objects.create_user(
            username="analista_sec",
            first_name="Ada",
            last_name="Lovelace",
            email="ada@arcamitte.local",
            password="WorkerPassword123!",
        )
        membership_sec = UserUOMembership.objects.create(
            user=worker,
            uo=self.uo_security,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        # Crear usuario libre
        User.objects.create_user(
            username="usuario_libre",
            first_name="Alan",
            last_name="Turing",
            email="alan@arcamitte.local",
            password="FreePassword123!",
        )

        self.client.force_login(self.admin_user)

        # 1. Comprobar GET en uo_members de LEGAL: worker debe salir marcado como ocupado
        resp_get = self.client.get(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id})
        )
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, "available-users-json")

        json_data = resp_get.context["available_users_json"]
        import json as py_json

        parsed_users = py_json.loads(json_data)
        worker_info = next(
            (u for u in parsed_users if u["username"] == "analista_sec"), None
        )
        free_info = next(
            (u for u in parsed_users if u["username"] == "usuario_libre"), None
        )

        self.assertIsNotNone(worker_info)
        self.assertTrue(worker_info["is_occupied"])
        self.assertEqual(worker_info["assigned_uo_alias"], self.uo_security.alias)

        self.assertIsNotNone(free_info)
        self.assertFalse(free_info["is_occupied"])
        self.assertEqual(free_info["assigned_uo_alias"], "")

        # 2. Intentar asignar worker a LEGAL mientras sigue activo en SEGURIDAD -> Bloqueado
        resp_add_blocked = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {
                "action": "add_member",
                "user_id": worker.id,
                "role": UserUOMembership.Role.OPERATOR,
            },
            follow=True,
        )
        self.assertEqual(resp_add_blocked.status_code, 200)
        self.assertFalse(
            UserUOMembership.objects.filter(user=worker, uo=self.uo_legal).exists()
        )
        self.assertContains(
            resp_add_blocked, "ya se encuentra asignado a la Unidad Organizativa"
        )
        self.assertContains(resp_add_blocked, "Debe ser desvinculado previamente")

        # 3. Desvincular a worker de SEGURIDAD (dejarlo libre)
        resp_remove = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_security.id}),
            {"action": "remove_member", "membership_id": membership_sec.id},
            follow=True,
        )
        self.assertEqual(resp_remove.status_code, 200)
        self.assertFalse(
            UserUOMembership.objects.filter(user=worker, uo=self.uo_security).exists()
        )

        # 4. Ahora worker está libre: Asignarlo a LEGAL debe permitirse satisfactoriamente
        resp_add_success = self.client.post(
            reverse("dashboard:uo_members", kwargs={"uo_id": self.uo_legal.id}),
            {
                "action": "add_member",
                "user_id": worker.id,
                "role": UserUOMembership.Role.AUDITOR,
            },
            follow=True,
        )
        self.assertEqual(resp_add_success.status_code, 200)
        self.assertTrue(
            UserUOMembership.objects.filter(
                user=worker, uo=self.uo_legal, is_active=True
            ).exists()
        )
        m_legal = UserUOMembership.objects.get(user=worker, uo=self.uo_legal)
        self.assertEqual(m_legal.role, UserUOMembership.Role.AUDITOR)

    def test_dashboard_auditor_sees_audit_download_button_and_downloads_preserved(
        self,
    ) -> None:
        """Verifica que el usuario Auditor vea el botón de descarga y pueda descargar la copia de auditoría."""
        auditor_user = User.objects.create_user(
            username="auditor_test",
            email="auditor_test@arcamitte.local",
            password="AuditorPassword123!",
        )
        UserUOMembership.objects.create(
            user=auditor_user,
            uo=self.uo_legal,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )

        test_content = b"%PDF-1.4\nContenido confidencial para prueba forense\n%%EOF"
        upload_file = SimpleUploadedFile(
            "informe_auditoria.pdf", test_content, content_type="application/pdf"
        )
        doc = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=["auditor_dest@external.org"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            uploaded_by=auditor_user,
            origin_uo=self.uo_legal,
        )

        self.client.force_login(auditor_user)

        # 1. El auditor entra al detalle: debe ver el botón de Descarga de Auditoría y su rol "Auditor"
        detail_url = reverse(
            "dashboard:document_detail", kwargs={"file_hash": doc.file_hash}
        )
        resp_detail = self.client.get(detail_url)
        self.assertEqual(resp_detail.status_code, 200)
        self.assertTrue(resp_detail.context["can_audit_download"])
        self.assertContains(resp_detail, "Descarga de Auditoría")
        self.assertContains(resp_detail, "Descargar copia de auditoría")
        # Verificar visualización del rol en la barra/menú
        self.assertContains(resp_detail, "Auditor")
        self.assertContains(resp_detail, self.uo_legal.alias)

        # 2. Descarga de auditoría efectiva
        audit_download_url = reverse(
            "dashboard:document_audit_download", kwargs={"file_hash": doc.file_hash}
        )
        resp_download = self.client.get(audit_download_url)
        self.assertEqual(resp_download.status_code, 200)
        self.assertEqual(resp_download.content, test_content)
        self.assertIn("informe_auditoria.pdf", resp_download["Content-Disposition"])

        # 3. El documento NO debe quedar consumido ni destruido en disco
        doc.refresh_from_db()
        self.assertFalse(doc.is_consumed)
        self.assertTrue(os.path.exists(doc.encrypted_file.path))

        # 4. Comprobar que se ha registrado el log de auditoría
        audit_log = DocumentAccessLog.objects.filter(
            document=doc,
            action=DocumentAccessLog.Action.ADMIN_DESCARGA_PRESERVADA,
        ).first()
        self.assertIsNotNone(audit_log)
        self.assertIn("auditor_test", audit_log.details or "")

    def test_dashboard_operator_cannot_audit_download(self) -> None:
        """Verifica que un Operador no vea el botón de descarga de auditoría y no pueda ejecutarla."""
        operator_user = User.objects.create_user(
            username="operador_test",
            email="operador_test@arcamitte.local",
            password="OperatorPassword123!",
        )
        UserUOMembership.objects.create(
            user=operator_user,
            uo=self.uo_legal,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        test_content = b"%PDF-1.4\nArchivo operativo normal\n%%EOF"
        upload_file = SimpleUploadedFile(
            "operacion.pdf", test_content, content_type="application/pdf"
        )
        doc = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=["operacion@external.org"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            uploaded_by=operator_user,
            origin_uo=self.uo_legal,
        )

        self.client.force_login(operator_user)

        # 1. El operador no debe tener can_audit_download=True
        detail_url = reverse(
            "dashboard:document_detail", kwargs={"file_hash": doc.file_hash}
        )
        resp_detail = self.client.get(detail_url)
        self.assertEqual(resp_detail.status_code, 200)
        self.assertFalse(resp_detail.context["can_audit_download"])
        self.assertNotContains(resp_detail, "Descargar copia de auditoría")

        # 2. Si intenta forzar la descarga de auditoría vía URL, debe ser denegado y redirigido
        audit_download_url = reverse(
            "dashboard:document_audit_download", kwargs={"file_hash": doc.file_hash}
        )
        resp_download = self.client.get(audit_download_url, follow=True)
        self.assertEqual(resp_download.status_code, 200)
        self.assertContains(resp_download, "No tiene permisos de auditoría")

    def test_physical_file_missing_auto_closes_asiento_with_vicisitud(self) -> None:
        """Verifica que si el archivo físico en disco no existe, el asiento se clausura automáticamente con vicisitud."""
        test_content = b"%PDF-1.4\nDocumento para prueba de perdida fisica\n%%EOF"
        upload_file = SimpleUploadedFile(
            "perdida_fisica.pdf", test_content, content_type="application/pdf"
        )
        doc = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=["dest@empresa.com"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            uploaded_by=self.admin_user,
            origin_uo=self.uo_legal,
        )

        self.assertTrue(doc.is_active)
        self.assertFalse(doc.is_consumed)
        file_path = doc.encrypted_file.path
        self.assertTrue(os.path.exists(file_path))

        # Simular pérdida/eliminación física del archivo en disco
        os.remove(file_path)
        self.assertFalse(os.path.exists(file_path))

        self.client.force_login(self.admin_user)
        detail_url = reverse(
            "dashboard:document_detail", kwargs={"file_hash": doc.file_hash}
        )
        resp = self.client.get(detail_url)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context["file_exists_on_disk"])

        # Verificar que el modelo se ha clausurado automáticamente
        doc.refresh_from_db()
        self.assertFalse(doc.is_active)
        self.assertTrue(doc.is_consumed)
        self.assertIsNotNone(doc.consumed_at)

        # Verificar que se ha levantado una vicisitud formal
        log_entry = DocumentAccessLog.objects.filter(
            document=doc,
            action=DocumentAccessLog.Action.FINALIZACION_MANUAL,
        ).first()
        self.assertIsNotNone(log_entry)
        self.assertIn("Cierre automático del asiento", log_entry.details)

    def test_actions_hidden_when_user_lacks_permissions(self) -> None:
        """Verifica que si un usuario no tiene permisos para 'Terminar y Destruir', la acción no aparezca en la UI."""
        operador = User.objects.create_user(
            username="operador_ui_check",
            email="operador_ui@arcamitte.local",
            password="Password123!",
        )
        UserUOMembership.objects.create(
            user=operador,
            uo=self.uo_legal,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        test_content = b"%PDF-1.4\nDocumento para verificacion UI\n%%EOF"
        upload_file = SimpleUploadedFile(
            "ui_doc.pdf", test_content, content_type="application/pdf"
        )
        doc = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=["ui_dest@empresa.com"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            uploaded_by=self.admin_user,
            origin_uo=self.uo_legal,
        )

        self.client.force_login(operador)

        # 1. En el listado: el operador NO debe ver el botón de terminar (basurero rojo)
        resp_list = self.client.get(reverse("dashboard:document_list"))
        self.assertEqual(resp_list.status_code, 200)
        self.assertNotIn(doc.id, resp_list.context["terminable_doc_ids"])

        # 2. En el detalle: el operador NO debe tener can_terminate=True ni ver el botón 'Terminar y Destruir'
        detail_url = reverse(
            "dashboard:document_detail", kwargs={"file_hash": doc.file_hash}
        )
        resp_detail = self.client.get(detail_url)
        self.assertEqual(resp_detail.status_code, 200)
        self.assertFalse(resp_detail.context["can_terminate"])
        self.assertNotContains(resp_detail, "Terminar y Destruir")

        # 3. En el menú lateral: el operador NO debe ver 'Usuarios y Accesos' ni 'Unidades Organizativas'
        self.assertNotContains(resp_detail, "Usuarios y Accesos")
        self.assertNotContains(resp_detail, "Unidades Organizativas")

    def test_auditor_uploads_document_with_no_origin_uo_and_can_inspect(self) -> None:
        """Verifica que un Auditor pueda subir un documento personal (sin UO origen) y pueda verlo sin PermissionDenied."""
        auditor = User.objects.create_user(
            username="auditor_personal",
            email="auditor_personal@arcamitte.local",
            password="AuditorPassword123!",
        )
        UserUOMembership.objects.create(
            user=auditor,
            uo=self.uo_legal,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )

        test_content = b"%PDF-1.4\nDocumento personal sin UO\n%%EOF"
        upload_file = SimpleUploadedFile(
            "personal.pdf", test_content, content_type="application/pdf"
        )
        doc = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=["auditor_dest@empresa.com"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            uploaded_by=auditor,
            origin_uo=None,
            target_uo=self.uo_security,
        )

        self.client.force_login(auditor)

        # Debe poder acceder al detalle sin PermissionDenied
        detail_url = reverse(
            "dashboard:document_detail", kwargs={"file_hash": doc.file_hash}
        )
        resp_detail = self.client.get(detail_url)
        self.assertEqual(resp_detail.status_code, 200)
        self.assertTrue(resp_detail.context["can_audit_download"])
        self.assertContains(resp_detail, "Descarga de Auditoría")

        # Debe poder descargar la copia de auditoría
        audit_download_url = reverse(
            "dashboard:document_audit_download", kwargs={"file_hash": doc.file_hash}
        )
        resp_download = self.client.get(audit_download_url)
        self.assertEqual(resp_download.status_code, 200)
        self.assertEqual(resp_download.content, test_content)

    def test_auditor_strictly_scoped_to_assigned_uos(self) -> None:
        """Verifica que el Auditor esté estrictamente delimitado a sus UOs asignadas y no pueda acceder a UOs ajenas."""
        uo_other = OrganizationalUnit.objects.create(
            numeric_code=1005,
            alias="EXTERNAL",
            name="Organización Externa",
            email="external@arcamitte.local",
            is_active=True,
        )
        auditor_user = User.objects.create_user(
            username="auditor_scoped_test",
            email="auditor_scoped@arcamitte.local",
            password="Password123!",
        )
        UserUOMembership.objects.create(
            user=auditor_user,
            uo=self.uo_security,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )

        # Documento entre LEGAL y EXTERNAL (sin relación con SEGURIDAD)
        test_content = b"%PDF-1.4\nDocumento confidencial ajeno\n%%EOF"
        upload_file = SimpleUploadedFile(
            "unrelated.pdf", test_content, content_type="application/pdf"
        )
        doc = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=["dest@empresa.com"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            uploaded_by=self.admin_user,
            origin_uo=self.uo_legal,
            target_uo=uo_other,
        )

        self.client.force_login(auditor_user)

        # 1. El auditor NO ve el documento ajeno en su listado
        resp_list = self.client.get(reverse("dashboard:document_list"))
        self.assertEqual(resp_list.status_code, 200)
        self.assertNotIn(doc, resp_list.context["documents"])

        # 2. El auditor NO puede inspeccionar el detalle (403 PermissionDenied)
        detail_url = reverse(
            "dashboard:document_detail", kwargs={"file_hash": doc.file_hash}
        )
        resp_detail = self.client.get(detail_url)
        self.assertEqual(resp_detail.status_code, 403)

        # 3. El auditor NO puede realizar la descarga de auditoría de UO ajena
        audit_download_url = reverse(
            "dashboard:document_audit_download", kwargs={"file_hash": doc.file_hash}
        )
        resp_download = self.client.get(audit_download_url)
        self.assertEqual(resp_download.status_code, 302)

    def test_password_policy_enforcement_and_no_reuse(self) -> None:
        """
        Verifica el cumplimiento estricto de la política de contraseñas (NIST SP 800-63B / ENS):
        - Mínimo 10 caracteres
        - Mayúscula, minúscula, dígito y símbolo
        - No similitud con usuario/email
        - Prohibición de reutilizar la contraseña actual/temporal
        """
        pwd_user = User.objects.create_user(
            username="carlos_seguridad",
            email="carlos.seguridad@arcamitte.local",
            password="InitialTemp#2026",
        )
        profile = get_or_create_user_profile(pwd_user)
        profile.must_change_password = True
        profile.save()

        self.client.force_login(pwd_user)
        change_url = reverse("dashboard:password_change")

        invalid_passwords = [
            "Short1!a",  # Menos de 10 caracteres
            "minusculas1234!#",  # Sin mayúsculas
            "MAYUSCULAS1234!#",  # Sin minúsculas
            "SinNumerosAqui!#",  # Sin dígitos
            "SinSimbolos12345",  # Sin caracteres especiales
            "Carlos_seguridad1!",  # Similar al username
            "InitialTemp#2026",  # Reutilización de la contraseña actual/temporal
        ]

        for bad_pwd in invalid_passwords:
            resp = self.client.post(
                change_url,
                {
                    "current_password": "InitialTemp#2026",
                    "new_password": bad_pwd,
                    "confirm_password": bad_pwd,
                },
            )
            self.assertEqual(
                resp.status_code,
                200,
                f"Debería haber rechazado la contraseña débil: {bad_pwd}",
            )
            profile.refresh_from_db()
            self.assertTrue(
                profile.must_change_password,
                f"No debería haber permitido el cambio con: {bad_pwd}",
            )

        # Contraseña robusta que cumple toda la política
        valid_pwd = "Str0ngC0rp!Key#2026"
        resp_ok = self.client.post(
            change_url,
            {
                "current_password": "InitialTemp#2026",
                "new_password": valid_pwd,
                "confirm_password": valid_pwd,
            },
            follow=True,
        )
        self.assertEqual(resp_ok.status_code, 200)
        profile.refresh_from_db()
        pwd_user.refresh_from_db()
        self.assertFalse(profile.must_change_password)
        self.assertTrue(pwd_user.check_password(valid_pwd))

    def test_open_redirect_mitigation(self) -> None:
        """Verifica que las vistas con parámetro 'next' bloqueen redirecciones abiertas (CWE-601)."""
        # 1. set_language_view
        resp_lang = self.client.get(
            reverse("arcamitte:set-language")
            + "?lang=en&next=https://evil-attacker.example.com/phish"
        )
        self.assertEqual(resp_lang.status_code, 302)
        self.assertNotIn("evil-attacker.example.com", resp_lang["Location"])

        # 2. DashboardModeSelectionView
        self.client.force_login(self.admin_user)
        resp_mode = self.client.get(
            reverse("dashboard:mode_selection")
            + "?set=operational&next=//evil-attacker.example.com"
        )
        self.assertEqual(resp_mode.status_code, 302)
        self.assertEqual(resp_mode["Location"], reverse("dashboard:home"))

    def test_login_brute_force_protection(self) -> None:
        """Verifica que tras 5 intentos fallidos de login se bloquee temporalmente con HTTP 429."""
        from django.core.cache import cache

        cache.clear()
        self.client.logout()
        login_url = reverse("dashboard:login")

        for _ in range(5):
            resp = self.client.post(
                login_url, {"username": "operador1", "password": "WrongPassword!"}
            )
            self.assertEqual(resp.status_code, 200)

        # El 6º intento debe ser rechazado con 429 Too Many Requests
        resp_locked = self.client.post(
            login_url, {"username": "operador1", "password": "WrongPassword!"}
        )
        self.assertEqual(resp_locked.status_code, 429)
        cache.clear()

    def test_client_ip_anti_spoofing_and_no_store_headers(self) -> None:
        """Verifica la protección contra falsificación de X-Forwarded-For y cabeceras anti-caché."""
        from django.test import RequestFactory
        from arcamitte.utils import get_client_ip

        rf = RequestFactory()
        req = rf.get("/", REMOTE_ADDR="10.0.0.15", HTTP_X_FORWARDED_FOR="203.0.113.99")
        # Por defecto ARCAMITTE_TRUST_X_FORWARDED_FOR=False -> ignora XFF
        self.assertEqual(get_client_ip(req), "10.0.0.15")

        with override_settings(ARCAMITTE_TRUST_X_FORWARDED_FOR=True):
            self.assertEqual(get_client_ip(req), "203.0.113.99")
            # Si XFF contiene payload malicioso que no es IP válida, cae a REMOTE_ADDR
            req_spoof = rf.get(
                "/",
                REMOTE_ADDR="10.0.0.15",
                HTTP_X_FORWARDED_FOR="malicious_sql_injection",
            )
            self.assertEqual(get_client_ip(req_spoof), "10.0.0.15")

        # Verificar created_by en token generado desde Dashboard y cabeceras no-store en descarga de auditoría
        self.client.force_login(self.admin_user)
        self.client.post(
            reverse("dashboard:api_tokens"),
            {
                "name": "Token Con Autor",
                "scopes": ["documents:read"],
                "rate_limit": 60,
                "validity_days": 30,
            },
        )
        tok = APIToken.objects.get(name="Token Con Autor")
        self.assertEqual(tok.created_by, self.admin_user)

        audit_resp = self.client.get(
            reverse(
                "dashboard:document_audit_download",
                kwargs={"file_hash": self.doc_sec.file_hash},
            )
        )
        self.assertEqual(audit_resp.status_code, 200)
        self.assertIn("no-store", audit_resp["Cache-Control"])
