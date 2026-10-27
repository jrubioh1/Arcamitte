import json
import os
import shutil
import tempfile
from io import StringIO

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import IntegrityError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from arcamitte.models import (
    OrganizationalUnit,
    PasswordHistory,
    UserUOMembership,
)
from arcamitte.services import (
    admin_decrypt_document,
    get_uo_recipient_emails,
    process_batch_import_json,
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
class OrganizationalUnitModelTestCase(TestCase):
    """Pruebas unitarias para los modelos de Unidad Organizativa y Membresías de Usuario."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            username="test_user",
            email="test_user@empresa.com",
            password="TestPassword#2026",
        )
        self.uo = OrganizationalUnit.objects.create(
            numeric_code=1001,
            alias="RRHH",
            name="Recursos Humanos",
            email="rrhh@empresa.com",
            description="Departamento de Gestión del Talento",
        )

    def test_uo_creation_and_string_representation(self) -> None:
        """Verifica la creación y formato canónico del modelo OrganizationalUnit."""
        self.assertEqual(str(self.uo), "[1001] RRHH - Recursos Humanos")
        self.assertTrue(self.uo.is_active)

    def test_numeric_code_uniqueness(self) -> None:
        """El código numérico de una UO debe ser estrictamente unívoco."""
        with self.assertRaises(IntegrityError):
            OrganizationalUnit.objects.create(
                numeric_code=1001,  # Código duplicado
                alias="RRHH_BIS",
                name="Recursos Humanos Duplicado",
                email="rrhh_bis@empresa.com",
            )

    def test_alias_uniqueness(self) -> None:
        """El alias de una UO debe ser estrictamente unívoco."""
        with self.assertRaises(IntegrityError):
            OrganizationalUnit.objects.create(
                numeric_code=1002,
                alias="RRHH",  # Alias duplicado
                name="Otro RRHH",
                email="otro_rrhh@empresa.com",
            )

    def test_user_uo_membership_creation_and_uniqueness(self) -> None:
        """Verifica la vinculación de usuario con UO y la restricción única (user, uo)."""
        membership = UserUOMembership.objects.create(
            user=self.user,
            uo=self.uo,
            role=UserUOMembership.Role.ADMIN,
        )
        self.assertIn("Administrador de UO", str(membership))
        self.assertTrue(membership.is_active)

        with self.assertRaises(IntegrityError):
            UserUOMembership.objects.create(
                user=self.user,
                uo=self.uo,
                role=UserUOMembership.Role.OPERATOR,
            )


@override_settings(ARCAMITTE_FERNET_KEY=TEST_FERNET_KEY)
class UOMeshDataIsolationTestCase(TestCase):
    """
    Pruebas de aislamiento estricto de datos en la Malla Organizativa (Anti-IDOR / OWASP A01).
    Garantiza que usuarios de una UO solo puedan ver y operar con documentos de su propia UO
    (emisora o receptora), mientras que el Rol Maestro (Superuser) tiene visibilidad total.
    """

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._temp_media = tempfile.mkdtemp()
        cls._media_override = override_settings(MEDIA_ROOT=cls._temp_media)
        cls._media_override.enable()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._media_override.disable()
        shutil.rmtree(cls._temp_media, ignore_errors=True)
        super().tearDownClass()

    def setUp(self) -> None:
        self.client = Client()

        # UO Emisora (RRHH)
        self.uo_rrhh = OrganizationalUnit.objects.create(
            numeric_code=1001,
            alias="RRHH",
            name="Recursos Humanos",
            email="rrhh@empresa.com",
        )
        # UO Receptora (LEGAL)
        self.uo_legal = OrganizationalUnit.objects.create(
            numeric_code=2040,
            alias="LEGAL",
            name="Asesoría Jurídica",
            email="legal@empresa.com",
        )
        # UO Ajena (CONTABILIDAD)
        self.uo_conta = OrganizationalUnit.objects.create(
            numeric_code=3050,
            alias="CONTA",
            name="Contabilidad y Finanzas",
            email="conta@empresa.com",
        )

        # Usuarios Staff
        perm_view_doc = Permission.objects.get(codename="view_encrypteddocument")
        perm_change_doc = Permission.objects.get(codename="change_encrypteddocument")
        perm_add_doc = Permission.objects.get(codename="add_encrypteddocument")

        # Operador RRHH
        self.user_rrhh = User.objects.create_user(
            username="operador_rrhh",
            email="rrhh_user@empresa.com",
            password="Password#2026",
            is_staff=True,
        )
        self.user_rrhh.user_permissions.add(perm_view_doc, perm_change_doc, perm_add_doc)
        UserUOMembership.objects.create(
            user=self.user_rrhh,
            uo=self.uo_rrhh,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        # Operador LEGAL
        self.user_legal = User.objects.create_user(
            username="operador_legal",
            email="legal_user@empresa.com",
            password="Password#2026",
            is_staff=True,
        )
        self.user_legal.user_permissions.add(perm_view_doc, perm_change_doc)
        UserUOMembership.objects.create(
            user=self.user_legal,
            uo=self.uo_legal,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        # Operador CONTABILIDAD (ajeno a la comunicación RRHH -> LEGAL)
        self.user_conta = User.objects.create_user(
            username="operador_conta",
            email="conta_user@empresa.com",
            password="Password#2026",
            is_staff=True,
        )
        self.user_conta.user_permissions.add(perm_view_doc, perm_change_doc)
        UserUOMembership.objects.create(
            user=self.user_conta,
            uo=self.uo_conta,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        # Superusuario (Rol Maestro)
        self.superuser = User.objects.create_superuser(
            username="master_admin",
            email="master@arcamitte.local",
            password="MasterPassword#2026",
        )

        # Documento confidencial en la Malla: RRHH -> LEGAL
        upload_file = SimpleUploadedFile("expediente_mesh.pdf", MINIMAL_TEST_PDF)
        self.doc_mesh = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=["legal_destinatario@empresa.com"],
            origin_uo=self.uo_rrhh,
            target_uo=self.uo_legal,
            uploaded_by=self.user_rrhh,
            admin_user=self.superuser,
        )

    def test_mesh_document_visibility_for_origin_uo(self) -> None:
        """El operador de la UO emisora (RRHH) puede visualizar el documento en el admin."""
        self.client.force_login(self.user_rrhh)
        changelist_url = reverse("admin:arcamitte_encrypteddocument_changelist")
        resp = self.client.get(changelist_url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.doc_mesh.original_filename)

        change_url = reverse("admin:arcamitte_encrypteddocument_change", args=[self.doc_mesh.pk])
        resp_detail = self.client.get(change_url)
        self.assertEqual(resp_detail.status_code, 200)

    def test_mesh_document_visibility_for_target_uo(self) -> None:
        """El operador de la UO receptora (LEGAL) puede visualizar el documento que le fue destinado."""
        self.client.force_login(self.user_legal)
        changelist_url = reverse("admin:arcamitte_encrypteddocument_changelist")
        resp = self.client.get(changelist_url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.doc_mesh.original_filename)

        change_url = reverse("admin:arcamitte_encrypteddocument_change", args=[self.doc_mesh.pk])
        resp_detail = self.client.get(change_url)
        self.assertEqual(resp_detail.status_code, 200)

    def test_mesh_document_isolation_blocks_unrelated_uo(self) -> None:
        """Un usuario de una UO ajena (CONTABILIDAD) no puede ver ni acceder al documento (Anti-IDOR)."""
        self.client.force_login(self.user_conta)
        changelist_url = reverse("admin:arcamitte_encrypteddocument_changelist")
        resp = self.client.get(changelist_url)
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, self.doc_mesh.original_filename)

        # Intento de acceso directo por ID es redirigido por get_object -> None (aislado por get_queryset)
        change_url = reverse("admin:arcamitte_encrypteddocument_change", args=[self.doc_mesh.pk])
        resp_detail = self.client.get(change_url)
        self.assertEqual(resp_detail.status_code, 302)
        self.assertRedirects(resp_detail, reverse("admin:index"))

    def test_superuser_sees_all_documents(self) -> None:
        """El Rol Maestro (Superusuario) tiene acceso global a todos los documentos de la malla."""
        self.client.force_login(self.superuser)
        changelist_url = reverse("admin:arcamitte_encrypteddocument_changelist")
        resp = self.client.get(changelist_url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.doc_mesh.original_filename)

    def test_non_superuser_cannot_upload_for_unassigned_uo(self) -> None:
        """Un usuario no superusuario no puede emitir un documento bajo una UO a la que no pertenece."""
        new_pdf = SimpleUploadedFile("documento_fraude.pdf", MINIMAL_TEST_PDF)
        with self.assertRaises((PermissionDenied, ValidationError)):
            upload_and_encrypt_document(
                original_file=new_pdf,
                allowed_emails=["alguien@empresa.com"],
                origin_uo=self.uo_conta,  # user_rrhh NO pertenece a CONTA
                admin_user=self.user_rrhh,
            )


@override_settings(ARCAMITTE_FERNET_KEY=TEST_FERNET_KEY)
class UOMeshAuditDownloadSecurityTestCase(TestCase):
    """
    Pruebas de seguridad para la descarga de auditoría administrativa (admin_decrypt_document)
    dentro del ecosistema de mallas de UO.
    """

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._temp_media = tempfile.mkdtemp()
        cls._media_override = override_settings(MEDIA_ROOT=cls._temp_media)
        cls._media_override.enable()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._media_override.disable()
        shutil.rmtree(cls._temp_media, ignore_errors=True)
        super().tearDownClass()

    def setUp(self) -> None:
        self.uo_emisor = OrganizationalUnit.objects.create(
            numeric_code=1001, alias="EMISOR", name="UO Emisora", email="emisor@corp.local"
        )
        self.uo_receptor = OrganizationalUnit.objects.create(
            numeric_code=2002, alias="RECEPTOR", name="UO Receptora", email="receptor@corp.local"
        )
        self.uo_tercero = OrganizationalUnit.objects.create(
            numeric_code=3003, alias="TERCERO", name="UO Tercero", email="tercero@corp.local"
        )

        # Auditor Emisor
        self.auditor_emisor = User.objects.create_user(
            username="auditor_emisor", email="aud_e@corp.local", password="Password#2026", is_staff=True
        )
        UserUOMembership.objects.create(
            user=self.auditor_emisor, uo=self.uo_emisor, role=UserUOMembership.Role.AUDITOR
        )

        # Auditor Receptor
        self.auditor_receptor = User.objects.create_user(
            username="auditor_receptor", email="aud_r@corp.local", password="Password#2026", is_staff=True
        )
        UserUOMembership.objects.create(
            user=self.auditor_receptor, uo=self.uo_receptor, role=UserUOMembership.Role.AUDITOR
        )

        # Auditor Ajeno (Tercero)
        self.auditor_tercero = User.objects.create_user(
            username="auditor_tercero", email="aud_t@corp.local", password="Password#2026", is_staff=True
        )
        UserUOMembership.objects.create(
            user=self.auditor_tercero, uo=self.uo_tercero, role=UserUOMembership.Role.AUDITOR
        )

        # Operador Emisor (Pertenece a UO pero NO tiene rol AUDITOR ni ADMIN)
        self.operador_emisor = User.objects.create_user(
            username="operador_emisor", email="op_e@corp.local", password="Password#2026", is_staff=True
        )
        UserUOMembership.objects.create(
            user=self.operador_emisor, uo=self.uo_emisor, role=UserUOMembership.Role.OPERATOR
        )

        upload_file = SimpleUploadedFile("auditoria_test.pdf", MINIMAL_TEST_PDF)
        self.doc = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=["dest@corp.local"],
            origin_uo=self.uo_emisor,
            target_uo=self.uo_receptor,
        )

    def test_auditor_emisor_can_audit_decrypt(self) -> None:
        """El auditor de la UO emisora tiene autorización para realizar descargas de auditoría."""
        success, content, filename, msg = admin_decrypt_document(
            document=self.doc, admin_user=self.auditor_emisor
        )
        self.assertTrue(success)
        self.assertEqual(content, MINIMAL_TEST_PDF)

    def test_auditor_receptor_can_audit_decrypt(self) -> None:
        """El auditor de la UO receptora tiene autorización para realizar descargas de auditoría."""
        success, content, filename, msg = admin_decrypt_document(
            document=self.doc, admin_user=self.auditor_receptor
        )
        self.assertTrue(success)
        self.assertEqual(content, MINIMAL_TEST_PDF)

    def test_auditor_tercero_denied_audit_decrypt(self) -> None:
        """Un auditor de una UO no relacionada con el documento es rechazado tajantemente."""
        success, content, filename, msg = admin_decrypt_document(
            document=self.doc, admin_user=self.auditor_tercero
        )
        self.assertFalse(success)
        self.assertEqual(content, b"")
        self.assertIn("permisos de auditoría", msg)

    def test_operador_emisor_denied_audit_decrypt(self) -> None:
        """Un operador de la UO emisora (sin rol AUDITOR o ADMIN) es rechazado."""
        success, content, filename, msg = admin_decrypt_document(
            document=self.doc, admin_user=self.operador_emisor
        )
        self.assertFalse(success)
        self.assertEqual(content, b"")
        self.assertIn("permisos de auditoría", msg)


@override_settings(ARCAMITTE_FERNET_KEY=TEST_FERNET_KEY)
class UORecipientsHelperTestCase(TestCase):
    """Pruebas de la función de resolución y endpoint AJAX de destinatarios por UO."""

    def setUp(self) -> None:
        self.uo = OrganizationalUnit.objects.create(
            numeric_code=1001,
            alias="MARKETING",
            name="Dirección de Marketing",
            email="marketing@empresa.com",
        )
        self.u1 = User.objects.create_user(username="mkt1", email="ana@empresa.com", is_active=True)
        self.u2 = User.objects.create_user(username="mkt2", email="pedro@empresa.com", is_active=True)
        self.u_inactive = User.objects.create_user(username="mkt3", email="inactivo@empresa.com", is_active=False)

        UserUOMembership.objects.create(user=self.u1, uo=self.uo, role=UserUOMembership.Role.OPERATOR, is_active=True)
        UserUOMembership.objects.create(user=self.u2, uo=self.uo, role=UserUOMembership.Role.AUDITOR, is_active=True)
        UserUOMembership.objects.create(user=self.u_inactive, uo=self.uo, role=UserUOMembership.Role.OPERATOR, is_active=True)

    def test_get_uo_recipient_emails_helper(self) -> None:
        """get_uo_recipient_emails devuelve el buzón corporativo y los miembros activos."""
        emails = get_uo_recipient_emails(self.uo, include_members=True)
        self.assertIn("marketing@empresa.com", emails)
        self.assertIn("ana@empresa.com", emails)
        self.assertIn("pedro@empresa.com", emails)
        # El usuario inactivo no debe ser incluido
        self.assertNotIn("inactivo@empresa.com", emails)

    def test_uo_recipients_ajax_view(self) -> None:
        """El endpoint AJAX /admin/arcamitte/encrypteddocument/uo-recipients/<id>/ retorna JSON con buzón y miembros."""
        superuser = User.objects.create_superuser(username="admin_ajax", email="admin@arcamitte.local", password="Password#2026")
        client = Client()
        client.force_login(superuser)

        url = reverse("admin:arcamitte_encrypteddocument_uo_recipients", args=[self.uo.pk])
        resp = client.get(url)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["uo_alias"], "MARKETING")
        self.assertEqual(data["uo_email"], "marketing@empresa.com")
        self.assertIn("ana@empresa.com", data["member_emails"])
        self.assertIn("pedro@empresa.com", data["member_emails"])
        self.assertNotIn("inactivo@empresa.com", data["member_emails"])
        # Valida que se devuelvan los objetos detallados para selección individual
        self.assertIn("members", data)
        self.assertTrue(len(data["members"]) >= 2)
        ana_member = next(m for m in data["members"] if m["email"] == "ana@empresa.com")
        self.assertEqual(ana_member["role"], UserUOMembership.Role.OPERATOR)


@override_settings(ARCAMITTE_FERNET_KEY=TEST_FERNET_KEY)
class BatchImportProvisioningTestCase(TestCase):
    """
    Pruebas completas del módulo de aprovisionamiento masivo JSON:
    - Servicio `process_batch_import_json` (idempotencia y validaciones).
    - Comando CLI `manage.py load_batch`.
    - Vista web en Dashboard `/dashboard/unidades-organizativas/carga-masiva/`.
    """

    def setUp(self) -> None:
        self.client = Client()
        self.superuser = User.objects.create_superuser(
            username="master_super", email="master@arcamitte.local", password="MasterPassword#2026"
        )
        self.regular_staff = User.objects.create_user(
            username="regular_staff", email="staff@arcamitte.local", password="StaffPassword#2026", is_staff=True
        )

        self.valid_batch_data = {
            "organizational_units": [
                {
                    "numeric_code": 5001,
                    "alias": "SEGURIDAD",
                    "name": "Dirección de Ciberseguridad y Riesgos",
                    "email": "ciso@empresa.com",
                    "description": "SOC y gestión de incidentes",
                },
                {
                    "numeric_code": 5002,
                    "alias": "COMPLIANCE",
                    "name": "Oficina de Cumplimiento Normativo",
                    "email": "dpo@empresa.com",
                    "description": "Auditorías RGPD e ISO 27001",
                },
            ],
            "users": [
                {
                    "username": "lucia.ciso",
                    "email": "lucia@empresa.com",
                    "first_name": "Lucía",
                    "last_name": "Sánchez",
                    "role": "ADMIN",
                    "uo_alias": "SEGURIDAD",
                },
                {
                    "username": "david.auditor",
                    "email": "david@empresa.com",
                    "first_name": "David",
                    "last_name": "Molina",
                    "role": "AUDITOR",
                    "uo_numeric_code": 5002,
                },
                {
                    "username": "ciso.corp",
                    "email": "ciso.corp@empresa.com",
                    "first_name": "Marcos",
                    "last_name": "Alonso",
                    "is_global_admin": True,
                    "is_mfa_enforced": True,
                    "uo_alias": "SEGURIDAD",
                    "role": "ADMIN",
                },
                {
                    "username": "global.indep",
                    "email": "global.indep@empresa.com",
                    "first_name": "Clara",
                    "last_name": "Vega",
                    "is_global_admin": True,
                },
            ],
        }

    def test_process_batch_import_json_success_and_idempotence(self) -> None:
        """La carga masiva procesa UOs y usuarios y es completamente idempotente."""
        uos_count, users_count, notes = process_batch_import_json(self.valid_batch_data)
        self.assertEqual(uos_count, 2)
        self.assertEqual(users_count, 4)

        uo_sec = OrganizationalUnit.objects.get(numeric_code=5001)
        self.assertEqual(uo_sec.alias, "SEGURIDAD")
        self.assertEqual(uo_sec.email, "ciso@empresa.com")

        # Usuario departamental puro: is_staff=False, pertenencia en UO
        user_lucia = User.objects.get(username="lucia.ciso")
        self.assertEqual(user_lucia.first_name, "Lucía")
        self.assertFalse(user_lucia.is_staff)
        self.assertFalse(user_lucia.arcamitte_profile.is_global_admin)
        self.assertTrue(PasswordHistory.objects.filter(user=user_lucia).exists())

        membership_lucia = UserUOMembership.objects.get(user=user_lucia, uo=uo_sec)
        self.assertEqual(membership_lucia.role, UserUOMembership.Role.ADMIN)

        # Superusuario con UO y rol departamental
        user_ciso = User.objects.get(username="ciso.corp")
        self.assertTrue(user_ciso.is_staff)
        self.assertTrue(user_ciso.is_superuser)
        self.assertTrue(user_ciso.arcamitte_profile.is_global_admin)
        self.assertTrue(user_ciso.arcamitte_profile.is_mfa_enforced)
        membership_ciso = UserUOMembership.objects.get(user=user_ciso, uo=uo_sec)
        self.assertEqual(membership_ciso.role, UserUOMembership.Role.ADMIN)

        # Superusuario transversal sin UO
        user_indep = User.objects.get(username="global.indep")
        self.assertTrue(user_indep.is_staff)
        self.assertTrue(user_indep.is_superuser)
        self.assertTrue(user_indep.arcamitte_profile.is_global_admin)
        self.assertEqual(UserUOMembership.objects.filter(user=user_indep).count(), 0)

        # Ejecución repetida idéntica (idempotencia garantizada)
        uos_count2, users_count2, notes2 = process_batch_import_json(self.valid_batch_data)
        self.assertEqual(uos_count2, 2)
        self.assertEqual(users_count2, 4)
        self.assertEqual(OrganizationalUnit.objects.filter(numeric_code=5001).count(), 1)
        self.assertEqual(User.objects.filter(username="lucia.ciso").count(), 1)
        self.assertEqual(User.objects.filter(username="ciso.corp").count(), 1)

    def test_process_batch_import_json_validation_errors(self) -> None:
        """Validaciones defensivas ante JSON mal estructurado o con campos faltantes."""
        # 1. No es un diccionario
        with self.assertRaises(ValidationError):
            process_batch_import_json(["no", "es", "dict"])

        # 2. Falta alias o numeric_code en UO
        invalid_uo_data = {
            "organizational_units": [{"alias": "SOLO_ALIAS", "name": "Sin código"}]
        }
        with self.assertRaises(ValidationError):
            process_batch_import_json(invalid_uo_data)

        # 3. Usuario referencia UO inexistente
        invalid_user_data = {
            "organizational_units": [],
            "users": [{"username": "fantasma", "uo_alias": "NO_EXISTE"}],
        }
        with self.assertRaises(ValidationError):
            process_batch_import_json(invalid_user_data)

    def test_cli_load_batch_management_command(self) -> None:
        """El comando CLI 'load_batch' lee el JSON y aprovisiona correctamente."""
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            json.dump(self.valid_batch_data, tf)
            temp_path = tf.name

        try:
            out = StringIO()
            call_command("load_batch", temp_path, stdout=out)
            output_str = out.getvalue()
            self.assertIn("Carga masiva completada exitosamente", output_str)
            self.assertTrue(OrganizationalUnit.objects.filter(numeric_code=5001).exists())
            self.assertTrue(User.objects.filter(username="lucia.ciso").exists())
            self.assertTrue(User.objects.filter(username="ciso.corp").exists())
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_dashboard_batch_import_view_security_and_upload(self) -> None:
        """La vista de carga masiva en el Dashboard está reservada para Rol Maestro y procesa JSON."""
        # Usuario sin privilegios -> 403 Forbidden
        user_operator = User.objects.create_user(
            username="simple_op", email="op@arcamitte.local", password="OpPassword#2026"
        )
        self.client.force_login(user_operator)
        url = reverse("dashboard:batch_import")
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 403)

        # Superusuario -> 200 OK
        self.client.force_login(self.superuser)
        resp_super = self.client.get(url)
        self.assertEqual(resp_super.status_code, 200)
        self.assertContains(resp_super, "Aprovisionamiento Masivo JSON")

        # Subida exitosa vía formulario POST
        json_bytes = json.dumps(self.valid_batch_data).encode("utf-8")
        uploaded_file = SimpleUploadedFile("batch.json", json_bytes, content_type="application/json")
        post_resp = self.client.post(url, {"json_file": uploaded_file})
        self.assertEqual(post_resp.status_code, 302)  # Redirección a la lista de UOs
        self.assertRedirects(post_resp, reverse("dashboard:uo_list"))
        self.assertTrue(OrganizationalUnit.objects.filter(numeric_code=5001).exists())
        self.assertTrue(User.objects.filter(username="ciso.corp").exists())

    def test_sync_user_role_permissions_operator_and_auditor(self) -> None:
        """Verifica que la asignación de permisos según rol opere con el principio de menor privilegio."""
        from arcamitte.services import sync_user_role_permissions

        uo_test = OrganizationalUnit.objects.create(
            numeric_code=7001,
            alias="TEST_PERM",
            name="Unidad de Pruebas Permisos",
            email="testperm@arcamitte.local",
        )

        operator_user = User.objects.create_user(
            username="test_op",
            email="test_op@arcamitte.local",
            password="TestPassword#2026",
        )
        UserUOMembership.objects.create(
            user=operator_user,
            uo=uo_test,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )
        sync_user_role_permissions(operator_user)

        self.assertFalse(operator_user.is_staff)
        self.assertTrue(operator_user.has_perm("arcamitte.view_encrypteddocument"))
        self.assertTrue(operator_user.has_perm("arcamitte.add_encrypteddocument"))
        self.assertFalse(operator_user.has_perm("arcamitte.can_audit_download"))
        self.assertFalse(operator_user.has_perm("arcamitte.delete_encrypteddocument"))

        auditor_user = User.objects.create_user(
            username="test_audit",
            email="test_audit@arcamitte.local",
            password="TestPassword#2026",
        )
        UserUOMembership.objects.create(
            user=auditor_user,
            uo=uo_test,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )
        sync_user_role_permissions(auditor_user)

        self.assertFalse(auditor_user.is_staff)
        self.assertTrue(auditor_user.has_perm("arcamitte.view_encrypteddocument"))
        self.assertTrue(auditor_user.has_perm("arcamitte.can_audit_download"))
        self.assertTrue(auditor_user.has_perm("arcamitte.add_encrypteddocument"))
        self.assertFalse(auditor_user.has_perm("arcamitte.delete_encrypteddocument"))

    def test_staging_departmental_employee_admin_access_and_isolation(self) -> None:
        """Verifica que un empleado departamental de staging pueda operar el admin de acuerdo a su UO y rol."""
        from arcamitte.services import sync_user_role_permissions

        uo_rrhh = OrganizationalUnit.objects.create(
            numeric_code=7010,
            alias="STAGING_RRHH",
            name="Recursos Humanos Staging",
            email="rrhh_staging@arcamitte.local",
        )
        uo_legal = OrganizationalUnit.objects.create(
            numeric_code=7020,
            alias="STAGING_LEGAL",
            name="Asesoría Jurídica Staging",
            email="legal_staging@arcamitte.local",
        )

        # Configurar gestor RRHH
        gestor = User.objects.create_user(
            username="gestor_rrhh_test",
            email="gestor.rrhh@arcamitte.local",
            password="GestorPassword#2026",
            is_staff=True,
        )
        UserUOMembership.objects.create(
            user=gestor,
            uo=uo_rrhh,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )
        sync_user_role_permissions(gestor)

        self.client.force_login(gestor)
        admin_index = self.client.get(reverse("admin:index"))
        self.assertEqual(admin_index.status_code, 200)
        self.assertContains(admin_index, "Documentos Cifrados")

        # Acceso al listado de documentos
        doc_list = self.client.get(reverse("admin:arcamitte_encrypteddocument_changelist"))
        self.assertEqual(doc_list.status_code, 200)

        # Formulario de alta: origin_uo solo debe permitir su UO asignada
        add_form = self.client.get(reverse("admin:arcamitte_encrypteddocument_add"))
        self.assertEqual(add_form.status_code, 200)
        form_choices = add_form.context["adminform"].form.fields["origin_uo"].choices
        choice_labels = [c[1] for c in form_choices]
        self.assertTrue(any(uo_rrhh.alias in str(label) for label in choice_labels))
        self.assertFalse(any(uo_legal.alias in str(label) for label in choice_labels))

        # Auditor RRHH: en el modelo jerárquico tiene permiso de ver, añadir y auditar documentos
        auditor = User.objects.create_user(
            username="auditor_rrhh_test",
            email="auditor.rrhh@arcamitte.local",
            password="AuditorPassword#2026",
            is_staff=True,
        )
        UserUOMembership.objects.create(
            user=auditor,
            uo=uo_rrhh,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )
        sync_user_role_permissions(auditor)

        self.client.force_login(auditor)
        auditor_list = self.client.get(reverse("admin:arcamitte_encrypteddocument_changelist"))
        self.assertEqual(auditor_list.status_code, 200)
        auditor_add = self.client.get(reverse("admin:arcamitte_encrypteddocument_add"))
        self.assertEqual(auditor_add.status_code, 200)
