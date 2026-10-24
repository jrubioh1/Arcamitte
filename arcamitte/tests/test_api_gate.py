import hashlib
import shutil
import tempfile
from django.test import TestCase, RequestFactory, override_settings
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed

from arcamitte.authentication import APITokenAuthentication
from arcamitte.models import APIToken, OrganizationalUnit
from arcamitte.permissions import HasDocumentsCreateScope, HasDocumentsReadScope


class APITokenGateTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._temp_media = tempfile.mkdtemp(prefix="arca_test_gate_")
        cls._media_override = override_settings(MEDIA_ROOT=cls._temp_media)
        cls._media_override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._media_override.disable()
        shutil.rmtree(cls._temp_media, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.factory = RequestFactory()
        self.auth = APITokenAuthentication()
        self.uo = OrganizationalUnit.objects.create(
            numeric_code=8888,
            alias="SISTEMAS",
            name="Departamento de Sistemas",
            email="sistemas@arcamitte.local",
        )

    def test_generate_and_authenticate_token_success(self):
        """Valida que un token generado se autentique correctamente mediante X-API-Key."""
        token_obj, raw_token = APIToken.generate_token(
            name="Microservicio Facturación",
            uo=self.uo,
            scopes=["documents:create", "documents:read"],
        )

        self.assertTrue(raw_token.startswith("arca_live_"))
        self.assertEqual(token_obj.prefix, raw_token[:14])
        # El hash en BD coincide con SHA-256
        self.assertEqual(
            token_obj.hashed_token,
            hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        )

        # 1. Autenticación con X-API-Key
        request = self.factory.post("/api/v1/documents/", HTTP_X_API_KEY=raw_token)
        user, token_auth = self.auth.authenticate(request)
        self.assertEqual(token_auth, token_obj)
        self.assertIsNotNone(token_auth.last_used_at)

        # 2. Autenticación con Authorization: Bearer
        request_bearer = self.factory.post("/api/v1/documents/", HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        _, token_auth_bearer = self.auth.authenticate(request_bearer)
        self.assertEqual(token_auth_bearer, token_obj)

    def test_invalid_token_format_raises_error(self):
        """Rechaza tokens sin el prefijo requerido arca_live_."""
        request = self.factory.post("/api/v1/documents/", HTTP_X_API_KEY="invalid_prefix_12345")
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(request)

    def test_revoked_token_raises_error(self):
        """Rechaza tokens con is_active=False de forma inmediata."""
        token_obj, raw_token = APIToken.generate_token(name="Token Revocado", uo=self.uo)
        token_obj.is_active = False
        token_obj.save()

        request = self.factory.post("/api/v1/documents/", HTTP_X_API_KEY=raw_token)
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(request)

    def test_expired_token_raises_error(self):
        """Rechaza tokens cuya fecha expires_at ha vencido."""
        past_date = timezone.now() - timezone.timedelta(days=1)
        token_obj, raw_token = APIToken.generate_token(
            name="Token Expirado",
            uo=self.uo,
            expires_at=past_date,
        )

        request = self.factory.post("/api/v1/documents/", HTTP_X_API_KEY=raw_token)
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(request)

    def test_token_scope_permission_check(self):
        """Valida que HasTokenScope apruebe o deniegue la petición según los scopes concedidos."""
        token_obj, raw_token = APIToken.generate_token(
            name="Token Solo Lectura",
            uo=self.uo,
            scopes=["documents:read"],
        )

        request = self.factory.post("/api/v1/documents/")
        request.user = None
        request.auth = token_obj

        perm_create = HasDocumentsCreateScope()
        perm_read = HasDocumentsReadScope()

        self.assertFalse(perm_create.has_permission(request, None))
        self.assertTrue(perm_read.has_permission(request, None))

    def test_api_v1_documents_upload_and_status_flow(self):
        """Prueba end-to-end de subida protegida con APIToken y posterior consulta de status."""
        from rest_framework.test import APIClient
        from django.core.files.uploadedfile import SimpleUploadedFile

        client = APIClient()
        token_obj, raw_token = APIToken.generate_token(
            name="Servicio Nóminas",
            uo=self.uo,
            scopes=["documents:create", "documents:read"],
        )

        valid_pdf = SimpleUploadedFile(
            "informe_confidencial.pdf",
            b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF",
            content_type="application/pdf",
        )

        # 1. Petición sin token -> 401
        res_no_auth = client.post(
            "/api/v1/documents/",
            {
                "original_file": valid_pdf,
                "allowed_emails": '["empleado@empresa.com"]',
            },
            format="multipart",
        )
        self.assertEqual(res_no_auth.status_code, 401)

        # 2. Petición con token válido -> 201 Created
        valid_pdf.seek(0)
        res_upload = client.post(
            "/api/v1/documents/",
            {
                "original_file": valid_pdf,
                "allowed_emails": '["empleado@empresa.com"]',
                "burn_policy": "FIRST_ACCESS",
                "origin_uo": "SISTEMAS",
            },
            format="multipart",
            HTTP_X_API_KEY=raw_token,
        )
        self.assertEqual(res_upload.status_code, 201)
        resp_json = res_upload.json()
        self.assertEqual(resp_json["status"], "created")
        file_hash = resp_json["file_hash"]
        self.assertEqual(len(file_hash), 64)

        # 3. Consultar status del documento recién creado
        res_status = client.get(
            f"/api/v1/documents/{file_hash}/status/",
            HTTP_X_API_KEY=raw_token,
        )
        self.assertEqual(res_status.status_code, 200)
        status_json = res_status.json()
        self.assertEqual(status_json["file_hash"], file_hash)
        self.assertFalse(status_json["is_consumed"])
        self.assertFalse(status_json["is_expired"])
