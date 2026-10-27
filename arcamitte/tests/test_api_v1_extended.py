from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from arcamitte.models import (
    APIToken,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
)
from arcamitte.services import upload_and_encrypt_document

User = get_user_model()


class APIV1ExtendedTestCase(TestCase):
    def setUp(self) -> None:
        self.client = APIClient()

        # Unidades Organizativas
        self.uo1 = OrganizationalUnit.objects.create(
            numeric_code=1001,
            alias="RRHH",
            name="Recursos Humanos",
            email="rrhh@arcamitte.local",
        )
        self.uo2 = OrganizationalUnit.objects.create(
            numeric_code=2001,
            alias="LEGAL",
            name="Asesoría Jurídica",
            email="legal@arcamitte.local",
        )
        self.uo3 = OrganizationalUnit.objects.create(
            numeric_code=3001,
            alias="AUDITORIA",
            name="Auditoría Interna",
            email="auditoria@arcamitte.local",
        )

        # Usuarios
        self.superuser = User.objects.create_superuser(
            username="admin_global",
            email="admin@arcamitte.local",
            password="AdminPassword123!",
        )
        self.user_rrhh = User.objects.create_user(
            username="gestor_rrhh",
            email="gestor@rrhh.local",
            password="UserPassword123!",
        )
        UserUOMembership.objects.create(
            user=self.user_rrhh,
            uo=self.uo1,
            role=UserUOMembership.Role.OPERATOR,
        )

        self.user_auditor = User.objects.create_user(
            username="auditor_legal",
            email="auditor@legal.local",
            password="UserPassword123!",
        )
        UserUOMembership.objects.create(
            user=self.user_auditor,
            uo=self.uo2,
            role=UserUOMembership.Role.AUDITOR,
        )

        # Tokens M2M protegidos con scopes operativos estrictos
        # 1. Master token (Global, Superuser-created, no UO restriction)
        self.master_token_obj, self.master_token_raw = APIToken.generate_token(
            name="Master Service",
            created_by=self.superuser,
            uo=None,
            scopes=[s[0] for s in APIToken.Scope.choices],
        )

        # 2. Token UO1 (RRHH) con scopes estándar
        self.token_uo1_obj, self.token_uo1_raw = APIToken.generate_token(
            name="M2M RRHH",
            created_by=self.superuser,
            uo=self.uo1,
            scopes=[
                "documents:create",
                "documents:read",
                "uos:read",
            ],
        )

        # 3. Token UO2 (LEGAL) con scopes de solo lectura
        self.token_uo2_obj, self.token_uo2_raw = APIToken.generate_token(
            name="M2M Legal Reader",
            created_by=self.superuser,
            uo=self.uo2,
            scopes=[
                "documents:read",
                "uos:read",
            ],
        )

        # 4. Documentos de prueba cifrados
        pdf_content = b"%PDF-1.4 test confidential document content for cryptographic test"
        self.file_rrhh = SimpleUploadedFile("contrato.pdf", pdf_content, content_type="application/pdf")
        self.doc_rrhh = upload_and_encrypt_document(
            original_file=self.file_rrhh,
            description="Contrato de prueba confidencial",
            allowed_emails=["candidato@externo.local", "empleado@rrhh.local"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            origin_uo=self.uo1,
            target_uo=self.uo2,
            uploaded_by=self.user_rrhh,
            client_ip="127.0.0.1",
            user_agent="PyTest-Agent/1.0",
        )

        pdf_content_uo3 = b"%PDF-1.4 internal confidential report from auditoria"
        self.file_uo3 = SimpleUploadedFile("informe.pdf", pdf_content_uo3, content_type="application/pdf")
        self.doc_uo3 = upload_and_encrypt_document(
            original_file=self.file_uo3,
            description="Informe confidencial UO3",
            allowed_emails=["auditor@auditoria.local"],
            burn_policy=EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
            origin_uo=self.uo3,
            target_uo=None,
            uploaded_by=self.superuser,
            client_ip="127.0.0.1",
            user_agent="PyTest-Agent/1.0",
        )

    def test_health_check_endpoint(self) -> None:
        """El health check público /api/v1/health/ responde 200 sin autenticación."""
        resp = self.client.get("/api/v1/health/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("details", data)
        self.assertEqual(data["details"]["database"], "ok")
        self.assertEqual(data["details"]["cryptography_fernet"], "ok")
        self.assertTrue(data["details"]["media_storage_writable"])

    def test_openapi_schema_and_docs_endpoints(self) -> None:
        """Los endpoints de documentación OpenAPI 3 responden 200 OK."""
        resp_schema = self.client.get("/api/schema/")
        self.assertEqual(resp_schema.status_code, status.HTTP_200_OK)

        resp_docs = self.client.get("/api/docs/")
        self.assertEqual(resp_docs.status_code, status.HTTP_200_OK)

        resp_redoc = self.client.get("/api/redoc/")
        self.assertEqual(resp_redoc.status_code, status.HTTP_200_OK)

    def test_list_documents_uo_scoping_and_filters(self) -> None:
        """GET /api/v1/documents/ aísla los documentos por perímetro de Unidad Organizativa."""
        # UO1 sólo ve doc_rrhh (origin_uo=UO1), NO ve doc_uo3 (origin=UO3, target=None)
        resp_uo1 = self.client.get(
            "/api/v1/documents/",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_uo1.status_code, status.HTTP_200_OK)
        hashes_uo1 = [item["file_hash"] for item in resp_uo1.json()["results"]]
        self.assertIn(self.doc_rrhh.file_hash, hashes_uo1)
        self.assertNotIn(self.doc_uo3.file_hash, hashes_uo1)

        # UO2 ve doc_rrhh porque target_uo=UO2, pero tampoco ve doc_uo3
        resp_uo2 = self.client.get(
            "/api/v1/documents/",
            HTTP_X_API_KEY=self.token_uo2_raw,
        )
        self.assertEqual(resp_uo2.status_code, status.HTTP_200_OK)
        hashes_uo2 = [item["file_hash"] for item in resp_uo2.json()["results"]]
        self.assertIn(self.doc_rrhh.file_hash, hashes_uo2)
        self.assertNotIn(self.doc_uo3.file_hash, hashes_uo2)

        # Master Token ve ambos documentos
        resp_master = self.client.get(
            "/api/v1/documents/",
            HTTP_X_API_KEY=self.master_token_raw,
        )
        self.assertEqual(resp_master.status_code, status.HTTP_200_OK)
        hashes_master = [item["file_hash"] for item in resp_master.json()["results"]]
        self.assertIn(self.doc_rrhh.file_hash, hashes_master)
        self.assertIn(self.doc_uo3.file_hash, hashes_master)

        # Filtros: search
        resp_search = self.client.get(
            "/api/v1/documents/?search=contrato",
            HTTP_X_API_KEY=self.master_token_raw,
        )
        self.assertEqual(resp_search.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp_search.json()["results"]), 1)
        self.assertEqual(resp_search.json()["results"][0]["file_hash"], self.doc_rrhh.file_hash)

    def test_check_hash_endpoint(self) -> None:
        """POST /api/v1/documents/check-hash/ verifica existencia y respeta perímetro confidencial."""
        # Consulta hash existente en el perímetro de UO1
        resp_in_scope = self.client.post(
            "/api/v1/documents/check-hash/",
            data={"file_hash": self.doc_rrhh.file_hash},
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_in_scope.status_code, status.HTTP_200_OK)
        data = resp_in_scope.json()
        self.assertTrue(data["exists"])
        self.assertTrue(data["accessible"])
        self.assertEqual(data["original_filename"], "contrato.pdf")

        # Consulta hash fuera del perímetro de UO1
        resp_out_of_scope = self.client.post(
            "/api/v1/documents/check-hash/",
            data={"file_hash": self.doc_uo3.file_hash},
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_out_of_scope.status_code, status.HTTP_200_OK)
        data_out = resp_out_of_scope.json()
        self.assertTrue(data_out["exists"])
        self.assertFalse(data_out["accessible"])
        self.assertNotIn("original_filename", data_out)  # Cero fuga de metadatos

        # Consulta hash inexistente
        fake_hash = "a" * 64
        resp_not_found = self.client.post(
            "/api/v1/documents/check-hash/",
            data={"file_hash": fake_hash},
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_not_found.status_code, status.HTTP_200_OK)
        self.assertFalse(resp_not_found.json()["exists"])

    def test_detail_and_status_document_endpoints(self) -> None:
        """GET /api/v1/documents/<file_hash>/ y /status/ retornan metadatos respetando el perímetro."""
        # En perímetro para UO1
        resp_ok = self.client.get(
            f"/api/v1/documents/{self.doc_rrhh.file_hash}/",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_ok.status_code, status.HTTP_200_OK)
        self.assertEqual(resp_ok.json()["original_filename"], "contrato.pdf")

        resp_status_ok = self.client.get(
            f"/api/v1/documents/{self.doc_rrhh.file_hash}/status/",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_status_ok.status_code, status.HTTP_200_OK)
        self.assertFalse(resp_status_ok.json()["is_consumed"])

        # Fuera de perímetro para UO1
        resp_forbidden = self.client.get(
            f"/api/v1/documents/{self.doc_uo3.file_hash}/",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_forbidden.status_code, status.HTTP_403_FORBIDDEN)

    def test_upload_document_endpoint(self) -> None:
        """POST /api/v1/documents/ permite la ingesta de documentos cifrados por API."""
        new_pdf = SimpleUploadedFile("alta_empleado.pdf", b"%PDF-1.4 new employee confidential data", content_type="application/pdf")
        resp = self.client.post(
            "/api/v1/documents/",
            data={
                "original_file": new_pdf,
                "description": "Alta en la seguridad social",
                "allowed_emails": "nuevo@empresa.local",
                "origin_uo": "RRHH",
                "target_uo": "LEGAL",
                "burn_policy": EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            },
            format="multipart",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn("file_hash", resp.json())
        self.assertEqual(resp.json()["origin_uo"], "RRHH")

    def test_email_template_generation(self) -> None:
        """GET /api/v1/documents/<file_hash>/email-template/ genera la plantilla corporativa."""
        resp = self.client.get(
            f"/api/v1/documents/{self.doc_rrhh.file_hash}/email-template/",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.json()
        self.assertIn("subject", data)
        self.assertIn("body", data)
        self.assertIn(self.doc_rrhh.file_hash, data["body"])

    def test_uo_directory_and_recipients(self) -> None:
        """GET /api/v1/uos/ y /recipients/ retornan el directorio y destinatarios de la malla."""
        # Listado de UOs
        resp_uos = self.client.get(
            "/api/v1/uos/",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_uos.status_code, status.HTTP_200_OK)
        aliases = [u["alias"] for u in resp_uos.json()]
        self.assertIn("RRHH", aliases)
        self.assertIn("LEGAL", aliases)
        self.assertIn("AUDITORIA", aliases)

        # Miembros de UO1 por alias y por código numérico
        resp_recipients_alias = self.client.get(
            "/api/v1/uos/RRHH/recipients/",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_recipients_alias.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp_recipients_alias.json()), 1)
        self.assertEqual(resp_recipients_alias.json()[0]["email"], "gestor@rrhh.local")

        resp_recipients_code = self.client.get(
            "/api/v1/uos/1001/recipients/",
            HTTP_X_API_KEY=self.token_uo1_raw,
        )
        self.assertEqual(resp_recipients_code.status_code, status.HTTP_200_OK)
        self.assertEqual(resp_recipients_code.json()[0]["username"], "gestor_rrhh")

    def test_critical_endpoints_are_strictly_absent_from_api(self) -> None:
        """
        DIRECTIVA ZERO TRUST:
        Las acciones críticas (borrado físico, descifrado pericial, reactivación y
        extracción de auditorías) NO EXISTEN en la API REST pública / M2M.
        Deben retornar 404 NOT FOUND invariablemente.
        """
        # 1. Intento de revocación / borrado físico
        resp_term = self.client.post(
            f"/api/v1/documents/{self.doc_rrhh.file_hash}/terminate/",
            data={"reason": "Intento de borrado no permitido por API"},
            HTTP_X_API_KEY=self.master_token_raw,
        )
        self.assertEqual(resp_term.status_code, status.HTTP_404_NOT_FOUND)

        # 2. Intento de descifrado pericial
        resp_decrypt = self.client.post(
            f"/api/v1/documents/{self.doc_rrhh.file_hash}/audit-decrypt/",
            HTTP_X_API_KEY=self.master_token_raw,
        )
        self.assertEqual(resp_decrypt.status_code, status.HTTP_404_NOT_FOUND)

        # 3. Intento de reactivación / reapertura
        resp_reactivate = self.client.post(
            f"/api/v1/documents/{self.doc_rrhh.file_hash}/reactivate/",
            data={"allowed_emails": ["hacker@externo.local"]},
            HTTP_X_API_KEY=self.master_token_raw,
        )
        self.assertEqual(resp_reactivate.status_code, status.HTTP_404_NOT_FOUND)

        # 4. Intento de volcado de logs de auditoría
        resp_logs = self.client.get(
            "/api/v1/audit/logs/",
            HTTP_X_API_KEY=self.master_token_raw,
        )
        self.assertEqual(resp_logs.status_code, status.HTTP_404_NOT_FOUND)

        # 5. Intento de exportación masiva forense
        resp_export = self.client.get(
            "/api/v1/audit/export/?format=csv",
            HTTP_X_API_KEY=self.master_token_raw,
        )
        self.assertEqual(resp_export.status_code, status.HTTP_404_NOT_FOUND)
