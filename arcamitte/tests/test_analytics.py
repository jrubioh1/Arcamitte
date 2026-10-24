from __future__ import annotations

import tempfile
import shutil
from datetime import timedelta
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from arcamitte.models import (
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
)
from arcamitte.services import upload_and_encrypt_document

User = get_user_model()
TEST_FERNET_KEY = Fernet.generate_key().decode()


@override_settings(ARCAMITTE_FERNET_KEY=TEST_FERNET_KEY)
class AnalyticsDashboardTestCase(TestCase):
    """
    Suite de pruebas para el módulo de Analítica y Métricas con Apache ECharts.
    Verifica control de accesos RBAC, aislamiento de datos por UO y agregaciones.
    """

    def setUp(self) -> None:
        self.temp_storage = tempfile.mkdtemp()
        self.client = Client()

        # Unidades Organizativas
        self.uo_tech = OrganizationalUnit.objects.create(
            numeric_code=1001,
            alias="TECH",
            name="Tecnología e Infraestructura",
            email="tech@empresa.com",
        )
        self.uo_legal = OrganizationalUnit.objects.create(
            numeric_code=1002,
            alias="LEGAL",
            name="Asesoría Jurídica y Cumplimiento",
            email="legal@empresa.com",
        )

        # Usuarios
        self.superuser = User.objects.create_superuser(
            username="admin_global",
            email="admin@empresa.com",
            password="SuperPassword#2026",
        )
        self.admin_tech = User.objects.create_user(
            username="admin_tech",
            email="admin_tech@empresa.com",
            password="TechPassword#2026",
        )
        UserUOMembership.objects.create(
            user=self.admin_tech,
            uo=self.uo_tech,
            role=UserUOMembership.Role.ADMIN,
        )

        self.auditor_legal = User.objects.create_user(
            username="auditor_legal",
            email="auditor_legal@empresa.com",
            password="LegalPassword#2026",
        )
        UserUOMembership.objects.create(
            user=self.auditor_legal,
            uo=self.uo_legal,
            role=UserUOMembership.Role.AUDITOR,
        )

        self.operator_user = User.objects.create_user(
            username="operator_user",
            email="operator@empresa.com",
            password="OperatorPassword#2026",
        )
        UserUOMembership.objects.create(
            user=self.operator_user,
            uo=self.uo_tech,
            role=UserUOMembership.Role.OPERATOR,
        )

        self.plain_user = User.objects.create_user(
            username="plain_user",
            email="plain@empresa.com",
            password="PlainPassword#2026",
        )

        # Documentos de prueba
        now = timezone.now()
        f1 = SimpleUploadedFile("blueprint_tech.pdf", b"%PDF-1.4 Fake blueprint content for tech")
        self.doc_tech = upload_and_encrypt_document(
            original_file=f1,
            allowed_emails=["legal@empresa.com"],
            origin_uo=self.uo_tech,
            target_uo=self.uo_legal,
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        )

        f2 = SimpleUploadedFile("contrato_legal.pdf", b"%PDF-1.4 Fake legal contract content")
        self.doc_legal = upload_and_encrypt_document(
            original_file=f2,
            allowed_emails=["tech@empresa.com"],
            origin_uo=self.uo_legal,
            target_uo=self.uo_tech,
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        )
        self.doc_legal.is_consumed = True
        self.doc_legal.consumed_at = now
        self.doc_legal.save(update_fields=["is_consumed", "consumed_at"])

        # Logs de auditoría
        DocumentAccessLog.objects.create(
            document=self.doc_tech,
            origin_uo=self.uo_tech,
            target_uo=self.uo_legal,
            action=DocumentAccessLog.Action.SOLICITUD_OTP,
            ip_address="192.168.1.50",
        )
        DocumentAccessLog.objects.create(
            document=self.doc_tech,
            origin_uo=self.uo_tech,
            target_uo=self.uo_legal,
            action=DocumentAccessLog.Action.OTP_INVALIDO_BLOQUEADO,
            ip_address="192.168.1.50",
            details="3 intentos fallidos",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_storage, ignore_errors=True)

    def test_unauthenticated_access_redirects(self) -> None:
        """Verifica que usuarios anónimos son redirigidos al login."""
        resp_html = self.client.get(reverse("dashboard:analytics"))
        self.assertEqual(resp_html.status_code, 302)
        self.assertIn("/login", resp_html.url)

        resp_api = self.client.get(reverse("dashboard:analytics_data"))
        self.assertEqual(resp_api.status_code, 302)

    def test_operator_user_cannot_access_analytics(self) -> None:
        """Verifica que un operador común no tiene permiso de acceso (403)."""
        self.client.login(username="operator_user", password="OperatorPassword#2026")

        resp_html = self.client.get(reverse("dashboard:analytics"))
        self.assertEqual(resp_html.status_code, 403)

        resp_api = self.client.get(reverse("dashboard:analytics_data"))
        self.assertEqual(resp_api.status_code, 403)

    def test_plain_user_without_uo_cannot_access(self) -> None:
        """Verifica que un usuario sin UO ni rol obtiene 403."""
        self.client.login(username="plain_user", password="PlainPassword#2026")

        resp_html = self.client.get(reverse("dashboard:analytics"))
        self.assertEqual(resp_html.status_code, 403)

    def test_uo_admin_access_allowed_and_scoped(self) -> None:
        """Verifica que el Administrador de UO puede ver la analítica de sus departamentos."""
        self.client.login(username="admin_tech", password="TechPassword#2026")

        resp_html = self.client.get(reverse("dashboard:analytics"))
        self.assertEqual(resp_html.status_code, 200)
        self.assertContains(resp_html, "Analítica y Métricas de Custodia")
        self.assertContains(resp_html, "TECH")

        resp_api = self.client.get(reverse("dashboard:analytics_data"))
        self.assertEqual(resp_api.status_code, 200)
        data = resp_api.json()
        self.assertIn("kpis", data)
        self.assertIn("timeline", data)
        self.assertIn("uo_mesh", data)
        self.assertIn("custody", data)
        self.assertIn("security", data)

        # Prohibir filtrar por una UO que no administra
        resp_forbidden = self.client.get(f"{reverse('dashboard:analytics_data')}?uo=LEGAL")
        self.assertEqual(resp_forbidden.status_code, 403)

        # Permitir filtrar por su propia UO
        resp_ok = self.client.get(f"{reverse('dashboard:analytics_data')}?uo=TECH")
        self.assertEqual(resp_ok.status_code, 200)
        self.assertEqual(resp_ok.json()["scope_info"]["uo_alias"], "TECH")

    def test_uo_auditor_access_allowed(self) -> None:
        """Verifica que el Auditor de UO tiene acceso a las métricas de su departamento."""
        self.client.login(username="auditor_legal", password="LegalPassword#2026")

        resp_html = self.client.get(reverse("dashboard:analytics"))
        self.assertEqual(resp_html.status_code, 200)

        resp_api = self.client.get(reverse("dashboard:analytics_data"))
        self.assertEqual(resp_api.status_code, 200)
        data = resp_api.json()
        self.assertEqual(data["scope_info"]["uo_alias"], "LEGAL")

    def test_superuser_global_access_and_filtering(self) -> None:
        """Verifica que el Superusuario tiene acceso global y puede filtrar por cualquier UO."""
        self.client.login(username="admin_global", password="SuperPassword#2026")

        resp_html = self.client.get(reverse("dashboard:analytics"))
        self.assertEqual(resp_html.status_code, 200)
        self.assertContains(resp_html, "Toda la Organización (Global)")

        # Datos globales
        resp_api = self.client.get(reverse("dashboard:analytics_data"))
        self.assertEqual(resp_api.status_code, 200)
        data = resp_api.json()
        self.assertTrue(data["scope_info"]["is_global"])
        self.assertEqual(data["kpis"]["total_documents"], 2)
        self.assertEqual(data["kpis"]["active_documents"], 1)
        self.assertEqual(data["kpis"]["consumed_documents"], 1)
        self.assertEqual(data["kpis"]["burn_rate"], 50.0)
        self.assertEqual(data["kpis"]["security_alerts"], 1)  # 1 OTP bloqueado

        # Filtrado por UO específica
        resp_filtered = self.client.get(f"{reverse('dashboard:analytics_data')}?uo=LEGAL")
        self.assertEqual(resp_filtered.status_code, 200)
        data_filtered = resp_filtered.json()
        self.assertEqual(data_filtered["scope_info"]["uo_alias"], "LEGAL")

        # Filtrado por UO inexistente
        resp_404 = self.client.get(f"{reverse('dashboard:analytics_data')}?uo=NO_EXISTE")
        self.assertEqual(resp_404.status_code, 404)

    def test_analytics_drilldown_documents_nominal_access(self) -> None:
        """Verifica que el drilldown devuelve los documentos nominales correctos."""
        self.client.login(username="admin_global", password="SuperPassword#2026")

        # 1. Asientos Activos
        resp_active = self.client.get(f"{reverse('dashboard:analytics_drilldown')}?type=active")
        self.assertEqual(resp_active.status_code, 200)
        data_active = resp_active.json()
        self.assertEqual(data_active["mode"], "documents")
        self.assertEqual(data_active["count"], 1)
        self.assertEqual(data_active["items"][0]["filename"], "blueprint_tech.pdf")

        # 2. Asientos Consumidos / Destruidos
        resp_consumed = self.client.get(f"{reverse('dashboard:analytics_drilldown')}?type=consumed")
        self.assertEqual(resp_consumed.status_code, 200)
        data_consumed = resp_consumed.json()
        self.assertEqual(data_consumed["count"], 1)
        self.assertEqual(data_consumed["items"][0]["filename"], "contrato_legal.pdf")

    def test_analytics_drilldown_security_alerts_nominal_access(self) -> None:
        """Verifica que el drilldown forense lista los intentos y bloqueos con sus IPs."""
        self.client.login(username="admin_global", password="SuperPassword#2026")

        resp_alerts = self.client.get(f"{reverse('dashboard:analytics_drilldown')}?type=security_alerts")
        self.assertEqual(resp_alerts.status_code, 200)
        data_alerts = resp_alerts.json()
        self.assertEqual(data_alerts["mode"], "logs")
        self.assertEqual(data_alerts["count"], 1)
        self.assertEqual(data_alerts["items"][0]["ip_address"], "192.168.1.50")
        self.assertIn("fallidos", data_alerts["items"][0]["details"])

    def test_analytics_drilldown_rbac_isolation(self) -> None:
        """Verifica que un Admin de UO no puede consultar registros de otras dependencias."""
        self.client.login(username="admin_tech", password="TechPassword#2026")

        # Su propia UO -> 200
        resp_ok = self.client.get(f"{reverse('dashboard:analytics_drilldown')}?type=active&uo=TECH")
        self.assertEqual(resp_ok.status_code, 200)

        # UO ajena -> 403
        resp_forbidden = self.client.get(f"{reverse('dashboard:analytics_drilldown')}?type=active&uo=LEGAL")
        self.assertEqual(resp_forbidden.status_code, 403)

    def test_analytics_temporal_and_multicriteria_filters(self) -> None:
        """Verifica el filtrado multicriterio temporal, por política BAR, estado y búsqueda de texto."""
        self.client.login(username="admin_global", password="SuperPassword#2026")

        # 1. Filtro temporal de 7 días
        resp_7d = self.client.get(f"{reverse('dashboard:analytics_data')}?range=7d")
        self.assertEqual(resp_7d.status_code, 200)
        data_7d = resp_7d.json()
        self.assertEqual(data_7d["meta"]["range"], "7d")
        self.assertEqual(len(data_7d["timeline"]["labels"]), 7)

        # 2. Filtro temporal personalizado
        resp_custom = self.client.get(
            f"{reverse('dashboard:analytics_data')}?range=custom&date_from=2026-10-01&date_to=2026-10-31"
        )
        self.assertEqual(resp_custom.status_code, 200)
        self.assertEqual(resp_custom.json()["meta"]["range"], "custom")

        # 3. Filtro por política BAR
        resp_policy = self.client.get(f"{reverse('dashboard:analytics_data')}?burn_policy=FIRST_ACCESS")
        self.assertEqual(resp_policy.status_code, 200)

        # 4. Filtro por estado
        resp_status = self.client.get(f"{reverse('dashboard:analytics_data')}?status=active")
        self.assertEqual(resp_status.status_code, 200)
        self.assertEqual(resp_status.json()["kpis"]["total_documents"], 1)

        # 5. Drilldown con búsqueda de texto 'blueprint'
        resp_search = self.client.get(f"{reverse('dashboard:analytics_drilldown')}?type=total&q=blueprint")
        self.assertEqual(resp_search.status_code, 200)
        data_search = resp_search.json()
        self.assertEqual(data_search["count"], 1)
        self.assertEqual(data_search["items"][0]["filename"], "blueprint_tech.pdf")


