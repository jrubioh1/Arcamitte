from __future__ import annotations

import json
from django.contrib.auth.models import User
from django.test import TestCase, Client
from django.urls import reverse
from arcamitte.models import (
    OrganizationalUnit,
    PlatformSecurityPolicy,
    UserUOMembership,
    get_or_create_user_profile,
)
from arcamitte.permissions import (
    can_manage_api_tokens,
    can_manage_security_perimeter,
    is_global_admin,
    is_uo_admin,
    is_uo_auditor,
    is_uo_operator,
)
from arcamitte.services import is_totp_required_for_user
from arcamitte.forms import UserManagementForm


class RoleAnd2FAGovernanceTestCase(TestCase):
    """
    Suite de pruebas unitarias y de integración para:
    1. Desacoplamiento de roles institucionales (Administrador Global vs Django Admin).
    2. Redirección de /admin/ hacia /dashboard/login/.
    3. Gobernanza dinámica de 2FA por rol desde UI (PlatformSecurityPolicy).
    4. Limpieza del formulario UserManagementForm (cero is_staff visible).
    """

    def setUp(self) -> None:
        self.client = Client()

        # Unidad Organizativa de pruebas
        self.uo = OrganizationalUnit.objects.create(
            numeric_code=1001,
            alias="LEGAL",
            name="Asesoría Jurídica",
            email="legal@arcamitte.local",
            is_active=True,
        )

        # 1. Superusuario / Administrador Global de Seguridad
        self.global_admin = User.objects.create_user(
            username="super_security_admin",
            email="secadmin@arcamitte.local",
            password="AdminPassword#2026",
            is_superuser=True,
            is_staff=True,
        )
        self.global_profile = get_or_create_user_profile(self.global_admin)
        self.global_profile.is_global_admin = True
        self.global_profile.save(update_fields=["is_global_admin"])

        # 2. Administrador de UO
        self.uo_admin_user = User.objects.create_user(
            username="uo_admin",
            email="uo_admin@arcamitte.local",
            password="UOPassword#2026",
        )
        UserUOMembership.objects.create(
            user=self.uo_admin_user,
            uo=self.uo,
            role=UserUOMembership.Role.ADMIN,
            is_active=True,
        )

        # 3. Auditor de UO
        self.auditor_user = User.objects.create_user(
            username="auditor_lead",
            email="auditor@arcamitte.local",
            password="AuditorPassword#2026",
        )
        UserUOMembership.objects.create(
            user=self.auditor_user,
            uo=self.uo,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )

        # 4. Operador de UO
        self.operator_user = User.objects.create_user(
            username="operator_regular",
            email="operator@arcamitte.local",
            password="OperatorPassword#2026",
        )
        UserUOMembership.objects.create(
            user=self.operator_user,
            uo=self.uo,
            role=UserUOMembership.Role.OPERATOR,
            is_active=True,
        )

        # Resetear política de seguridad a estado inicial (falso)
        policy = PlatformSecurityPolicy.get_solo()
        policy.mfa_enforced_for_auditors = False
        policy.mfa_enforced_for_operators = False
        policy.save()

    def test_admin_url_redirects_unauthenticated(self) -> None:
        """Verifica que el endpoint /admin/ redirija de forma segura si no está autenticado."""
        response = self.client.get("/admin/", follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_domain_permissions_helpers(self) -> None:
        """Verifica las funciones de autorización de dominio desacopladas."""
        # Global Admin
        self.assertTrue(is_global_admin(self.global_admin))
        self.assertTrue(can_manage_security_perimeter(self.global_admin))
        self.assertTrue(can_manage_api_tokens(self.global_admin))
        self.assertTrue(is_uo_admin(self.global_admin, self.uo))

        # UO Admin
        self.assertFalse(is_global_admin(self.uo_admin_user))
        self.assertFalse(can_manage_security_perimeter(self.uo_admin_user))
        self.assertFalse(can_manage_api_tokens(self.uo_admin_user))
        self.assertTrue(is_uo_admin(self.uo_admin_user, self.uo))

        # Auditor
        self.assertTrue(is_uo_auditor(self.auditor_user, self.uo))
        self.assertFalse(is_uo_admin(self.auditor_user, self.uo))

        # Operator
        self.assertTrue(is_uo_operator(self.operator_user, self.uo))
        self.assertFalse(is_uo_auditor(self.operator_user, self.uo))

    def test_2fa_mandatory_for_global_admin_and_uo_admin(self) -> None:
        """Verifica que 2FA sea innegociablemente obligatorio para Superusuario y Admin de UO."""
        self.assertTrue(is_totp_required_for_user(self.global_admin))
        self.assertTrue(is_totp_required_for_user(self.uo_admin_user))

        # Intento de desactivar 2FA siendo usuario con directiva obligatoria -> bloqueado
        self.client.force_login(self.uo_admin_user)
        resp_disable = self.client.post(
            reverse("dashboard:totp_disable"),
            {"confirmation_code": "UOPassword#2026"},
        )
        self.assertEqual(resp_disable.status_code, 302)
        # Redirige a setup porque la directiva lo prohíbe
        self.assertEqual(resp_disable.url, reverse("dashboard:totp_setup"))

    def test_dynamic_2fa_governance_via_ui_for_auditors_and_operators(self) -> None:
        """
        Verifica el control dinámico de 2FA por rol desde la UI (/dashboard/seguridad/2fa-config/):
        1. Inicialmente opcional para Auditores y Operadores.
        2. Superusuario activa exigencia para Auditores -> pasa a ser obligatorio.
        3. Superusuario activa exigencia para Operadores -> pasa a ser obligatorio.
        4. Superusuario desactiva -> vuelve a ser opcional.
        """
        # Inicialmente opcional
        self.assertFalse(is_totp_required_for_user(self.auditor_user))
        self.assertFalse(is_totp_required_for_user(self.operator_user))

        self.client.force_login(self.global_admin)

        # 1. Cargar vista GET de gobernanza
        resp_get = self.client.get(reverse("dashboard:2fa_governance"))
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(
            resp_get, "Directivas Institucionales de Exigencia de 2FA por Rol"
        )
        self.assertContains(resp_get, "Innegociable")

        # 2. Activar 2FA obligatorio para Auditores
        resp_post_auditors = self.client.post(
            reverse("dashboard:2fa_governance"),
            {
                "action": "update_role_policies",
                "mfa_enforced_for_auditors": "on",
            },
        )
        self.assertEqual(resp_post_auditors.status_code, 302)

        policy = PlatformSecurityPolicy.get_solo()
        self.assertTrue(policy.mfa_enforced_for_auditors)
        self.assertFalse(policy.mfa_enforced_for_operators)

        # Ahora el auditor tiene 2FA obligatorio
        self.assertTrue(is_totp_required_for_user(self.auditor_user))
        self.assertFalse(is_totp_required_for_user(self.operator_user))

        # 3. Activar 2FA obligatorio también para Operadores
        resp_post_both = self.client.post(
            reverse("dashboard:2fa_governance"),
            {
                "action": "update_role_policies",
                "mfa_enforced_for_auditors": "on",
                "mfa_enforced_for_operators": "on",
            },
        )
        self.assertEqual(resp_post_both.status_code, 302)

        policy.refresh_from_db()
        self.assertTrue(policy.mfa_enforced_for_auditors)
        self.assertTrue(policy.mfa_enforced_for_operators)

        # Ambos tienen 2FA obligatorio
        self.assertTrue(is_totp_required_for_user(self.auditor_user))
        self.assertTrue(is_totp_required_for_user(self.operator_user))

        # 4. Desactivar para ambos
        resp_post_none = self.client.post(
            reverse("dashboard:2fa_governance"),
            {
                "action": "update_role_policies",
            },
        )
        self.assertEqual(resp_post_none.status_code, 302)

        policy.refresh_from_db()
        self.assertFalse(policy.mfa_enforced_for_auditors)
        self.assertFalse(policy.mfa_enforced_for_operators)

        # Vuelven a ser opcionales
        self.assertFalse(is_totp_required_for_user(self.auditor_user))
        self.assertFalse(is_totp_required_for_user(self.operator_user))

    def test_user_management_form_decoupled_from_is_staff(self) -> None:
        """
        Verifica que UserManagementForm no tenga campo is_staff en el formulario,
        pero exponga is_global_admin, y persista limpiamente.
        """
        form = UserManagementForm(
            is_superuser=True,
            current_user=self.global_admin,
        )
        # Campo is_staff NO existe en el formulario
        self.assertNotIn("is_staff", form.fields)
        # Campo is_global_admin SI existe
        self.assertIn("is_global_admin", form.fields)

        # Guardar un nuevo usuario con is_global_admin=True
        form_create = UserManagementForm(
            data={
                "username": "nuevo_global_admin",
                "email": "nuevo_global@arcamitte.local",
                "first_name": "Nuevo",
                "last_name": "Admin",
                "is_active": True,
                "is_global_admin": True,
            },
            is_superuser=True,
            current_user=self.global_admin,
        )
        self.assertTrue(form_create.is_valid(), form_create.errors)
        created_user = form_create.save()

        # El usuario creado tiene is_global_admin en profile y Django sync
        self.assertTrue(created_user.arcamitte_profile.is_global_admin)
        self.assertTrue(created_user.is_superuser)
        self.assertTrue(created_user.is_staff)
        self.assertEqual(
            created_user.arcamitte_profile.role_display_name,
            "Administrador Global de Seguridad",
        )
