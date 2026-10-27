from __future__ import annotations

import io
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from arcamitte.models import PasswordHistory, get_or_create_user_profile
from arcamitte.permissions import is_global_admin

User = get_user_model()


class InitAdminCommandTestCase(TestCase):
    """
    Pruebas unitarias para el comando de bootstrap en producción `init_admin`.
    Verifica que el Administrador Global se inicializa de forma completamente desacoplada
    de Django Admin (is_staff=False, is_superuser=False, is_global_admin=True).
    """

    def test_init_admin_unattended(self) -> None:
        """Crea un nuevo Administrador Global en modo desatendido con credenciales explícitas."""
        out = io.StringIO()
        call_command(
            "init_admin",
            username="master_ciso",
            email="ciso@empresa.com",
            password="CisoMasterPassword#2026",
            no_input=True,
            stdout=out,
        )

        user = User.objects.get(username="master_ciso")
        self.assertEqual(user.email, "ciso@empresa.com")
        self.assertTrue(user.check_password("CisoMasterPassword#2026"))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        profile = get_or_create_user_profile(user)
        self.assertTrue(profile.is_global_admin)
        self.assertFalse(profile.must_change_password)
        self.assertTrue(is_global_admin(user))

        # Historial de contraseña registrado
        self.assertTrue(PasswordHistory.objects.filter(user=user).exists())
        self.assertIn("✓ Administrador Global 'master_ciso' creado exitosamente", out.getvalue())

    def test_init_admin_generated_password(self) -> None:
        """Crea un Administrador Global autogenerando una contraseña temporal de alta entropía."""
        out = io.StringIO()
        call_command(
            "init_admin",
            username="auto_admin",
            email="auto@empresa.com",
            generate_password=True,
            no_input=True,
            stdout=out,
        )

        user = User.objects.get(username="auto_admin")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(is_global_admin(user))
        self.assertIn("Contraseña generada:", out.getvalue())

    def test_init_admin_idempotent_update(self) -> None:
        """Ejecutar init_admin sobre un usuario existente actualiza su perfil sin duplicar."""
        user = User.objects.create_user(
            username="legacy_admin",
            email="old@empresa.com",
            password="OldPassword#2026",
            is_staff=False,
            is_superuser=False,
        )
        profile = get_or_create_user_profile(user)
        self.assertFalse(profile.is_global_admin)

        out = io.StringIO()
        call_command(
            "init_admin",
            username="legacy_admin",
            email="new@empresa.com",
            password="NewPassword#2026",
            no_input=True,
            stdout=out,
        )

        user.refresh_from_db()
        self.assertEqual(user.email, "new@empresa.com")
        self.assertTrue(user.check_password("NewPassword#2026"))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(is_global_admin(user))
        self.assertIn("actualizado exitosamente", out.getvalue())

    def test_post_save_signal_superuser_fallback(self) -> None:
        """Si un usuario se crea con is_superuser (ej. createsuperuser nativo), la señal sincroniza is_global_admin."""
        su = User.objects.create_superuser(
            username="django_native_su",
            email="native@empresa.com",
            password="NativePassword#2026",
        )
        su_profile = get_or_create_user_profile(su)
        self.assertTrue(su_profile.is_global_admin)
        self.assertTrue(is_global_admin(su))
