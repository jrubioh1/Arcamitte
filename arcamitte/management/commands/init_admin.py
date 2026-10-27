from __future__ import annotations

import getpass
import os
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from arcamitte.models import get_or_create_user_profile
from arcamitte.services import (
    generate_secure_temporary_password,
    record_password_change,
)

User = get_user_model()


class Command(BaseCommand):
    help = (
        "Inicializa o actualiza el Administrador Global institucional para el despliegue "
        "en producción de Arcamitte, asegurando directivas NIST/ENS y gobernanza sin is_staff/is_superuser."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--username",
            type=str,
            default=os.getenv("ARCAMITTE_ADMIN_USERNAME", ""),
            help="Nombre de usuario del Administrador Global.",
        )
        parser.add_argument(
            "--email",
            type=str,
            default=os.getenv("ARCAMITTE_ADMIN_EMAIL", ""),
            help="Dirección de correo institucional.",
        )
        parser.add_argument(
            "--password",
            type=str,
            default=os.getenv("ARCAMITTE_ADMIN_PASSWORD", ""),
            help="Contraseña segura (si se omite se solicitará de forma segura).",
        )
        parser.add_argument(
            "--generate-password",
            action="store_true",
            help="Genera automáticamente una contraseña de alta entropía y la imprime en consola.",
        )
        parser.add_argument(
            "--no-input",
            action="store_true",
            help="Ejecución desatendida para scripts de despliegue, Docker o CI/CD.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        username = (options.get("username") or "").strip()
        email = (options.get("email") or "").strip()
        password = options.get("password") or ""
        gen_pass = options.get("generate_password", False)
        no_input = options.get("no_input", False)

        if not username:
            if no_input:
                username = "admin"
            else:
                raw_u = input("Nombre de usuario [admin]: ").strip()
                username = raw_u if raw_u else "admin"

        if not email:
            if no_input:
                email = f"{username}@arcamitte.local"
            else:
                email = input("Correo electrónico institucional: ").strip()
                if not email:
                    raise CommandError("El correo electrónico es obligatorio.")

        if gen_pass:
            password = generate_secure_temporary_password(length=16)
        elif not password:
            if no_input:
                raise CommandError(
                    "En modo desatendido (--no-input) debe proveer --password, "
                    "--generate-password o la variable ARCAMITTE_ADMIN_PASSWORD."
                )
            while True:
                p1 = getpass.getpass("Contraseña segura: ")
                p2 = getpass.getpass("Confirmar contraseña: ")
                if p1 != p2:
                    self.stdout.write(
                        self.style.ERROR(
                            "Las contraseñas no coinciden. Inténtelo de nuevo."
                        )
                    )
                    continue
                try:
                    validate_password(p1)
                except ValidationError as e:
                    self.stdout.write(
                        self.style.ERROR(
                            f"Contraseña no válida: {'; '.join(e.messages)}"
                        )
                    )
                    continue
                password = p1
                break

        # Crear o actualizar el usuario desacoplado de Django Admin
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": email,
                "is_staff": False,
                "is_superuser": False,
                "is_active": True,
            },
        )
        user.email = email
        user.is_staff = False
        user.is_superuser = False
        user.is_active = True
        user.set_password(password)
        user.save()

        profile = get_or_create_user_profile(user)
        profile.is_global_admin = True
        profile.must_change_password = False
        profile.save(update_fields=["is_global_admin", "must_change_password"])
        record_password_change(user, password)

        status_msg = "creado exitosamente" if created else "actualizado exitosamente"
        self.stdout.write(
            self.style.SUCCESS(f"✓ Administrador Global '{username}' {status_msg}.")
        )
        if gen_pass:
            self.stdout.write(self.style.WARNING(f"  Contraseña generada: {password}"))
