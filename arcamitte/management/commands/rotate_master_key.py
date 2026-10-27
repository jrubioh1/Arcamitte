from __future__ import annotations

import logging
from typing import Any

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from arcamitte.models import EncryptedDocument, UserProfile
from arcamitte.services import rotate_master_keys

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Ejecuta la rotación criptográfica de la clave maestra del servidor (MultiFernet Keyring).\n"
        "Recifra de forma atómica todas las claves de datos (DEK) de documentos y secretos TOTP (NIST SP 800-57)."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--new-key",
            type=str,
            help="Nueva clave maestra Fernet (32 bytes url-safe base64).",
        )
        parser.add_argument(
            "--generate",
            action="store_true",
            help="Genera automáticamente una nueva clave maestra Fernet criptográficamente segura.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simula la operación y muestra el número de registros afectados sin modificar la base de datos.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run = options.get("dry_run", False)
        generate = options.get("generate", False)
        new_key = options.get("new_key")

        if generate:
            new_key = Fernet.generate_key().decode("utf-8")
            self.stdout.write(
                self.style.SUCCESS(
                    f"[ROTACIÓN] Nueva clave maestra generada criptográficamente: {new_key}"
                )
            )
        elif not new_key:
            raise CommandError(
                "Debe proporcionar una nueva clave con '--new-key <KEY>' o usar la bandera '--generate'."
            )

        new_key = new_key.strip()
        try:
            Fernet(new_key.encode("utf-8"))
        except Exception as exc:
            raise CommandError(
                f"La clave maestra proporcionada no es una clave Fernet válida de 32 bytes base64 url-safe: {exc}"
            )

        doc_count = EncryptedDocument.objects.exclude(encrypted_dek="").count()
        totp_count = UserProfile.objects.exclude(totp_secret="").count()

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"[DRY-RUN] Simulación de rotación:\n"
                    f"  • Documentos con DEK activa a recifrar: {doc_count}\n"
                    f"  • Perfiles con secreto 2FA a recifrar : {totp_count}\n"
                    f"  • Clave objetivo: {new_key[:8]}...{new_key[-8:]}\n"
                    f"No se han realizado cambios en la base de datos."
                )
            )
            return

        self.stdout.write(
            f"Iniciando rotación atómica de claves maestras sobre {doc_count} documentos y {totp_count} perfiles..."
        )

        try:
            result = rotate_master_keys(
                new_primary_key=new_key,
                operator=None,
                client_ip="127.0.0.1",
            )
        except Exception as exc:
            logger.exception("Error crítico durante la rotación de clave maestra")
            raise CommandError(f"Error al ejecutar la rotación de clave maestra: {exc}")

        current_keys = getattr(
            settings, "ARCAMITTE_FERNET_KEYS", [settings.ARCAMITTE_FERNET_KEY]
        )
        updated_ring = [new_key] + [k for k in current_keys if k != new_key]
        ring_str = ",".join(updated_ring)

        self.stdout.write(
            self.style.SUCCESS(
                f"\n✔ Rotación completada con éxito:\n"
                f"  • Documentos recifrados : {result['rotated_documents']}\n"
                f"  • Perfiles 2FA recifrados: {result['rotated_profiles']}\n"
                f"  • Huella de clave nueva : {result['new_key_fingerprint']}...\n\n"
                f"ACCIONES REQUERIDAS:\n"
                f"1. Actualice 'arcamitte.ini' en la sección [security] con la directiva:\n\n"
                f"   [security]\n"
                f"   fernet_keys = {ring_str}\n\n"
                f"2. Reinicie el servidor o servicio de Arcamitte para aplicar el nuevo llavero en memoria."
            )
        )
