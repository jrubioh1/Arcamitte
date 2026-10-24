import logging
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from arcamitte.models import EncryptedDocument
from arcamitte.services import process_expired_documents

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Cierra de forma automática y desatendida todos los asientos documentales cuya fecha de "
        "caducidad (por defecto 2 semanas) haya vencido sin haberse completado su descarga. "
        "Tritura físicamente los archivos confidenciales en disco y registra la correspondiente "
        "constancia de vicisitud en la auditoría legal."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Muestra los asientos caducados que serían cerrados sin alterar la base de datos ni los archivos físicos.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run: bool = options["dry_run"]
        now = timezone.now()

        expired_qs = EncryptedDocument.objects.filter(is_consumed=False, expires_at__lte=now)
        count = expired_qs.count()

        if count == 0:
            self.stdout.write(self.style.NOTICE("No se encontraron asientos caducados pendientes de cierre."))
            return

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"[DRY-RUN] Se identificaron {count} asiento(s) caducado(s) para cierre y trituración. "
                    "Ningún archivo ni registro fue modificado."
                )
            )
            for doc in expired_qs:
                self.stdout.write(f"  • ID {doc.pk}: '{doc.original_filename}' (Caducó: {doc.expires_at})")
            return

        closed_count = process_expired_documents()
        self.stdout.write(
            self.style.SUCCESS(
                f"Proceso de caducidad completado: {closed_count} asiento(s) cerrado(s) exitosamente. "
                "Los archivos físicos asociados han sido triturados y se ha generado la constancia en auditoría."
            )
        )
