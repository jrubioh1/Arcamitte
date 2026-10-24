import logging
from typing import Any

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from arcamitte.models import AccessVerificationToken

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Purga de forma segura y eficiente los tokens de verificación OTP caducados o consumidos "
        "para optimizar el rendimiento de la base de datos bajo alta concurrencia."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Calcula y muestra los tokens a purgar sin eliminarlos físicamente de la base de datos.",
        )
        parser.add_argument(
            "--days",
            type=int,
            default=0,
            help="Purga tokens cuya fecha de expiración o creación sea anterior a N días (por defecto 0: inmediatamente caducados/usados).",
        )
        parser.add_argument(
            "--only-expired",
            action="store_true",
            help="Purga exclusivamente los tokens con fecha de caducidad superada, conservando los usados.",
        )
        parser.add_argument(
            "--only-used",
            action="store_true",
            help="Purga exclusivamente los tokens que hayan sido marcados como utilizados.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run: bool = options["dry_run"]
        days: int = options["days"]
        only_expired: bool = options["only_expired"]
        only_used: bool = options["only_used"]

        now = timezone.now()
        cutoff_date = now - timezone.timedelta(days=days) if days > 0 else now

        if only_expired:
            filter_query = Q(expires_at__lt=cutoff_date)
        elif only_used:
            filter_query = Q(is_used=True)
            if days > 0:
                filter_query &= Q(created_at__lt=cutoff_date)
        else:
            filter_query = Q(expires_at__lt=cutoff_date) | Q(is_used=True)

        tokens_qs = AccessVerificationToken.objects.filter(filter_query)
        total_count = tokens_qs.count()

        if total_count == 0:
            self.stdout.write(self.style.NOTICE("No se encontraron tokens caducados o usados para purgar."))
            return

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"[DRY-RUN] Se identificaron {total_count} token(s) de verificación para purga. "
                    "Ningún registro fue alterado."
                )
            )
            return

        deleted_count, _ = tokens_qs.delete()
        self.stdout.write(
            self.style.SUCCESS(
                f"Purga completada con éxito: {deleted_count} token(s) de verificación eliminados permanentemente."
            )
        )
        logger.info(f"[ARCAMITTE PURGE] Se han purgado {deleted_count} tokens de verificación.")
