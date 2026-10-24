import sys
from typing import Any
from django.core.management.base import BaseCommand
from django.db.models import Q

from arcamitte.models import EncryptedDocument


class Command(BaseCommand):
    help = "Permite listar o eliminar documentos confidenciales de la base de datos y de disco."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "target",
            nargs="?",
            type=str,
            help="Nombre del archivo o hash SHA-256 del documento a eliminar.",
        )
        parser.add_argument(
            "--list",
            "-l",
            action="store_true",
            help="Lista todos los documentos confidenciales registrados con sus detalles.",
        )
        parser.add_argument(
            "--all",
            action="store_true",
            help="Elimina TODOS los documentos registrados (y tritura sus archivos físicos asociados).",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if options["list"]:
            docs = EncryptedDocument.objects.all().order_by("-created_at")
            if not docs.exists():
                self.stdout.write(self.style.WARNING("No hay documentos confidenciales registrados en el sistema."))
                return

            self.stdout.write(
                self.style.NOTICE(
                    f"\n{'ID':<5} {'NOMBRE ARCHIVO':<28} {'ESTADO':<14} {'CONSUMIDO POR':<24} {'ALTA':<16} {'HASH (SHA-256)'}"
                )
            )
            self.stdout.write("-" * 110)
            for d in docs:
                status_str = "🔥 Consumido" if d.is_consumed else "🟢 Activo"
                consumed_by = d.consumed_by or "-"
                created_str = d.created_at.strftime("%Y-%m-%d %H:%M") if d.created_at else "-"
                self.stdout.write(
                    f"{d.id:<5} {d.original_filename[:26]:<28} {status_str:<14} {consumed_by[:22]:<24} {created_str:<16} {d.file_hash[:16]}..."
                )
            self.stdout.write(self.style.SUCCESS(f"\nTotal: {docs.count()} documento(s) registrado(s).\n"))
            return

        if options["all"]:
            count = EncryptedDocument.objects.count()
            if count == 0:
                self.stdout.write(self.style.WARNING("No hay documentos para finalizar."))
                return
            from arcamitte.services import terminate_document_manually
            for doc in EncryptedDocument.objects.all():
                if not doc.is_consumed:
                    terminate_document_manually(doc, admin_user="CLI", reason="Finalización masiva CLI")
            self.stdout.write(self.style.SUCCESS(f"✅ Se han finalizado y triturado los archivos físicos de los {count} documentos."))
            return

        target = options.get("target")
        if not target:
            self.stdout.write(self.style.ERROR("Error: Debe especificar el nombre del archivo o hash, o usar --list."))
            sys.exit(1)

        docs = EncryptedDocument.objects.filter(
            Q(original_filename__icontains=target) | Q(file_hash__icontains=target)
        )

        if not docs.exists():
            self.stdout.write(self.style.ERROR(f"❌ No se encontró ningún documento que coincida con '{target}'."))
            sys.exit(1)

        from arcamitte.services import terminate_document_manually
        for doc in docs:
            name = doc.original_filename
            h = doc.file_hash[:12]
            if not doc.is_consumed:
                terminate_document_manually(doc, admin_user="CLI", reason=f"Finalización CLI para {target}")
            self.stdout.write(self.style.SUCCESS(f"✅ Asiento '{name}' (hash {h}...) finalizado y archivo triturado con éxito."))
