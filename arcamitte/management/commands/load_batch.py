import json
import sys
from pathlib import Path
from typing import Any
from django.core.management.base import BaseCommand, CommandError
from arcamitte.services import process_batch_import_json


class Command(BaseCommand):
    help = "Carga masiva desatendida de Unidades Organizativas (UO) y Usuarios desde un archivo JSON estructurado."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("json_file", type=str, help="Ruta al archivo .json con las definiciones de UOs y usuarios.")

    def handle(self, *args: Any, **options: Any) -> None:
        file_path = Path(options["json_file"])
        if not file_path.exists():
            raise CommandError(f"El archivo especificado no existe: {file_path}")

        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except Exception as exc:
            raise CommandError(f"Error al leer o parsear el archivo JSON: {exc}")

        self.stdout.write(self.style.NOTICE(f"Iniciando procesamiento de carga masiva desde '{file_path.name}'..."))
        try:
            uos_count, users_count, notes = process_batch_import_json(data)
            self.stdout.write(self.style.SUCCESS("\n✅ Carga masiva completada exitosamente:"))
            self.stdout.write(f"   • Unidades Organizativas procesadas: {uos_count}")
            self.stdout.write(f"   • Usuarios procesados y vinculados:   {users_count}\n")
            for note in notes:
                self.stdout.write(f"   - {note}")
        except Exception as exc:
            self.stdout.write(self.style.ERROR(f"❌ Error durante la carga masiva: {exc}"))
            sys.exit(1)
