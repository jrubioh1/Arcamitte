import sys
from pathlib import Path
from typing import Any
from django.core.management.base import BaseCommand

from arcamitte.models import EncryptedDocument
from arcamitte.services import admin_decrypt_document, consume_document_with_otp


class Command(BaseCommand):
    help = "Descifra un documento confidencial de Arcamitte utilizando un código OTP o auditoría administrativa."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("target", type=str, help="Hash SHA-256 (64 hex) o ruta al archivo .enc.")
        parser.add_argument("--otp", type=str, required=False, help="Código OTP de 6 dígitos recibido por correo.")
        parser.add_argument("--email", "-e", type=str, required=False, help="Correo electrónico autorizado (requerido con --otp).")
        parser.add_argument("--admin", action="store_true", help="Descarga de auditoría administrativa preservada (Audit Bypass).")
        parser.add_argument("--output", "-o", type=str, required=False, help="Ruta de destino del archivo descifrado.")

    def handle(self, *args: Any, **options: Any) -> None:
        target = options["target"].strip()
        otp = options.get("otp")
        email = options.get("email")
        is_admin = options.get("admin")
        output_arg = options.get("output")

        # Buscar documento por hash SHA-256 o por archivo
        doc = EncryptedDocument.objects.filter(file_hash__iexact=target).first()
        if not doc:
            p = Path(target)
            if p.exists():
                doc = EncryptedDocument.objects.filter(original_filename__icontains=p.stem).first()

        if not doc:
            self.stdout.write(self.style.ERROR(f"❌ No se encontró ningún documento registrado que coincida con '{target}'."))
            sys.exit(1)

        if is_admin:
            self.stdout.write(self.style.NOTICE(f"Ejecutando descifrado de auditoría administrativa para '{doc.original_filename}'..."))
            success, decrypted_bytes, filename, message = admin_decrypt_document(
                document=doc,
                admin_user="cli_admin",
            )
        else:
            if not otp or not email:
                self.stdout.write(self.style.ERROR("Error: Debe especificar --otp y --email para canjear el documento, o usar --admin."))
                sys.exit(1)

            self.stdout.write(self.style.NOTICE(f"Consumiendo y triturando documento '{doc.original_filename}' (Burn-After-Read)..."))
            success, decrypted_bytes, filename, message = consume_document_with_otp(
                file_hash=doc.file_hash,
                email=email,
                entered_otp=otp,
            )

        if not success:
            self.stdout.write(self.style.ERROR(f"❌ Fallo al descifrar: {message}"))
            sys.exit(1)

        if output_arg:
            out_path = Path(output_arg)
        else:
            out_path = Path.cwd() / filename

        out_path.write_bytes(decrypted_bytes)
        self.stdout.write(self.style.SUCCESS("\n✅ ¡Documento descifrado exitosamente!"))
        self.stdout.write(self.style.SUCCESS(f"   Archivo guardado en: {out_path.resolve()}"))
        self.stdout.write(f"   Tamaño: {len(decrypted_bytes):,} bytes\n")
