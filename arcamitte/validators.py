import ast
import io
import json
import logging
import os
import re
import zipfile
from typing import Any

logger = logging.getLogger(__name__)
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.utils.translation import gettext_lazy as _

# ==============================================================================
# WHITELIST DE FORMATOS PERMITIDOS: PDF, LIBREOFFICE Y MICROSOFT OFFICE
# ==============================================================================

# Extensiones autorizadas
ALLOWED_EXTENSIONS = {
    # Formatos de LibreOffice / OpenDocument Format (ODF)
    ".odt",  # LibreOffice Writer
    ".ods",  # LibreOffice Calc
    ".odp",  # LibreOffice Impress
    ".odg",  # LibreOffice Draw
    # Formatos de Microsoft Office modernos (OpenXML)
    ".docx",  # MS Word
    ".xlsx",  # MS Excel
    ".pptx",  # MS PowerPoint
    # Formatos de Microsoft Office clásicos (OLE2 Binary)
    ".doc",  # MS Word 97-2003
    ".xls",  # MS Excel 97-2003
    ".ppt",  # MS PowerPoint 97-2003
    # Formato PDF
    ".pdf",
}

# Firmas de cabecera binaria (Magic Bytes)
MAGIC_PDF = b"%PDF-"
MAGIC_OLE2 = b"\xd0\xcf\x11\xe0"  # Microsoft Compound File Binary Format (.doc, .xls, .ppt)
MAGIC_ZIP = b"PK\x03\x04"        # Base de contenedores ZIP (.docx, .xlsx, .pptx, .odt, .ods, .odp, .odg)

# Límites de seguridad contra ataques Zip Bomb / Descompresión Maliciosa
MAX_ZIP_ENTRIES = 500
MAX_UNCOMPRESSED_ZIP_SIZE = 100 * 1024 * 1024  # 100 MB máximo descomprimido


def validate_safe_email(email: str) -> str:
    """
    Valida y desinfecta una dirección de correo electrónico contra ataques de Inyección
    de Cabeceras de Correo (CRLF Injection - OWASP A03:2021).
    """
    if not isinstance(email, str):
        raise ValidationError("La dirección de correo debe ser una cadena de texto.")

    # Mitigación estricta de CRLF (retornos de carro y saltos de línea)
    if "\r" in email or "\n" in email or "%0a" in email.lower() or "%0d" in email.lower():
        raise ValidationError("Carácter de control CRLF no permitido en la dirección de correo.")

    email_clean = email.strip()
    validator = EmailValidator(message="El formato del correo electrónico no es válido.")
    validator(email_clean)

    return email_clean.lower()


def normalize_and_validate_email_list(raw_input) -> list[str]:
    """
    Normaliza y valida una colección de correos electrónicos provista en múltiples formatos:
    - Lista o tupla de correos: ['user1@corp.com', 'user2@corp.com']
    - Cadena JSON: '["user1@corp.com", "user2@corp.com"]'
    - Cadena de texto plano separada por comas, punto y coma o saltos de línea
    - Múltiples inputs de formulario web ('allowed_emails')
    - Representación literal de lista de Python: "['user1@corp.com', 'user2@corp.com']"

    Aplica sanitización anti-CRLF y validación RFC a cada entrada.
    Retorna la lista ordenada y desduplicada en minúsculas.
    """
    if raw_input is None:
        raise ValidationError("Debe indicar al menos una dirección de correo válida.")

    candidates = []

    def extract_candidates(item):
        if item is None:
            return
        if isinstance(item, (list, tuple, set)):
            for sub_item in item:
                extract_candidates(sub_item)
            return

        item_str = str(item).strip()
        if not item_str:
            return

        # Detección de cadenas que representen listas JSON o literales Python
        if (item_str.startswith("[") and item_str.endswith("]")) or (
            item_str.startswith("(") and item_str.endswith(")")
        ):
            try:
                parsed = json.loads(item_str)
                if isinstance(parsed, (list, tuple)):
                    extract_candidates(parsed)
                    return
            except (json.JSONDecodeError, ValueError, TypeError):
                logger.debug("Cadena de entrada no es un array JSON válido, continuando análisis sintáctico.")

            try:
                parsed = ast.literal_eval(item_str)
                if isinstance(parsed, (list, tuple, set)):
                    extract_candidates(parsed)
                    return
            except (ValueError, SyntaxError, MemoryError, TypeError):
                logger.debug("Cadena de entrada no es un literal Python evaluable de forma segura.")

        # Descomposición por comas, puntos y comas o saltos de línea
        for part in item_str.replace(";", ",").replace("\n", ",").split(","):
            cleaned_part = part.strip().strip("'\"")
            if cleaned_part:
                candidates.append(cleaned_part)

    extract_candidates(raw_input)

    if not candidates:
        raise ValidationError("Debe indicar al menos una dirección de correo válida.")

    normalized = set()
    for email_cand in candidates:
        clean = validate_safe_email(email_cand)
        normalized.add(clean)

    if not normalized:
        raise ValidationError("Debe indicar al menos una dirección de correo válida.")

    return sorted(list(normalized))


def validate_document_file(file_obj):
    """
    Valida exhaustivamente un archivo subido combinando comprobación de extensión,
    inspección de cabeceras binarias (Magic Bytes) y verificación estructural profunda.
    
    Mitiga OWASP A03 (Inyección/Carga Maliciosa) y OWASP A08 (Integridad de Software/Datos):
    - Impide el enmascaramiento de ejecutables (ej. renombrar 'malware.exe' a 'documento.pdf').
    - Previene ataques de descompresión maliciosa (Zip Bombs) en formatos Office y ODF.
    """
    if not hasattr(file_obj, "name") or not file_obj.name:
        raise ValidationError("El archivo debe contener un nombre válido.")

    # 1. Validación de extensión contra lista blanca
    filename = file_obj.name.lower()
    ext = os.path.splitext(filename)[1]

    if ext not in ALLOWED_EXTENSIONS:
        allowed_list_str = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise ValidationError(
            f"Tipo de archivo no permitido ('{ext}'). Solo se autorizan formatos "
            f"PDF, LibreOffice (.odt, .ods, .odp, .odg) y Microsoft Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt). "
            f"Formatos permitidos: {allowed_list_str}"
        )

    # 2. Guardar cursor del archivo
    original_pos = 0
    if hasattr(file_obj, "tell"):
        try:
            original_pos = file_obj.tell()
        except (OSError, AttributeError):
            original_pos = 0

    if hasattr(file_obj, "seek"):
        file_obj.seek(0)

    # 3. Lectura de primeros bytes (Magic Bytes)
    header = file_obj.read(2048)

    if hasattr(file_obj, "seek"):
        file_obj.seek(0)

    if len(header) < 4:
        raise ValidationError("El archivo es demasiado pequeño o está corrupto.")

    # 4. Verificación de firmas binarias según extensión
    if ext == ".pdf":
        if not header.startswith(MAGIC_PDF):
            raise ValidationError(
                "Firma de archivo PDF inválida. El archivo no corresponde a un documento PDF legítimo."
            )

    elif ext in {".doc", ".xls", ".ppt"}:
        if not header.startswith(MAGIC_OLE2):
            raise ValidationError(
                f"Firma binaria inválida para formato clásico Office ('{ext}'). "
                f"El archivo debe ser un contenedor OLE2 legítimo."
            )

    elif ext in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".odg"}:
        # Deben ser contenedores ZIP válidos
        if not header.startswith(MAGIC_ZIP):
            raise ValidationError(
                f"Firma binaria inválida para formato ('{ext}'). "
                f"El archivo debe corresponder a un contenedor OpenXML u ODF legítimo."
            )

        # Inspección estructural profunda del ZIP (Anti-Zip Bomb & Anti-Spoofing)
        try:
            # Leer el archivo a memoria para validación ZIP sin extraer al disco
            file_obj.seek(0)
            zip_buffer = io.BytesIO(file_obj.read())
            file_obj.seek(0)

            with zipfile.ZipFile(zip_buffer, "r") as zf:
                # Comprobación de límites (Anti-Zip Bomb)
                entries = zf.infolist()
                if len(entries) > MAX_ZIP_ENTRIES:
                    raise ValidationError("El archivo excede el número máximo permitido de entradas internas.")

                total_uncompressed = sum(entry.file_size for entry in entries)
                if total_uncompressed > MAX_UNCOMPRESSED_ZIP_SIZE:
                    raise ValidationError("El tamaño descomprimido del documento excede los límites de seguridad.")

                filenames = [entry.filename for entry in entries]

                # Validación estructural específica
                if ext in {".odt", ".ods", ".odp", ".odg"}:
                    # LibreOffice / ODF requiere un archivo 'mimetype' en la raíz del contenedor
                    if "mimetype" not in filenames:
                        raise ValidationError("Estructura ODF inválida: falta el descriptor 'mimetype'.")
                    
                    mimetype_content = zf.read("mimetype").decode("ascii", errors="ignore").strip()
                    if not mimetype_content.startswith("application/vnd.oasis.opendocument"):
                        raise ValidationError("El contenido del descriptor ODF no corresponde a LibreOffice/ODF.")

                elif ext in {".docx", ".xlsx", ".pptx"}:
                    # MS Office OpenXML requiere '[Content_Types].xml'
                    if "[Content_Types].xml" not in filenames:
                        raise ValidationError("Estructura OpenXML inválida: falta '[Content_Types].xml'.")

        except zipfile.BadZipFile:
            raise ValidationError("El archivo ZIP del documento se encuentra corrupto o dañado.")

    # Restaurar puntero de lectura original
    if hasattr(file_obj, "seek"):
        file_obj.seek(original_pos)

    return file_obj


class CorporatePasswordComplexityValidator:
    """
    Validador de complejidad corporativa para contraseñas de usuarios en Arcamitte
    (NIST SP 800-63B / ENS op.acc.5 / OWASP A07:2021).
    Exige longitud mínima, mayúsculas, minúsculas, dígitos y caracteres especiales.
    """

    def __init__(self, min_length: int = 10) -> None:
        self.min_length = min_length

    def validate(self, password: str, user: Any = None) -> None:
        errors = []
        if len(password) < self.min_length:
            errors.append(
                ValidationError(
                    _("La contraseña debe contener al menos %(min_length)d caracteres."),
                    code="password_too_short",
                    params={"min_length": self.min_length},
                )
            )
        if not re.search(r"[A-Z]", password):
            errors.append(
                ValidationError(
                    _("Debe incluir al menos una letra mayúscula (A-Z)."),
                    code="password_no_upper",
                )
            )
        if not re.search(r"[a-z]", password):
            errors.append(
                ValidationError(
                    _("Debe incluir al menos una letra minúscula (a-z)."),
                    code="password_no_lower",
                )
            )
        if not re.search(r"[0-9]", password):
            errors.append(
                ValidationError(
                    _("Debe incluir al menos un dígito numérico (0-9)."),
                    code="password_no_digit",
                )
            )
        if not re.search(r"[^A-Za-z0-9\s]", password):
            errors.append(
                ValidationError(
                    _("Debe incluir al menos un carácter especial o símbolo (ej. !@#$%&*+-_=)."),
                    code="password_no_symbol",
                )
            )

        if errors:
            raise ValidationError(errors)

    def get_help_text(self) -> str:
        return str(
            _(
                "Su contraseña debe contener al menos %(min_length)d caracteres e incluir "
                "mayúsculas, minúsculas, números y símbolos especiales."
            )
            % {"min_length": self.min_length}
        )
