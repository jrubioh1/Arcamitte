"""
Módulo de Estampado y Marca de Agua Forense Dinámica (Dynamic Forensic PDF Watermarking).

Cumplimiento Normativo y Estándares:
- ENS (Esquema Nacional de Seguridad) - Nivel ALTO: Trazabilidad, integridad y prevención de fugas de información.
- NIST SP 800-53 Rev. 5 (AC-21 Information Sharing, AU-10 Non-repudiation).
- ISO/IEC 27001:2022 - Control A.8.12 (Data Leakage Prevention).

Permite inyectar de forma transparente e indelible la identidad del destinatario,
dirección IP de consulta, marca temporal exacta (UTC) y huella criptográfica del
documento en cada página de un archivo PDF antes de su descarga o visualización.
"""

from __future__ import annotations

import io
import logging
from typing import Optional
from django.conf import settings
from django.utils import timezone
import pypdf

logger = logging.getLogger("arcamitte.security")


class WatermarkError(Exception):
    """Excepción base para fallos durante el estampado de marcas de agua forenses."""

    pass


def _escape_pdf_text(text: str) -> str:
    """
    Escapa caracteres especiales en cadenas de texto para flujos de operadores PDF (Tj).
    Sustituye barras invertidas y paréntesis no balanceados.
    """
    # Limitar a caracteres imprimibles Latin-1 / ASCII para tipografía estándar Type1
    sanitized = text.encode("ascii", "replace").decode("ascii")
    return sanitized.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_watermark_page_bytes(
    width: float,
    height: float,
    lines: list[str],
    opacity: float = 0.18,
) -> bytes:
    """
    Genera un documento PDF de una sola página en memoria con texto oblicuo semitransparente
    construido bajo especificación ISO 32000-1 (PDF 1.4+).
    No depende de ReportLab ni librerías pesadas en C/C++.
    """
    header = b"%PDF-1.4\n"
    objs: list[bytes] = []

    # Objeto 1: Catalog
    objs.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    # Objeto 2: Pages
    objs.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

    # Construcción de operadores del flujo gráfico
    stream_lines = [
        "q",
        "/GS1 gs",
        "0.35 0.35 0.35 rg",  # Gris oscuro atenuado
        "BT",
        "/F1 14 Tf",
    ]

    # Calcular posiciones repetitivas diagonales (45 grados) a lo largo del plano
    # Matriz de rotación a 45 grados: cos(45)=0.7071, sin(45)=0.7071, -sin(45)=-0.7071, cos(45)=0.7071
    # Colocar 2 o 3 bloques escalonados según el tamaño de la página
    offsets_y = [height * 0.25, height * 0.60] if height < 600 else [height * 0.20, height * 0.50, height * 0.80]

    for y_pos in offsets_y:
        x_pos = width * 0.15
        stream_lines.append(f"0.7071 0.7071 -0.7071 0.7071 {x_pos:.2f} {y_pos:.2f} cm")
        for idx, line in enumerate(lines):
            safe = _escape_pdf_text(line)
            if idx == 0:
                stream_lines.append(f"({safe}) Tj")
            else:
                stream_lines.append("0 -20 Td")
                stream_lines.append(f"({safe}) Tj")
        # Resetear matriz de transformación
        stream_lines.append("1 0 0 1 0 0 cm")

    stream_lines.extend(["ET", "Q\n"])
    stream_content = "\n".join(stream_lines).encode("latin-1")

    # Objeto 3: Page con ExtGState para opacidad/transparencia y fuente Helvetica-Bold
    page_def = (
        f"3 0 obj\n<<\n  /Type /Page\n  /Parent 2 0 R\n"
        f"  /MediaBox [0 0 {width:.2f} {height:.2f}]\n"
        f"  /Resources <<\n"
        f"    /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> >>\n"
        f"    /ExtGState << /GS1 << /Type /ExtGState /ca {opacity:.2f} /CA {opacity:.2f} >> >>\n"
        f"  >>\n"
        f"  /Contents 4 0 R\n"
        f">>\nendobj\n"
    ).encode("latin-1")
    objs.append(page_def)

    # Objeto 4: Flujo de contenido
    stream_obj = (
        f"4 0 obj\n<< /Length {len(stream_content)} >>\nstream\n".encode("latin-1")
        + stream_content
        + b"\nendstream\nendobj\n"
    )
    objs.append(stream_obj)

    # Cálculo exacto de desplazamientos (XREF Table)
    body = bytearray(header)
    offsets: list[int] = [0]
    for obj in objs:
        offsets.append(len(body))
        body.extend(obj)

    startxref = len(body)
    xref = [f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("latin-1")]
    for off in offsets[1:]:
        xref.append(f"{off:010d} 00000 n \n".encode("latin-1"))

    trailer = (
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n"
    ).encode("latin-1")

    return bytes(body + b"".join(xref) + trailer)


def apply_pdf_watermark(
    pdf_content: bytes,
    recipient_email: str,
    client_ip: str,
    timestamp_str: Optional[str] = None,
    doc_hash: Optional[str] = None,
    opacity: Optional[float] = None,
) -> bytes:
    """
    Aplica una marca de agua forense oblicua y semitransparente a todas las páginas de un PDF.

    Parámetros:
    - pdf_content: Bytes binarios del archivo PDF original descifrado.
    - recipient_email: Correo electrónico o identificador del usuario que retira el documento.
    - client_ip: Dirección IP del solicitante.
    - timestamp_str: Marca temporal legible (si es None, toma la hora UTC actual).
    - doc_hash: Hash SHA-256 del documento original (para traza forense).
    - opacity: Nivel de opacidad alfa (0.0 a 1.0). Si es None, utiliza settings.ARCAMITTE_WATERMARK_OPACITY.

    Retorna:
    - Bytes binarios del archivo PDF resultante con la marca de agua forense integrada.
    """
    if not pdf_content:
        raise WatermarkError("El contenido del PDF a marcar está vacío.")

    if opacity is None:
        opacity = getattr(settings, "ARCAMITTE_WATERMARK_OPACITY", 0.18)

    if not timestamp_str:
        timestamp_str = timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    hash_preview = f"ID: {doc_hash[:16]}..." if doc_hash else "ID: N/A"

    lines = [
        "ARCAMITTE AUDIT TRAIL - COPIA CONTROLADA",
        f"DESTINATARIO: {recipient_email.strip().lower()}",
        f"IP: {client_ip} | FECHA: {timestamp_str}",
        f"HUELLA: {hash_preview}",
    ]

    try:
        reader = pypdf.PdfReader(io.BytesIO(pdf_content))
    except Exception as exc:
        raise WatermarkError(f"Error al analizar estructura del archivo PDF original: {exc}") from exc

    if len(reader.pages) == 0:
        raise WatermarkError("El archivo PDF no contiene ninguna página procesable.")

    writer = pypdf.PdfWriter()

    for idx, page in enumerate(reader.pages):
        try:
            mb = page.mediabox
            width = float(mb.width)
            height = float(mb.height)

            # Generar capa de marca de agua con dimensiones exactas de la página
            wm_pdf_bytes = _build_watermark_page_bytes(
                width=width,
                height=height,
                lines=lines,
                opacity=opacity,
            )
            wm_reader = pypdf.PdfReader(io.BytesIO(wm_pdf_bytes))
            wm_page = wm_reader.pages[0]

            # Agregar la página al writer y fusionar la capa de marca de agua
            added_page = writer.add_page(page)
            added_page.merge_page(wm_page)
        except Exception as exc:
            logger.error(f"[WATERMARK] Fallo al estampar página #{idx + 1}: {exc}")
            raise WatermarkError(f"Fallo al estampar página #{idx + 1}: {exc}") from exc

    output_stream = io.BytesIO()
    writer.write(output_stream)
    watermarked_bytes = output_stream.getvalue()

    logger.info(
        f"[WATERMARK] Marca forense aplicada con éxito a PDF ({len(watermarked_bytes)} bytes, "
        f"{len(reader.pages)} págs) para {recipient_email} desde {client_ip}."
    )
    return watermarked_bytes
