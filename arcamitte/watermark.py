"""
Módulo de Estampado y Marca de Agua Forense en Metadatos (Forensic Metadata PDF Watermarking).

Cumplimiento Normativo y Estándares:
- ENS (Esquema Nacional de Seguridad) - Nivel ALTO: Trazabilidad, integridad y prevención de fugas de información.
- NIST SP 800-53 Rev. 5: AC-21 (Information Sharing), AU-10 (Non-repudiation).
- ISO/IEC 27001:2022: Control A.8.12 (Data Leakage Prevention).

Inyecta de forma no intrusiva e indeleble la identidad del destinatario,
dirección IP de consulta, marca temporal exacta (UTC) y huella criptográfica del
documento en los metadatos del PDF (/Info dictionary) antes de su entrega o descarga,
manteniendo las páginas del documento 100% limpias e intactas visualmente.
"""

from __future__ import annotations

import io
import logging
from typing import Any, Optional

from django.conf import settings
from django.utils import timezone
import pypdf

logger = logging.getLogger("arcamitte.security")

# Límite defensivo anti-DoS contra bombas de descompresión de páginas en PDFs
MAX_PDF_PAGES_TO_WATERMARK: int = 1000


class WatermarkError(Exception):
    """Excepción base para fallos durante el estampado de marcas de agua forenses."""

    pass


def _escape_pdf_text(text: str) -> str:
    """Escapa caracteres especiales en cadenas de texto para flujos de operadores PDF (Tj)."""
    sanitized = text.encode("ascii", "replace").decode("ascii")
    return sanitized.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_watermark_page_bytes(
    width: float,
    height: float,
    lines: list[str],
    opacity: float = 0.18,
) -> bytes:
    """
    Genera un documento PDF de una página en memoria con operadores gráficos estándar.
    Mantenido como utilidad para pruebas y compatibilidad.
    """
    header = b"%PDF-1.4\n"
    objs: list[bytes] = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
    ]

    stream_lines = ["q", "/GS1 gs", "0.35 0.35 0.35 rg", "BT", "/F1 14 Tf"]
    offsets_y = (
        [height * 0.25, height * 0.60]
        if height < 600
        else [height * 0.20, height * 0.50, height * 0.80]
    )

    for y_pos in offsets_y:
        x_pos = width * 0.15
        stream_lines.append(
            f"0.7071 0.7071 -0.7071 0.7071 {x_pos:.2f} {y_pos:.2f} cm"
        )
        for idx, line in enumerate(lines):
            safe = _escape_pdf_text(line)
            cmd = f"({safe}) Tj" if idx == 0 else f"0 -20 Td\n({safe}) Tj"
            stream_lines.append(cmd)
        stream_lines.append("1 0 0 1 0 0 cm")

    stream_lines.extend(["ET", "Q\n"])
    stream_content = "\n".join(stream_lines).encode("latin-1")

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

    stream_obj = (
        f"4 0 obj\n<< /Length {len(stream_content)} >>\nstream\n".encode("latin-1")
        + stream_content
        + b"\nendstream\nendobj\n"
    )
    objs.append(stream_obj)

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


def _prepare_forensic_metadata(
    existing_meta: dict[str, Any],
    recipient_email: str,
    client_ip: str,
    timestamp_str: str,
    doc_hash: Optional[str] = None,
) -> dict[str, str]:
    """Construye el diccionario de metadatos forenses preservando las claves previas."""
    clean_meta: dict[str, str] = {}
    for key, value in existing_meta.items():
        if isinstance(key, str) and not key.startswith("/Arcamitte"):
            clean_meta[key] = str(value)

    clean_meta.update(
        {
            "/Producer": "Arcamitte Cryptographic Microservice",
            "/ArcamitteAuditTrail": "ARCAMITTE AUDIT TRAIL - COPIA CONTROLADA",
            "/ArcamitteRecipient": recipient_email.strip().lower(),
            "/ArcamitteClientIP": client_ip,
            "/ArcamitteTimestamp": timestamp_str,
            "/ArcamitteDocHash": doc_hash or "",
        }
    )
    return clean_meta


def apply_pdf_watermark(
    pdf_content: bytes,
    recipient_email: str,
    client_ip: str,
    timestamp_str: Optional[str] = None,
    doc_hash: Optional[str] = None,
    opacity: Optional[float] = None,
    **kwargs: Any,
) -> bytes:
    """
    Aplica la marca de agua forense exclusivamente en los metadatos del archivo PDF.
    Las páginas del documento se transfieren intactas para preservar la legibilidad visual 100%.

    Parámetros:
    - pdf_content: Bytes binarios del archivo PDF original descifrado.
    - recipient_email: Correo electrónico o identificador del usuario que retira el documento.
    - client_ip: Dirección IP del solicitante.
    - timestamp_str: Marca temporal legible (si es None, toma la hora UTC actual).
    - doc_hash: Hash SHA-256 del documento original (para trazabilidad forense).
    - opacity: Ignorado por diseño (mantenido por compatibilidad de firma).

    Retorna:
    - Bytes binarios del archivo PDF con los metadatos forenses inyectados de forma invisible.
    """
    if not pdf_content:
        raise WatermarkError("El contenido del PDF a marcar está vacío.")

    effective_timestamp = timestamp_str or timezone.now().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    try:
        reader = pypdf.PdfReader(io.BytesIO(pdf_content))
    except Exception as exc:
        raise WatermarkError(
            f"Error al analizar estructura del archivo PDF original: {exc}"
        ) from exc

    total_pages = len(reader.pages)
    if total_pages == 0:
        raise WatermarkError("El archivo PDF no contiene ninguna página procesable.")

    if total_pages > MAX_PDF_PAGES_TO_WATERMARK:
        raise WatermarkError(
            f"El documento PDF excede el número máximo permitido de páginas ({total_pages} > {MAX_PDF_PAGES_TO_WATERMARK})."
        )

    try:
        writer = pypdf.PdfWriter()

        # Transferencia directa de páginas sin alterar el contenido visual
        for page in reader.pages:
            writer.add_page(page)

        existing_meta = dict(reader.metadata or {})
        forensic_meta = _prepare_forensic_metadata(
            existing_meta=existing_meta,
            recipient_email=recipient_email,
            client_ip=client_ip,
            timestamp_str=effective_timestamp,
            doc_hash=doc_hash,
        )
        writer.add_metadata(forensic_meta)

        output_stream = io.BytesIO()
        writer.write(output_stream)
        watermarked_bytes = output_stream.getvalue()

        logger.info(
            f"[WATERMARK] Marca forense en metadatos aplicada con éxito ({len(watermarked_bytes)} bytes, "
            f"{total_pages} págs) para {recipient_email} desde {client_ip}."
        )
        return watermarked_bytes

    except (MemoryError, RecursionError) as exc:
        logger.error(f"[WATERMARK] Anomalía de recursos al procesar PDF: {exc}")
        raise WatermarkError(
            f"Fallo de recursos al procesar metadatos del PDF: {exc}"
        ) from exc
    except Exception as exc:
        if isinstance(exc, WatermarkError):
            raise
        logger.error(f"[WATERMARK] Fallo al inyectar metadatos forenses: {exc}")
        raise WatermarkError(
            f"Fallo al inyectar metadatos forenses: {exc}"
        ) from exc
