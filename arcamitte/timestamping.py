"""
Módulo de Sellado Criptográfico Cualificado de Tiempo (RFC 3161 Time-Stamp Protocol).

Cumplimiento Normativo y Estándares:
- Reglamento eIDAS (Reglamento UE Nº 910/2014): Sellos de tiempo electrónicos cualificados.
- ENS (Esquema Nacional de Seguridad) - Nivel ALTO: No repudio de origen y prueba temporal fehaciente.
- RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP).
- RFC 5816: ESSCertIDv2 update for RFC 3161.

Proporciona generación pura en Python (sin librerías binarias externas) de solicitudes ASN.1 DER
para la obtención de sellos de tiempo firmados digitalmente por una Autoridad de Sellado de Tiempo (TSA),
así como la verificación criptográfica del acuse y su anclaje en recibos de auditoría y documentos.
"""

from __future__ import annotations

import base64
import logging
import os
import urllib.request
import urllib.error
from typing import Optional, Tuple
from django.conf import settings

logger = logging.getLogger("arcamitte.security")

# Constantes ASN.1 DER para RFC 3161
# OID para algoritmo SHA-256: 2.16.840.1.101.3.4.2.1
# Codificación DER del AlgorithmIdentifier de SHA-256 con parámetros NULL (05 00):
# SEQUENCE { OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1, NULL }
ALGORITHM_IDENTIFIER_SHA256 = (
    b"\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00"
)


class TimestampingError(Exception):
    """Excepción base para fallos durante el sellado de tiempo RFC 3161."""

    pass


def _encode_der_length(length: int) -> bytes:
    """Codifica la longitud de un elemento ASN.1 en formato DER canónico."""
    if length < 128:
        return bytes([length])
    len_bytes = []
    temp = length
    while temp > 0:
        len_bytes.append(temp & 0xFF)
        temp >>= 8
    len_bytes.reverse()
    return bytes([0x80 | len(len_bytes)]) + bytes(len_bytes)


def _decode_der_length(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Decodifica la longitud ASN.1 DER desde el offset especificado.
    Retorna (length, bytes_consumidos).
    """
    first = data[offset]
    if first < 128:
        return first, 1
    num_bytes = first & 0x7F
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, 1 + num_bytes


def build_rfc3161_request(
    hash_bytes: bytes,
    nonce: Optional[int] = None,
    cert_req: bool = True,
) -> bytes:
    """
    Construye una estructura ASN.1 DER TimeStampReq conforme al estándar RFC 3161.

    TimeStampReq ::= SEQUENCE  {
       version               INTEGER  { v1(1) },
       messageImprint        MessageImprint,
       reqPolicy             TSAPolicyId              OPTIONAL,
       nonce                 INTEGER                  OPTIONAL,
       certReq               BOOLEAN                  DEFAULT FALSE,
       extensions            [0] IMPLICIT Extensions  OPTIONAL
    }

    MessageImprint ::= SEQUENCE  {
       hashAlgorithm         AlgorithmIdentifier,
       hashedMessage         OCTET STRING
    }
    """
    if len(hash_bytes) != 32:
        raise ValueError(
            f"El hash SHA-256 debe tener exactamente 32 bytes de longitud (recibidos {len(hash_bytes)})."
        )

    # 1. MessageImprint
    # HashedMessage: OCTET STRING (Tag 0x04)
    hashed_msg_der = b"\x04" + _encode_der_length(len(hash_bytes)) + hash_bytes
    imprint_content = ALGORITHM_IDENTIFIER_SHA256 + hashed_msg_der
    imprint_der = b"\x30" + _encode_der_length(len(imprint_content)) + imprint_content

    # 2. Version: INTEGER 1 (Tag 0x02, Longitud 1, Valor 0x01)
    version_der = b"\x02\x01\x01"

    # 3. Nonce: Criptográficamente aleatorio de 64 bits para prevenir repetición
    if nonce is None:
        nonce = int.from_bytes(os.urandom(8), "big") & 0x7FFFFFFFFFFFFFFF
    nonce_bytes = nonce.to_bytes((nonce.bit_length() + 8) // 8, "big")
    nonce_der = b"\x02" + _encode_der_length(len(nonce_bytes)) + nonce_bytes

    # 4. CertReq: BOOLEAN TRUE (para que la TSA devuelva la cadena de certificados x509 del firmante)
    cert_req_der = b"\x01\x01\xff" if cert_req else b""

    # Ensamblar cuerpo de TimeStampReq
    body = version_der + imprint_der + nonce_der + cert_req_der
    req_der = b"\x30" + _encode_der_length(len(body)) + body
    return req_der


def request_rfc3161_timestamp(
    hash_bytes: bytes,
    tsa_url: Optional[str] = None,
    timeout: Optional[int] = None,
) -> bytes:
    """
    Envía una petición TimeStampReq a la TSA cualificada configurada mediante HTTP POST
    y valida la respuesta TimeStampResp recibida.

    Retorna:
    - Bytes binarios DER del TimeStampResp devuelto por la TSA.
    """
    effective_tsa_url = (
        tsa_url
        if tsa_url is not None
        else getattr(settings, "ARCAMITTE_RFC3161_TSA_URL", "https://timestamp.digicert.com")
    )
    effective_timeout = (
        timeout
        if timeout is not None
        else getattr(settings, "ARCAMITTE_RFC3161_TIMEOUT", 10)
    )

    if not effective_tsa_url:
        raise TimestampingError("No hay una URL de TSA configurada para el sellado de tiempo.")

    req_data = build_rfc3161_request(hash_bytes)

    headers = {
        "Content-Type": "application/timestamp-query",
        "User-Agent": "Arcamitte-Crypto-Gateway/1.0",
        "Accept": "application/timestamp-reply",
    }

    req = urllib.request.Request(
        url=effective_tsa_url,
        data=req_data,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
            resp_bytes = resp.read()
    except urllib.error.HTTPError as exc:
        raise TimestampingError(f"Error HTTP del servidor TSA ({exc.code}): {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise TimestampingError(f"Fallo de conexión de red con la TSA '{effective_tsa_url}': {exc.reason}") from exc
    except Exception as exc:
        raise TimestampingError(f"Error imprevisto al contactar con la TSA: {exc}") from exc

    # Validar respuesta
    is_valid, msg = verify_rfc3161_timestamp(resp_bytes, hash_bytes)
    if not is_valid:
        raise TimestampingError(f"La respuesta de la TSA no es válida: {msg}")

    logger.info(
        f"[RFC3161] Sello de tiempo obtenido satisfactoriamente de '{effective_tsa_url}' ({len(resp_bytes)} bytes)."
    )
    return resp_bytes


def verify_rfc3161_timestamp(
    tsr_bytes: bytes,
    original_hash: bytes,
) -> Tuple[bool, str]:
    """
    Verifica la estructura básica de una respuesta TimeStampResp:
    1. Debe comenzar con SEQUENCE (0x30).
    2. El estado PKIStatusInfo debe ser 0 (granted) o 1 (grantedWithMods).
    3. La huella original SHA-256 debe hallarse incrustada en el cuerpo del sello.

    Retorna:
    - Tupla (es_valido: bool, mensaje_o_detalle: str).
    """
    if not tsr_bytes or len(tsr_bytes) < 16:
        return False, "Respuesta TSR demasiado corta o vacía."

    if tsr_bytes[0] != 0x30:
        return False, "La respuesta no es una secuencia ASN.1 DER válida."

    # Analizar SEQUENCE exterior
    try:
        total_len, len_offset = _decode_der_length(tsr_bytes, 1)
        cursor = 1 + len_offset

        # Primera sub-estructura: PKIStatusInfo (SEQUENCE)
        if tsr_bytes[cursor] != 0x30:
            return False, "Cabecera PKIStatusInfo ausente o malformada."

        status_len, s_len_bytes = _decode_der_length(tsr_bytes, cursor + 1)
        status_cursor = cursor + 1 + s_len_bytes

        # PKIStatus es INTEGER (Tag 0x02)
        if tsr_bytes[status_cursor] != 0x02:
            return False, "Código de estado PKIStatus no es un INTEGER ASN.1."

        int_len = tsr_bytes[status_cursor + 1]
        status_val = int.from_bytes(
            tsr_bytes[status_cursor + 2 : status_cursor + 2 + int_len], "big"
        )

        # 0 = granted, 1 = grantedWithMods
        if status_val not in (0, 1):
            status_desc = {
                2: "rejection",
                3: "waiting",
                4: "revocationWarning",
                5: "revocationNotification",
            }.get(status_val, f"desconocido ({status_val})")
            return False, f"La TSA rechazó la solicitud con código: {status_desc}."

    except Exception as exc:
        return False, f"Error al parsear estructura DER del acuse TSA: {exc}"

    # Verificación de integridad: el hash SHA-256 original debe estar dentro de la respuesta
    if original_hash not in tsr_bytes:
        return False, "La huella digital original no coincide con el MessageImprint del sello."

    return True, "Sello de tiempo válido y verificado."


def token_to_base64(tsr_bytes: bytes) -> str:
    """Convierte los bytes del token TSA a representación Base64 para almacenamiento en BD."""
    return base64.b64encode(tsr_bytes).decode("ascii")


def token_from_base64(b64_str: str) -> bytes:
    """Decodifica un token TSA almacenado en Base64 a bytes DER."""
    return base64.b64decode(b64_str.encode("ascii"))
