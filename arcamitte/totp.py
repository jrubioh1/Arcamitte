"""
Módulo de Autenticación Multifactor Nativa (2FA / TOTP - RFC 6238 / RFC 4226).

Proporciona generación de secretos, validación de códigos temporales de 6 dígitos
con ventana de deriva, generación de códigos de rescate (scratch codes) con hash SHA-256
y renderizado de códigos QR en formato SVG Data URI (ENS ALTA / NIST SP 800-63B AAL2).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse
from typing import Tuple

import segno


def generate_totp_secret(num_bytes: int = 20) -> str:
    """
    Genera un secreto criptográficamente seguro de 160 bits (20 bytes)
    codificado en Base32 estándar conforme a RFC 6238.
    """
    random_bytes = secrets.token_bytes(num_bytes)
    # Base32 estándar sin padding para compatibilidad con todas las aplicaciones
    return base64.b32encode(random_bytes).decode("ascii").replace("=", "")


def _normalize_b32_secret(secret: str) -> bytes:
    """Normaliza y decodifica un secreto Base32 añadiendo el padding si es necesario."""
    clean_secret = secret.strip().replace(" ", "").upper()
    missing_padding = (8 - len(clean_secret) % 8) % 8
    clean_secret += "=" * missing_padding
    return base64.b32decode(clean_secret, casefold=True)


def get_totp_uri(
    secret: str,
    username: str,
    issuer: str = "Arcamitte",
) -> str:
    """
    Construye la URI canónica 'otpauth://totp/...' compatible con Google Authenticator,
    Microsoft Authenticator, Aegis, FreeOTP, Bitwarden y 1Password.
    """
    clean_secret = secret.strip().replace(" ", "").upper()
    label = f"{issuer}:{username}"
    encoded_label = urllib.parse.quote(label)
    params = {
        "secret": clean_secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    }
    return f"otpauth://totp/{encoded_label}?{urllib.parse.urlencode(params)}"


def generate_totp_code(
    secret: str,
    timestamp: int | None = None,
    interval: int = 30,
) -> str:
    """
    Calcula el código TOTP de 6 dígitos en un instante temporal según RFC 6238 / RFC 4226.
    """
    current_time = int(time.time()) if timestamp is None else timestamp
    counter = current_time // interval

    key_bytes = _normalize_b32_secret(secret)
    msg_bytes = struct.pack(">Q", counter)

    hmac_digest = hmac.new(key_bytes, msg_bytes, hashlib.sha1).digest()
    offset = hmac_digest[19] & 0x0F
    truncated_hash = (
        struct.unpack(">I", hmac_digest[offset : offset + 4])[0] & 0x7FFFFFFF
    )
    code = truncated_hash % 1_000_000
    return f"{code:06d}"


def verify_totp_code(
    secret: str,
    code: str,
    window: int = 1,
    interval: int = 30,
    timestamp: int | None = None,
) -> bool:
    """
    Verifica un código TOTP en tiempo constante contra una ventana de deriva (por defecto +/- 1 intervalo).
    """
    if not secret or not code:
        return False

    clean_code = code.strip().replace(" ", "").replace("-", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False

    current_time = int(time.time()) if timestamp is None else timestamp
    current_counter = current_time // interval

    try:
        key_bytes = _normalize_b32_secret(secret)
    except Exception:
        return False

    for step in range(-window, window + 1):
        counter = current_counter + step
        msg_bytes = struct.pack(">Q", counter)
        hmac_digest = hmac.new(key_bytes, msg_bytes, hashlib.sha1).digest()
        offset = hmac_digest[19] & 0x0F
        truncated_hash = (
            struct.unpack(">I", hmac_digest[offset : offset + 4])[0] & 0x7FFFFFFF
        )
        candidate = f"{(truncated_hash % 1_000_000):06d}"

        if hmac.compare_digest(candidate, clean_code):
            return True

    return False


def normalize_scratch_code(code: str) -> str:
    """Normaliza un código de rescate eliminando espacios, guiones y convirtiendo a mayúsculas."""
    return code.strip().replace(" ", "").replace("-", "").upper()


def hash_scratch_code(code: str) -> str:
    """Calcula el hash SHA-256 seguro de un código de rescate normalizado."""
    clean = normalize_scratch_code(code)
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def generate_scratch_codes(count: int = 8) -> Tuple[list[str], list[str]]:
    """
    Genera códigos de rescate unívocos para recuperación de emergencia en formato XXXX-XXXX.
    Retorna una tupla: (códigos_en_claro_para_el_usuario, hashes_sha256_para_base_de_datos).
    """
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # Excluye 0, O, 1, I para evitar ambigüedades
    plain_codes: list[str] = []
    hashed_codes: list[str] = []

    for _ in range(count):
        part1 = "".join(secrets.choice(alphabet) for _ in range(4))
        part2 = "".join(secrets.choice(alphabet) for _ in range(4))
        code_str = f"{part1}-{part2}"
        plain_codes.append(code_str)
        hashed_codes.append(hash_scratch_code(code_str))

    return plain_codes, hashed_codes


def generate_qr_svg_data_uri(uri: str) -> str:
    """
    Genera un Data URI con la imagen vectorial SVG del código QR
    para su inclusión segura en plantillas HTML (<img src='data:image/svg+xml...'>).
    """
    qr = segno.make(uri, error="m")
    return qr.svg_data_uri(scale=4)
