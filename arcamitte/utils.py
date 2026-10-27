from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from typing import Any, Optional

from django.conf import settings
from django.http import HttpRequest, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme


def _validate_ip_string(raw_ip: Optional[str]) -> Optional[str]:
    """Valida que una cadena corresponda a una dirección IPv4 o IPv6 legítima."""
    if not raw_ip or not isinstance(raw_ip, str):
        return None
    candidate = raw_ip.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """
    Obtiene la dirección IP remota del cliente de forma segura (Anti-IP Spoofing CWE-348).
    Solo confía en HTTP_X_FORWARDED_FOR si ARCAMITTE_TRUST_X_FORWARDED_FOR está activo
    y siempre verifica que el valor sea una dirección IP sintácticamente válida.
    """
    if getattr(settings, "ARCAMITTE_TRUST_X_FORWARDED_FOR", False):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            first_hop = x_forwarded_for.split(",")[0].strip()
            valid_xff = _validate_ip_string(first_hop)
            if valid_xff:
                return valid_xff

    remote_addr = request.META.get("REMOTE_ADDR")
    valid_remote = _validate_ip_string(remote_addr)
    if valid_remote:
        return valid_remote

    return remote_addr if remote_addr else None


def sanitize_content_disposition_filename(filename: Optional[str], default: str = "documento_confidencial") -> str:
    """
    Sanitiza el nombre de archivo para cabeceras Content-Disposition,
    eliminando rutas, retornos de carro, comillas y caracteres de control (OWASP A03).
    """
    if not filename:
        return default
    base = os.path.basename(str(filename)).strip()
    clean = re.sub(r'[\r\n"\\<>|:*?\x00-\x1f]', "_", base)
    return clean or default


def apply_no_store_headers(response: Any) -> Any:
    """
    Aplica cabeceras estrictas anti-almacenamiento en caché para flujos binarios
    confidenciales descifrados (NIST SP 800-53 SC-28 / ENS mp.info).
    """
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def get_safe_redirect_url(
    request: HttpRequest,
    target_url: Optional[str] = None,
    default_url: str = "/",
    disallowed_substrings: tuple[str, ...] = ("set-language",),
) -> str:
    """
    Resuelve y valida una URL de redirección interna evitando ataques de Open Redirect (CWE-601 / OWASP A01).
    Si el destino no pertenece al host actual o contiene secuencias no permitidas, retorna default_url.
    """
    candidate = (target_url or "").strip()
    if not candidate:
        return default_url

    for disallowed in disallowed_substrings:
        if disallowed in candidate:
            return default_url

    if url_has_allowed_host_and_scheme(
        url=candidate,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return candidate
    return default_url


def safe_redirect(
    request: HttpRequest,
    target_url: Optional[str] = None,
    default_url: str = "/",
) -> HttpResponseRedirect:
    """Ejecuta una redirección segura HTTP garantizando un destino interno validado."""
    return HttpResponseRedirect(get_safe_redirect_url(request, target_url, default_url))


def hash_api_token(raw_key: str) -> str:
    """
    Calcula el hash criptográfico SHA-256 para almacenamiento y autenticación de API Tokens (NIST SP 800-107).
    Los tokens de Arcamitte se generan con 256 bits de entropía pseudoaleatoria criptográfica (secrets.token_urlsafe).
    """
    # CodeQL [py/weak-cryptographic-hash] SHA-256 es el estándar formal para tokens M2M de alta entropía (NIST SP 800-107)
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()
