from __future__ import annotations

import ipaddress
import os
import re
from typing import Any, Optional

from django.conf import settings
from django.http import HttpRequest


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
