from __future__ import annotations

from typing import Optional
from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """Obtiene la dirección IP remota del cliente considerando proxies inversos."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")
