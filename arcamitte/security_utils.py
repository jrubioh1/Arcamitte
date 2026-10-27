from __future__ import annotations

import hashlib
import logging
from typing import Optional

from django.http import HttpRequest, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
from rest_framework import status
from rest_framework.response import Response

logger = logging.getLogger(__name__)


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
    """Valida y redirige de forma segura sin duplicar lógica."""
    return HttpResponseRedirect(get_safe_redirect_url(request, target_url, default_url))


def redirect_to_next_or_default(
    request: HttpRequest,
    default_url: str = "/",
) -> HttpResponseRedirect:
    """Extrae 'next' o 'HTTP_REFERER' de la petición y redirige con validación anti-Open Redirect."""
    target_url = (
        request.POST.get("next")
        or request.GET.get("next")
        or request.META.get("HTTP_REFERER")
    )
    return safe_redirect(request, target_url=target_url, default_url=default_url)


def handle_api_exception(
    exc: Exception,
    log_message: str = "Error procesando la solicitud",
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    user_message: str = "Ha ocurrido un error al procesar la solicitud.",
) -> Response:
    """Manejo centralizado de excepciones para no exponer trazas internas ni duplicar responses."""
    logger.error(f"{log_message}: {exc}", exc_info=True)
    return Response(
        {"error": user_message},
        status=status_code,
    )


def hash_api_token(raw_key: str) -> str:
    """
    Calcula el hash criptográfico SHA-256 para almacenamiento y autenticación de API Tokens (NIST SP 800-107).
    Los tokens de Arcamitte se generan con 256 bits de entropía pseudoaleatoria criptográfica (secrets.token_urlsafe).
    """
    # CodeQL [py/weak-cryptographic-hash] SHA-256 es el estándar formal para tokens M2M de alta entropía (NIST SP 800-107)
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()
