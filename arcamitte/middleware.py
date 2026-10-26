from __future__ import annotations

import logging
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse

logger = logging.getLogger(__name__)


class IPBanMiddleware:
    """
    Middleware perimetral de ultra-baja latencia para interceptar direcciones IP
    incluidas en la lista negra (BannedIP).
    Utiliza django.core.cache para evitar consultas repetitivas a base de datos.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        from arcamitte.utils import get_client_ip
        from django.core.cache import cache
        from django.http import HttpResponseForbidden
        from django.utils.translation import gettext as _

        client_ip = get_client_ip(request)
        if client_ip:
            cache_key = f"arcamitte_banned_ip_{client_ip}"
            cached_status = cache.get(cache_key)

            if cached_status == "BANNED":
                logger.warning(
                    f"[ARCAMITTE SECURITY] Petición bloqueada desde IP baneada: {client_ip}"
                )
                return HttpResponseForbidden(
                    _(
                        "Acceso denegado: Su dirección IP se encuentra bloqueada por motivos de seguridad."
                    )
                )

            if cached_status is None:
                from arcamitte.models import BannedIP
                from django.utils import timezone

                banned_entry = BannedIP.objects.filter(
                    ip_address=client_ip, is_active=True
                ).first()
                if banned_entry and banned_entry.is_currently_banned():
                    ttl = 300
                    if banned_entry.banned_until:
                        rem = int(
                            (banned_entry.banned_until - timezone.now()).total_seconds()
                        )
                        ttl = max(10, min(ttl, rem))
                    cache.set(cache_key, "BANNED", timeout=ttl)
                    logger.warning(
                        f"[ARCAMITTE SECURITY] Petición bloqueada desde IP baneada en BD: {client_ip}"
                    )
                    return HttpResponseForbidden(
                        _(
                            "Acceso denegado: Su dirección IP se encuentra bloqueada por motivos de seguridad."
                        )
                    )
                else:
                    cache.set(cache_key, "ALLOWED", timeout=60)

        return self.get_response(request)


class RequirePasswordChangeMiddleware:
    """
    Middleware de seguridad que intercepta a usuarios autenticados cuya bandera
    must_change_password está activa o cuya contraseña ha superado el ciclo de
    vida máximo por antigüedad (política de 90 días ENS / NIST SP 800-63B).
    Fuerza la redirección hacia la pantalla de cambio de contraseña obligatoria
    antes de permitir el acceso a cualquier otra sección del sistema.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.user.is_authenticated:
            profile = getattr(request.user, "arcamitte_profile", None)
            if profile is None:
                try:
                    profile = request.user.arcamitte_profile
                except Exception:
                    profile = None

            if profile and (
                profile.must_change_password or profile.is_password_expired
            ):
                exempt_paths = [
                    reverse("dashboard:password_change"),
                    reverse("dashboard:logout"),
                ]
                # Rutas exentas de cambio de idioma y recursos
                path = request.path
                is_exempt = (
                    any(path == ep for ep in exempt_paths)
                    or path.startswith("/i18n/")
                    or path.startswith(settings.STATIC_URL)
                )

                if not is_exempt:
                    return redirect("dashboard:password_change")

        return self.get_response(request)
