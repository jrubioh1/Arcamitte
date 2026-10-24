from __future__ import annotations

import logging
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse

logger = logging.getLogger(__name__)


class RequirePasswordChangeMiddleware:
    """
    Middleware de seguridad que intercepta a usuarios autenticados cuya bandera
    must_change_password está activa (ej. contraseñas temporales por reseteo).
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

            if profile and profile.must_change_password:
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
