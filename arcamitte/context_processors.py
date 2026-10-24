from __future__ import annotations

from typing import Any

from django.http import HttpRequest

from arcamitte.models import UserUOMembership


def arcamitte_dashboard_context(request: HttpRequest) -> dict[str, Any]:
    """
    Inyecta en todas las plantillas el estado de gobernanza del usuario y el modo de interfaz.
    """
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return {
            "dashboard_mode": "operational",
            "user_is_uo_admin": False,
        }

    # Modo para superusuario (por defecto governance si no está seleccionado)
    mode = request.session.get("dashboard_mode", "governance")

    # Determinar si el usuario es administrador de alguna UO o superusuario
    is_admin = user.is_superuser or UserUOMembership.objects.filter(
        user=user,
        role=UserUOMembership.Role.ADMIN,
        is_active=True,
    ).exists()

    return {
        "dashboard_mode": mode,
        "user_is_uo_admin": is_admin,
    }
