from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _

from arcamitte.models import UserUOMembership
from arcamitte.permissions import is_global_admin


def arcamitte_dashboard_context(request: HttpRequest) -> dict[str, Any]:
    """
    Inyecta en todas las plantillas el estado de gobernanza del usuario, el modo de interfaz
    y la información de rol y Unidad Organizativa activa, utilizando exclusivamente is_global_admin.
    """
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return {
            "dashboard_mode": "operational",
            "is_global_admin": False,
            "user_is_uo_admin": False,
            "user_is_auditor": False,
            "user_can_view_audit_logs": False,
            "user_can_view_analytics": False,
            "user_primary_role": None,
            "user_primary_role_display": "",
            "user_primary_uo_alias": "",
            "user_primary_uo_name": "",
        }

    mode = request.session.get("dashboard_mode", "governance")

    primary_membership = (
        UserUOMembership.objects.filter(user=user, is_active=True)
        .select_related("uo")
        .first()
    )

    is_global = is_global_admin(user)

    is_admin = is_global or (
        primary_membership is not None
        and primary_membership.role == UserUOMembership.Role.ADMIN
    )

    is_auditor = is_global or (
        primary_membership is not None
        and primary_membership.role == UserUOMembership.Role.AUDITOR
    )

    can_view_audit_logs = is_global or is_admin or is_auditor
    can_view_analytics = is_global or is_admin or is_auditor or (
        UserUOMembership.objects.filter(
            user=user,
            is_active=True,
            role__in=[UserUOMembership.Role.ADMIN, UserUOMembership.Role.AUDITOR],
        ).exists()
    )

    if is_global:
        user_primary_role = "GLOBAL_ADMIN"
        user_primary_role_display = str(_("Administrador Global"))
        user_primary_uo_alias = ""
        user_primary_uo_name = ""
    elif primary_membership:
        user_primary_role = primary_membership.role
        user_primary_role_display = str(primary_membership.get_role_display())
        user_primary_uo_alias = primary_membership.uo.alias
        user_primary_uo_name = primary_membership.uo.name
    else:
        user_primary_role = "STANDALONE"
        user_primary_role_display = str(_("Personal / Sin UO"))
        user_primary_uo_alias = ""
        user_primary_uo_name = ""

    return {
        "dashboard_mode": mode,
        "is_global_admin": is_global,
        "user_is_uo_admin": is_admin,
        "user_is_auditor": is_auditor,
        "user_can_view_audit_logs": can_view_audit_logs,
        "user_can_view_analytics": can_view_analytics,
        "user_primary_role": user_primary_role,
        "user_primary_role_display": user_primary_role_display,
        "user_primary_uo_alias": user_primary_uo_alias,
        "user_primary_uo_name": user_primary_uo_name,
        "primary_membership": primary_membership,
    }
