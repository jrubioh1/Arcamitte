from __future__ import annotations

from typing import Any
from rest_framework import permissions
from arcamitte.models import APIToken, UserUOMembership


def is_global_admin(user: Any) -> bool:
    """
    Comprueba si el usuario tiene el rol de Administrador Global de Seguridad de Arcamitte.
    Evaluado exclusivamente sobre el perfil institucional (UserProfile.is_global_admin),
    completamente desacoplado de las marcas internas de Django (is_staff / is_superuser).
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    profile = getattr(user, "arcamitte_profile", None)
    return bool(profile and getattr(profile, "is_global_admin", False))


def is_uo_admin(user: Any, uo: Any = None) -> bool:
    """
    Comprueba si el usuario es Administrador de una UO específica o de alguna UO activa.
    Los Administradores Globales tienen potestad administrativa sobre todas las UOs.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if is_global_admin(user):
        return True
    qs = UserUOMembership.objects.filter(
        user=user, is_active=True, role=UserUOMembership.Role.ADMIN
    )
    if uo is not None:
        qs = qs.filter(uo=uo)
    return qs.exists()


def is_uo_auditor(user: Any, uo: Any = None) -> bool:
    """
    Comprueba si el usuario es Auditor de una UO específica o de alguna UO activa.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if is_global_admin(user):
        return True
    qs = UserUOMembership.objects.filter(
        user=user, is_active=True, role=UserUOMembership.Role.AUDITOR
    )
    if uo is not None:
        qs = qs.filter(uo=uo)
    return qs.exists()


def is_uo_operator(user: Any, uo: Any = None) -> bool:
    """
    Comprueba si el usuario es Operador de una UO específica o de alguna UO activa.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if is_global_admin(user):
        return True
    qs = UserUOMembership.objects.filter(
        user=user, is_active=True, role=UserUOMembership.Role.OPERATOR
    )
    if uo is not None:
        qs = qs.filter(uo=uo)
    return qs.exists()


def can_manage_security_perimeter(user: Any) -> bool:
    """Determina si el usuario puede administrar el perímetro de seguridad (SOC, IPs, 2FA global)."""
    return is_global_admin(user)


def can_manage_api_tokens(user: Any) -> bool:
    """Determina si el usuario puede crear, consultar y revocar API tokens M2M."""
    return is_global_admin(user)


def can_manage_uo_members(user: Any, uo: Any) -> bool:
    """Determina si el usuario puede administrar miembros dentro de una UO."""
    return is_global_admin(user) or is_uo_admin(user, uo)


def can_burn_download(user: Any, document: Any) -> bool:
    """Determina si el usuario puede descargar y clausurar destructivamente un asiento."""
    if is_global_admin(user):
        return True
    origin_uo = getattr(document, "origin_uo", None)
    return is_uo_admin(user, origin_uo)


def can_audit_download(user: Any, document: Any) -> bool:
    """Determina si el usuario puede realizar descargas de auditoría administrativa preservada."""
    if is_global_admin(user):
        return True
    origin_uo = getattr(document, "origin_uo", None)
    return is_uo_auditor(user, origin_uo) or is_uo_admin(user, origin_uo)


class IsAuthenticatedOrToken(permissions.BasePermission):
    """
    Permite el acceso si el usuario está autenticado en sesión o si la petición
    ha sido autenticada con un APIToken válido.
    """

    def has_permission(self, request: Any, view: Any) -> bool:
        if (
            request.auth
            and isinstance(request.auth, APIToken)
            and request.auth.is_valid()
        ):
            return True
        return bool(request.user and request.user.is_authenticated)


class HasTokenScope(permissions.BasePermission):
    """
    Permiso granular para verificar que el token de API autenticado dispone
    del scope requerido para la acción.
    """

    required_scope: str = ""

    def __init__(self, required_scope: str = "") -> None:
        if required_scope:
            self.required_scope = required_scope

    def has_permission(self, request: Any, view: Any) -> bool:
        # Los superusuarios en sesiones web siempre tienen permiso
        if request.user and request.user.is_authenticated and is_global_admin(request.user):
            return True

        token = request.auth
        if isinstance(token, APIToken):
            scope = getattr(view, "required_scope", self.required_scope)
            if not scope:
                return True
            return token.has_scope(scope)

        return False


class HasDocumentsCreateScope(HasTokenScope):
    required_scope = "documents:create"


class HasDocumentsReadScope(HasTokenScope):
    required_scope = "documents:read"


class HasUOsReadScope(HasTokenScope):
    required_scope = "uos:read"
