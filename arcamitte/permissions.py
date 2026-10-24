from __future__ import annotations

from typing import Any
from rest_framework import permissions
from arcamitte.models import APIToken


class IsAuthenticatedOrToken(permissions.BasePermission):
    """
    Permite el acceso si el usuario está autenticado en sesión o si la petición
    ha sido autenticada con un APIToken válido.
    """

    def has_permission(self, request: Any, view: Any) -> bool:
        if request.auth and isinstance(request.auth, APIToken) and request.auth.is_valid():
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
        if request.user and request.user.is_authenticated and request.user.is_superuser:
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
