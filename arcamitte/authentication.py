from __future__ import annotations

import hashlib
from typing import Any, Optional, Tuple

from django.contrib.auth.models import AnonymousUser
from django.utils.translation import gettext_lazy as _
from rest_framework import authentication, exceptions

from arcamitte.models import APIToken
from arcamitte.utils import get_client_ip


class APITokenAuthentication(authentication.BaseAuthentication):
    """
    Autenticación criptográfica de alta seguridad para la API REST de Arcamitte.
    Cumple con NIST SP 800-53 (SC-28) y OWASP API Security (API2:2023):
    
    Acepta tokens en:
    1. Cabecera 'X-API-Key: arca_live_...'
    2. Cabecera 'Authorization: Bearer arca_live_...'
    3. Cabecera 'Authorization: Api-Key arca_live_...'
    
    Verifica el token mediante su hash SHA-256 (Zero-Knowledge Server Storage).
    """

    keyword_bearer = "bearer"
    keyword_apikey = "api-key"

    def authenticate(self, request: Any) -> Optional[Tuple[Any, APIToken]]:
        raw_token = self._extract_token(request)
        if not raw_token:
            return None

        clean_token = raw_token.strip()
        if not clean_token.startswith(("arca_live_", "fdec_live_")):
            raise exceptions.AuthenticationFailed(
                _("Formato de token de API inválido. Debe comenzar con 'arca_live_'."),
                code="invalid_token_format",
            )

        token_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()

        try:
            token = (
                APIToken.objects.select_related("uo", "created_by")
                .filter(hashed_token=token_hash, is_active=True)
                .first()
            )
        except Exception as exc:
            raise exceptions.AuthenticationFailed(_("Error al verificar credenciales."), code="auth_error") from exc

        if not token or not token.is_valid():
            raise exceptions.AuthenticationFailed(
                _("Token de API inválido, revocado o expirado."),
                code="invalid_or_expired_token",
            )

        # Registro de uso (trazabilidad legal y de seguridad)
        client_ip = get_client_ip(request)
        try:
            token.record_usage(ip_address=client_ip)
        except Exception:
            pass

        # Si el token fue emitido por un usuario registrado, lo asociamos; si no, usuario anónimo autenticado por token
        user = token.created_by if token.created_by and token.created_by.is_active else AnonymousUser()
        return user, token

    def authenticate_header(self, request: Any) -> str:
        return 'Bearer realm="api"'

    def _extract_token(self, request: Any) -> Optional[str]:
        # 1. Cabecera directa X-API-Key
        api_key_header = request.headers.get("X-API-Key") or request.META.get("HTTP_X_API_KEY")
        if api_key_header:
            return api_key_header

        # 2. Cabecera estándar Authorization
        auth_header = request.headers.get("Authorization") or request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
            return None

        parts = auth_header.split()
        if len(parts) == 2:
            scheme = parts[0].lower()
            if scheme in (self.keyword_bearer, self.keyword_apikey):
                return parts[1]

        return None
