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


class SessionSecurityMiddleware:
    """
    Middleware de control y endurecimiento de sesión (ENS / NIST SP 800-63B / OWASP A07):
    1. Vinculación estricta de IP (session_ip_binding) contra robo y secuestro de cookies (Session Hijacking).
    2. Sesión concurrente única por usuario (single_session_per_user) contra accesos simultáneos no autorizados.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.user.is_authenticated:
            path = request.path
            exempt_paths = [
                reverse("dashboard:logout"),
                reverse("dashboard:login"),
            ]
            if (
                any(path == ep for ep in exempt_paths)
                or path.startswith("/i18n/")
                or path.startswith(settings.STATIC_URL)
            ):
                return self.get_response(request)

            from arcamitte.utils import get_client_ip
            from django.contrib import messages
            from django.contrib.auth import logout
            from django.utils.translation import gettext as _

            current_ip = get_client_ip(request)

            # 1. Control de Session Hijacking (IP Binding)
            if getattr(settings, "ARCAMITTE_SESSION_IP_BINDING", True):
                session_ip = request.session.get("_arca_client_ip")
                if session_ip and current_ip and session_ip != current_ip:
                    username = getattr(request.user, "username", str(request.user))
                    logger.warning(
                        f"[ARCAMITTE SECURITY] Posible secuestro de sesión detectado para usuario '{username}'. "
                        f"IP de sesión: {session_ip}, IP entrante: {current_ip}."
                    )
                    from arcamitte.models import DocumentAccessLog
                    from arcamitte.services import dispatch_siem_event, record_audit_log

                    record_audit_log(
                        action=DocumentAccessLog.Action.SECUESTRO_SESION_DETECTADO,
                        email=getattr(request.user, "email", "") or username,
                        ip=current_ip,
                        user_agent=request.META.get("HTTP_USER_AGENT", ""),
                        details={
                            "usuario": username,
                            "ip_registrada": session_ip,
                            "ip_discrepante": current_ip,
                            "accion": "cierre_forzoso_sesion",
                        },
                    )
                    dispatch_siem_event(
                        event_type="session_hijack_detected",
                        details={"expected_ip": session_ip, "actual_ip": current_ip},
                        actor=username,
                        ip=current_ip,
                    )
                    logout(request)
                    messages.error(
                        request,
                        _(
                            "Su sesión ha sido invalidada por motivos de seguridad debido a una discrepancia de red (posible secuestro de sesión)."
                        ),
                        fail_silently=True,
                    )
                    return redirect("dashboard:login")
                elif not session_ip and current_ip:
                    request.session["_arca_client_ip"] = current_ip

            # 2. Control de Sesión Concurrente Única (Single Session)
            if getattr(settings, "ARCAMITTE_SINGLE_SESSION_PER_USER", True):
                profile = getattr(request.user, "arcamitte_profile", None)
                if profile is None:
                    try:
                        profile = request.user.arcamitte_profile
                    except Exception:
                        profile = None

                session_key = request.session.session_key
                if profile and session_key:
                    if not profile.current_session_key:
                        profile.current_session_key = session_key
                        profile.save(
                            update_fields=["current_session_key", "updated_at"]
                        )
                    elif profile.current_session_key != session_key:
                        if request.session.get("_arca_session_initialized"):
                            username = getattr(
                                request.user, "username", str(request.user)
                            )
                            logger.info(
                                f"[ARCAMITTE SECURITY] Sesión concurrente previa revocada para '{username}'."
                            )
                            from arcamitte.models import DocumentAccessLog
                            from arcamitte.services import record_audit_log

                            record_audit_log(
                                action=DocumentAccessLog.Action.SESION_CONCURRENTE_TERMINADA,
                                email=getattr(request.user, "email", "") or username,
                                ip=current_ip,
                                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                                details={
                                    "usuario": username,
                                    "sesion_expirada": session_key,
                                    "sesion_activa": profile.current_session_key,
                                },
                            )
                            logout(request)
                            messages.info(
                                request,
                                _(
                                    "Su sesión ha expirado porque se ha iniciado sesión desde otro navegador o dispositivo."
                                ),
                                fail_silently=True,
                            )
                            return redirect("dashboard:login")
                        else:
                            profile.current_session_key = session_key
                            profile.save(
                                update_fields=["current_session_key", "updated_at"]
                            )

                    request.session["_arca_session_initialized"] = True

        return self.get_response(request)
