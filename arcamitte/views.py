from __future__ import annotations

import io
import logging
from typing import Any, Optional, Tuple

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.http import FileResponse, HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import activate, check_for_language, gettext as _
from django.views import View
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from arcamitte.authentication import APITokenAuthentication
from arcamitte.forms import RedeemOtpForm, RequestAccessForm
from arcamitte.models import APIToken, EncryptedDocument
from arcamitte.permissions import (
    HasDocumentsCreateScope,
    HasDocumentsReadScope,
    IsAuthenticatedOrToken,
)
from arcamitte.serializers import (
    APIDocumentUploadSerializer,
    PublicAccessRequestSerializer,
    PublicConsumeSerializer,
)
from arcamitte.services import (
    consume_document_with_otp,
    request_document_access,
    upload_and_encrypt_document,
)
from arcamitte.utils import get_client_ip

logger = logging.getLogger(__name__)



def set_language_view(request: HttpRequest) -> HttpResponseRedirect:
    """Cambia el idioma activo de la interfaz y redirige a la vista previa."""
    lang_code = request.GET.get("lang") or request.POST.get("language")
    try:
        fallback_url = reverse("arcamitte:request-access")
    except Exception:
        fallback_url = "/arcamitte/solicitar/"

    next_url = request.GET.get("next") or request.META.get("HTTP_REFERER") or fallback_url
    if "set-language" in next_url:
        next_url = fallback_url
    response = HttpResponseRedirect(next_url)

    if lang_code and check_for_language(lang_code):
        if hasattr(request, "session"):
            request.session["django_language"] = lang_code
            request.session["_language"] = lang_code
        cookie_name = getattr(settings, "LANGUAGE_COOKIE_NAME", "django_language")
        response.set_cookie(
            cookie_name,
            lang_code,
            max_age=getattr(settings, "LANGUAGE_COOKIE_AGE", 365 * 24 * 60 * 60),
            path=getattr(settings, "LANGUAGE_COOKIE_PATH", "/"),
            domain=getattr(settings, "LANGUAGE_COOKIE_DOMAIN", None),
            secure=getattr(settings, "LANGUAGE_COOKIE_SECURE", not getattr(settings, "DEBUG", True)),
            httponly=getattr(settings, "LANGUAGE_COOKIE_HTTPONLY", True),
            samesite=getattr(settings, "LANGUAGE_COOKIE_SAMESITE", "Lax"),
        )
        activate(lang_code)
        request.LANGUAGE_CODE = lang_code
    return response


class ArcamitteI18nViewMixin:
    """
    Garantiza que el idioma activo se determine y active correctamente
    a partir del parámetro GET, sesión, cookie o cabeceras HTTP, incluso si el
    proyecto anfitrión no dispone de 'LocaleMiddleware' en su configuración.
    """

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        lang_code = request.GET.get("lang")
        if not lang_code and hasattr(request, "session"):
            lang_code = request.session.get("django_language") or request.session.get("_language")
        if not lang_code:
            cookie_name = getattr(settings, "LANGUAGE_COOKIE_NAME", "django_language")
            lang_code = request.COOKIES.get(cookie_name)
        if not lang_code or not check_for_language(lang_code):
            lang_code = getattr(request, "LANGUAGE_CODE", None)
        if not lang_code or not check_for_language(lang_code):
            lang_code = getattr(settings, "LANGUAGE_CODE", "es")

        if lang_code and check_for_language(lang_code):
            activate(lang_code)
            request.LANGUAGE_CODE = lang_code

        response = super().dispatch(request, *args, **kwargs)

        if hasattr(response, "set_cookie") and lang_code and check_for_language(lang_code):
            cookie_name = getattr(settings, "LANGUAGE_COOKIE_NAME", "django_language")
            if request.COOKIES.get(cookie_name) != lang_code:
                response.set_cookie(
                    cookie_name,
                    lang_code,
                    max_age=getattr(settings, "LANGUAGE_COOKIE_AGE", 365 * 24 * 60 * 60),
                    path=getattr(settings, "LANGUAGE_COOKIE_PATH", "/"),
                    domain=getattr(settings, "LANGUAGE_COOKIE_DOMAIN", None),
                    secure=getattr(settings, "LANGUAGE_COOKIE_SECURE", not getattr(settings, "DEBUG", True)),
                    httponly=getattr(settings, "LANGUAGE_COOKIE_HTTPONLY", True),
                    samesite=getattr(settings, "LANGUAGE_COOKIE_SAMESITE", "Lax"),
                )
        return response



class AccessRequestRateThrottle(AnonRateThrottle):
    scope = "access_request"
    rate: Optional[str] = None

    def get_rate(self) -> Optional[str]:
        if self.rate is not None:
            return self.rate
        return super().get_rate()

    def get_cache_key(self, request: HttpRequest, view: Any) -> Optional[str]:
        ident = get_client_ip(request) or "anon"
        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }


class AccessConsumeRateThrottle(AnonRateThrottle):
    scope = "access_consume"
    rate: Optional[str] = None

    def get_rate(self) -> Optional[str]:
        if self.rate is not None:
            return self.rate
        return super().get_rate()

    def get_cache_key(self, request: HttpRequest, view: Any) -> Optional[str]:
        ident = get_client_ip(request) or "anon"
        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }


class RequestAccessView(ArcamitteI18nViewMixin, View):
    """
    Vista Web GUI para solicitar acceso mediante Hash SHA-256 y OTP.

    Regla de Oro:
    El usuario final NUNCA sube el archivo .enc.
    El localizador oficial y prueba de trámite es exclusivamente el hash SHA-256.
    Soporta recibir ?hash=... por URL para auto-completar el formulario.
    """

    template_name = "arcamitte/public_request.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        initial = {}
        url_hash = request.GET.get("hash")
        if url_hash:
            initial["file_hash"] = url_hash.strip().lower()

        # Reseteo estricto del formulario: nunca autocompletar correo para garantizar confidencialidad
        form = RequestAccessForm(initial=initial)
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "LANGUAGE_CODE": getattr(request, "LANGUAGE_CODE", "es"),
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        client_ip = get_client_ip(request) or "unknown"
        cache_key = f"arcamitte_web_flood_{client_ip}"
        limit = int(getattr(settings, "ARCAMITTE_WEB_REQUEST_LIMIT_PER_MINUTE", 15))
        request_count = cache.get(cache_key, 0)
        if request_count >= limit:
            messages.error(
                request,
                _("Ha superado el límite de solicitudes permitidas. Por favor, espere un minuto antes de reintentar."),
            )
            form = RequestAccessForm(request.POST)
            return render(request, self.template_name, {"form": form}, status=429)

        cache.set(cache_key, request_count + 1, timeout=60)

        form = RequestAccessForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "LANGUAGE_CODE": getattr(request, "LANGUAGE_CODE", "es"),
                },
                status=400,
            )

        file_hash = form.cleaned_data["file_hash"]
        email = form.cleaned_data["email"]

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")
        base_url = request.build_absolute_uri("/").rstrip("/")

        success, message = request_document_access(
            file_hash=file_hash,
            email=email,
            client_ip=client_ip,
            user_agent=user_agent,
            base_url=base_url,
        )

        request.session["arcamitte_file_hash"] = file_hash
        request.session["arcamitte_email"] = email
        messages.info(request, message)

        try:
            redeem_url = reverse("arcamitte:redeem-otp")
        except Exception:
            redeem_url = "/arcamitte/canjear/"

        return HttpResponseRedirect(f"{redeem_url}?hash={file_hash}")


class RedeemOtpView(ArcamitteI18nViewMixin, View):
    """
    Vista Web GUI para el canje seguro mediante código OTP de 6 dígitos.

    Si el canje es exitoso, devuelve inmediatamente un FileResponse con los bytes
    descifrados en memoria RAM (io.BytesIO) y activa la política Burn-After-Read.
    """

    template_name = "arcamitte/public_decrypt.html"

    def _resolve_credentials(self, request: HttpRequest) -> Tuple[str, str]:
        file_hash = (
            request.GET.get("hash")
            or request.POST.get("file_hash")
            or request.session.get("arcamitte_file_hash")
            or ""
        ).strip().lower()

        email = (
            request.GET.get("email")
            or request.POST.get("email")
            or request.session.get("arcamitte_email")
            or ""
        ).strip().lower()

        return file_hash, email

    def get(self, request: HttpRequest) -> HttpResponse:
        file_hash, email = self._resolve_credentials(request)
        if not file_hash or not email:
            messages.warning(
                request,
                _("Debe solicitar el acceso con el identificador del documento antes de introducir el código de verificación."),
            )
            try:
                request_url = reverse("arcamitte:request-access")
            except Exception:
                request_url = "/arcamitte/solicitar/"
            return HttpResponseRedirect(request_url)

        form = RedeemOtpForm(initial={"file_hash": file_hash, "email": email})
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "file_hash": file_hash,
                "email": email,
                "LANGUAGE_CODE": getattr(request, "LANGUAGE_CODE", "es"),
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        file_hash, email = self._resolve_credentials(request)
        data = request.POST.copy()
        if not data.get("file_hash") and file_hash:
            data["file_hash"] = file_hash
        if not data.get("email") and email:
            data["email"] = email

        form = RedeemOtpForm(data)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "file_hash": file_hash,
                    "email": email,
                    "LANGUAGE_CODE": getattr(request, "LANGUAGE_CODE", "es"),
                },
                status=400,
            )

        valid_hash = form.cleaned_data["file_hash"]
        valid_email = form.cleaned_data["email"]
        otp_code = form.cleaned_data["otp_code"]

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        success, decrypted_bytes, original_filename, message = consume_document_with_otp(
            file_hash=valid_hash,
            email=valid_email,
            entered_otp=otp_code,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        if not success:
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "error_message": message,
                    "file_hash": valid_hash,
                    "email": valid_email,
                    "LANGUAGE_CODE": getattr(request, "LANGUAGE_CODE", "es"),
                },
                status=400,
            )

        # Limpiar credenciales temporales de solicitud tras el canje exitoso
        request.session.pop("arcamitte_file_hash", None)
        request.session.pop("arcamitte_email", None)
        request.session.pop("arcamitte_verified_email", None)

        response = FileResponse(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            filename=original_filename,
        )
        return response


# ==============================================================================
# ENDPOINTS REST API (DRF) PARA ACCESO DESATENDIDO
# ==============================================================================
class PublicAccessRequestView(APIView):
    """Endpoint REST para solicitar código OTP con hash SHA-256."""

    permission_classes = [AllowAny]
    throttle_classes = [AccessRequestRateThrottle]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        serializer = PublicAccessRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        file_hash = serializer.validated_data["file_hash"]
        email = serializer.validated_data["email"]

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")
        base_url = request.build_absolute_uri("/").rstrip("/")

        success, message = request_document_access(
            file_hash=file_hash,
            email=email,
            client_ip=client_ip,
            user_agent=user_agent,
            base_url=base_url,
        )

        return Response(
            {"status": "processed", "message": message},
            status=status.HTTP_200_OK,
        )


class PublicConsumeView(APIView):
    """Endpoint REST para canjear y descargar documento mediante OTP (Burn-After-Read)."""

    permission_classes = [AllowAny]
    throttle_classes = [AccessConsumeRateThrottle]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        serializer = PublicConsumeSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        file_hash = serializer.validated_data["file_hash"]
        email = serializer.validated_data["email"]
        otp_code = serializer.validated_data["otp_code"]

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        success, decrypted_bytes, original_filename, message = consume_document_with_otp(
            file_hash=file_hash,
            email=email,
            entered_otp=otp_code,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        if not success:
            return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)

        response = HttpResponse(decrypted_bytes, content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{original_filename}"'
        return response


class APIDocumentUploadView(APIView):
    """
    Endpoint de alta seguridad para subir y cifrar documentos confidenciales desde
    microservicios y aplicaciones externas (Machine-to-Machine).
    Requiere autenticación con APIToken y scope 'documents:create'.
    """

    authentication_classes = [APITokenAuthentication]
    permission_classes = [IsAuthenticatedOrToken, HasDocumentsCreateScope]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        serializer = APIDocumentUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        origin_uo = data.get("origin_uo")
        token = request.auth
        if isinstance(token, APIToken) and token.uo:
            origin_uo = token.uo

        uploader_user = request.user if request.user.is_authenticated else None

        try:
            document = upload_and_encrypt_document(
                original_file=data["original_file"],
                description=data.get("description", ""),
                allowed_emails=data["allowed_emails"],
                burn_policy=data.get("burn_policy", EncryptedDocument.BurnPolicy.FIRST_ACCESS),
                expires_at=data.get("expires_at"),
                origin_uo=origin_uo,
                target_uo=data.get("target_uo"),
                uploaded_by=uploader_user,
            )
        except Exception as exc:
            logger.error(f"[ARCAMITTE API ERROR] Fallo al procesar subida de documento: {exc}")
            return Response(
                {"error": f"Error al procesar y cifrar el documento: {exc}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "status": "created",
                "file_hash": document.file_hash,
                "original_filename": document.original_filename,
                "burn_policy": document.burn_policy,
                "allowed_emails": document.allowed_emails,
                "expires_at": document.expires_at.isoformat() if document.expires_at else None,
                "origin_uo": document.origin_uo.alias if document.origin_uo else None,
                "target_uo": document.target_uo.alias if document.target_uo else None,
            },
            status=status.HTTP_201_CREATED,
        )


class APIDocumentStatusView(APIView):
    """
    Endpoint para consultar el estado del trámite de un documento por su hash SHA-256.
    Requiere autenticación con APIToken y scope 'documents:read'.
    """

    authentication_classes = [APITokenAuthentication]
    permission_classes = [IsAuthenticatedOrToken, HasDocumentsReadScope]

    def get(self, request: HttpRequest, file_hash: str, *args: Any, **kwargs: Any) -> Response:
        clean_hash = (file_hash or "").strip().lower()
        doc = EncryptedDocument.objects.filter(file_hash=clean_hash).first()
        if not doc:
            return Response(
                {"error": _("No se encontró ningún documento con el hash especificado.")},
                status=status.HTTP_404_NOT_FOUND,
            )

        token = request.auth
        if isinstance(token, APIToken) and token.uo:
            if doc.origin_uo != token.uo and doc.target_uo != token.uo:
                return Response(
                    {"error": _("No tiene permisos para acceder a documentos de otra Unidad Organizativa.")},
                    status=status.HTTP_403_FORBIDDEN,
                )

        return Response(
            {
                "file_hash": doc.file_hash,
                "original_filename": doc.original_filename,
                "is_consumed": doc.is_consumed,
                "consumed_by": doc.consumed_by,
                "consumed_at": doc.consumed_at.isoformat() if doc.consumed_at else None,
                "is_expired": doc.is_expired(),
                "expires_at": doc.expires_at.isoformat() if doc.expires_at else None,
                "burn_policy": doc.burn_policy,
                "created_at": doc.created_at.isoformat() if doc.created_at else None,
            },
            status=status.HTTP_200_OK,
        )
