from __future__ import annotations

import csv
import io
import logging
from typing import Any, Optional, Tuple

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.db import models
from django.http import FileResponse, HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import activate, check_for_language, gettext as _
from django.views import View
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from arcamitte.authentication import APITokenAuthentication
from arcamitte.forms import RedeemOtpForm, RequestAccessForm
from arcamitte.models import APIToken, DocumentAccessLog, EncryptedDocument, OrganizationalUnit
from arcamitte.permissions import (
    HasDocumentsCreateScope,
    HasDocumentsReadScope,
    HasUOsReadScope,
    IsAuthenticatedOrToken,
)
from arcamitte.serializers import (
    APIDocumentCheckHashSerializer,
    APIDocumentDetailSerializer,
    APIDocumentListSerializer,
    APIDocumentUploadSerializer,
    APIOUListSerializer,
    APIOURecipientSerializer,
    PublicAccessRequestSerializer,
    PublicConsumeSerializer,
)
from arcamitte.services import (
    consume_document_with_otp,
    generate_corporate_email_text,
    get_scoped_documents_for_request,
    get_uo_recipient_emails,
    request_document_access,
    upload_and_encrypt_document,
)
from arcamitte.utils import (
    apply_no_store_headers,
    get_client_ip,
    sanitize_content_disposition_filename,
)

logger = logging.getLogger(__name__)



def set_language_view(request: HttpRequest) -> HttpResponseRedirect:
    """Cambia el idioma activo de la interfaz y redirige a la vista previa."""
    lang_code = request.GET.get("lang") or request.POST.get("language")
    try:
        fallback_url = reverse("arcamitte:request-access")
    except Exception:
        fallback_url = "/arcamitte/solicitar/"

    next_url = request.GET.get("next") or request.META.get("HTTP_REFERER") or fallback_url
    if "set-language" in next_url or not url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
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

        client_ip_str = get_client_ip(request) or "unknown"
        consume_cache_key = f"arcamitte_web_consume_flood_{client_ip_str}"
        consume_limit = int(getattr(settings, "ARCAMITTE_WEB_REQUEST_LIMIT_PER_MINUTE", 15)) * 2
        consume_count = cache.get(consume_cache_key, 0)
        if consume_count >= consume_limit:
            form = RedeemOtpForm(data)
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "error_message": _("Ha superado el límite de intentos por minuto. Por favor, espere antes de reintentar."),
                    "file_hash": file_hash,
                    "email": email,
                    "LANGUAGE_CODE": getattr(request, "LANGUAGE_CODE", "es"),
                },
                status=429,
            )
        cache.set(consume_cache_key, consume_count + 1, timeout=60)

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

        safe_name = sanitize_content_disposition_filename(original_filename)
        response = FileResponse(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            filename=safe_name,
        )
        return apply_no_store_headers(response)


# ==============================================================================
# ENDPOINTS REST API (DRF) PARA ACCESO DESATENDIDO
# ==============================================================================
class PublicAccessRequestView(APIView):
    """Endpoint REST para solicitar código OTP con hash SHA-256."""

    permission_classes = [AllowAny]
    throttle_classes = [AccessRequestRateThrottle]

    @extend_schema(
        summary="Solicitud de código OTP para descarga",
        description="Emite y remite un OTP criptográfico al buzón de un destinatario autorizado.",
        request=PublicAccessRequestSerializer,
        responses={200: OpenApiTypes.OBJECT, 400: OpenApiTypes.OBJECT},
    )
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

    @extend_schema(
        summary="Canje de OTP y descarga confidencial (Burn-After-Read)",
        description="Verifica el código OTP y entrega el flujo binario descifrado, ejecutando la política de destrucción.",
        request=PublicConsumeSerializer,
        responses={(200, "application/octet-stream"): OpenApiTypes.BINARY, 400: OpenApiTypes.OBJECT},
    )
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

        safe_name = sanitize_content_disposition_filename(original_filename)
        response = HttpResponse(decrypted_bytes, content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{safe_name}"'
        return apply_no_store_headers(response)


class APIDocumentRootView(APIView):
    """
    Endpoint raíz para documentos confidenciales (M2M y Sesión):
    - GET: Listado paginado y filtrable de asientos dentro del perímetro de la UO (scope 'documents:read').
    - POST: Alta y cifrado de nuevo asiento confidencial mediante envelope encryption (scope 'documents:create').
    """

    authentication_classes = [APITokenAuthentication]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_permissions(self) -> list[Any]:
        if self.request.method == "POST":
            return [IsAuthenticatedOrToken(), HasDocumentsCreateScope()]
        return [IsAuthenticatedOrToken(), HasDocumentsReadScope()]

    @extend_schema(
        summary="Listado paginado de documentos de la UO",
        description="Retorna los asientos confidenciales dentro del perímetro autorizado con filtros y paginación.",
        parameters=[
            OpenApiParameter("status", str, description="Filtro por estado: 'active', 'consumed', 'expired'"),
            OpenApiParameter("burn_policy", str, description="Filtro por política: 'FIRST_ACCESS', 'ALL_RECIPIENTS'"),
            OpenApiParameter("search", str, description="Búsqueda por nombre de archivo o hash"),
            OpenApiParameter("page", int, description="Número de página"),
        ],
        responses={200: APIDocumentListSerializer(many=True)},
    )
    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        qs = get_scoped_documents_for_request(request)
        now = timezone.now()

        status_filter = request.query_params.get("status")
        if status_filter == "consumed":
            qs = qs.filter(is_consumed=True)
        elif status_filter == "active":
            qs = qs.filter(is_consumed=False).filter(models.Q(expires_at__gt=now) | models.Q(expires_at__isnull=True))
        elif status_filter == "expired":
            qs = qs.filter(is_consumed=False, expires_at__lte=now)

        burn_policy = request.query_params.get("burn_policy")
        if burn_policy:
            qs = qs.filter(burn_policy=burn_policy)

        search = request.query_params.get("search")
        if search:
            search_clean = search.strip()
            qs = qs.filter(
                models.Q(original_filename__icontains=search_clean)
                | models.Q(file_hash__icontains=search_clean)
            )

        qs = qs.order_by("-created_at")
        paginator = PageNumberPagination()
        paginator.page_size = 25
        page = paginator.paginate_queryset(qs, request)
        serializer = APIDocumentListSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    @extend_schema(
        summary="Alta y cifrado de nuevo documento confidencial",
        description="Registra y cifra un documento con clave simétrica única DEK envuelta en Fernet (Zero-Knowledge Storage).",
        request=APIDocumentUploadSerializer,
        responses={201: OpenApiTypes.OBJECT},
    )
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
        api_token_obj = token if isinstance(token, APIToken) else None
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:255]

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
                api_token=api_token_obj,
                client_ip=client_ip,
                user_agent=user_agent,
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


# Alias para retrocompatibilidad interna de nombres de vista
APIDocumentUploadView = APIDocumentRootView
APIDocumentListView = APIDocumentRootView


class APIDocumentStatusView(APIView):
    """
    Endpoint para consultar el estado del trámite de un documento por su hash SHA-256.
    Requiere autenticación con APIToken y scope 'documents:read'.
    """

    authentication_classes = [APITokenAuthentication]
    permission_classes = [IsAuthenticatedOrToken, HasDocumentsReadScope]

    @extend_schema(
        summary="Consulta de estado de trámite por hash SHA-256",
        description="Retorna el estado de custodia, vigencia y consumo del expediente identificado por su hash.",
        responses={200: APIDocumentDetailSerializer, 403: OpenApiTypes.OBJECT, 404: OpenApiTypes.OBJECT},
    )
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


class APIDocumentCheckHashView(APIView):
    """
    Comprobación preliminar (pre-flight check) de hash SHA-256.
    Permite a los microservicios emisores verificar si un documento ya fue registrado
    o consumido antes de transmitir el binario grande por la red.
    """

    authentication_classes = [APITokenAuthentication]
    permission_classes = [IsAuthenticatedOrToken, HasDocumentsCreateScope]

    @extend_schema(
        summary="Pre-flight check de hash SHA-256",
        description="Comprueba si una huella SHA-256 ya existe en el sistema o si está disponible para alta.",
        request=APIDocumentCheckHashSerializer,
        responses={200: OpenApiTypes.OBJECT},
    )
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        serializer = APIDocumentCheckHashSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        clean_hash = serializer.validated_data["file_hash"]
        scoped_doc = get_scoped_documents_for_request(request).filter(file_hash=clean_hash).first()
        exists_globally = EncryptedDocument.objects.filter(file_hash=clean_hash).exists()

        if exists_globally and not scoped_doc:
            return Response(
                {
                    "file_hash": clean_hash,
                    "exists": True,
                    "accessible": False,
                    "message": _("El documento existe pero pertenece a otra Unidad Organizativa fuera de su perímetro."),
                },
                status=status.HTTP_200_OK,
            )

        if scoped_doc:
            return Response(
                {
                    "file_hash": clean_hash,
                    "exists": True,
                    "accessible": True,
                    "original_filename": scoped_doc.original_filename,
                    "is_consumed": scoped_doc.is_consumed,
                    "is_expired": scoped_doc.is_expired(),
                    "burn_policy": scoped_doc.burn_policy,
                    "created_at": scoped_doc.created_at.isoformat() if scoped_doc.created_at else None,
                    "expires_at": scoped_doc.expires_at.isoformat() if scoped_doc.expires_at else None,
                    "can_reactivate": scoped_doc.is_consumed or scoped_doc.is_expired(),
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {
                "file_hash": clean_hash,
                "exists": False,
                "accessible": True,
                "message": _("Huella SHA-256 no registrada. Asiento documental libre para su alta."),
            },
            status=status.HTTP_200_OK,
        )


class APIDocumentDetailView(APIView):
    """
    Consulta detallada de metadatos de un asiento documental confidencial.
    """

    authentication_classes = [APITokenAuthentication]
    permission_classes = [IsAuthenticatedOrToken, HasDocumentsReadScope]

    @extend_schema(
        summary="Metadatos detallados del documento",
        description="Devuelve todos los metadatos y trazabilidad de consumo del documento indicado.",
        responses={200: APIDocumentDetailSerializer},
    )
    def get(self, request: HttpRequest, file_hash: str, *args: Any, **kwargs: Any) -> Response:
        clean_hash = (file_hash or "").strip().lower()
        doc = EncryptedDocument.objects.filter(file_hash=clean_hash).first()
        if not doc:
            return Response(
                {"error": _("No se encontró ningún documento con el hash especificado.")},
                status=status.HTTP_404_NOT_FOUND,
            )

        scoped_qs = get_scoped_documents_for_request(request)
        if not scoped_qs.filter(pk=doc.pk).exists():
            return Response(
                {"error": _("No tiene permisos para acceder a documentos de otra Unidad Organizativa.")},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = APIDocumentDetailSerializer(doc)
        return Response(serializer.data, status=status.HTTP_200_OK)


class APIDocumentEmailTemplateView(APIView):
    """
    Genera el texto corporativo de notificación con el enlace de canje directo.
    Permite que sistemas externos de mensajería (CRM, ticketing, correo institucional)
    despachen el aviso oficial al destinatario.
    """

    authentication_classes = [APITokenAuthentication]
    permission_classes = [IsAuthenticatedOrToken, HasDocumentsReadScope]

    @extend_schema(
        summary="Plantilla de correo de notificación formal",
        description="Genera el texto institucional y enlaces de canje para el documento indicado.",
        responses={200: OpenApiTypes.OBJECT},
    )
    def get(self, request: HttpRequest, file_hash: str, *args: Any, **kwargs: Any) -> Response:
        clean_hash = (file_hash or "").strip().lower()
        doc = EncryptedDocument.objects.filter(file_hash=clean_hash).first()
        if not doc:
            return Response(
                {"error": _("No se encontró ningún documento con el hash especificado.")},
                status=status.HTTP_404_NOT_FOUND,
            )

        scoped_qs = get_scoped_documents_for_request(request)
        if not scoped_qs.filter(pk=doc.pk).exists():
            return Response(
                {"error": _("No tiene permisos para acceder a documentos de otra Unidad Organizativa.")},
                status=status.HTTP_403_FORBIDDEN,
            )

        base_url = request.build_absolute_uri("/").rstrip("/")
        email_text = generate_corporate_email_text(doc, base_url=base_url)
        return Response(
            {
                "file_hash": doc.file_hash,
                "subject": f"Documento disponible para su descarga: {doc.original_filename}",
                "body": email_text,
                "allowed_emails": doc.allowed_emails,
            },
            status=status.HTTP_200_OK,
        )


class APIOUListView(APIView):
    """
    Directorio de Unidades Organizativas (UO Mesh).
    Permite consultar las dependencias activas del sistema para el enrutamiento interdepartamental.
    """

    authentication_classes = [APITokenAuthentication]
    permission_classes = [IsAuthenticatedOrToken, HasUOsReadScope]

    @extend_schema(
        summary="Directorio de Unidades Organizativas activas",
        description="Devuelve el catálogo de Unidades Organizativas activas para routing de expedientes.",
        responses={200: APIOUListSerializer(many=True)},
    )
    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        uos = OrganizationalUnit.objects.filter(is_active=True).order_by("numeric_code")
        serializer = APIOUListSerializer(uos, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class APIOURecipientsView(APIView):
    """
    Buzones y miembros autorizados de una Unidad Organizativa destinataria.
    """

    authentication_classes = [APITokenAuthentication]
    permission_classes = [IsAuthenticatedOrToken, HasUOsReadScope]

    @extend_schema(
        summary="Miembros y buzones autorizados de una UO",
        description="Consulta los integrantes y buzones institucionales de una dependencia para auto-completado de destinatarios.",
        responses={200: APIOURecipientSerializer(many=True)},
    )
    def get(self, request: HttpRequest, identifier: str, *args: Any, **kwargs: Any) -> Response:
        val_str = str(identifier).strip()
        uo = OrganizationalUnit.objects.filter(alias__iexact=val_str, is_active=True).first()
        if not uo and val_str.isdigit():
            uo = OrganizationalUnit.objects.filter(
                models.Q(numeric_code=int(val_str)) | models.Q(id=int(val_str)),
                is_active=True,
            ).first()

        if not uo:
            return Response(
                {"error": _(f"No existe ninguna Unidad Organizativa activa identificada como '{val_str}'.")},
                status=status.HTTP_404_NOT_FOUND,
            )

        from arcamitte.models import UserUOMembership
        memberships = (
            UserUOMembership.objects.filter(uo=uo, is_active=True, user__is_active=True)
            .exclude(user__email="")
            .select_related("user")
            .order_by("user__first_name", "user__last_name", "user__username")
        )

        results = [
            {
                "id": m.user.id,
                "username": m.user.username,
                "email": m.user.email,
                "full_name": m.user.get_full_name() or m.user.username,
                "role": m.role,
            }
            for m in memberships
        ]
        return Response(results, status=status.HTTP_200_OK)


class APIHealthCheckView(APIView):
    """
    Sonda técnica de salud y disponibilidad (Liveness / Readiness Probe).
    Apta para chequeos periódicos de orquestadores Docker / Kubernetes.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        summary="Sonda de salud técnica y observabilidad",
        description="Verifica conectividad con base de datos, motor de cifrado Fernet y almacenamiento de medios.",
        responses={200: OpenApiTypes.OBJECT},
    )
    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        health_status = "healthy"
        details: dict[str, Any] = {}

        # 1. Base de datos
        try:
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            details["database"] = "ok"
        except Exception as exc:
            health_status = "unhealthy"
            details["database"] = f"error: {exc}"

        # 2. Motor de Cifrado Fernet
        try:
            from cryptography.fernet import Fernet
            key = settings.ARCAMITTE_FERNET_KEY
            f = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
            test_token = f.encrypt(b"arcamitte_health_check")
            f.decrypt(test_token)
            details["cryptography_fernet"] = "ok"
        except Exception as exc:
            health_status = "unhealthy"
            details["cryptography_fernet"] = f"error: {exc}"

        # 3. Almacenamiento multimedia
        try:
            import os
            media_path = settings.MEDIA_ROOT
            details["media_storage_writable"] = os.access(media_path, os.W_OK)
        except Exception as exc:
            details["media_storage_writable"] = f"error: {exc}"

        code = status.HTTP_200_OK if health_status == "healthy" else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(
            {
                "status": health_status,
                "timestamp": timezone.now().isoformat(),
                "details": details,
            },
            status=code,
        )
