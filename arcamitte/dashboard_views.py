from __future__ import annotations

import datetime
import json
import logging
import os
from typing import Any, List, Optional

logger = logging.getLogger(__name__)

from django import forms
from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import models
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic import ListView, TemplateView

from arcamitte.models import (
    APIToken,
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
    default_document_expiry,
)
from arcamitte.services import (
    terminate_document_manually,
    upload_and_encrypt_document,
)
from arcamitte.utils import get_client_ip
from arcamitte.validators import normalize_and_validate_email_list, validate_document_file


def get_user_accessible_uos(user: Any) -> models.QuerySet[OrganizationalUnit]:
    """
    Retorna el conjunto de Unidades Organizativas sobre las que el usuario tiene potestad:
    - Superusuarios: Todas las UOs activas.
    - Usuarios regulares: UOs en las que ostenta membresía activa.
    """
    if user.is_superuser:
        return OrganizationalUnit.objects.filter(is_active=True)
    return OrganizationalUnit.objects.filter(
        memberships__user=user,
        memberships__is_active=True,
        is_active=True,
    ).distinct()


def get_scoped_documents_queryset(user: Any) -> models.QuerySet[EncryptedDocument]:
    """
    Filtra los documentos según el perímetro departamental del usuario.
    Si un documento carece de UO emisora (asiento personal), solo puede verlo su autor
    (uploaded_by) o un superusuario.
    """
    if user.is_superuser:
        return EncryptedDocument.objects.all().select_related("origin_uo", "target_uo", "uploaded_by")
    user_uos = get_user_accessible_uos(user)
    return EncryptedDocument.objects.filter(
        models.Q(origin_uo__in=user_uos)
        | models.Q(target_uo__in=user_uos)
        | models.Q(origin_uo__isnull=True, uploaded_by=user)
    ).select_related("origin_uo", "target_uo", "uploaded_by").distinct()


class DashboardLoginView(auth_views.LoginView):
    """
    Vista de autenticación administrativa para Arcamitte.
    Protegida con cabeceras estrictas, sesión HttpOnly y CSRF token.
    """

    template_name = "arcamitte/login.html"
    redirect_authenticated_user = True

    def get_success_url(self) -> str:
        return reverse_lazy("dashboard:home")


class DashboardLogoutView(auth_views.LogoutView):
    """
    Cierre de sesión seguro con redirección al login.
    """

    next_page = reverse_lazy("dashboard:login")


class DashboardHomeView(LoginRequiredMixin, TemplateView):
    """
    Panel central de control y métricas criptográficas.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/dashboard.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        user = self.request.user
        now = timezone.now()

        docs_qs = get_scoped_documents_queryset(user)
        total_docs = docs_qs.count()
        consumed_docs = docs_qs.filter(is_consumed=True).count()
        active_docs = docs_qs.filter(is_consumed=False).filter(models.Q(expires_at__gt=now) | models.Q(expires_at__isnull=True)).count()
        expired_docs = docs_qs.filter(is_consumed=False, expires_at__lte=now).count()

        recent_docs = docs_qs.order_by("-created_at")[:6]

        if user.is_superuser:
            logs_qs = DocumentAccessLog.objects.all().select_related("document", "origin_uo", "target_uo")
        else:
            logs_qs = DocumentAccessLog.objects.filter(
                models.Q(document__in=docs_qs)
            ).select_related("document", "origin_uo", "target_uo").distinct()

        recent_logs = logs_qs.order_by("-created_at")[:6]

        context.update(
            {
                "active_nav": "dashboard",
                "total_documents": total_docs,
                "active_documents": active_docs,
                "consumed_documents": consumed_docs,
                "expired_documents": expired_docs,
                "recent_documents": recent_docs,
                "recent_logs": recent_logs,
            }
        )
        return context


class DashboardDocumentListView(LoginRequiredMixin, ListView):
    """
    Listado y filtrado avanzado de asientos confidenciales en custodia.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/document_list.html"
    context_object_name = "documents"
    paginate_by = 15

    def get_queryset(self) -> models.QuerySet[EncryptedDocument]:
        user = self.request.user
        qs = get_scoped_documents_queryset(user).order_by("-created_at")

        query = self.request.GET.get("q", "").strip()
        if query:
            qs = qs.filter(
                models.Q(original_filename__icontains=query)
                | models.Q(file_hash__icontains=query)
                | models.Q(description__icontains=query)
            )

        status_filter = self.request.GET.get("status", "").strip().lower()
        now = timezone.now()
        if status_filter == "active":
            qs = qs.filter(is_consumed=False).filter(models.Q(expires_at__gt=now) | models.Q(expires_at__isnull=True))
        elif status_filter == "consumed":
            qs = qs.filter(is_consumed=True)
        elif status_filter == "expired":
            qs = qs.filter(is_consumed=False, expires_at__lte=now)

        return qs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["active_nav"] = "documents"
        context["query"] = self.request.GET.get("q", "")
        context["status_filter"] = self.request.GET.get("status", "")
        return context


class DashboardDocumentUploadView(LoginRequiredMixin, View):
    """
    Formulario interactivo para registrar y cifrar un documento confidencial.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/document_upload.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        user = request.user
        available_uos = get_user_accessible_uos(user)
        all_uos = OrganizationalUnit.objects.filter(is_active=True).order_by("name")

        context = {
            "active_nav": "upload",
            "available_origin_uos": available_uos,
            "all_target_uos": all_uos,
            "default_expires_at": default_document_expiry().strftime("%Y-%m-%dT%H:%M"),
            "form_errors": [],
            "allowed_emails_list": [""],
            "allowed_emails_json": json.dumps([""]),
            "description_val": "",
            "selected_origin_uo": "",
            "selected_target_uo": "",
        }
        return render(request, self.template_name, context)

    def post(self, request: HttpRequest) -> HttpResponse:
        user = request.user
        available_uos = get_user_accessible_uos(user)
        all_uos = OrganizationalUnit.objects.filter(is_active=True).order_by("name")
        errors: List[str] = []

        file_obj = request.FILES.get("original_file")
        if not file_obj:
            errors.append(_("Debe seleccionar un archivo confidencial para cifrar."))
        else:
            try:
                validate_document_file(file_obj)
            except ValidationError as ve:
                errors.extend(ve.messages)

        origin_uo_id = request.POST.get("origin_uo", "").strip()
        origin_uo: Optional[OrganizationalUnit] = None
        if origin_uo_id:
            if user.is_superuser:
                origin_uo = all_uos.filter(id=origin_uo_id).first()
                if not origin_uo:
                    errors.append(_("La UO emisora seleccionada no existe."))
            else:
                origin_uo = available_uos.filter(id=origin_uo_id).first()
                if not origin_uo:
                    errors.append(_("No tiene autorización operativa sobre la UO emisora seleccionada."))

        target_uo_id = request.POST.get("target_uo", "").strip()
        target_uo: Optional[OrganizationalUnit] = None
        if target_uo_id:
            target_uo = all_uos.filter(id=target_uo_id).first()

        raw_emails_list = request.POST.getlist("allowed_emails")
        split_emails: List[str] = []
        for item in raw_emails_list:
            for e in item.replace("\n", ",").replace(";", ",").split(","):
                cleaned = e.strip()
                if cleaned:
                    split_emails.append(cleaned)

        validated_emails: List[str] = []
        if not split_emails:
            errors.append(_("Debe especificar al menos una dirección de correo para el canje."))
        else:
            try:
                validated_emails = normalize_and_validate_email_list(split_emails)
            except ValidationError as ve:
                errors.extend(ve.messages)

        burn_policy = request.POST.get("burn_policy", EncryptedDocument.BurnPolicy.FIRST_ACCESS)
        if burn_policy not in (EncryptedDocument.BurnPolicy.FIRST_ACCESS, EncryptedDocument.BurnPolicy.ALL_RECIPIENTS):
            burn_policy = EncryptedDocument.BurnPolicy.FIRST_ACCESS

        raw_expires = request.POST.get("expires_at", "").strip()
        expires_at: Optional[datetime.datetime] = None
        if raw_expires:
            parsed = parse_datetime(raw_expires)
            if not parsed:
                # Intentar formato local sin zona horaria
                try:
                    parsed = datetime.datetime.strptime(raw_expires, "%Y-%m-%dT%H:%M")
                    if timezone.is_naive(parsed):
                        parsed = timezone.make_aware(parsed)
                except Exception:
                    errors.append(_("El formato de fecha de caducidad es inválido."))
            else:
                if timezone.is_naive(parsed):
                    parsed = timezone.make_aware(parsed)
            if parsed and parsed <= timezone.now():
                errors.append(_("La fecha de caducidad debe ser posterior a la fecha y hora actual."))
            expires_at = parsed
        else:
            expires_at = default_document_expiry()

        description = request.POST.get("description", "").strip()

        if errors:
            context = {
                "active_nav": "upload",
                "available_origin_uos": available_uos,
                "all_target_uos": all_uos,
                "default_expires_at": raw_expires or default_document_expiry().strftime("%Y-%m-%dT%H:%M"),
                "form_errors": errors,
                "allowed_emails_list": split_emails or [""],
                "allowed_emails_json": json.dumps(split_emails or [""]),
                "description_val": description,
                "selected_origin_uo": origin_uo_id,
                "selected_target_uo": target_uo_id,
            }
            return render(request, self.template_name, context, status=400)

        # Proceder al cifrado seguro
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:255]

        doc = upload_and_encrypt_document(
            original_file=file_obj,
            allowed_emails=validated_emails,
            burn_policy=burn_policy,
            description=description,
            origin_uo=origin_uo,
            target_uo=target_uo,
            uploaded_by=user,
            admin_user=user,
            client_ip=client_ip,
            user_agent=user_agent,
            expires_at=expires_at,
        )

        messages.success(
            request,
            _(f"Asiento cifrado con éxito. Hash SHA-256: {doc.file_hash}"),
        )
        return redirect("dashboard:document_detail", file_hash=doc.file_hash)


class DashboardDocumentDetailView(LoginRequiredMixin, View):
    """
    Vista detallada de trazabilidad, metadatos y estado de canjes de un asiento.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/document_detail.html"

    def get(self, request: HttpRequest, file_hash: str) -> HttpResponse:
        user = request.user
        doc = get_object_or_404(EncryptedDocument, file_hash=file_hash)

        # Verificar autorización de acceso departamental o personal
        if not user.is_superuser:
            user_uos = get_user_accessible_uos(user)
            has_uo_access = (doc.origin_uo in user_uos) or (doc.target_uo in user_uos)
            is_personal_owner = (doc.origin_uo is None and doc.uploaded_by == user)
            if not (has_uo_access or is_personal_owner):
                raise PermissionDenied(_("No tiene autorización para inspeccionar este documento."))

        file_exists = False
        if doc.encrypted_file:
            try:
                file_exists = os.path.exists(doc.encrypted_file.path)
            except Exception:
                file_exists = False

        # Mapear estado de consumo por destinatario
        consumed_dict = doc.consumed_recipients or {}
        recipient_status_list = []
        for email in (doc.allowed_emails or []):
            is_consumed = email in consumed_dict
            info = consumed_dict.get(email, {}) if is_consumed else {}
            consumed_at = None
            if info.get("consumed_at"):
                try:
                    consumed_at = parse_datetime(info["consumed_at"])
                except Exception:
                    consumed_at = None
            recipient_status_list.append(
                {
                    "email": email,
                    "consumed": is_consumed,
                    "consumed_at": consumed_at,
                    "consumed_ip": info.get("ip_address", ""),
                }
            )

        logs = DocumentAccessLog.objects.filter(document=doc).order_by("-created_at")
        public_url = request.build_absolute_uri(reverse("arcamitte:request-access"))

        context = {
            "active_nav": "documents",
            "doc": doc,
            "file_exists_on_disk": file_exists,
            "recipient_status_list": recipient_status_list,
            "access_logs": logs,
            "public_request_url": public_url,
        }
        return render(request, self.template_name, context)


class DashboardDocumentTerminateView(LoginRequiredMixin, View):
    """
    Clausura anticipada y destrucción física del archivo cifrado con motivo justificado.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/document_terminate.html"

    def get(self, request: HttpRequest, file_hash: str) -> HttpResponse:
        user = request.user
        doc = get_object_or_404(EncryptedDocument, file_hash=file_hash)

        if not user.is_superuser:
            user_uos = get_user_accessible_uos(user)
            has_uo_access = (doc.origin_uo in user_uos)
            is_personal_owner = (doc.origin_uo is None and doc.uploaded_by == user)
            if not (has_uo_access or is_personal_owner):
                raise PermissionDenied(_("Solo la UO emisora, el autor del asiento personal o un superadministrador puede clausurar el documento."))

        if not doc.is_active:
            messages.warning(request, _("Este documento ya no se encuentra activo."))
            return redirect("dashboard:document_detail", file_hash=doc.file_hash)

        context = {
            "active_nav": "documents",
            "doc": doc,
        }
        return render(request, self.template_name, context)

    def post(self, request: HttpRequest, file_hash: str) -> HttpResponse:
        user = request.user
        doc = get_object_or_404(EncryptedDocument, file_hash=file_hash)

        if not user.is_superuser:
            user_uos = get_user_accessible_uos(user)
            has_uo_access = (doc.origin_uo in user_uos)
            is_personal_owner = (doc.origin_uo is None and doc.uploaded_by == user)
            if not (has_uo_access or is_personal_owner):
                raise PermissionDenied(_("Solo la UO emisora, el autor del asiento personal o un superadministrador puede clausurar el documento."))

        justification = request.POST.get("justification", "").strip()
        if not justification:
            messages.error(request, _("Debe proporcionar un motivo justificado para la destrucción anticipada."))
            return render(request, self.template_name, {"active_nav": "documents", "doc": doc}, status=400)

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:255]

        success, msg = terminate_document_manually(
            document=doc,
            admin_user=user,
            client_ip=client_ip,
            user_agent=user_agent,
            reason=justification,
        )

        if success:
            messages.success(request, _(f"Asiento terminado con éxito: {msg}"))
        else:
            messages.error(request, _(f"Error al terminar el asiento: {msg}"))

        return redirect("dashboard:document_detail", file_hash=doc.file_hash)


class DashboardAuditLogView(LoginRequiredMixin, ListView):
    """
    Visualización forense inmutable de logs de seguridad.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/audit_logs.html"
    context_object_name = "logs"
    paginate_by = 25

    def get_queryset(self) -> models.QuerySet[DocumentAccessLog]:
        user = self.request.user
        if user.is_superuser:
            qs = DocumentAccessLog.objects.all().select_related("document", "origin_uo", "target_uo").order_by("-created_at")
        else:
            docs_qs = get_scoped_documents_queryset(user)
            qs = DocumentAccessLog.objects.filter(
                models.Q(document__in=docs_qs)
            ).select_related("document", "origin_uo", "target_uo").order_by("-created_at").distinct()

        query = self.request.GET.get("q", "").strip()
        if query:
            qs = qs.filter(
                models.Q(ip_address__icontains=query)
                | models.Q(details__icontains=query)
                | models.Q(email__icontains=query)
                | models.Q(document__file_hash__icontains=query)
                | models.Q(document__original_filename__icontains=query)
            )

        action = self.request.GET.get("action", "").strip()
        if action:
            qs = qs.filter(action=action)

        return qs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["active_nav"] = "audit"
        context["query"] = self.request.GET.get("q", "")
        context["action_filter"] = self.request.GET.get("action", "")
        context["action_choices"] = DocumentAccessLog.Action.choices
        return context


class DashboardUOListView(LoginRequiredMixin, ListView):
    """
    Directorio de Unidades Organizativas que integran la malla de custodia.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/uo_list.html"
    context_object_name = "uos"

    def get_queryset(self) -> models.QuerySet[OrganizationalUnit]:
        return (
            OrganizationalUnit.objects.all()
            .annotate(
                active_members_count=models.Count(
                    "memberships",
                    filter=models.Q(memberships__is_active=True),
                )
            )
            .order_by("numeric_code")
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["active_nav"] = "uos"
        return context


class DashboardApiTokenView(LoginRequiredMixin, View):
    """
    Gestión de Tokens API para microservicios y clientes máquina a máquina (M2M).
    Permite generar tokens Zero-Knowledge con clave mostrada solo una vez.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/api_tokens.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        if not (request.user.is_superuser or request.user.is_staff):
            raise PermissionDenied(_("Se requieren privilegios administrativos para gestionar API Tokens."))

        tokens = APIToken.objects.all().order_by("-created_at")
        new_token = request.session.pop("new_raw_token", None)

        context = {
            "active_nav": "tokens",
            "tokens": tokens,
            "new_raw_token": new_token,
        }
        return render(request, self.template_name, context)

    def post(self, request: HttpRequest) -> HttpResponse:
        if not (request.user.is_superuser or request.user.is_staff):
            raise PermissionDenied(_("Se requieren privilegios administrativos para gestionar API Tokens."))

        name = request.POST.get("name", "").strip()
        if not name:
            messages.error(request, _("Debe proporcionar un nombre o identificador para el servicio."))
            return redirect("dashboard:api_tokens")

        scopes = request.POST.getlist("scopes")
        if not scopes:
            scopes = [APIToken.Scope.DOCUMENTS_CREATE, APIToken.Scope.DOCUMENTS_READ]

        try:
            rate_limit = int(request.POST.get("rate_limit", 60))
        except ValueError:
            rate_limit = 60

        try:
            validity_days = int(request.POST.get("validity_days", 365))
        except ValueError:
            validity_days = 365

        expires_at = timezone.now() + datetime.timedelta(days=validity_days)

        token_obj, raw_secret = APIToken.generate_token(
            name=name,
            scopes=scopes,
            rate_limit=rate_limit,
            expires_at=expires_at,
        )

        # Registrar en logs de auditoría del sistema
        client_ip = get_client_ip(request)
        logger.info(
            f"[ARCAMITTE AUDIT] API Token generado: '{token_obj.name}' (prefijo: {token_obj.prefix}..., scopes: {scopes}) por {request.user.username} (IP: {client_ip})"
        )

        request.session["new_raw_token"] = raw_secret
        messages.success(request, _(f"API Token '{token_obj.name}' generado correctamente."))
        return redirect("dashboard:api_tokens")


class DashboardApiTokenRevokeView(LoginRequiredMixin, View):
    """
    Revocación inmediata e irreversible de un API Token.
    """

    login_url = "dashboard:login"

    def post(self, request: HttpRequest, token_id: int) -> HttpResponse:
        if not (request.user.is_superuser or request.user.is_staff):
            raise PermissionDenied(_("Se requieren privilegios administrativos para revocar API Tokens."))

        token = get_object_or_404(APIToken, id=token_id)
        token.is_active = False
        token.save(update_fields=["is_active"])

        # Registrar en logs de auditoría del sistema
        client_ip = get_client_ip(request)
        logger.info(
            f"[ARCAMITTE AUDIT] API Token revocado: '{token.name}' (prefijo: {token.prefix}...) por {request.user.username} (IP: {client_ip})"
        )

        messages.warning(request, _(f"El API Token '{token.name}' ha sido revocado inmediatamente."))
        return redirect("dashboard:api_tokens")


class DashboardUOMembersAjaxView(LoginRequiredMixin, View):
    """
    Endpoint JSON para obtener buzón y personal activo de una UO
    para selección interactiva de destinatarios en el panel de control.
    """

    login_url = "dashboard:login"

    def get(self, request: HttpRequest, uo_id: int) -> JsonResponse:
        try:
            uo = OrganizationalUnit.objects.get(pk=uo_id, is_active=True)
        except OrganizationalUnit.DoesNotExist:
            return JsonResponse({"error": _("Unidad Organizativa no encontrada.")}, status=404)

        memberships = (
            UserUOMembership.objects.filter(uo=uo, is_active=True, user__is_active=True)
            .exclude(user__email="")
            .select_related("user")
            .order_by("user__first_name", "user__last_name", "user__username")
        )

        members_list = []
        member_emails = []
        for m in memberships:
            em = m.user.email.strip().lower()
            if em and em not in member_emails:
                member_emails.append(em)
                full_name = f"{m.user.first_name} {m.user.last_name}".strip()
                display_name = full_name or m.user.username
                members_list.append(
                    {
                        "id": m.user.id,
                        "username": m.user.username,
                        "name": display_name,
                        "email": em,
                        "role": m.role,
                        "role_display": str(m.get_role_display()),
                    }
                )

        return JsonResponse(
            {
                "uo_id": uo.id,
                "uo_alias": uo.alias,
                "uo_name": uo.name,
                "uo_email": uo.email or "",
                "member_emails": member_emails,
                "members": members_list,
            }
        )

