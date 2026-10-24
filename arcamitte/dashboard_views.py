from __future__ import annotations

import datetime
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic import ListView, TemplateView

from arcamitte.forms import (
    OrganizationalUnitForm,
    PasswordChangeCustomForm,
    PasswordResetRequestForm,
    UserManagementForm,
)
from arcamitte.models import (
    APIToken,
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
    default_document_expiry,
    get_or_create_user_profile,
)
from arcamitte.services import (
    get_user_administered_uos,
    is_uo_admin,
    reset_user_password_and_notify,
    terminate_document_manually,
    upload_and_encrypt_document,
)

User = get_user_model()

from arcamitte.utils import get_client_ip
from arcamitte.validators import (
    normalize_and_validate_email_list,
    validate_document_file,
)


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
        if self.request.user.is_superuser:
            return reverse_lazy("dashboard:mode_selection")
        return reverse_lazy("dashboard:home")


class DashboardModeSelectionView(LoginRequiredMixin, UserPassesTestMixin, View):
    """
    Selector de modo de trabajo exclusivo para superusuarios (Mode Gateway).
    Permite alternar entre el Modo Gobernanza Global y el Modo Operativa Documental.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/mode_selection.html"

    def test_func(self) -> bool:
        return self.request.user.is_superuser

    def get(self, request: HttpRequest) -> HttpResponse:
        set_mode = request.GET.get("set")
        if set_mode in ["governance", "operational"]:
            request.session["dashboard_mode"] = set_mode
            next_url = request.GET.get("next") or reverse("dashboard:home")
            return redirect(next_url)

        current_mode = request.session.get("dashboard_mode", "governance")
        return render(
            request,
            self.template_name,
            {
                "current_mode": current_mode,
                "active_nav": "mode_selection",
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        mode = request.POST.get("mode", "governance")
        if mode not in ["governance", "operational"]:
            mode = "governance"
        request.session["dashboard_mode"] = mode
        return redirect("dashboard:home")


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
        errors: list[str] = []

        file_obj = request.FILES.get("original_file")
        if not file_obj:
            errors.append(_("Debe seleccionar un archivo confidencial para cifrar."))
        else:
            try:
                validate_document_file(file_obj)
            except ValidationError as ve:
                errors.extend(ve.messages)

        origin_uo_id = request.POST.get("origin_uo", "").strip()
        origin_uo: OrganizationalUnit | None = None
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
        target_uo: OrganizationalUnit | None = None
        if target_uo_id:
            target_uo = all_uos.filter(id=target_uo_id).first()

        raw_emails_list = request.POST.getlist("allowed_emails")
        split_emails: list[str] = []
        for item in raw_emails_list:
            for e in item.replace("\n", ",").replace(";", ",").split(","):
                cleaned = e.strip()
                if cleaned:
                    split_emails.append(cleaned)

        validated_emails: list[str] = []
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
        expires_at: datetime.datetime | None = None
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
        context["administered_uo_ids"] = set(
            get_user_administered_uos(self.request.user).values_list("id", flat=True)
        )
        context["is_superuser"] = self.request.user.is_superuser
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


class DashboardUOCreateView(LoginRequiredMixin, UserPassesTestMixin, View):
    """
    Creación de una nueva Unidad Organizativa (restringido a superusuarios).
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/uo_form.html"

    def test_func(self) -> bool:
        return self.request.user.is_superuser

    def get(self, request: HttpRequest) -> HttpResponse:
        form = OrganizationalUnitForm(is_superuser=True)
        return render(
            request,
            self.template_name,
            {"form": form, "is_new": True, "active_nav": "uos"},
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        form = OrganizationalUnitForm(request.POST, is_superuser=True)
        if form.is_valid():
            uo = form.save()
            messages.success(
                request,
                _("Unidad Organizativa %(alias)s creada exitosamente.") % {"alias": uo.alias},
            )
            return redirect("dashboard:uo_list")
        return render(
            request,
            self.template_name,
            {"form": form, "is_new": True, "active_nav": "uos"},
        )


class DashboardUOEditView(LoginRequiredMixin, View):
    """
    Edición de una Unidad Organizativa existente.
    Permitido para superusuarios (todos los campos) y Administradores de la propia UO (campos descriptivos).
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/uo_form.html"

    def get_uo(self, request: HttpRequest, uo_id: int) -> OrganizationalUnit:
        uo = get_object_or_404(OrganizationalUnit, pk=uo_id)
        if not is_uo_admin(request.user, uo):
            raise PermissionDenied(_("No tiene privilegios para administrar esta Unidad Organizativa."))
        return uo

    def get(self, request: HttpRequest, uo_id: int) -> HttpResponse:
        uo = self.get_uo(request, uo_id)
        form = OrganizationalUnitForm(instance=uo, is_superuser=request.user.is_superuser)
        return render(
            request,
            self.template_name,
            {"form": form, "uo": uo, "is_new": False, "active_nav": "uos"},
        )

    def post(self, request: HttpRequest, uo_id: int) -> HttpResponse:
        uo = self.get_uo(request, uo_id)
        form = OrganizationalUnitForm(
            request.POST,
            instance=uo,
            is_superuser=request.user.is_superuser,
        )
        if form.is_valid():
            form.save()
            messages.success(
                request,
                _("Unidad Organizativa %(alias)s actualizada exitosamente.") % {"alias": uo.alias},
            )
            return redirect("dashboard:uo_list")
        return render(
            request,
            self.template_name,
            {"form": form, "uo": uo, "is_new": False, "active_nav": "uos"},
        )


class DashboardUOMembersView(LoginRequiredMixin, View):
    """
    Administración de personal y roles de una Unidad Organizativa.
    Permite incorporar miembros, cambiar roles, activar/desactivar y desvincular.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/uo_members.html"

    def get_uo(self, request: HttpRequest, uo_id: int) -> OrganizationalUnit:
        uo = get_object_or_404(OrganizationalUnit, pk=uo_id)
        if not is_uo_admin(request.user, uo):
            raise PermissionDenied(_("No tiene privilegios para administrar miembros en esta Unidad Organizativa."))
        return uo

    def get(self, request: HttpRequest, uo_id: int) -> HttpResponse:
        uo = self.get_uo(request, uo_id)
        memberships = (
            UserUOMembership.objects.filter(uo=uo)
            .select_related("user")
            .order_by("user__username")
        )
        current_user_ids = memberships.values_list("user_id", flat=True)
        available_users = (
            User.objects.exclude(id__in=current_user_ids)
            .filter(is_active=True)
            .order_by("username")
        )

        return render(
            request,
            self.template_name,
            {
                "uo": uo,
                "memberships": memberships,
                "available_users": available_users,
                "roles": UserUOMembership.Role.choices,
                "active_nav": "uos",
            },
        )

    def post(self, request: HttpRequest, uo_id: int) -> HttpResponse:
        uo = self.get_uo(request, uo_id)
        action = request.POST.get("action")

        if action == "add_member":
            user_id = request.POST.get("user_id")
            role = request.POST.get("role", UserUOMembership.Role.OPERATOR)
            target_user = get_object_or_404(User, pk=user_id)
            membership, created = UserUOMembership.objects.get_or_create(
                user=target_user,
                uo=uo,
                defaults={"role": role, "is_active": True},
            )
            if not created:
                membership.role = role
                membership.is_active = True
                membership.save(update_fields=["role", "is_active"])
            messages.success(
                request,
                _("Usuario %(username)s asignado a %(alias)s.") % {"username": target_user.username, "alias": uo.alias},
            )

        elif action == "update_role":
            membership_id = request.POST.get("membership_id")
            new_role = request.POST.get("role")
            membership = get_object_or_404(UserUOMembership, pk=membership_id, uo=uo)
            if new_role in dict(UserUOMembership.Role.choices):
                membership.role = new_role
                membership.save(update_fields=["role"])
                messages.success(
                    request,
                    _("Rol de %(username)s actualizado a %(role)s.") % {
                        "username": membership.user.username,
                        "role": membership.get_role_display(),
                    },
                )

        elif action == "toggle_active":
            membership_id = request.POST.get("membership_id")
            membership = get_object_or_404(UserUOMembership, pk=membership_id, uo=uo)
            membership.is_active = not membership.is_active
            membership.save(update_fields=["is_active"])
            state_str = _("activada") if membership.is_active else _("desactivada")
            messages.info(
                request,
                _("Membresía de %(username)s %(state)s.") % {
                    "username": membership.user.username,
                    "state": state_str,
                },
            )

        elif action == "remove_member":
            membership_id = request.POST.get("membership_id")
            membership = get_object_or_404(UserUOMembership, pk=membership_id, uo=uo)
            username = membership.user.username
            membership.delete()
            messages.warning(
                request,
                _("Usuario %(username)s retirado de %(alias)s.") % {"username": username, "alias": uo.alias},
            )

        return redirect("dashboard:uo_members", uo_id=uo.id)


class DashboardUserListView(LoginRequiredMixin, View):
    """
    Listado y gestión de usuarios.
    Superusuarios: visión y gestión global de todos los usuarios.
    Administradores de UO: gestión de los usuarios que forman parte de sus UOs.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/user_list.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        if request.user.is_superuser:
            users = User.objects.all().prefetch_related("uo_memberships__uo").order_by("username")
            can_create_user = True
        else:
            admin_uos = get_user_administered_uos(request.user)
            if not admin_uos.exists():
                raise PermissionDenied(_("No tiene permisos para administrar usuarios ni Unidades Organizativas."))
            users = (
                User.objects.filter(uo_memberships__uo__in=admin_uos)
                .distinct()
                .prefetch_related("uo_memberships__uo")
                .order_by("username")
            )
            can_create_user = True

        return render(
            request,
            self.template_name,
            {
                "users": users,
                "can_create_user": can_create_user,
                "active_nav": "users",
            },
        )


class DashboardUserCreateView(LoginRequiredMixin, View):
    """
    Alta de un nuevo usuario en la plataforma.
    Genera automáticamente una contraseña temporal robusta y la remite por email.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/user_form.html"

    def get_admin_uos(self, request: HttpRequest) -> Any:
        if request.user.is_superuser:
            return OrganizationalUnit.objects.all().order_by("numeric_code")
        return get_user_administered_uos(request.user)

    def get(self, request: HttpRequest) -> HttpResponse:
        admin_uos = self.get_admin_uos(request)
        if not request.user.is_superuser and not admin_uos.exists():
            raise PermissionDenied(_("No tiene permisos para crear usuarios."))

        form = UserManagementForm(is_superuser=request.user.is_superuser)
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "is_new": True,
                "admin_uos": admin_uos,
                "roles": UserUOMembership.Role.choices,
                "active_nav": "users",
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        admin_uos = self.get_admin_uos(request)
        if not request.user.is_superuser and not admin_uos.exists():
            raise PermissionDenied(_("No tiene permisos para crear usuarios."))

        form = UserManagementForm(request.POST, is_superuser=request.user.is_superuser)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_unusable_password()
            user.save()

            uo_id = request.POST.get("initial_uo")
            initial_role = request.POST.get("initial_role", UserUOMembership.Role.OPERATOR)
            if uo_id:
                try:
                    uo = admin_uos.get(pk=uo_id)
                    UserUOMembership.objects.create(
                        user=user,
                        uo=uo,
                        role=initial_role,
                        is_active=True,
                    )
                except OrganizationalUnit.DoesNotExist:
                    pass

            if user.email:
                reset_user_password_and_notify(user, requested_by=request.user)
                messages.success(
                    request,
                    _("Usuario %(username)s creado exitosamente. Se ha remitido una contraseña temporal a su correo.")
                    % {"username": user.username},
                )
            else:
                messages.warning(
                    request,
                    _("Usuario %(username)s creado sin correo electrónico. Deberá asignarle uno para remitirle la contraseña.")
                    % {"username": user.username},
                )

            return redirect("dashboard:user_list")

        return render(
            request,
            self.template_name,
            {
                "form": form,
                "is_new": True,
                "admin_uos": admin_uos,
                "roles": UserUOMembership.Role.choices,
                "active_nav": "users",
            },
        )


class DashboardUserEditView(LoginRequiredMixin, View):
    """
    Edición de los datos de un usuario existente.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/user_form.html"

    def get_target_user(self, request: HttpRequest, user_id: int) -> User:
        target = get_object_or_404(User, pk=user_id)
        if request.user.is_superuser:
            return target
        admin_uos = get_user_administered_uos(request.user)
        if not UserUOMembership.objects.filter(user=target, uo__in=admin_uos).exists():
            raise PermissionDenied(_("No tiene permisos para administrar a este usuario."))
        return target

    def get(self, request: HttpRequest, user_id: int) -> HttpResponse:
        target = self.get_target_user(request, user_id)
        form = UserManagementForm(instance=target, is_superuser=request.user.is_superuser)
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "target_user": target,
                "is_new": False,
                "active_nav": "users",
            },
        )

    def post(self, request: HttpRequest, user_id: int) -> HttpResponse:
        target = self.get_target_user(request, user_id)
        form = UserManagementForm(
            request.POST,
            instance=target,
            is_superuser=request.user.is_superuser,
        )
        if form.is_valid():
            form.save()
            messages.success(
                request,
                _("Usuario %(username)s actualizado exitosamente.") % {"username": target.username},
            )
            return redirect("dashboard:user_list")
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "target_user": target,
                "is_new": False,
                "active_nav": "users",
            },
        )


class DashboardUserResetPasswordView(LoginRequiredMixin, View):
    """
    Acción administrativa para resetear la contraseña de un usuario, generando una clave
    temporal aleatoria y forzando el cambio en el próximo acceso.
    """

    login_url = "dashboard:login"

    def post(self, request: HttpRequest, user_id: int) -> HttpResponse:
        target = get_object_or_404(User, pk=user_id)
        if not request.user.is_superuser:
            admin_uos = get_user_administered_uos(request.user)
            if not UserUOMembership.objects.filter(user=target, uo__in=admin_uos).exists():
                raise PermissionDenied(_("No tiene permisos para resetear la contraseña de este usuario."))

        ok, msg = reset_user_password_and_notify(target, requested_by=request.user)
        if ok:
            messages.success(request, msg)
        else:
            messages.error(request, msg)

        next_url = request.POST.get("next") or request.META.get("HTTP_REFERER") or reverse("dashboard:user_list")
        return redirect(next_url)


class DashboardPasswordResetRequestView(View):
    """
    Autoservicio público «¿Olvidó su contraseña?».
    Genera clave temporal y la envía al buzón registrado, forzando cambio en primer acceso.
    """

    template_name = "arcamitte/password_reset_request.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        form = PasswordResetRequestForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request: HttpRequest) -> HttpResponse:
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            identity = form.cleaned_data["identity"]
            user = User.objects.filter(
                models.Q(username__iexact=identity) | models.Q(email__iexact=identity)
            ).first()
            if user and user.email and user.is_active:
                reset_user_password_and_notify(user, requested_by=None)

            messages.success(
                request,
                _("Si la cuenta indicada existe y dispone de un correo configurado, se ha enviado una clave temporal con instrucciones."),
            )
            return redirect("dashboard:login")

        return render(request, self.template_name, {"form": form})


class DashboardPasswordChangeView(LoginRequiredMixin, View):
    """
    Formulario de actualización de contraseña.
    Obligatorio para cuentas con must_change_password=True y accesible voluntariamente.
    """

    login_url = "dashboard:login"
    template_name = "arcamitte/password_change.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        form = PasswordChangeCustomForm(user=request.user)
        profile = getattr(request.user, "arcamitte_profile", None)
        is_mandatory = profile.must_change_password if profile else False
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "is_mandatory": is_mandatory,
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        form = PasswordChangeCustomForm(request.user, request.POST)
        if form.is_valid():
            new_password = form.cleaned_data["new_password"]
            validate_password(new_password, user=request.user)
            request.user.set_password(new_password)
            request.user.save(update_fields=["password"])

            profile = get_or_create_user_profile(request.user)
            profile.must_change_password = False
            profile.save(update_fields=["must_change_password", "updated_at"])

            update_session_auth_hash(request, request.user)
            messages.success(request, _("Su contraseña ha sido actualizada con éxito."))
            return redirect("dashboard:home")

        profile = getattr(request.user, "arcamitte_profile", None)
        is_mandatory = profile.must_change_password if profile else False
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "is_mandatory": is_mandatory,
            },
        )


