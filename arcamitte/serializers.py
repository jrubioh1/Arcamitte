from __future__ import annotations

import re
from typing import Any, List, Optional
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from arcamitte.models import EncryptedDocument, OrganizationalUnit, default_document_expiry
from arcamitte.validators import (
    normalize_and_validate_email_list,
    validate_document_file,
    validate_safe_email,
)

HASH_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


def _format_error_message(exc: Exception) -> str:
    """Extrae un mensaje de error limpio sin envoltorios de listas o comillas."""
    if hasattr(exc, "messages") and exc.messages:
        return str(exc.messages[0])
    return str(exc).strip("[]'\"")


class PublicAccessRequestSerializer(serializers.Serializer):
    """
    Serializador REST para solicitud desatendida mediante Hash SHA-256 y correo.
    Regla de Oro: Cero transporte del binario por el cliente.
    """

    file_hash = serializers.CharField(
        required=True,
        max_length=64,
        min_length=64,
        trim_whitespace=True,
        help_text="Hash SHA-256 (64 hex) del documento confidencial.",
    )
    email = serializers.CharField(
        required=True,
        trim_whitespace=True,
        help_text="Correo electrónico oficial del solicitante.",
    )

    def validate_file_hash(self, value: str) -> str:
        clean = (value or "").strip().lower()
        if not HASH_REGEX.match(clean):
            raise serializers.ValidationError(
                _("El hash SHA-256 debe componerse exactamente de 64 caracteres hexadecimales.")
            )
        return clean

    def validate_email(self, value: str) -> str:
        try:
            return validate_safe_email(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(_format_error_message(exc))
        except Exception as exc:
            raise serializers.ValidationError(str(exc))


class PublicConsumeSerializer(serializers.Serializer):
    """
    Serializador REST para canjear documento mediante OTP de 6 dígitos.
    """

    file_hash = serializers.CharField(
        required=True,
        max_length=64,
        min_length=64,
        trim_whitespace=True,
        help_text="Hash SHA-256 del documento.",
    )
    email = serializers.CharField(
        required=True,
        trim_whitespace=True,
        help_text="Correo electrónico del solicitante.",
    )
    otp_code = serializers.CharField(
        required=True,
        max_length=12,  # Permite recibir espacios accidentales y limpiarlos en el validator
        min_length=1,
        trim_whitespace=True,
        help_text="Código OTP numérico de 6 dígitos.",
    )

    def validate_file_hash(self, value: str) -> str:
        clean = (value or "").strip().lower()
        if not HASH_REGEX.match(clean):
            raise serializers.ValidationError(_("Hash SHA-256 inválido."))
        return clean

    def validate_email(self, value: str) -> str:
        try:
            return validate_safe_email(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(_format_error_message(exc))
        except Exception as exc:
            raise serializers.ValidationError(str(exc))

    def validate_otp_code(self, value: str) -> str:
        clean = (value or "").strip()
        if not clean.isdigit() or len(clean) != 6:
            raise serializers.ValidationError(_("El código OTP debe ser estrictamente numérico de 6 dígitos."))
        return clean


class APIDocumentUploadSerializer(serializers.Serializer):
    """
    Serializador protegido para que aplicaciones y microservicios externos suban y cifren
    documentos confidenciales mediante el API Gate.
    """

    original_file = serializers.FileField(
        required=True,
        help_text="Archivo confidencial original (PDF, LibreOffice o Microsoft Office).",
    )
    description = serializers.CharField(
        required=False,
        default="Documento confidencial tramitado a través de la pasarela segura Arcamitte.",
        help_text="Descripción informativa o motivo confidencial del trámite.",
    )
    allowed_emails = serializers.JSONField(
        required=True,
        help_text="Lista de correos autorizados (ej. ['destinatario@empresa.com']) o cadena separada por comas.",
    )
    burn_policy = serializers.ChoiceField(
        choices=EncryptedDocument.BurnPolicy.choices,
        default=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        required=False,
        help_text="Política de destrucción ('FIRST_ACCESS' o 'ALL_RECIPIENTS').",
    )
    expires_at = serializers.DateTimeField(
        required=False,
        default=default_document_expiry,
        help_text="Fecha y hora de expiración en formato ISO 8601 (por defecto, 2 semanas).",
    )
    origin_uo = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Alias o código numérico de la UO emisora (ej. 'RRHH' o 1001).",
    )
    target_uo = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Alias o código numérico de la UO receptora (opcional).",
    )

    def validate_original_file(self, value: Any) -> Any:
        try:
            return validate_document_file(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(_format_error_message(exc))

    def validate_allowed_emails(self, value: Any) -> List[str]:
        try:
            return normalize_and_validate_email_list(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(_format_error_message(exc))

    def validate_expires_at(self, value: Optional[Any]) -> Optional[Any]:
        if value and value <= timezone.now():
            raise serializers.ValidationError(_("La fecha de caducidad debe ser posterior al momento actual."))
        return value

    def validate_origin_uo(self, value: Optional[str]) -> Optional[OrganizationalUnit]:
        if not value:
            return None
        val_str = str(value).strip()
        uo = OrganizationalUnit.objects.filter(alias__iexact=val_str, is_active=True).first()
        if not uo and val_str.isdigit():
            uo = OrganizationalUnit.objects.filter(numeric_code=int(val_str), is_active=True).first()
        if not uo:
            raise serializers.ValidationError(
                _(f"No existe ninguna Unidad Organizativa activa con alias o código '{val_str}'.")
            )
        return uo

    def validate_target_uo(self, value: Optional[str]) -> Optional[OrganizationalUnit]:
        if not value:
            return None
        val_str = str(value).strip()
        uo = OrganizationalUnit.objects.filter(alias__iexact=val_str, is_active=True).first()
        if not uo and val_str.isdigit():
            uo = OrganizationalUnit.objects.filter(numeric_code=int(val_str), is_active=True).first()
        if not uo:
            raise serializers.ValidationError(
                _(f"No existe ninguna Unidad Organizativa activa con alias o código '{val_str}'.")
            )
        return uo
