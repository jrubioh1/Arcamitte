from __future__ import annotations

import logging
import re
from typing import Any, List, Optional
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from arcamitte.models import EncryptedDocument, OrganizationalUnit, default_document_expiry
from arcamitte.validators import (
    normalize_and_validate_email_list,
    validate_document_file,
    validate_safe_email,
)

logger = logging.getLogger(__name__)

HASH_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


def _handle_validation_error(exc: Exception, user_message: str, field_name: str = "") -> None:
    """Registra internamente la excepción y lanza ValidationError con mensaje seguro (Anti-Information Exposure)."""
    logger.warning("Fallo de validación en campo '%s': %s", field_name, exc)
    raise serializers.ValidationError(user_message)


@extend_schema_field(serializers.ListField(child=serializers.EmailField()))
class EmailListField(serializers.Field):
    """
    Campo flexible que valida y normaliza listas de correos electrónicos en
    formatos múltiples: array JSON, string separado por comas o punto y coma.
    """

    def to_internal_value(self, data: Any) -> list[str]:
        if data is None:
            return []
        try:
            return normalize_and_validate_email_list(data)
        except DjangoValidationError as exc:
            _handle_validation_error(
                exc,
                _("La lista de correos electrónicos no es válida o contiene formatos erróneos."),
                "allowed_emails",
            )

    def to_representation(self, value: Any) -> list[str]:
        if isinstance(value, list):
            return value
        if not value:
            return []
        try:
            return normalize_and_validate_email_list(value)
        except Exception:
            return [str(value)]


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
            _handle_validation_error(
                exc,
                _("El correo electrónico introducido no es válido o no cumple los requisitos corporativos."),
                "email",
            )
        except Exception as exc:
            logger.error("Error inesperado validando email: %s", exc, exc_info=True)
            raise serializers.ValidationError(_("Error al validar el correo electrónico."))


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
            _handle_validation_error(
                exc,
                _("El correo electrónico introducido no es válido o no cumple los requisitos corporativos."),
                "email",
            )
        except Exception as exc:
            logger.error("Error inesperado validando email: %s", exc, exc_info=True)
            raise serializers.ValidationError(_("Error al validar el correo electrónico."))

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
    allowed_emails = EmailListField(
        required=True,
        help_text="Lista de correos autorizados (ej. ['destinatario@empresa.com'] o cadena separada por comas).",
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
    validity_hours = serializers.IntegerField(
        required=False,
        min_value=1,
        max_value=8760,
        help_text="Plazo de caducidad en horas a partir del momento de subida (opcional).",
    )

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        hours = attrs.pop("validity_hours", None)
        if hours is not None and "expires_at" not in attrs:
            attrs["expires_at"] = timezone.now() + timezone.timedelta(hours=hours)
        return attrs

    def validate_original_file(self, value: Any) -> Any:
        try:
            return validate_document_file(value)
        except DjangoValidationError as exc:
            _handle_validation_error(
                exc,
                _("El archivo proporcionado no es válido o su formato/contenido no está permitido."),
                "original_file",
            )

    def validate_allowed_emails(self, value: Any) -> List[str]:
        try:
            return normalize_and_validate_email_list(value)
        except DjangoValidationError as exc:
            _handle_validation_error(
                exc,
                _("La lista de correos electrónicos autorizados no es válida o contiene formatos erróneos."),
                "allowed_emails",
            )

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
                _("No existe ninguna Unidad Organizativa activa con alias o código '%(val)s'.")
                % {"val": val_str}
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
                _("No existe ninguna Unidad Organizativa activa con alias o código '%(val)s'.")
                % {"val": val_str}
            )
        return uo


class APIDocumentCheckHashSerializer(serializers.Serializer):
    """
    Serializador para comprobación preliminar (pre-flight check) de hash SHA-256.
    """

    file_hash = serializers.CharField(
        required=True,
        max_length=64,
        min_length=64,
        trim_whitespace=True,
        help_text="Hash SHA-256 (64 hex) a comprobar.",
    )

    def validate_file_hash(self, value: str) -> str:
        clean = (value or "").strip().lower()
        if not HASH_REGEX.match(clean):
            raise serializers.ValidationError(
                _("El hash SHA-256 debe componerse exactamente de 64 caracteres hexadecimales.")
            )
        return clean


class APIDocumentListSerializer(serializers.ModelSerializer):
    """
    Serializador conciso para listados paginados de documentos en la API v1.
    """

    origin_uo_alias = serializers.CharField(source="origin_uo.alias", read_only=True, default=None)
    target_uo_alias = serializers.CharField(source="target_uo.alias", read_only=True, default=None)
    status = serializers.SerializerMethodField()

    class Meta:
        model = EncryptedDocument
        fields = [
            "file_hash",
            "original_filename",
            "burn_policy",
            "is_consumed",
            "status",
            "origin_uo_alias",
            "target_uo_alias",
            "created_at",
            "expires_at",
        ]

    def get_status(self, obj: EncryptedDocument) -> str:
        if obj.is_consumed:
            return "consumed"
        if obj.is_expired():
            return "expired"
        return "active"


class APIDocumentDetailSerializer(serializers.ModelSerializer):
    """
    Serializador exhaustivo de metadatos de un asiento confidencial.
    """

    origin_uo_alias = serializers.CharField(source="origin_uo.alias", read_only=True, default=None)
    origin_uo_name = serializers.CharField(source="origin_uo.name", read_only=True, default=None)
    target_uo_alias = serializers.CharField(source="target_uo.alias", read_only=True, default=None)
    target_uo_name = serializers.CharField(source="target_uo.name", read_only=True, default=None)
    status = serializers.SerializerMethodField()
    recipients_count = serializers.SerializerMethodField()

    class Meta:
        model = EncryptedDocument
        fields = [
            "file_hash",
            "original_filename",
            "description",
            "burn_policy",
            "is_consumed",
            "consumed_at",
            "consumed_by",
            "status",
            "allowed_emails",
            "recipients_count",
            "origin_uo_alias",
            "origin_uo_name",
            "target_uo_alias",
            "target_uo_name",
            "created_at",
            "expires_at",
        ]

    def get_status(self, obj: EncryptedDocument) -> str:
        if obj.is_consumed:
            return "consumed"
        if obj.is_expired():
            return "expired"
        return "active"

    def get_recipients_count(self, obj: EncryptedDocument) -> int:
        return len(obj.allowed_emails or [])


class APIOUListSerializer(serializers.ModelSerializer):
    """
    Serializador del directorio de Unidades Organizativas (UO Mesh).
    """

    class Meta:
        model = OrganizationalUnit
        fields = [
            "id",
            "numeric_code",
            "alias",
            "name",
            "description",
            "email",
            "is_active",
        ]


class APIOURecipientSerializer(serializers.Serializer):
    """
    Serializador para miembros autorizados de una UO destinataria.
    """

    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(read_only=True)
    email = serializers.EmailField(read_only=True)
    full_name = serializers.CharField(read_only=True)
    role = serializers.CharField(read_only=True)

