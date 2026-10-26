from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import models
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)


def default_document_expiry() -> Any:
    """Retorna la fecha de caducidad por defecto a dos semanas desde el momento actual."""
    return timezone.now() + timezone.timedelta(weeks=2)


class OrganizationalUnit(models.Model):
    """
    Unidad Organizativa (UO) plana para estructurar departamentos, divisiones
    o dependencias en la malla de intercambio de documentos.
    """

    numeric_code = models.PositiveIntegerField(
        unique=True,
        db_index=True,
        verbose_name=_("Código numérico único"),
        help_text=_("Identificador numérico único de la Unidad Organizativa (ej. 1001)."),
    )
    alias = models.SlugField(
        max_length=50,
        unique=True,
        db_index=True,
        verbose_name=_("Alias / Siglas"),
        help_text=_("Siglas o código textual único en mayúsculas (ej. RRHH, LEGAL, AUDITORIA)."),
    )
    name = models.CharField(
        max_length=255,
        verbose_name=_("Nombre descriptivo"),
        help_text=_("Denominación oficial completa de la Unidad Organizativa."),
    )
    email = models.EmailField(
        unique=True,
        verbose_name=_("Correo oficial / Buzón general de la UO"),
        help_text=_("Dirección de correo electrónico corporativo o buzón compartido de la UO."),
    )
    description = models.TextField(
        blank=True,
        default="",
        verbose_name=_("Descripción"),
        help_text=_("Descripción informativa sobre las funciones de esta unidad."),
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_("¿Activa?"),
        help_text=_("Indica si la UO está operativa para emitir y recibir trámites."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de alta"),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Fecha de actualización"),
    )

    class Meta:
        verbose_name = _("Unidad Organizativa")
        verbose_name_plural = _("Unidades Organizativas")
        ordering = ["numeric_code", "name"]

    def __str__(self) -> str:
        return f"[{self.numeric_code:04d}] {self.alias} - {self.name}"

    def clean(self) -> None:
        super().clean()
        if self.alias:
            self.alias = self.alias.strip().upper()
        if self.email:
            self.email = self.email.strip().lower()

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.clean()
        super().save(*args, **kwargs)


class UserUOMembership(models.Model):
    """
    Asignación de pertenencia y rol de un usuario a una Unidad Organizativa.
    """

    class Role(models.TextChoices):
        OPERATOR = "OPERATOR", _("Operador (Emisión y consulta de trámites)")
        AUDITOR = "AUDITOR", _("Auditor (Emisión, inspección y descarga legal preservada)")
        ADMIN = "ADMIN", _("Administrador de UO (Gestión de usuarios y documentos de la UO)")

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="uo_memberships",
        verbose_name=_("Usuario"),
    )
    uo = models.ForeignKey(
        OrganizationalUnit,
        on_delete=models.CASCADE,
        related_name="memberships",
        verbose_name=_("Unidad Organizativa"),
    )
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.OPERATOR,
        verbose_name=_("Rol en la UO"),
        help_text=_("Nivel de privilegios dentro de esta Unidad Organizativa."),
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name=_("¿Membresía activa?"),
        help_text=_("Indica si el usuario tiene acceso operativo actual a esta UO."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de asignación"),
    )

    class Meta:
        verbose_name = _("Membresía de Usuario en UO")
        verbose_name_plural = _("Membresías de Usuarios en UOs")
        unique_together = ("user", "uo")
        ordering = ["uo", "user"]

    def __str__(self) -> str:
        username = getattr(self.user, "username", str(self.user))
        return f"{username} @ {self.uo.alias} ({self.get_role_display()})"


class UserProfile(models.Model):
    """
    Perfil complementario para usuarios del sistema Arcamitte.
    Controla directivas de ciclo de vida de credenciales y seguridad.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="arcamitte_profile",
        verbose_name=_("Usuario"),
    )
    must_change_password = models.BooleanField(
        default=False,
        verbose_name=_("¿Debe cambiar la contraseña en el próximo acceso?"),
        help_text=_("Si está marcado, se exigirá actualizar la contraseña tras iniciar sesión."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de creación"),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Última actualización"),
    )

    class Meta:
        verbose_name = _("Perfil de Usuario")
        verbose_name_plural = _("Perfiles de Usuario")

    def __str__(self) -> str:
        username = getattr(self.user, "username", str(self.user))
        return f"Perfil de {username}"


def get_or_create_user_profile(user: Any) -> UserProfile:
    """Obtiene o inicializa de forma segura el perfil de un usuario."""
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_sync_user_profile(sender: Any, instance: Any, created: bool, **kwargs: Any) -> None:
    """Garantiza la existencia automática del perfil para cada usuario creado."""
    if created:
        UserProfile.objects.get_or_create(user=instance)


class EncryptedDocument(models.Model):
    """
    Modelo de almacenamiento de documentos confidenciales cifrados.
    
    Criterios de seguridad y arquitectura:
    1. Cero transporte del binario por el cliente: El identificador unívoco
       y prueba de trámite es exclusivamente el hash SHA-256 del contenido original.
    2. Zero Human-Readable Passwords: No existen contraseñas humanas.
       El cifrado se realiza con una Clave Maestra de Datos (DEK) protegida a su vez
       con settings.ARCAMITTE_FERNET_KEY (Envelope Encryption).
    3. Burn-After-Read con opciones de política:
       - FIRST_ACCESS: Destrucción al primer acceso de cualquiera.
       - ALL_RECIPIENTS: Destrucción física cuando todos los autorizados hayan accedido.
    4. Reactivación y reapertura por hash idéntico conservando la trazabilidad.
    """

    class BurnPolicy(models.TextChoices):
        FIRST_ACCESS = "FIRST_ACCESS", _("Descarga única (primer acceso)")
        ALL_RECIPIENTS = "ALL_RECIPIENTS", _("Disponible para todos los destinatarios")

    original_filename = models.CharField(
        max_length=255,
        default="documento",
        verbose_name=_("Nombre original del documento"),
        help_text=_("Nombre del archivo original cargado en el sistema."),
    )
    description = models.TextField(
        default="Documento confidencial compartido a través de la pasarela segura Arcamitte.",
        blank=True,
        verbose_name=_("Descripción del documento"),
        help_text=_("Descripción informativa para las notificaciones por correo electrónico."),
    )
    file_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        verbose_name=_("Hash SHA-256"),
        help_text=_("Hash SHA-256 hexadecimal (64 caracteres) del archivo original."),
    )
    encrypted_file = models.FileField(
        upload_to="encrypted_docs/%Y/%m/",
        verbose_name=_("Archivo cifrado"),
        help_text=_("Archivo binario cifrado en reposo con la DEK."),
    )
    encrypted_dek = models.TextField(
        default="",
        verbose_name=_("Clave Maestra de Datos (DEK) cifrada"),
        help_text=_("DEK cifrada internamente con settings.ARCAMITTE_FERNET_KEY."),
    )
    allowed_emails = models.JSONField(
        default=list,
        verbose_name=_("Correos autorizados"),
        help_text=_("Lista de correos autorizados en minúsculas."),
    )
    burn_policy = models.CharField(
        max_length=20,
        choices=BurnPolicy.choices,
        default=BurnPolicy.FIRST_ACCESS,
        verbose_name=_("Política de destrucción"),
        help_text=_("Determina si se destruye al primer acceso o tras el acceso de todos."),
    )
    origin_uo = models.ForeignKey(
        OrganizationalUnit,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="dispatched_documents",
        verbose_name=_("UO Emisora"),
        help_text=_("Unidad Organizativa responsable de la emisión del documento."),
    )
    target_uo = models.ForeignKey(
        OrganizationalUnit,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="received_documents",
        verbose_name=_("UO Receptora (Malla)"),
        help_text=_("Unidad Organizativa de destino si se trata de un trámite inter-departamental."),
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="uploaded_documents",
        verbose_name=_("Subido por"),
        help_text=_("Usuario que dio de alta el documento en el sistema."),
    )
    uploaded_by_token = models.ForeignKey(
        "APIToken",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="uploaded_documents",
        verbose_name=_("API Token emisor"),
        help_text=_("Credencial M2M utilizada cuando el asiento fue registrado a través de la API REST."),
    )
    consumed_recipients = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_("Destinatarios que han consumido"),
        help_text=_("Lista de correos que ya han descargado su copia individual."),
    )
    is_consumed = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("¿Documento consumido?"),
        help_text=_("Indica si el documento ya fue canjeado y destruido del almacenamiento."),
    )
    consumed_by = models.CharField(
        max_length=254,
        null=True,
        blank=True,
        verbose_name=_("Consumido por"),
        help_text=_("Correo del usuario o resumen de destinatarios que retiraron el documento."),
    )
    consumed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Fecha y hora del canje"),
        help_text=_("Momento exacto en el que el documento fue canjeado."),
    )
    expires_at = models.DateTimeField(
        default=default_document_expiry,
        db_index=True,
        verbose_name=_("Fecha de caducidad"),
        help_text=_("Fecha límite tras la cual el asiento se cerrará y el archivo será destruido físicamente (por defecto 2 semanas)."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de alta"),
        help_text=_("Marca temporal de creación del registro."),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Fecha de actualización"),
        help_text=_("Marca temporal de la última actualización."),
    )

    class Meta:
        verbose_name = _("Documento Cifrado")
        verbose_name_plural = _("Documentos Cifrados")
        ordering = ["-created_at"]
        permissions = [
            ("can_audit_download", _("Puede realizar descarga de auditoría administrativa")),
        ]
        indexes = [
            models.Index(fields=["origin_uo", "is_consumed"], name="arca_doc_orig_cons_idx"),
            models.Index(fields=["target_uo", "is_consumed"], name="arca_doc_targ_cons_idx"),
            models.Index(fields=["file_hash", "is_consumed"], name="arca_doc_hash_cons_idx"),
        ]

    def __str__(self) -> str:
        status_suffix = f" [CONSUMIDO por {self.consumed_by}]" if self.is_consumed else " [ACTIVO]"
        return f"{self.original_filename} (hash={self.file_hash[:8]}...){status_suffix}"

    def is_email_authorized(self, email: str) -> bool:
        """
        Comprueba si una dirección de correo está autorizada para acceder al documento.
        Normaliza a minúsculas y elimina espacios en blanco para evitar evasiones.
        """
        if not email or not isinstance(self.allowed_emails, list):
            return False
        normalized_email = email.strip().lower()
        return normalized_email in [
            e.strip().lower() for e in self.allowed_emails if isinstance(e, str)
        ]

    def is_email_consumed(self, email: str) -> bool:
        """Comprueba si un correo específico ya ha descargado su copia."""
        if not email or not isinstance(self.consumed_recipients, list):
            return False
        normalized_email = email.strip().lower()
        return normalized_email in [
            e.strip().lower() for e in self.consumed_recipients if isinstance(e, str)
        ]

    def are_all_recipients_consumed(self) -> bool:
        """Comprueba si todos los correos autorizados ya han descargado su copia."""
        if not isinstance(self.allowed_emails, list) or not self.allowed_emails:
            return True
        allowed_set = {e.strip().lower() for e in self.allowed_emails if isinstance(e, str) and e.strip()}
        consumed_set = {e.strip().lower() for e in self.consumed_recipients if isinstance(e, str) and e.strip()}
        return allowed_set.issubset(consumed_set)

    @property
    def is_active(self) -> bool:
        """Indica si el documento está activo (no consumido y no expirado)."""
        return not self.is_consumed and not self.is_expired()

    @property
    def mime_type(self) -> str:
        """Determina el tipo MIME del documento a partir de su nombre original."""
        import mimetypes
        guessed, _ = mimetypes.guess_type(self.original_filename or "")
        return guessed or "application/octet-stream"

    def is_expired(self) -> bool:
        """Indica si el documento ha superado su plazo de caducidad."""
        if not self.expires_at:
            return False
        return timezone.now() >= self.expires_at

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """
        Garantía de inmutabilidad: los asientos documentales no pueden ser eliminados.
        Para cerrar un trámite de forma deliberada se debe utilizar la finalización
        de asiento con constancia de vicisitud y borrado físico del archivo.
        """
        if kwargs.pop("force_hard_delete", False):
            return super().delete(*args, **kwargs)
        raise PermissionDenied(
            _("Los asientos documentales son inmutables y no pueden eliminarse. "
              "Utilice la función de finalización de asiento con constancia de vicisitud.")
        )


class AccessVerificationToken(models.Model):
    """
    Token de verificación temporal y de un solo uso para verificación OTP en tiempo real.
    """

    document = models.ForeignKey(
        EncryptedDocument,
        on_delete=models.CASCADE,
        related_name="verification_tokens",
        verbose_name=_("Documento"),
    )
    email = models.EmailField(
        db_index=True,
        verbose_name=_("Correo oficial del solicitante"),
    )
    otp_code = models.CharField(
        max_length=6,
        verbose_name=_("Código OTP"),
        help_text=_("Código numérico de 6 dígitos generado criptográficamente."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de creación"),
    )
    expires_at = models.DateTimeField(
        verbose_name=_("Fecha de caducidad"),
        help_text=_("Caducidad estricta a 15 minutos."),
    )
    is_used = models.BooleanField(
        default=False,
        verbose_name=_("¿Utilizado?"),
        help_text=_("Indica si el token ya fue consumido o revocado."),
    )
    failed_attempts = models.PositiveSmallIntegerField(
        default=0,
        verbose_name=_("Intentos fallidos"),
        help_text=_("Contador de intentos fallidos. Se revoca al alcanzar 3."),
    )

    class Meta:
        verbose_name = _("Token de Verificación OTP")
        verbose_name_plural = _("Tokens de Verificación OTP")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["document", "email", "is_used"], name="arca_tok_doc_em_used_idx"),
            models.Index(fields=["expires_at", "is_used"], name="arca_tok_exp_used_idx"),
        ]

    def __str__(self) -> str:
        status = "USADO" if self.is_used else ("ACTIVO" if self.is_valid() else "EXPIRADO/BLOQUEADO")
        return f"Token [{status}] {self.email} ({self.document.original_filename})"

    def is_valid(self) -> bool:
        """
        Retorna True si no ha sido usado, no ha caducado y no supera los 3 intentos fallidos.
        """
        return (not self.is_used) and (timezone.now() <= self.expires_at) and (self.failed_attempts < 3)

    def register_failed_attempt(self) -> None:
        """
        Incrementa failed_attempts en 1. Si alcanza 3, marca is_used = True
        para revocar el token permanentemente.
        """
        self.failed_attempts += 1
        if self.failed_attempts >= 3:
            self.is_used = True
        self.save(update_fields=["failed_attempts", "is_used"])


class DocumentAccessLog(models.Model):
    """
    Registro histórico de auditoría legal de accesos y ciclo de vida del documento.
    """

    class Action(models.TextChoices):
        SOLICITUD_OTP = "solicitud_otp", _("Solicitud de código de verificación")
        OTP_ENVIADO = "otp_enviado", _("Código de verificación enviado")
        DESCIFRADO_EXITOSO_BURN = "descifrado_exitoso_burn", _("Descarga completada y retirada de la pasarela")
        DESCIFRADO_PARCIAL_PRESERVADO = "descifrado_parcial_preservado", _("Descarga individual completada (en espera de restantes destinatarios)")
        REACTIVACION_DOCUMENTO = "reactivacion_documento", _("Reactivación de documento")
        FINALIZACION_MANUAL = "finalizacion_manual", _("Finalización manual del asiento (destrucción física)")
        CADUCIDAD_AUTOMATICA = "caducidad_automatica", _("Caducidad automática del asiento por vencimiento")
        INTENTO_POST_CONSUMO = "intento_post_consumo", _("Acceso a documento no disponible")
        OTP_INVALIDO_BLOQUEADO = "otp_invalido_bloqueado", _("Código bloqueado por intentos fallidos")
        ADMIN_DESCARGA_PRESERVADA = "admin_descarga_preservada", _("Descarga de auditoría administrativa")

    document = models.ForeignKey(
        EncryptedDocument,
        on_delete=models.CASCADE,
        related_name="access_logs",
        verbose_name=_("Documento"),
    )
    email = models.CharField(
        max_length=254,
        verbose_name=_("Correo del solicitante"),
    )
    action = models.CharField(
        max_length=50,
        choices=Action.choices,
        verbose_name=_("Acción"),
    )
    details = models.TextField(
        blank=True,
        default="",
        verbose_name=_("Detalles / Constancia de vicisitud"),
        help_text=_("Información contextual, motivo de la vicisitud o justificación legal."),
    )
    origin_uo = models.ForeignKey(
        OrganizationalUnit,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_logs_as_origin",
        verbose_name=_("UO Emisora"),
    )
    target_uo = models.ForeignKey(
        OrganizationalUnit,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_logs_as_target",
        verbose_name=_("UO Receptora"),
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_("Dirección IP"),
    )
    user_agent = models.TextField(
        null=True,
        blank=True,
        verbose_name=_("User-Agent"),
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        verbose_name=_("Fecha y hora"),
    )

    class Meta:
        verbose_name = _("Registro de Auditoría de Acceso")
        verbose_name_plural = _("Registros de Auditoría de Accesos")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["document", "created_at"], name="arca_log_doc_created_idx"),
            models.Index(fields=["origin_uo", "created_at"], name="arca_log_orig_created_idx"),
        ]

    def __str__(self) -> str:
        return f"[{self.created_at:%Y-%m-%d %H:%M:%S}] {self.email} -> {self.action} ({self.document.original_filename})"

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """
        Garantía de inmutabilidad: los registros de auditoría legal son estrictamente inmutables.
        """
        if kwargs.pop("force_hard_delete", False):
            return super().delete(*args, **kwargs)
        raise PermissionDenied(
            _("Los registros de auditoría legal son estrictamente inmutables y no pueden eliminarse del sistema.")
        )


class APIToken(models.Model):
    """
    Token criptográfico de alta seguridad para autenticación de microservicios y aplicaciones externas.
    Cumple con NIST SP 800-53 (SC-28) y OWASP API Security (API2:2023):
    - Zero-Knowledge Storage: En base de datos NUNCA se almacena el token en texto claro,
      exclusivamente su hash SHA-256 (64 hex).
    - Control granular por scopes de privilegios (Principio de Menor Privilegio).
    - Trazabilidad y revocación instantánea.
    """

    class Scope(models.TextChoices):
        DOCUMENTS_CREATE = "documents:create", _("Subir y registrar documentos cifrados")
        DOCUMENTS_READ = "documents:read", _("Consultar estado y metadatos de documentos")
        UOS_READ = "uos:read", _("Consultar directorio de Unidades Organizativas")

    name = models.CharField(
        max_length=120,
        verbose_name=_("Nombre descriptivo del servicio / cliente"),
        help_text=_("Nombre del microservicio o sistema autorizado (ej. 'ERP Nóminas', 'CRM Ventas')."),
    )
    prefix = models.CharField(
        max_length=16,
        db_index=True,
        verbose_name=_("Prefijo público visible"),
        help_text=_("Primeros caracteres del token para identificación (ej. 'arca_live_a1b2')."),
    )
    hashed_token = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        verbose_name=_("Hash SHA-256 del token"),
        help_text=_("Hash criptográfico en reposo. El secreto original nunca se almacena en el servidor."),
    )
    uo = models.ForeignKey(
        OrganizationalUnit,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="api_tokens",
        verbose_name=_("Unidad Organizativa asignada"),
        help_text=_("UO a la que se circunscriben los trámites emitidos por este token (opcional)."),
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_api_tokens",
        verbose_name=_("Emitido por"),
    )
    scopes = models.JSONField(
        default=list,
        verbose_name=_("Permisos / Scopes autorizados"),
        help_text=_("Lista de scopes concedidos (ej. ['documents:create', 'documents:read'])."),
    )
    rate_limit = models.PositiveIntegerField(
        default=60,
        verbose_name=_("Límite de peticiones por minuto"),
        help_text=_("Tasa máxima de peticiones por minuto permitidas para este token."),
    )
    last_used_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Fecha de último uso"),
    )
    last_used_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_("Última dirección IP"),
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Fecha de caducidad"),
        help_text=_("Fecha límite tras la cual el token queda automáticamente invalidado (opcional)."),
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_("¿Activo?"),
        help_text=_("Permite revocar el token de forma instantánea sin eliminar el registro histórico."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de creación"),
    )

    class Meta:
        verbose_name = _("Token de API")
        verbose_name_plural = _("Tokens de API")
        ordering = ["-created_at"]

    def __str__(self) -> str:
        status = "ACTIVO" if self.is_valid() else "INACTIVO/EXPIRADO"
        return f"[{status}] {self.name} ({self.prefix}...)"

    @classmethod
    def generate_token(
        cls,
        name: str,
        uo: Optional[OrganizationalUnit] = None,
        created_by: Any = None,
        scopes: Optional[List[str]] = None,
        expires_at: Optional[Any] = None,
        rate_limit: int = 60,
    ) -> tuple[APIToken, str]:
        """
        Genera un nuevo token criptográfico seguro con prefijo arca_live_.
        Retorna la tupla (instancia_en_bd, raw_secret_token).
        El token en texto claro se debe mostrar una sola vez al usuario.
        """
        import hashlib
        import secrets

        secret_entropy = secrets.token_urlsafe(32)
        raw_token = f"arca_live_{secret_entropy}"
        prefix = raw_token[:14]
        hashed = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        effective_scopes = scopes or [cls.Scope.DOCUMENTS_CREATE, cls.Scope.DOCUMENTS_READ]

        token_instance = cls.objects.create(
            name=name,
            prefix=prefix,
            hashed_token=hashed,
            uo=uo,
            created_by=created_by,
            scopes=effective_scopes,
            expires_at=expires_at,
            rate_limit=rate_limit,
            is_active=True,
        )
        return token_instance, raw_token

    def is_valid(self) -> bool:
        """Comprueba si el token está activo y no ha caducado."""
        if not self.is_active:
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True

    def has_scope(self, required_scope: str) -> bool:
        """Verifica si el token cuenta con el permiso o scope requerido."""
        if not isinstance(self.scopes, list):
            return False
        return "*" in self.scopes or required_scope in self.scopes

    def record_usage(self, ip_address: Optional[str] = None) -> None:
        """Actualiza la marca temporal de uso y la IP de origen."""
        update_fields = ["last_used_at"]
        self.last_used_at = timezone.now()
        if ip_address:
            self.last_used_ip = ip_address
            update_fields.append("last_used_ip")
        self.save(update_fields=update_fields)


@receiver(post_delete, sender=EncryptedDocument)
def auto_delete_physical_file_on_delete(sender: Any, instance: EncryptedDocument, **kwargs: Any) -> None:
    """
    Elimina físicamente el archivo del disco con borrado seguro cuando
    se elimina el registro del documento de la base de datos.
    """
    if instance.encrypted_file:
        try:
            from arcamitte.services import shred_and_delete_file
            shred_and_delete_file(instance.encrypted_file)
        except Exception as exc:
            logger.warning(f"[ARCAMITTE] No se pudo ejecutar borrado seguro de {instance.encrypted_file}: {exc}")
