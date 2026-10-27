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
        help_text=_(
            "Identificador numérico único de la Unidad Organizativa (ej. 1001)."
        ),
    )
    alias = models.SlugField(
        max_length=50,
        unique=True,
        db_index=True,
        verbose_name=_("Alias / Siglas"),
        help_text=_(
            "Siglas o código textual único en mayúsculas (ej. RRHH, LEGAL, AUDITORIA)."
        ),
    )
    name = models.CharField(
        max_length=255,
        verbose_name=_("Nombre descriptivo"),
        help_text=_("Denominación oficial completa de la Unidad Organizativa."),
    )
    email = models.EmailField(
        unique=True,
        verbose_name=_("Correo oficial / Buzón general de la UO"),
        help_text=_(
            "Dirección de correo electrónico corporativo o buzón compartido de la UO."
        ),
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
        AUDITOR = "AUDITOR", _(
            "Auditor (Emisión, inspección y descarga legal preservada)"
        )
        ADMIN = "ADMIN", _(
            "Administrador de UO (Gestión de usuarios y documentos de la UO)"
        )

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
        help_text=_(
            "Si está marcado, se exigirá actualizar la contraseña tras iniciar sesión."
        ),
    )
    failed_login_attempts = models.PositiveSmallIntegerField(
        default=0,
        verbose_name=_("Intentos fallidos de acceso"),
        help_text=_("Contador de intentos fallidos consecutivos."),
    )
    locked_until = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("Bloqueado hasta"),
        help_text=_("Fecha y hora límite del bloqueo temporal por fuerza bruta."),
    )
    password_changed_at = models.DateTimeField(
        default=timezone.now,
        verbose_name=_("Última actualización de contraseña"),
        help_text=_(
            "Marca temporal del último cambio de contraseña para control de caducidad."
        ),
    )
    totp_secret = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("Secreto TOTP cifrado"),
        help_text=_("Secreto Base32 cifrado con la clave maestra de servidor."),
    )
    is_totp_enabled = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("¿2FA activo?"),
        help_text=_(
            "Indica si el usuario tiene activo el segundo factor de autenticación TOTP."
        ),
    )
    is_mfa_enforced = models.BooleanField(
        default=False,
        verbose_name=_("¿Exigir 2FA obligatorio?"),
        help_text=_(
            "Obliga al usuario a configurar y usar 2FA aunque no pertenezca al personal administrativo."
        ),
    )
    is_global_admin = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("Administrador Global de Seguridad"),
        help_text=_(
            "Otorga el máximo privilegio de gobierno criptográfico, perimetral y organizativo sobre toda la plataforma Arcamitte."
        ),
    )
    totp_scratch_codes = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_("Hashes de códigos de rescate"),
        help_text=_("Hashes SHA-256 de los códigos de recuperación de emergencia."),
    )
    current_session_key = models.CharField(
        max_length=40,
        blank=True,
        default="",
        verbose_name=_("Clave de sesión activa"),
        help_text=_(
            "Identificador de la última sesión activa del usuario para control de concurrencia."
        ),
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

    @property
    def is_locked(self) -> bool:
        """Determina si la cuenta de usuario se encuentra temporalmente bloqueada."""
        if self.locked_until is None:
            return False
        return timezone.now() < self.locked_until

    @property
    def is_totp_required(self) -> bool:
        """Indica si el usuario tiene exigencia obligatoria de 2FA."""
        from arcamitte.services import is_totp_required_for_user

        return is_totp_required_for_user(self.user)

    @property
    def role_display_name(self) -> str:
        """Retorna el nombre del rol institucional limpio de Arcamitte."""
        if self.is_global_admin:
            return str(_("Administrador Global de Seguridad"))
        memberships = self.user.uo_memberships.filter(is_active=True).select_related(
            "uo"
        )
        if memberships.exists():
            roles = [f"{m.get_role_display()} ({m.uo.alias})" for m in memberships]
            return ", ".join(roles)
        return str(_("Usuario Estándar"))

    @property
    def is_password_expired(self) -> bool:
        """Determina si la contraseña ha superado el plazo máximo de caducidad."""
        expiration_days = getattr(settings, "ARCAMITTE_PASSWORD_EXPIRATION_DAYS", 90)
        if expiration_days <= 0 or not self.password_changed_at:
            return False
        expiry_threshold = self.password_changed_at + timezone.timedelta(
            days=expiration_days
        )
        return timezone.now() >= expiry_threshold

    def lock_account(self, minutes: int = 30) -> None:
        """Bloquea temporalmente la cuenta por una duración en minutos."""
        self.locked_until = timezone.now() + timezone.timedelta(minutes=minutes)
        self.save(update_fields=["locked_until", "updated_at"])

    def unlock_account(self) -> None:
        """Desbloquea inmediatamente la cuenta y restablece el contador de intentos fallidos."""
        self.locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=["locked_until", "failed_login_attempts", "updated_at"])

    def register_failed_login(self) -> int:
        """Incrementa el contador de fallos y retorna el nuevo valor."""
        self.failed_login_attempts += 1
        self.save(update_fields=["failed_login_attempts", "updated_at"])
        return self.failed_login_attempts

    def reset_failed_logins(self) -> None:
        """Restablece el contador de fallos tras un inicio de sesión exitoso."""
        if self.failed_login_attempts > 0 or self.locked_until is not None:
            self.failed_login_attempts = 0
            self.locked_until = None
            self.save(
                update_fields=["failed_login_attempts", "locked_until", "updated_at"]
            )

    def set_totp_secret(self, plain_secret: str) -> None:
        """Cifra el secreto TOTP con el motor Fernet maestro del servidor."""
        from cryptography.fernet import MultiFernet, Fernet

        keys = getattr(
            settings, "ARCAMITTE_FERNET_KEYS", [settings.ARCAMITTE_FERNET_KEY]
        )
        engine = MultiFernet(
            [Fernet(k.encode("utf-8") if isinstance(k, str) else k) for k in keys]
        )
        self.totp_secret = engine.encrypt(plain_secret.strip().encode("utf-8")).decode(
            "utf-8"
        )

    def get_totp_secret(self) -> str:
        """Descifra y retorna el secreto TOTP en claro utilizando el llavero maestro."""
        if not self.totp_secret:
            return ""
        from cryptography.fernet import MultiFernet, Fernet

        keys = getattr(
            settings, "ARCAMITTE_FERNET_KEYS", [settings.ARCAMITTE_FERNET_KEY]
        )
        engine = MultiFernet(
            [Fernet(k.encode("utf-8") if isinstance(k, str) else k) for k in keys]
        )
        try:
            return engine.decrypt(self.totp_secret.encode("utf-8")).decode("utf-8")
        except Exception:
            return ""

    def enable_totp(self, secret: str, scratch_hashes: list[str]) -> None:
        """Habilita formalmente 2FA para el usuario guardando el secreto cifrado y los rescates."""
        self.set_totp_secret(secret)
        self.totp_scratch_codes = scratch_hashes
        self.is_totp_enabled = True
        self.save(
            update_fields=[
                "totp_secret",
                "totp_scratch_codes",
                "is_totp_enabled",
                "updated_at",
            ]
        )

    def disable_totp(self) -> None:
        """Desactiva 2FA para el usuario purgando el secreto y los rescates."""
        self.is_totp_enabled = False
        self.totp_secret = ""
        self.totp_scratch_codes = []
        self.save(
            update_fields=[
                "is_totp_enabled",
                "totp_secret",
                "totp_scratch_codes",
                "updated_at",
            ]
        )

    def consume_scratch_code(self, candidate_code: str) -> bool:
        """
        Valida si el código de rescate es válido, lo consume eliminándolo de la lista y persiste.
        """
        from .totp import hash_scratch_code

        candidate_hash = hash_scratch_code(candidate_code)
        current_hashes: list[str] = list(self.totp_scratch_codes or [])
        if candidate_hash in current_hashes:
            current_hashes.remove(candidate_hash)
            self.totp_scratch_codes = current_hashes
            self.save(update_fields=["totp_scratch_codes", "updated_at"])
            return True
        return False


class PasswordHistory(models.Model):
    """
    Registro histórico de contraseñas previas por usuario para impedir su reutilización
    (NIST SP 800-63B / ENS op.acc.5).
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="password_history",
        verbose_name=_("Usuario"),
    )
    hashed_password = models.CharField(
        max_length=255,
        verbose_name=_("Hash de contraseña previa"),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de fijación"),
    )

    class Meta:
        verbose_name = _("Historial de Contraseña")
        verbose_name_plural = _("Historiales de Contraseñas")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"], name="arca_pwd_hist_user_idx"),
        ]

    def __str__(self) -> str:
        username = getattr(self.user, "username", str(self.user))
        return f"Hash previo de {username} ({self.created_at:%Y-%m-%d %H:%M})"


class BannedIP(models.Model):
    """
    Lista negra perimetral de direcciones IP bloqueadas por actividades sospechosas,
    ataques de fuerza bruta o decisión manual del administrador.
    """

    ip_address = models.GenericIPAddressField(
        unique=True,
        db_index=True,
        verbose_name=_("Dirección IP"),
        help_text=_("Dirección IPv4 o IPv6 sujeta a bloqueo perimetral."),
    )
    reason = models.CharField(
        max_length=255,
        default=_("Bloqueo automático por sospecha de fuerza bruta"),
        verbose_name=_("Motivo del baneo"),
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_("¿Baneo activo?"),
        help_text=_(
            "Permite desactivar o reactivar el bloqueo sin borrar el registro."
        ),
    )
    banned_until = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("Baneada hasta"),
        help_text=_("Dejar en blanco para baneo permanente o indefinido."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de alta en lista negra"),
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="banned_ips_created",
        verbose_name=_("Baneada por"),
    )

    class Meta:
        verbose_name = _("IP Bloqueada / Lista Negra")
        verbose_name_plural = _("IPs Bloqueadas / Lista Negra")
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["ip_address", "is_active"], name="arca_ipban_active_idx"
            ),
            models.Index(
                fields=["banned_until", "is_active"], name="arca_ipban_until_idx"
            ),
        ]

    def __str__(self) -> str:
        status = "ACTIVO" if self.is_currently_banned() else "INACTIVO"
        return f"[{status}] {self.ip_address} - {self.reason}"

    def is_currently_banned(self) -> bool:
        """Verifica si el baneo sigue vigente en base a su estado y plazo."""
        if not self.is_active:
            return False
        if self.banned_until and timezone.now() >= self.banned_until:
            return False
        return True


def get_or_create_user_profile(user: Any) -> UserProfile:
    """Obtiene o inicializa de forma segura el perfil de un usuario."""
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_sync_user_profile(
    sender: Any, instance: Any, created: bool, **kwargs: Any
) -> None:
    """Garantiza la existencia automática y sincronización de privilegios para cada usuario."""
    profile, _ = UserProfile.objects.get_or_create(user=instance)
    if getattr(instance, "is_superuser", False) and not profile.is_global_admin:
        profile.is_global_admin = True
        profile.save(update_fields=["is_global_admin"])


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
        help_text=_(
            "Descripción informativa para las notificaciones por correo electrónico."
        ),
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
        help_text=_(
            "Determina si se destruye al primer acceso o tras el acceso de todos."
        ),
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
        help_text=_(
            "Unidad Organizativa de destino si se trata de un trámite inter-departamental."
        ),
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
        help_text=_(
            "Indica si el documento ya fue canjeado y destruido del almacenamiento."
        ),
    )
    consumed_by = models.CharField(
        max_length=254,
        null=True,
        blank=True,
        verbose_name=_("Consumido por"),
        help_text=_(
            "Correo del usuario o resumen de destinatarios que retiraron el documento."
        ),
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
        help_text=_(
            "Fecha límite tras la cual el asiento se cerrará y el archivo será destruido físicamente (por defecto 2 semanas)."
        ),
    )
    timestamp_token = models.TextField(
        blank=True,
        default="",
        verbose_name=_("Token de Sello de Tiempo RFC 3161"),
        help_text=_(
            "Token DER en Base64 emitido por una Autoridad de Sellado de Tiempo (TSA)."
        ),
    )
    timestamp_authority = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("Autoridad de Sellado de Tiempo (TSA)"),
        help_text=_("URL o entidad emisora del sello cualificado de tiempo."),
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
            (
                "can_audit_download",
                _("Puede realizar descarga de auditoría administrativa"),
            ),
        ]
        indexes = [
            models.Index(
                fields=["origin_uo", "is_consumed"], name="arca_doc_orig_cons_idx"
            ),
            models.Index(
                fields=["target_uo", "is_consumed"], name="arca_doc_targ_cons_idx"
            ),
            models.Index(
                fields=["file_hash", "is_consumed"], name="arca_doc_hash_cons_idx"
            ),
        ]

    def __str__(self) -> str:
        status_suffix = (
            f" [CONSUMIDO por {self.consumed_by}]" if self.is_consumed else " [ACTIVO]"
        )
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
        allowed_set = {
            e.strip().lower()
            for e in self.allowed_emails
            if isinstance(e, str) and e.strip()
        }
        consumed_set = {
            e.strip().lower()
            for e in self.consumed_recipients
            if isinstance(e, str) and e.strip()
        }
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
            _(
                "Los asientos documentales son inmutables y no pueden eliminarse. "
                "Utilice la función de finalización de asiento con constancia de vicisitud."
            )
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
            models.Index(
                fields=["document", "email", "is_used"], name="arca_tok_doc_em_used_idx"
            ),
            models.Index(
                fields=["expires_at", "is_used"], name="arca_tok_exp_used_idx"
            ),
        ]

    def __str__(self) -> str:
        status = (
            "USADO"
            if self.is_used
            else ("ACTIVO" if self.is_valid() else "EXPIRADO/BLOQUEADO")
        )
        return f"Token [{status}] {self.email} ({self.document.original_filename})"

    def is_valid(self) -> bool:
        """
        Retorna True si no ha sido usado, no ha caducado y no supera los 3 intentos fallidos.
        """
        return (
            (not self.is_used)
            and (timezone.now() <= self.expires_at)
            and (self.failed_attempts < 3)
        )

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
    Incorpora encadenamiento criptográfico (Hash Chaining) para garantizar el no repudio
    y la integridad estricta del registro histórico contra manipulaciones en base de datos.
    """

    class Action(models.TextChoices):
        SOLICITUD_OTP = "solicitud_otp", _("Solicitud de código de verificación")
        OTP_ENVIADO = "otp_enviado", _("Código de verificación enviado")
        DESCIFRADO_EXITOSO_BURN = "descifrado_exitoso_burn", _(
            "Descarga completada y retirada de la pasarela"
        )
        DESCIFRADO_PARCIAL_PRESERVADO = "descifrado_parcial_preservado", _(
            "Descarga individual completada (en espera de restantes destinatarios)"
        )
        REACTIVACION_DOCUMENTO = "reactivacion_documento", _(
            "Reactivación de documento"
        )
        FINALIZACION_MANUAL = "finalizacion_manual", _(
            "Finalización manual del asiento (destrucción física)"
        )
        CADUCIDAD_AUTOMATICA = "caducidad_automatica", _(
            "Caducidad automática del asiento por vencimiento"
        )
        INTENTO_POST_CONSUMO = "intento_post_consumo", _(
            "Acceso a documento no disponible"
        )
        OTP_INVALIDO_BLOQUEADO = "otp_invalido_bloqueado", _(
            "Código bloqueado por intentos fallidos"
        )
        ADMIN_DESCARGA_PRESERVADA = "admin_descarga_preservada", _(
            "Descarga de auditoría administrativa"
        )
        EXPORTACION_AUDITORIA = "exportacion_auditoria", _(
            "Exportación certificada de registros de auditoría"
        )
        BLOQUEO_USUARIO = "bloqueo_usuario", _(
            "Bloqueo de seguridad de cuenta de usuario"
        )
        BANEO_IP = "baneo_ip", _("Baneo de dirección IP en lista negra")
        ROTACION_CLAVE_MAESTRA = "rotacion_clave_maestra", _(
            "Rotación de clave maestra de cifrado"
        )
        SECUESTRO_SESION_DETECTADO = "secuestro_sesion_detectado", _(
            "Detección de posible secuestro de sesión (discrepancia IP)"
        )
        SESION_CONCURRENTE_TERMINADA = "sesion_concurrente_terminada", _(
            "Sesión concurrente anterior cerrada"
        )
        TOTP_CONFIGURADO = "totp_configurado", _(
            "Autenticación 2FA configurada/modificada"
        )
        TOTP_RECUPERACION_USADO = "totp_recuperacion_usado", _(
            "Código de recuperación 2FA consumido"
        )
        MALWARE_DETECTADO = "malware_detectado", _(
            "Amenaza de malware bloqueada por antivirus"
        )
        SELLO_TIEMPO_RFC3161_GENERADO = "sello_tiempo_rfc3161_generado", _(
            "Sello de tiempo RFC 3161 generado"
        )
        MARCA_AGUA_APLICADA = "marca_agua_aplicada", _(
            "Marca de agua forense aplicada a PDF"
        )
        TOKEN_API_CREADO = "token_api_creado", _("Token API M2M generado")
        TOKEN_API_REVOCADO = "token_api_revocado", _("Token API M2M revocado")

    document = models.ForeignKey(
        EncryptedDocument,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
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
        help_text=_(
            "Información contextual, motivo de la vicisitud o justificación legal."
        ),
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
    previous_hash = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        verbose_name=_("Hash del registro anterior"),
        help_text=_(
            "Hash criptográfico del registro inmediatamente anterior en la cadena."
        ),
    )
    log_hash = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        verbose_name=_("Hash criptográfico del registro"),
        help_text=_(
            "Hash SHA-256 del contenido de este registro vinculado al bloque anterior."
        ),
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
            models.Index(
                fields=["document", "created_at"], name="arca_log_doc_created_idx"
            ),
            models.Index(
                fields=["origin_uo", "created_at"], name="arca_log_orig_created_idx"
            ),
            models.Index(fields=["log_hash"], name="arca_log_hash_idx"),
            models.Index(fields=["previous_hash"], name="arca_log_prev_hash_idx"),
        ]

    def __str__(self) -> str:
        doc_name = (
            self.document.original_filename if self.document else "Global / Sistema"
        )
        return f"[{self.created_at:%Y-%m-%d %H:%M:%S}] {self.email} -> {self.action} ({doc_name})"

    def calculate_payload_hash(self, prev_hash: str) -> str:
        """Calcula el hash criptográfico SHA-256 del registro enlazado al bloque anterior."""
        import hashlib

        doc_hash = self.document.file_hash if self.document else ""
        dt_str = (
            self.created_at.isoformat()
            if self.created_at
            else timezone.now().isoformat()
        )
        payload = f"{prev_hash}|{dt_str}|{self.action}|{self.email}|{self.ip_address or ''}|{doc_hash}|{self.details}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Garantiza el encadenamiento criptográfico automático si no se ha computado previamente."""
        if not self.log_hash:
            if not self.previous_hash:
                last_log = DocumentAccessLog.objects.order_by("-id").first()
                if last_log and last_log.log_hash:
                    self.previous_hash = last_log.log_hash
                else:
                    self.previous_hash = "0" * 64
            self.log_hash = self.calculate_payload_hash(self.previous_hash)
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """
        Garantía de inmutabilidad: los registros de auditoría legal son estrictamente inmutables.
        """
        if kwargs.pop("force_hard_delete", False):
            return super().delete(*args, **kwargs)
        raise PermissionDenied(
            _(
                "Los registros de auditoría legal son estrictamente inmutables y no pueden eliminarse del sistema."
            )
        )


class AuditExportReceipt(models.Model):
    """
    Recibo oficial inmutable de exportación de registros de auditoría.
    Garantiza el no repudio registrando la fecha/hora, el operador, los filtros
    y el hash SHA-256 del contenido exacto del archivo descargado.
    """

    receipt_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        verbose_name=_("Identificador del recibo"),
        help_text=_("Código único del recibo oficial (ej. ARCA-EXP-YYYYMMDD-...)"),
    )
    export_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        verbose_name=_("Hash SHA-256 del archivo exportado"),
        help_text=_(
            "Huella digital del archivo CSV generado para verificación de no repudio."
        ),
    )
    exported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="audit_exports",
        verbose_name=_("Exportado por"),
    )
    records_count = models.PositiveIntegerField(
        verbose_name=_("Total de registros volcados"),
    )
    filter_criteria = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("Criterios de filtrado aplicados"),
    )
    client_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_("Dirección IP del solicitante"),
    )
    reason = models.TextField(
        blank=True,
        default="",
        verbose_name=_("Justificación / Motivo legal de la exportación"),
    )
    timestamp_token = models.TextField(
        blank=True,
        default="",
        verbose_name=_("Token de Sello de Tiempo RFC 3161"),
        help_text=_(
            "Token DER en Base64 emitido por una Autoridad de Sellado de Tiempo (TSA)."
        ),
    )
    timestamp_authority = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("Autoridad de Sellado de Tiempo (TSA)"),
        help_text=_("URL o entidad emisora del sello cualificado de tiempo."),
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        verbose_name=_("Fecha y hora de emisión"),
    )

    class Meta:
        verbose_name = _("Recibo de Exportación de Auditoría")
        verbose_name_plural = _("Recibos de Exportación de Auditoría")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["export_hash"], name="arca_rcpt_hash_idx"),
            models.Index(fields=["receipt_id"], name="arca_rcpt_id_idx"),
            models.Index(fields=["created_at"], name="arca_rcpt_created_idx"),
        ]

    def __str__(self) -> str:
        return f"[{self.receipt_id}] {self.records_count} logs - Hash={self.export_hash[:10]}... por {self.exported_by}"

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """Garantía de no repudio: los recibos de auditoría son estrictamente inmutables."""
        if kwargs.pop("force_hard_delete", False):
            return super().delete(*args, **kwargs)
        raise PermissionDenied(
            _(
                "Los recibos de auditoría de exportación son estrictamente inmutables y no pueden eliminarse."
            )
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
        DOCUMENTS_CREATE = "documents:create", _(
            "Subir y registrar documentos cifrados"
        )
        DOCUMENTS_READ = "documents:read", _(
            "Consultar estado y metadatos de documentos"
        )
        UOS_READ = "uos:read", _("Consultar directorio de Unidades Organizativas")

    name = models.CharField(
        max_length=120,
        verbose_name=_("Nombre descriptivo del servicio / cliente"),
        help_text=_(
            "Nombre del microservicio o sistema autorizado (ej. 'ERP Nóminas', 'CRM Ventas')."
        ),
    )
    prefix = models.CharField(
        max_length=16,
        db_index=True,
        verbose_name=_("Prefijo público visible"),
        help_text=_(
            "Primeros caracteres del token para identificación (ej. 'arca_live_a1b2')."
        ),
    )
    hashed_token = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        verbose_name=_("Hash SHA-256 del token"),
        help_text=_(
            "Hash criptográfico en reposo. El secreto original nunca se almacena en el servidor."
        ),
    )
    uo = models.ForeignKey(
        OrganizationalUnit,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="api_tokens",
        verbose_name=_("Unidad Organizativa asignada"),
        help_text=_(
            "UO a la que se circunscriben los trámites emitidos por este token (opcional)."
        ),
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
        help_text=_(
            "Lista de scopes concedidos (ej. ['documents:create', 'documents:read'])."
        ),
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
        help_text=_(
            "Fecha límite tras la cual el token queda automáticamente invalidado (opcional)."
        ),
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_("¿Activo?"),
        help_text=_(
            "Permite revocar el token de forma instantánea sin eliminar el registro histórico."
        ),
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Fecha de revocación"),
    )
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_api_tokens",
        verbose_name=_("Revocado por"),
    )
    revocation_reason = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("Motivo de revocación"),
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
        uo: OrganizationalUnit | None = None,
        created_by: Any = None,
        scopes: list[str] | None = None,
        expires_at: Any | None = None,
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

        effective_scopes = scopes or [
            cls.Scope.DOCUMENTS_CREATE,
            cls.Scope.DOCUMENTS_READ,
        ]

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

    def record_usage(self, ip_address: str | None = None) -> None:
        """Actualiza la marca temporal de uso y la IP de origen."""
        update_fields = ["last_used_at"]
        self.last_used_at = timezone.now()
        if ip_address:
            self.last_used_ip = ip_address
            update_fields.append("last_used_ip")
        self.save(update_fields=update_fields)


@receiver(post_delete, sender=EncryptedDocument)
def auto_delete_physical_file_on_delete(
    sender: Any, instance: EncryptedDocument, **kwargs: Any
) -> None:
    """
    Elimina físicamente el archivo del disco con borrado seguro cuando
    se elimina el registro del documento de la base de datos.
    """
    if instance.encrypted_file:
        try:
            from arcamitte.services import shred_and_delete_file

            shred_and_delete_file(instance.encrypted_file)
        except Exception as exc:
            logger.warning(
                f"[ARCAMITTE] No se pudo ejecutar borrado seguro de {instance.encrypted_file}: {exc}"
            )


class PlatformSecurityPolicy(models.Model):
    """
    Directivas institucionales de gobernanza y seguridad de la plataforma Arcamitte.
    Modelo Singleton administrado exclusivamente por el Administrador Global de Seguridad.
    """

    mfa_enforced_for_auditors = models.BooleanField(
        default=False,
        verbose_name=_("Exigir 2FA Obligatorio para Auditores de UO"),
        help_text=_(
            "Obliga a todos los usuarios con rol de Auditor en cualquier Unidad Organizativa a enrolar y validar un segundo factor TOTP."
        ),
    )
    mfa_enforced_for_operators = models.BooleanField(
        default=False,
        verbose_name=_("Exigir 2FA Obligatorio para Operadores de UO"),
        help_text=_(
            "Obliga a todos los usuarios con rol de Operador en cualquier Unidad Organizativa a enrolar y validar un segundo factor TOTP."
        ),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Última actualización"),
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_policies_updated",
        verbose_name=_("Actualizado por"),
    )

    class Meta:
        verbose_name = _("Directiva de Seguridad de Plataforma")
        verbose_name_plural = _("Directivas de Seguridad de Plataforma")

    def __str__(self) -> str:
        return "Directiva Global de Seguridad de Plataforma"

    @classmethod
    def get_solo(cls) -> "PlatformSecurityPolicy":
        """Retorna la instancia única de configuración de seguridad o la crea si no existe."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
