from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import os
import re
import secrets
import sys
from typing import Any

from cryptography.fernet import Fernet, MultiFernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.db import models, transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from arcamitte.permissions import is_global_admin
from arcamitte.models import (
    AccessVerificationToken,
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
    default_document_expiry,
    get_or_create_user_profile,
)
from arcamitte.validators import (
    normalize_and_validate_email_list,
    validate_document_file,
    validate_safe_email,
)

logger = logging.getLogger(__name__)

CHUNK_SIZE: int = (
    64 * 1024
)  # 64 KB para lectura segura por bloques anti-DoS (OWASP A04)
HASH_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
GENERIC_ACCESS_MESSAGE: str = _(
    "Si los datos indicados corresponden a un documento disponible y una dirección de correo "
    "autorizada, recibirá en breve un código de verificación en su buzón."
)
TIMING_ATTACK_PBKDF2_ITERATIONS: int = int(
    getattr(settings, "ARCAMITTE_TIMING_PBKDF2_ITERATIONS", 20_000)
)

_EMAIL_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None


def get_email_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Retorna la instancia global del pool de hilos acotado para envío no bloqueante de correos."""
    global _EMAIL_EXECUTOR
    if _EMAIL_EXECUTOR is None:
        max_workers = int(getattr(settings, "ARCAMITTE_EMAIL_MAX_WORKERS", 8))
        _EMAIL_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="arcamitte_email_worker",
        )
    return _EMAIL_EXECUTOR


def _send_mail_worker(
    subject: str,
    message: str,
    from_email: str,
    recipient_list: list[str],
    fail_silently: bool,
) -> None:
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=recipient_list,
            fail_silently=fail_silently,
        )
    except Exception as exc:
        logger.error(
            f"[ARCAMITTE ERROR] Fallo al enviar correo asíncrono a {recipient_list}: {exc}"
        )


def dispatch_email(
    subject: str,
    message: str,
    from_email: str | None = None,
    recipient_list: list[str] | None = None,
    fail_silently: bool = True,
    sync: bool | None = None,
) -> concurrent.futures.Future | None:
    """
    Despacha el envío de correos de forma desacoplada y no bloqueante.
    Bajo alta concurrencia, utiliza un ThreadPoolExecutor acotado para no saturar
    los hilos de los web workers (gunicorn/uvicorn/asgi).
    En entorno de tests o si ARCAMITTE_ASYNC_EMAIL está desactivado, se ejecuta síncronamente.
    """
    sender = from_email or getattr(
        settings, "DEFAULT_FROM_EMAIL", "no-reply@arcamitte.local"
    )
    recipients = recipient_list or []

    if sync is None:
        async_enabled = getattr(settings, "ARCAMITTE_ASYNC_EMAIL", True)
        is_testing = (
            getattr(settings, "TESTING", False)
            or ("test" in sys.argv)
            or ("pytest" in sys.modules)
            or str(getattr(settings, "EMAIL_BACKEND", "")).endswith(
                "locmem.EmailBackend"
            )
        )
        sync = (not async_enabled) or is_testing

    if sync:
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=sender,
                recipient_list=recipients,
                fail_silently=fail_silently,
            )
        except Exception as exc:
            logger.error(f"[ARCAMITTE ERROR] Fallo al enviar correo síncrono: {exc}")
            if not fail_silently:
                raise
        return None
    else:
        executor = get_email_executor()
        return executor.submit(
            _send_mail_worker,
            subject,
            message,
            sender,
            recipients,
            fail_silently,
        )


def get_uo_recipient_emails(
    uo: OrganizationalUnit | None, include_members: bool = True
) -> list[str]:
    """
    Obtiene la lista de correos destinatarios disponibles para una Unidad Organizativa:
    su buzón general oficial y opcionalmente los correos de sus miembros activos.
    """
    if not uo:
        return []
    emails: list[str] = []
    if uo.email:
        clean_uo_email = uo.email.strip().lower()
        if clean_uo_email not in emails:
            emails.append(clean_uo_email)

    if include_members:
        member_emails = uo.memberships.filter(
            is_active=True, user__is_active=True
        ).values_list("user__email", flat=True)
        for me in member_emails:
            if me and isinstance(me, str) and me.strip():
                clean_email = me.strip().lower()
                if clean_email not in emails:
                    emails.append(clean_email)
    return emails


def calculate_file_sha256(file_obj: Any) -> str:
    """
    Calcula el hash criptográfico SHA-256 de un archivo binario mediante lectura en streaming.
    Preserva y restaura el cursor de lectura del stream.
    """
    hasher = hashlib.sha256()
    original_position = 0

    if hasattr(file_obj, "tell"):
        try:
            original_position = file_obj.tell()
        except (OSError, AttributeError):
            original_position = 0

    if hasattr(file_obj, "seek"):
        file_obj.seek(0)

    if hasattr(file_obj, "chunks"):
        for chunk in file_obj.chunks(CHUNK_SIZE):
            hasher.update(chunk)
    else:
        while True:
            chunk = file_obj.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)

    if hasattr(file_obj, "seek"):
        file_obj.seek(original_position)

    return hasher.hexdigest().lower()


def shred_and_delete_file(file_field: Any) -> bool:
    """
    Función auxiliar de borrado seguro (Zeroization/Shredding):
    Sobrescribe el archivo en disco con bytes aleatorios (os.urandom) antes de
    eliminarlo del sistema de archivos físico, previniendo recuperación forense.
    """
    if not file_field:
        return False

    try:
        try:
            file_field.close()
        except Exception:
            pass

        path = None
        try:
            path = file_field.path
        except (AttributeError, NotImplementedError, ValueError):
            path = None

        if path and os.path.exists(path):
            file_size = os.path.getsize(path)
            if file_size > 0:
                with open(path, "ba+", buffering=0) as f:
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        to_write = min(remaining, CHUNK_SIZE)
                        f.write(os.urandom(to_write))
                        remaining -= to_write
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(path)
            logger.info(
                f"[ARCAMITTE AUDIT] Shredding físico completado por bloques para: {path}"
            )

        file_field.delete(save=False)
        return True
    except Exception as exc:
        logger.error(
            f"[ARCAMITTE ERROR] Fallo durante trituración segura de archivo: {exc}"
        )
        try:
            file_field.delete(save=False)
        except Exception as del_exc:
            logger.warning(
                f"[ARCAMITTE WARNING] Fallo secundario al desvincular campo de archivo: {del_exc}"
            )
        return False


def get_fernet_engine() -> MultiFernet:
    """
    Retorna una instancia de MultiFernet con el llavero de claves maestras configuradas.
    La primera clave es la clave activa primaria para operaciones de cifrado nuevas.
    Las restantes claves secundarias permiten el descifrado transparente de documentos
    históricos durante procesos de migración o rotación (NIST SP 800-57 Part 1).
    Garantiza que cualquier override dinámico de ARCAMITTE_FERNET_KEY tenga prioridad inmediata.
    """
    primary_key = getattr(settings, "ARCAMITTE_FERNET_KEY", None)
    configured_keys = getattr(settings, "ARCAMITTE_FERNET_KEYS", [])

    keys: list[str | bytes] = []
    if primary_key:
        keys.append(primary_key)
    for k in configured_keys:
        if k != primary_key and k not in keys:
            keys.append(k)

    if not keys:
        raise ValueError("settings.ARCAMITTE_FERNET_KEY no se encuentra configurada.")

    fernets: list[Fernet] = []
    for k in keys:
        k_bytes = k.encode("utf-8") if isinstance(k, str) else k
        fernets.append(Fernet(k_bytes))
    return MultiFernet(fernets)


def record_audit_log(
    action: str,
    email: str = "",
    ip: str | None = None,
    user_agent: str = "",
    details: str | dict[str, Any] = "",
    document: Any = None,
    origin_uo: Any = None,
    target_uo: Any = None,
) -> Any:
    """
    Crea y persiste un registro de auditoría en DocumentAccessLog con encadenamiento
    criptográfico íntegro (Hash Chaining) conforme a ENS ALTA / eIDAS.
    """
    import json
    from django.core.serializers.json import DjangoJSONEncoder
    from arcamitte.models import DocumentAccessLog

    details_str = (
        json.dumps(details, ensure_ascii=False, cls=DjangoJSONEncoder)
        if isinstance(details, dict)
        else str(details or "")
    )
    return DocumentAccessLog.objects.create(
        document=document,
        email=email,
        action=action,
        details=details_str,
        origin_uo=origin_uo,
        target_uo=target_uo,
        ip_address=ip,
        user_agent=user_agent,
    )


def get_server_fernet_key() -> bytes:
    """Obtiene y normaliza la clave activa de servidor ARCAMITTE_FERNET_KEY en bytes."""
    key = getattr(settings, "ARCAMITTE_FERNET_KEY", None)
    if not key:
        raise ValueError("settings.ARCAMITTE_FERNET_KEY no se encuentra configurada.")
    if isinstance(key, str):
        return key.strip().encode("utf-8")
    return key


def reactivate_document(
    document: EncryptedDocument,
    original_file: Any,
    new_emails: list[str] | str | Any = None,
    burn_policy: str | None = None,
    new_description: str | None = None,
    origin_uo: OrganizationalUnit | None = None,
    target_uo: OrganizationalUnit | None = None,
    uploaded_by: Any = None,
    admin_user: Any = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    expires_at: Any | None = None,
) -> EncryptedDocument:
    """
    Reactiva un documento existente (consumido o activo) re-cifrándolo con una nueva DEK,
    reemplazando la lista de destinatarios autorizados exclusivamente por los nuevos correos
    y preservando todo el historial previo en DocumentAccessLog.
    """
    validate_document_file(original_file)
    new_hash = calculate_file_sha256(original_file)
    if new_hash != document.file_hash:
        raise ValidationError(
            _(
                "El archivo proporcionado no coincide con el hash SHA-256 del documento original."
            )
        )

    dek: bytes = Fernet.generate_key()
    fernet_dek = Fernet(dek)

    original_file.seek(0)
    file_bytes = original_file.read()
    encrypted_bytes = fernet_dek.encrypt(file_bytes)

    engine = get_fernet_engine()
    encrypted_dek_str = engine.encrypt(dek).decode("utf-8")

    # Triturar archivo anterior en disco
    if document.encrypted_file:
        shred_and_delete_file(document.encrypted_file)

    filename = (
        getattr(original_file, "name", document.original_filename)
        or document.original_filename
    )
    clean_filename = os.path.basename(filename)
    enc_filename = f"{clean_filename}.enc"
    document.encrypted_file.save(enc_filename, ContentFile(encrypted_bytes), save=False)

    normalized_emails = (
        normalize_and_validate_email_list(new_emails)
        if new_emails is not None
        else document.allowed_emails
    )
    document.encrypted_dek = encrypted_dek_str
    document.allowed_emails = normalized_emails
    if burn_policy:
        document.burn_policy = burn_policy
    if new_description is not None:
        document.description = new_description
    if origin_uo is not None:
        document.origin_uo = origin_uo
    if target_uo is not None:
        document.target_uo = target_uo
    if uploaded_by is not None:
        document.uploaded_by = uploaded_by

    if expires_at is not None:
        document.expires_at = expires_at
    elif document.is_expired():
        document.expires_at = default_document_expiry()

    document.is_consumed = False
    document.consumed_by = None
    document.consumed_at = None
    document.consumed_recipients = []
    document.save()

    # Invalidar tokens pendientes previos de este documento
    AccessVerificationToken.objects.filter(document=document, is_used=False).update(
        is_used=True
    )

    admin_identifier = (
        getattr(admin_user, "email", None)
        or getattr(admin_user, "username", None)
        or str(admin_user or "admin")
    )
    DocumentAccessLog.objects.create(
        document=document,
        email=admin_identifier,
        action=DocumentAccessLog.Action.REACTIVACION_DOCUMENTO,
        origin_uo=document.origin_uo,
        target_uo=document.target_uo,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    logger.info(
        f"[ARCAMITTE AUDIT] Documento {document.file_hash[:12]}... reactivado exitosamente por '{admin_identifier}'."
    )
    return document


def terminate_document_manually(
    document: EncryptedDocument,
    admin_user: Any,
    client_ip: str | None = None,
    user_agent: str | None = None,
    reason: str = "",
) -> tuple[bool, str]:
    """
    Finaliza deliberadamente el asiento de un documento en la pasarela segura.
    Garantiza la inmutabilidad del asiento y de los logs de auditoría:
    1. Tritura físicamente el archivo cifrado en disco con borrado seguro (shredding).
    2. Marca el documento como consumido (is_consumed=True, consumed_at=now()).
    3. Registra la constancia de vicisitud en DocumentAccessLog con acción FINALIZACION_MANUAL.
    """
    if document.is_consumed:
        return False, _(
            "El asiento ya se encuentra finalizado y el archivo ha sido retirado."
        )

    user_identifier = getattr(admin_user, "username", str(admin_user))
    user_email = getattr(admin_user, "email", user_identifier) or user_identifier

    with transaction.atomic():
        if document.encrypted_file:
            shred_and_delete_file(document.encrypted_file)

        document.is_consumed = True
        document.consumed_at = timezone.now()
        document.consumed_by = f"Finalizado manualmente por {user_identifier}"
        document.save(
            update_fields=["is_consumed", "consumed_at", "consumed_by", "updated_at"]
        )

        detail_text = (
            f"Asiento finalizado manualmente por {user_identifier} ({user_email})."
        )
        if reason:
            detail_text += f" Motivo: {reason.strip()}"

        DocumentAccessLog.objects.create(
            document=document,
            email=user_email,
            action=DocumentAccessLog.Action.FINALIZACION_MANUAL,
            origin_uo=document.origin_uo,
            target_uo=document.target_uo,
            ip_address=client_ip,
            user_agent=user_agent,
            details=detail_text,
        )

        logger.info(
            f"[ARCAMITTE AUDIT] Asiento {document.file_hash[:12]}... finalizado manualmente por {user_identifier}."
        )

    return True, _(
        "Asiento finalizado correctamente. El archivo ha sido destruido físicamente y la vicisitud ha quedado registrada en la auditoría legal."
    )


def check_and_expire_document(
    document: EncryptedDocument,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> bool:
    """
    Comprueba si un documento ha sobrepasado su plazo de caducidad (expires_at).
    Si ha caducado y continúa activo:
    1. Tritura físicamente el archivo en disco.
    2. Marca el documento como consumido por caducidad automática.
    3. Registra la constancia de vicisitud en DocumentAccessLog con CADUCIDAD_AUTOMATICA.
    Retorna True si el documento caducó y fue cerrado, False en caso contrario.
    """
    if document.is_consumed or not document.is_expired():
        return False

    with transaction.atomic():
        doc = (
            EncryptedDocument.objects.select_for_update().filter(pk=document.pk).first()
        )
        if not doc or doc.is_consumed or not doc.is_expired():
            return False

        if doc.encrypted_file:
            shred_and_delete_file(doc.encrypted_file)

        doc.is_consumed = True
        doc.consumed_at = timezone.now()
        doc.consumed_by = "Sistema (Caducidad automática sin acceso en plazo)"
        doc.save(
            update_fields=["is_consumed", "consumed_at", "consumed_by", "updated_at"]
        )

        expiry_str = (
            doc.expires_at.strftime("%Y-%m-%d %H:%M")
            if doc.expires_at
            else "desconocida"
        )
        DocumentAccessLog.objects.create(
            document=doc,
            email="sistema@arcamitte.local",
            action=DocumentAccessLog.Action.CADUCIDAD_AUTOMATICA,
            origin_uo=doc.origin_uo,
            target_uo=doc.target_uo,
            ip_address=client_ip,
            user_agent=user_agent,
            details=f"Asiento cerrado automáticamente al haber vencido su plazo de disponibilidad ({expiry_str}) sin acceso previo.",
        )

        logger.info(
            f"[ARCAMITTE AUDIT] Asiento {doc.file_hash[:12]}... cerrado automáticamente por caducidad vencida."
        )

    document.is_consumed = True
    document.consumed_at = doc.consumed_at
    document.consumed_by = doc.consumed_by
    return True


def process_expired_documents() -> int:
    """
    Procesa por lotes todos los documentos activos cuya fecha de caducidad
    haya sido superada. Cierra los asientos, tritura sus archivos físicos
    y levanta las correspondientes vicisitudes de auditoría.
    Retorna el número de asientos cerrados por caducidad.
    """
    now = timezone.now()
    expired_docs = list(
        EncryptedDocument.objects.filter(is_consumed=False, expires_at__lte=now)
    )
    count = 0
    for doc in expired_docs:
        if check_and_expire_document(doc):
            count += 1
    logger.info(
        f"[ARCAMITTE] Proceso de caducidad completado: {count} documentos cerrados."
    )
    return count


def upload_and_encrypt_document(
    original_file: Any,
    allowed_emails: list[str] | str | Any,
    burn_policy: str = EncryptedDocument.BurnPolicy.FIRST_ACCESS,
    description: str | None = None,
    reopen_existing: bool = False,
    origin_uo: OrganizationalUnit | None = None,
    target_uo: OrganizationalUnit | None = None,
    uploaded_by: Any = None,
    admin_user: Any = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    precalculated_hash: str | None = None,
    expires_at: Any | None = None,
) -> EncryptedDocument:
    """
    Servicio de registro y cifrado desatendido de documentos confidenciales.

    Si 'reopen_existing=True' y ya existe un documento con el mismo hash SHA-256,
    se reactiva automáticamente re-cifrando en disco y actualizando destinatarios
    sin duplicar el identificador en base de datos.

    Retorna: EncryptedDocument (con atributo '_is_reactivated' indicando si fue reactivación)
    """
    validate_document_file(original_file)

    max_size = getattr(settings, "ARCAMITTE_MAX_FILE_SIZE", 50 * 1024 * 1024)
    file_size = getattr(original_file, "size", None)
    if file_size is not None and file_size > max_size:
        raise ValidationError(
            _("El archivo excede el tamaño máximo permitido de %(max_size)s MB.")
            % {"max_size": max_size // (1024 * 1024)}
        )

    # --------------------------------------------------------------------------
    # FASE B: Inspección Antivirus en Memoria (ClamAV zINSTREAM)
    # Zero Disk Footprint: Inspección del flujo antes del cifrado en reposo
    # --------------------------------------------------------------------------
    if getattr(settings, "ARCAMITTE_CLAMAV_ENABLED", False):
        import socket
        from arcamitte.antivirus import (
            scan_file_stream,
            AntivirusError,
            AntivirusConnectionError,
        )

        try:
            is_clean, threat_name = scan_file_stream(original_file)
            if not is_clean:
                record_audit_log(
                    action=DocumentAccessLog.Action.MALWARE_DETECTADO,
                    email=getattr(uploaded_by, "email", "desconocido"),
                    ip=client_ip,
                    user_agent=user_agent or "",
                    details={
                        "threat_name": threat_name,
                        "filename": getattr(original_file, "name", "documento"),
                        "file_size": file_size,
                    },
                    document=None,
                    origin_uo=origin_uo,
                    target_uo=target_uo,
                )
                dispatch_siem_event(
                    event_type="malware_detected",
                    details={
                        "threat_name": threat_name,
                        "filename": getattr(original_file, "name", "documento"),
                        "origin_uo": origin_uo.alias if origin_uo else None,
                        "uploaded_by": getattr(uploaded_by, "username", "anonymous"),
                    },
                    ip_address=client_ip,
                )
                raise ValidationError(
                    _(
                        "Amenaza de malware detectada por el motor antivirus: %(threat)s. "
                        "La subida ha sido bloqueada y registrada para auditoría legal."
                    )
                    % {"threat": threat_name}
                )
        except (AntivirusError, socket.error) as av_exc:
            fail_open = getattr(settings, "ARCAMITTE_CLAMAV_FAIL_OPEN", False)
            if not fail_open:
                raise ValidationError(
                    _(
                        "El motor antivirus ClamAV no está disponible para inspeccionar el archivo. "
                        "Por política de seguridad estricta (Fail-Secure), la subida ha sido bloqueada."
                    )
                ) from av_exc

    # Resolución del usuario que sube el archivo
    if uploaded_by is None and admin_user is not None:
        if hasattr(admin_user, "is_authenticated") and admin_user.is_authenticated:
            uploaded_by = admin_user

    # Comprobación de seguridad: El usuario debe pertenecer a la origin_uo si no es superusuario
    if (
        uploaded_by is not None
        and not is_global_admin(uploaded_by)
    ):
        if origin_uo is not None:
            if not UserUOMembership.objects.filter(
                user=uploaded_by, uo=origin_uo, is_active=True
            ).exists():
                raise ValidationError(
                    _("El usuario no pertenece a la UO emisora seleccionada.")
                )

    normalized_emails = normalize_and_validate_email_list(allowed_emails)
    file_hash = (precalculated_hash or "").strip().lower() or calculate_file_sha256(
        original_file
    )

    existing_doc = EncryptedDocument.objects.filter(file_hash=file_hash).first()
    if existing_doc:
        if reopen_existing:
            # Comprobación de seguridad: El usuario debe pertenecer a la origin_uo del documento existente si no es superusuario
            if (
                uploaded_by is not None
                and not is_global_admin(uploaded_by)
            ):
                if existing_doc.origin_uo is not None:
                    if not UserUOMembership.objects.filter(
                        user=uploaded_by, uo=existing_doc.origin_uo, is_active=True
                    ).exists():
                        raise ValidationError(
                            _(
                                "Ya existe un documento registrado con este mismo hash pero pertenece a otra Unidad Organizativa (%(alias)s). No tiene autorización para reactivarlo."
                            )
                            % {"alias": existing_doc.origin_uo.alias}
                        )
                elif existing_doc.uploaded_by != uploaded_by:
                    raise ValidationError(
                        _(
                            "Ya existe un documento registrado con este mismo hash correspondiente a un asiento personal de otro usuario. No tiene autorización para reactivarlo."
                        )
                    )

            reactivated = reactivate_document(
                document=existing_doc,
                original_file=original_file,
                new_emails=normalized_emails,
                burn_policy=burn_policy,
                new_description=description,
                origin_uo=origin_uo,
                target_uo=target_uo,
                uploaded_by=uploaded_by,
                admin_user=admin_user,
                client_ip=client_ip,
                user_agent=user_agent,
                expires_at=expires_at,
            )
            reactivated._is_reactivated = True
            return reactivated
        raise ValidationError(
            _("Ya existe un documento registrado con este mismo hash SHA-256.")
        )

    dek: bytes = Fernet.generate_key()
    fernet_dek = Fernet(dek)

    original_file.seek(0)
    original_bytes: bytes = original_file.read()
    ciphertext_bytes: bytes = fernet_dek.encrypt(original_bytes)

    engine = get_fernet_engine()
    encrypted_dek_str: str = engine.encrypt(dek).decode("utf-8")

    filename = getattr(original_file, "name", "documento")
    clean_filename = os.path.basename(filename)
    encrypted_filename = f"{clean_filename}.enc"

    doc_kwargs = {
        "original_filename": clean_filename,
        "file_hash": file_hash,
        "encrypted_dek": encrypted_dek_str,
        "allowed_emails": normalized_emails,
        "burn_policy": burn_policy or EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        "is_consumed": False,
        "origin_uo": origin_uo,
        "target_uo": target_uo,
        "uploaded_by": uploaded_by,
    }
    if description is not None:
        doc_kwargs["description"] = description
    if expires_at is not None:
        doc_kwargs["expires_at"] = expires_at

    # --------------------------------------------------------------------------
    # FASE B: Sellado Criptográfico Cualificado de Tiempo (RFC 3161)
    # --------------------------------------------------------------------------
    if getattr(settings, "ARCAMITTE_RFC3161_ENABLED", False):
        from arcamitte.timestamping import (
            request_rfc3161_timestamp,
            token_to_base64,
            TimestampingError,
        )

        try:
            raw_hash_bytes = bytes.fromhex(file_hash)
            tsr_bytes = request_rfc3161_timestamp(raw_hash_bytes)
            doc_kwargs["timestamp_token"] = token_to_base64(tsr_bytes)
            doc_kwargs["timestamp_authority"] = getattr(
                settings, "ARCAMITTE_RFC3161_TSA_URL", ""
            )
            record_audit_log(
                action=DocumentAccessLog.Action.SELLO_TIEMPO_RFC3161_GENERADO,
                email=getattr(uploaded_by, "email", "sistema"),
                ip=client_ip,
                user_agent=user_agent or "",
                details={
                    "doc_hash": file_hash,
                    "tsa_url": doc_kwargs["timestamp_authority"],
                },
                document=None,
                origin_uo=origin_uo,
                target_uo=target_uo,
            )
        except TimestampingError as ts_exc:
            logger.warning(
                f"[RFC3161] No se pudo obtener sello de tiempo para el documento {file_hash[:12]}: {ts_exc}"
            )

    document = EncryptedDocument(**doc_kwargs)
    document.encrypted_file.save(
        encrypted_filename, ContentFile(ciphertext_bytes), save=False
    )
    document.save()

    logger.info(
        f"[ARCAMITTE AUDIT] Documento registrado exitosamente: id={document.pk} "
        f"hash={document.file_hash[:12]}... política={document.burn_policy}"
    )
    document._is_reactivated = False
    return document


def request_document_access(
    file_hash: str,
    email: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
    base_url: str | None = None,
) -> tuple[bool, str]:
    """
    Servicio de solicitud desatendida de acceso a documentos confidenciales.
    Mitigación de enumeración y timing attacks con PBKDF2 simulado.
    """
    clean_hash = (file_hash or "").strip().lower()
    clean_email = (email or "").strip().lower()

    if not HASH_REGEX.match(clean_hash):
        hashlib.pbkdf2_hmac(
            "sha256",
            clean_email.encode("utf-8"),
            b"arcamitte_timing_salt",
            TIMING_ATTACK_PBKDF2_ITERATIONS,
        )
        return True, GENERIC_ACCESS_MESSAGE

    try:
        normalized_email = validate_safe_email(clean_email)
    except ValidationError:
        hashlib.pbkdf2_hmac(
            "sha256",
            b"invalid_email",
            b"arcamitte_timing_salt",
            TIMING_ATTACK_PBKDF2_ITERATIONS,
        )
        return True, GENERIC_ACCESS_MESSAGE

    document = EncryptedDocument.objects.filter(file_hash=clean_hash).first()

    if not document:
        hashlib.pbkdf2_hmac(
            "sha256",
            normalized_email.encode("utf-8"),
            b"arcamitte_timing_salt",
            TIMING_ATTACK_PBKDF2_ITERATIONS,
        )
        return True, GENERIC_ACCESS_MESSAGE

    # Verificación de autorización previa (Mitigación de enumeración y fuga de metadatos)
    if not document.is_email_authorized(normalized_email):
        hashlib.pbkdf2_hmac(
            "sha256",
            normalized_email.encode("utf-8"),
            b"arcamitte_timing_salt",
            TIMING_ATTACK_PBKDF2_ITERATIONS,
        )
        return True, GENERIC_ACCESS_MESSAGE

    # Verificación de caducidad del asiento (vencimiento de plazo)
    if not document.is_consumed and document.is_expired():
        check_and_expire_document(document, client_ip=client_ip, user_agent=user_agent)

    # Caso 1: El documento ya fue consumido por completo (notificar exclusivamente al autorizado)
    if document.is_consumed:
        consumed_at_str = (
            document.consumed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if document.consumed_at
            else _("fecha no registrada")
        )
        consumed_by_str = document.consumed_by or _("un usuario autorizado")
        doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
        desc_part = (
            f"• Descripción: {document.description}\n" if document.description else ""
        )

        post_consume_message = (
            f"Estimado/a usuario/a,\n\n"
            f"Le informamos de que el documento solicitado ya fue retirado de la pasarela el {consumed_at_str} por {consumed_by_str} "
            f"y no se encuentra disponible para su descarga.\n\n"
            f"DATOS DEL DOCUMENTO:\n"
            f"• Archivo: {doc_name}\n"
            f"{desc_part}"
            f"• Identificador (SHA-256): {document.file_hash}\n\n"
            f"Por motivos de confidencialidad y seguridad, el documento deja de estar accesible en la plataforma tras su entrega. "
            f"Si precisa una copia, por favor solicítela directamente a dicha dirección.\n\n"
            f"Atentamente,\n"
            f"Servicio de Entrega Segura - Arcamitte"
        )

        dispatch_email(
            subject=_("Información sobre su solicitud: Documento '%(filename)s'")
            % {"filename": doc_name},
            message=post_consume_message,
            from_email=getattr(
                settings, "DEFAULT_FROM_EMAIL", "no-reply@arcamitte.local"
            ),
            recipient_list=[normalized_email],
            fail_silently=True,
        )

        DocumentAccessLog.objects.create(
            document=document,
            email=normalized_email,
            action=DocumentAccessLog.Action.INTENTO_POST_CONSUMO,
            origin_uo=document.origin_uo,
            target_uo=document.target_uo,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        return True, GENERIC_ACCESS_MESSAGE

    # Caso 2: Política ALL_RECIPIENTS y el destinatario ya descargó su copia individual
    if (
        document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
        and document.is_email_consumed(normalized_email)
    ):
        DocumentAccessLog.objects.create(
            document=document,
            email=normalized_email,
            action=DocumentAccessLog.Action.INTENTO_POST_CONSUMO,
            origin_uo=document.origin_uo,
            target_uo=document.target_uo,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
        desc_part = (
            f"• Descripción: {document.description}\n" if document.description else ""
        )
        dispatch_email(
            subject=_("Aviso: Copia ya descargada de '%(filename)s'")
            % {"filename": doc_name},
            message=(
                f"Estimado/a usuario/a,\n\n"
                f"Le comunicamos que su dirección de correo ya ha descargado previamente este documento.\n\n"
                f"DATOS DEL DOCUMENTO:\n"
                f"• Archivo: {doc_name}\n"
                f"{desc_part}"
                f"• Identificador (SHA-256): {document.file_hash}\n\n"
                f"Por motivos de seguridad, cada destinatario autorizado dispone de una única descarga. "
                f"Si necesita volver a consultar el archivo, por favor revise sus descargas locales o contacte con el remitente.\n\n"
                f"Atentamente,\n"
                f"Servicio de Entrega Segura - Arcamitte"
            ),
            from_email=getattr(
                settings, "DEFAULT_FROM_EMAIL", "no-reply@arcamitte.local"
            ),
            recipient_list=[normalized_email],
            fail_silently=True,
        )
        return True, GENERIC_ACCESS_MESSAGE

    # Caso 3: Documento activo y correo en lista blanca
    if document.is_email_authorized(normalized_email):
        AccessVerificationToken.objects.filter(
            document=document,
            email=normalized_email,
            is_used=False,
        ).update(is_used=True)

        otp_code = "".join(secrets.choice("0123456789") for _ in range(6))
        expires_at = timezone.now() + timezone.timedelta(minutes=15)

        AccessVerificationToken.objects.create(
            document=document,
            email=normalized_email,
            otp_code=otp_code,
            expires_at=expires_at,
            is_used=False,
            failed_attempts=0,
        )

        try:
            redeem_path = reverse("arcamitte:redeem-otp")
        except Exception:
            redeem_path = "/arcamitte/canjear/"

        query_params = f"?hash={document.file_hash}&email={normalized_email}"
        redeem_url = (
            f"{base_url.rstrip('/')}{redeem_path}{query_params}"
            if base_url
            else f"{redeem_path}{query_params}"
        )

        policy_note = (
            "El documento permanecerá disponible hasta que todos los destinatarios autorizados hayan completado su descarga."
            if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
            else "Por motivos de seguridad y confidencialidad, el documento dejará de estar disponible una vez completada la primera descarga."
        )

        doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
        desc_part = (
            f"• Descripción: {document.description}\n" if document.description else ""
        )
        email_subject = _("Código de verificación para '%(filename)s' - Arcamitte") % {
            "filename": doc_name
        }
        email_body = (
            f"Estimado/a usuario/a,\n\n"
            f"Ha solicitado el acceso al siguiente documento:\n"
            f"• Archivo: {doc_name}\n"
            f"{desc_part}"
            f"• Identificador (SHA-256):\n"
            f"  {document.file_hash}\n\n"
            f"Su código de verificación temporal es:\n"
            f"{otp_code}\n\n"
            f"Validez: 15 minutos (máximo 3 intentos permitidos).\n\n"
            f"Puede acceder directamente a la descarga a través del siguiente enlace:\n"
            f"{redeem_url}\n\n"
            f"Aviso de seguridad:\n"
            f"{policy_note}\n\n"
            f"Atentamente,\n"
            f"Servicio de Entrega Segura - Arcamitte"
        )

        dispatch_email(
            subject=email_subject,
            message=email_body,
            from_email=getattr(
                settings, "DEFAULT_FROM_EMAIL", "no-reply@arcamitte.local"
            ),
            recipient_list=[normalized_email],
            fail_silently=False,
        )

        DocumentAccessLog.objects.create(
            document=document,
            email=normalized_email,
            action=DocumentAccessLog.Action.OTP_ENVIADO,
            origin_uo=document.origin_uo,
            target_uo=document.target_uo,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        return True, GENERIC_ACCESS_MESSAGE

    # Correo no autorizado: PBKDF2 simulado y respuesta neutra
    hashlib.pbkdf2_hmac(
        "sha256",
        normalized_email.encode("utf-8"),
        b"arcamitte_timing_salt",
        TIMING_ATTACK_PBKDF2_ITERATIONS,
    )
    return True, GENERIC_ACCESS_MESSAGE


def generate_corporate_email_text(
    document: EncryptedDocument, base_url: str | None = None
) -> str:
    """
    Genera el texto formal para notificar al destinatario,
    incluyendo nombre del archivo, descripción, identificador SHA-256 e instrucciones de acceso.
    """
    url_root = (
        base_url or getattr(settings, "ARCAMITTE_BASE_URL", "http://127.0.0.1:8000")
    ).rstrip("/")
    solicitar_url = f"{url_root}/arcamitte/solicitar/?hash={document.file_hash}"
    policy_desc = (
        "El documento permanecerá disponible en la plataforma hasta que todos los destinatarios autorizados hayan completado su descarga."
        if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
        else "Por motivos de seguridad y confidencialidad, el documento dejará de estar disponible una vez completada la primera descarga."
    )
    desc_part = (
        f"\n• Descripción: {document.description}" if document.description else ""
    )

    return (
        f"Estimado/a destinatario/a,\n\n"
        f"Le informamos de que se ha puesto a su disposición el siguiente documento para su descarga segura a través de Arcamitte:\n\n"
        f"DATOS DEL DOCUMENTO:\n"
        f"• Nombre del archivo: {document.original_filename}"
        f"{desc_part}\n"
        f"• Identificador (Hash SHA-256):\n"
        f"  {document.file_hash}\n\n"
        f"INSTRUCCIONES DE DESCARGA:\n"
        f"1. Acceda al siguiente enlace para iniciar la descarga:\n"
        f"   {solicitar_url}\n"
        f"2. Indique su dirección de correo electrónico para recibir un código de verificación temporal.\n"
        f"3. Introduzca el código recibido en la pasarela para descargar el archivo.\n\n"
        f"AVISO DE SEGURIDAD:\n"
        f"{policy_desc}\n\n"
        f"Atentamente,\n"
        f"Servicio de Entrega Segura - Arcamitte"
    )


def consume_document_with_otp(
    file_hash: str,
    email: str,
    entered_otp: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[bool, bytes, str, str]:
    """
    Servicio de canje, descifrado en memoria y gestión de política destructiva por OTP.
    Aplica política BurnPolicy.FIRST_ACCESS o BurnPolicy.ALL_RECIPIENTS.
    """
    clean_hash = (file_hash or "").strip().lower()
    clean_email = (email or "").strip().lower()
    clean_otp = (entered_otp or "").strip()

    token = (
        AccessVerificationToken.objects.select_related("document")
        .filter(
            document__file_hash__iexact=clean_hash,
            email__iexact=clean_email,
            is_used=False,
        )
        .order_by("-created_at")
        .first()
    )

    if not token or not token.is_valid():
        return (
            False,
            b"",
            "",
            _("El código de verificación no es válido o ha expirado."),
        )

    document = token.document

    # Comprobación de caducidad del asiento
    if not document.is_consumed and document.is_expired():
        check_and_expire_document(document, client_ip=client_ip, user_agent=user_agent)
        token.is_used = True
        token.save(update_fields=["is_used"])
        return (
            False,
            b"",
            "",
            _(
                "El plazo de disponibilidad de este documento ha expirado y el archivo ha sido retirado de la plataforma."
            ),
        )

    if document.is_consumed:
        token.is_used = True
        token.save(update_fields=["is_used"])
        return (
            False,
            b"",
            "",
            _("El documento ya no se encuentra disponible para su descarga."),
        )

    if (
        document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
        and document.is_email_consumed(token.email)
    ):
        token.is_used = True
        token.save(update_fields=["is_used"])
        return (
            False,
            b"",
            "",
            _(
                "Usted ya ha descargado este documento con anterioridad. Cada destinatario dispone de un único acceso."
            ),
        )

    is_match = secrets.compare_digest(
        token.otp_code.encode("utf-8"), clean_otp.encode("utf-8")
    )

    if not is_match:
        token.register_failed_attempt()
        if token.failed_attempts >= 3:
            DocumentAccessLog.objects.create(
                document=document,
                email=token.email,
                action=DocumentAccessLog.Action.OTP_INVALIDO_BLOQUEADO,
                origin_uo=document.origin_uo,
                target_uo=document.target_uo,
                ip_address=client_ip,
                user_agent=user_agent,
            )
            return (
                False,
                b"",
                "",
                _(
                    "Ha superado el número máximo de intentos permitidos. El acceso ha sido bloqueado por seguridad."
                ),
            )
        else:
            remaining = 3 - token.failed_attempts
            return (
                False,
                b"",
                "",
                _(
                    "Código de verificación incorrecto. Intentos restantes: %(remaining)d."
                )
                % {"remaining": remaining},
            )

    try:
        with transaction.atomic():
            token.is_used = True
            token.save(update_fields=["is_used"])

            engine = get_fernet_engine()
            dek_bytes = engine.decrypt(document.encrypted_dek.encode("utf-8"))

            if not document.encrypted_file:
                return (
                    False,
                    b"",
                    "",
                    _("El archivo cifrado no está disponible en el servidor."),
                )

            document.encrypted_file.seek(0)
            encrypted_file_bytes = document.encrypted_file.read()
            document.encrypted_file.close()

            dek_fernet = Fernet(dek_bytes)
            decrypted_bytes = dek_fernet.decrypt(encrypted_file_bytes)

            consumed_list = list(document.consumed_recipients or [])
            if token.email not in [
                e.strip().lower() for e in consumed_list if isinstance(e, str)
            ]:
                consumed_list.append(token.email)
            document.consumed_recipients = consumed_list

            should_burn = False
            if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
                if document.are_all_recipients_consumed():
                    should_burn = True
                    document.consumed_by = f"todos los destinatarios autorizados ({len(consumed_list)}/{len(document.allowed_emails)})"
                else:
                    should_burn = False
                    document.consumed_by = (
                        f"Parcial: {len(consumed_list)}/{len(document.allowed_emails)}"
                    )
            else:
                should_burn = True
                document.consumed_by = token.email

            if should_burn:
                shred_and_delete_file(document.encrypted_file)
                document.is_consumed = True
                document.consumed_at = timezone.now()
                document.save(
                    update_fields=[
                        "is_consumed",
                        "consumed_by",
                        "consumed_at",
                        "consumed_recipients",
                    ]
                )
                log_action = DocumentAccessLog.Action.DESCIFRADO_EXITOSO_BURN
                logger.info(
                    f"[ARCAMITTE AUDIT] Destrucción física final completada para documento {document.file_hash[:12]}... por {token.email}."
                )
            else:
                document.save(update_fields=["consumed_by", "consumed_recipients"])
                log_action = DocumentAccessLog.Action.DESCIFRADO_PARCIAL_PRESERVADO
                logger.info(
                    f"[ARCAMITTE AUDIT] Descifrado parcial preservado para documento {document.file_hash[:12]}... por {token.email}."
                )

            DocumentAccessLog.objects.create(
                document=document,
                email=token.email,
                action=log_action,
                origin_uo=document.origin_uo,
                target_uo=document.target_uo,
                ip_address=client_ip,
                user_agent=user_agent,
            )

        # ----------------------------------------------------------------------
        # FASE B: Marca de Agua Forense Dinámica (Dynamic Forensic PDF Watermarking)
        # Inyecta destinatario, IP, timestamp UTC y huella criptográfica en cada página
        # ----------------------------------------------------------------------
        if getattr(settings, "ARCAMITTE_WATERMARK_ENABLED", True) and (
            document.original_filename.lower().endswith(".pdf")
            or decrypted_bytes.startswith(b"%PDF")
        ):
            from arcamitte.watermark import apply_pdf_watermark

            try:
                decrypted_bytes = apply_pdf_watermark(
                    pdf_content=decrypted_bytes,
                    recipient_email=token.email,
                    client_ip=client_ip or "0.0.0.0",
                    doc_hash=document.file_hash,
                )
                DocumentAccessLog.objects.create(
                    document=document,
                    email=token.email,
                    action=DocumentAccessLog.Action.MARCA_AGUA_APLICADA,
                    details="Marca de agua forense inyectada en descarga con OTP.",
                    origin_uo=document.origin_uo,
                    target_uo=document.target_uo,
                    ip_address=client_ip,
                    user_agent=user_agent,
                )
            except Exception as wm_exc:
                logger.warning(
                    f"[WATERMARK] Fallo al aplicar marca forense a {document.file_hash[:12]}: {wm_exc}"
                )

        return (
            True,
            decrypted_bytes,
            document.original_filename,
            _("Documento descifrado con éxito."),
        )

    except Exception as exc:
        logger.error(
            f"[ARCAMITTE ERROR] Fallo durante descifrado y canje del documento: {exc}"
        )
        return (
            False,
            b"",
            "",
            _("Se produjo un error al procesar el descifrado del documento."),
        )


def check_and_auto_close_if_file_missing(
    document: EncryptedDocument,
    user_identifier: str = "sistema@arcamitte.local",
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> bool:
    """
    Verifica la existencia física del archivo cifrado en disco.
    Si el archivo no se encuentra y el documento aún figura como activo o no consumido,
    clausura formalmente el asiento (is_active=False, is_consumed=True) y levanta
    una vicisitud inmutable de auditoría en DocumentAccessLog.

    Retorna True si el archivo existe en disco; False si no existe (y se clausuró).
    """
    file_exists = False
    if document.encrypted_file:
        try:
            file_exists = os.path.exists(document.encrypted_file.path)
        except Exception:
            file_exists = False

    if not file_exists and (document.is_active or not document.is_consumed):
        document.is_consumed = True
        if not document.consumed_at:
            document.consumed_at = timezone.now()
        document.save(update_fields=["is_consumed", "consumed_at"])

        action = (
            DocumentAccessLog.Action.CADUCIDAD_AUTOMATICA
            if document.is_expired()
            else DocumentAccessLog.Action.FINALIZACION_MANUAL
        )
        DocumentAccessLog.objects.create(
            document=document,
            email=user_identifier or "sistema@arcamitte.local",
            action=action,
            details=_(
                "Cierre automático del asiento: el archivo físico cifrado ya no se encuentra en el almacenamiento seguro (retirada física consumada)."
            ),
            origin_uo=document.origin_uo,
            target_uo=document.target_uo,
            ip_address=client_ip or "127.0.0.1",
            user_agent=user_agent or "Arcamitte-Integrity-Guard",
        )
        logger.warning(
            f"[ARCAMITTE INTEGRITY] Asiento {document.file_hash[:12]} clausurado automáticamente: "
            f"el archivo físico cifrado no existe en almacenamiento seguro."
        )

    return file_exists


def admin_decrypt_document(
    document: EncryptedDocument,
    admin_user: Any = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[bool, bytes, str, str]:
    """
    Descarga de auditoría administrativa preservada:
    Permite al personal de auditoría descargar una copia descifrada mientras el documento
    NO haya sido consumido, SIN destruir el archivo ni marcar is_consumed = True.
    """
    file_present = check_and_auto_close_if_file_missing(
        document=document,
        user_identifier=getattr(admin_user, "email", None)
        or getattr(admin_user, "username", "admin"),
        client_ip=client_ip,
        user_agent=user_agent,
    )
    if not file_present:
        return (
            False,
            b"",
            "",
            _(
                "El archivo físico no se encuentra disponible en almacenamiento seguro. El asiento ha sido clausurado con constancia de vicisitud."
            ),
        )

    if document.is_consumed:
        return (
            False,
            b"",
            "",
            _("El documento ya ha sido consumido y destruido del servidor."),
        )

    if not document.encrypted_file:
        return False, b"", "", _("El archivo cifrado no está disponible.")

    if (
        admin_user
        and hasattr(admin_user, "is_authenticated")
        and admin_user.is_authenticated
        and not is_global_admin(admin_user)
    ):
        user_auditor_uos = list(
            UserUOMembership.objects.filter(
                user=admin_user,
                is_active=True,
                role__in=[UserUOMembership.Role.AUDITOR, UserUOMembership.Role.ADMIN],
            ).values_list("uo_id", flat=True)
        )
        is_origin_auditor = bool(
            document.origin_uo_id and document.origin_uo_id in user_auditor_uos
        )
        is_target_auditor = bool(
            document.target_uo_id and document.target_uo_id in user_auditor_uos
        )
        is_uploader = bool(
            document.uploaded_by_id
            and document.uploaded_by_id == getattr(admin_user, "id", None)
        )
        is_standalone_without_uo = (
            not document.origin_uo_id and not document.target_uo_id
        )

        is_authorized = (
            is_origin_auditor
            or is_target_auditor
            or (bool(user_auditor_uos) and is_uploader)
            or (document.origin_uo_id is None and is_uploader)
            or is_standalone_without_uo
        )

        if not is_authorized:
            return (
                False,
                b"",
                "",
                _("No tiene permisos de auditoría en la UO asociada a este documento."),
            )

    try:
        engine = get_fernet_engine()
        dek_bytes = engine.decrypt(document.encrypted_dek.encode("utf-8"))

        document.encrypted_file.seek(0)
        ciphertext = document.encrypted_file.read()

        dek_fernet = Fernet(dek_bytes)
        decrypted_bytes = dek_fernet.decrypt(ciphertext)

        admin_identifier = (
            getattr(admin_user, "email", None)
            or getattr(admin_user, "username", None)
            or str(admin_user or "admin_auditor")
        )

        DocumentAccessLog.objects.create(
            document=document,
            email=admin_identifier,
            action=DocumentAccessLog.Action.ADMIN_DESCARGA_PRESERVADA,
            details=f"Descarga de auditoría legal preservada realizada por '{admin_identifier}'.",
            origin_uo=document.origin_uo,
            target_uo=document.target_uo,
            ip_address=client_ip,
            user_agent=user_agent,
        )

        logger.info(
            f"[ARCAMITTE AUDIT] Descarga administrativa preservada realizada por '{admin_identifier}' "
            f"para documento {document.file_hash[:12]}..."
        )

        # ----------------------------------------------------------------------
        # FASE B: Marca de Agua Forense Dinámica en Descarga de Auditoría
        # ----------------------------------------------------------------------
        if getattr(settings, "ARCAMITTE_WATERMARK_ENABLED", True) and (
            document.original_filename.lower().endswith(".pdf")
            or decrypted_bytes.startswith(b"%PDF")
        ):
            from arcamitte.watermark import apply_pdf_watermark

            try:
                decrypted_bytes = apply_pdf_watermark(
                    pdf_content=decrypted_bytes,
                    recipient_email=f"AUDITOR:{admin_identifier}",
                    client_ip=client_ip or "0.0.0.0",
                    doc_hash=document.file_hash,
                )
                DocumentAccessLog.objects.create(
                    document=document,
                    email=admin_identifier,
                    action=DocumentAccessLog.Action.MARCA_AGUA_APLICADA,
                    details=f"Marca de agua forense inyectada en descarga administrativa por '{admin_identifier}'.",
                    origin_uo=document.origin_uo,
                    target_uo=document.target_uo,
                    ip_address=client_ip,
                    user_agent=user_agent,
                )
            except Exception as wm_exc:
                logger.warning(
                    f"[WATERMARK] Fallo al aplicar marca forense a {document.file_hash[:12]}: {wm_exc}"
                )

        return (
            True,
            decrypted_bytes,
            document.original_filename,
            _("Descarga de auditoría completada."),
        )

    except Exception as exc:
        logger.error(
            f"[ARCAMITTE ERROR] Error en descarga de auditoría administrativa: {exc}"
        )
        return False, b"", "", _("Error al descifrar el documento para auditoría.")


decrypt_document_for_audit = admin_decrypt_document


def admin_download_and_burn_document(
    document: EncryptedDocument,
    admin_user: Any = None,
    reason: str = "",
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[bool, bytes, str, str]:
    """
    Descarga de entrega y clausura definitiva del asiento documental (Consumo Destructivo):
    Descifra el archivo aplicando la marca de agua forense, destruye físicamente el binario
    del almacenamiento seguro en disco (shred_and_delete_file) y finaliza el asiento con
    constancia legal de vicisitud y justificación legal (ENS ALTO / NIST SP 800-88).
    """
    if document.is_consumed:
        return (
            False,
            b"",
            "",
            _("El documento ya ha sido consumido y destruido del servidor."),
        )

    if not document.encrypted_file:
        return False, b"", "", _("El archivo cifrado no está disponible.")

    # Control de autorización (Superusuario o personal de la UO)
    if (
        admin_user
        and hasattr(admin_user, "is_authenticated")
        and admin_user.is_authenticated
        and not is_global_admin(admin_user)
    ):
        user_admin_uos = list(
            UserUOMembership.objects.filter(
                user=admin_user,
                is_active=True,
                role__in=[
                    UserUOMembership.Role.ADMIN,
                    UserUOMembership.Role.AUDITOR,
                    UserUOMembership.Role.OPERATOR,
                ],
            ).values_list("uo_id", flat=True)
        )
        is_origin_member = bool(
            document.origin_uo_id and document.origin_uo_id in user_admin_uos
        )
        is_uploader = bool(
            document.uploaded_by_id
            and document.uploaded_by_id == getattr(admin_user, "id", None)
        )
        if not (
            is_origin_member
            or is_uploader
            or (not document.origin_uo_id and not document.target_uo_id)
        ):
            return (
                False,
                b"",
                "",
                _("No tiene autorización para clausurar este asiento documental."),
            )

    try:
        engine = get_fernet_engine()
        dek_bytes = engine.decrypt(document.encrypted_dek.encode("utf-8"))

        document.encrypted_file.seek(0)
        ciphertext = document.encrypted_file.read()

        dek_fernet = Fernet(dek_bytes)
        decrypted_bytes = dek_fernet.decrypt(ciphertext)

        admin_identifier = (
            getattr(admin_user, "email", None)
            or getattr(admin_user, "username", None)
            or str(admin_user or "admin_operador")
        )

        # Aplicar marca de agua forense si es PDF
        if getattr(settings, "ARCAMITTE_WATERMARK_ENABLED", True) and (
            document.original_filename.lower().endswith(".pdf")
            or decrypted_bytes.startswith(b"%PDF")
        ):
            from arcamitte.watermark import apply_pdf_watermark

            try:
                decrypted_bytes = apply_pdf_watermark(
                    pdf_content=decrypted_bytes,
                    recipient_email=f"CIERRE:{admin_identifier}",
                    client_ip=client_ip or "0.0.0.0",
                    doc_hash=document.file_hash,
                )
            except Exception as wm_exc:
                logger.warning(
                    f"[WATERMARK] Fallo al aplicar marca forense en clausura a {document.file_hash[:12]}: {wm_exc}"
                )

        # Destrucción física inmediata del archivo en disco
        shred_and_delete_file(document.encrypted_file)
        document.encrypted_file = None
        document.is_consumed = True
        document.consumed_at = timezone.now()
        document.consumed_by = admin_identifier
        document.save(
            update_fields=[
                "encrypted_file",
                "is_consumed",
                "consumed_at",
                "consumed_by",
                "updated_at",
            ]
        )

        details_text = (
            f"Asiento documental clausurado y descargado por '{admin_identifier}'. "
            f"Archivo físico destruido con borrado seguro NIST SP 800-88. Motivo legal: {reason or 'Clausura de asiento y entrega segura'}"
        )

        DocumentAccessLog.objects.create(
            document=document,
            email=admin_identifier,
            action=DocumentAccessLog.Action.FINALIZACION_MANUAL,
            details=details_text,
            origin_uo=document.origin_uo,
            target_uo=document.target_uo,
            ip_address=client_ip,
            user_agent=user_agent,
        )

        logger.info(
            f"[ARCAMITTE AUDIT] Descarga con clausura y destrucción física completada para {document.file_hash[:12]}... por {admin_identifier}."
        )
        return (
            True,
            decrypted_bytes,
            document.original_filename,
            _("Asiento documental clausurado y archivo descargado con éxito."),
        )

    except Exception as exc:
        logger.error(
            f"[ARCAMITTE ERROR] Error durante la clausura y descarga del documento: {exc}"
        )
        return (
            False,
            b"",
            "",
            _("Error al procesar la clausura y descarga del documento."),
        )


ROLE_PERMISSIONS_MAP: dict[str, list[str]] = {
    UserUOMembership.Role.OPERATOR: [
        "view_encrypteddocument",
        "add_encrypteddocument",
        "change_encrypteddocument",
        "view_documentaccesslog",
        "view_organizationalunit",
    ],
    UserUOMembership.Role.AUDITOR: [
        "view_encrypteddocument",
        "add_encrypteddocument",
        "change_encrypteddocument",
        "can_audit_download",
        "view_documentaccesslog",
        "view_organizationalunit",
        "view_accessverificationtoken",
    ],
    UserUOMembership.Role.ADMIN: [
        "view_encrypteddocument",
        "add_encrypteddocument",
        "change_encrypteddocument",
        "delete_encrypteddocument",
        "can_audit_download",
        "view_documentaccesslog",
        "delete_documentaccesslog",
        "view_accessverificationtoken",
        "delete_accessverificationtoken",
        "view_organizationalunit",
        "change_organizationalunit",
    ],
}


def sync_user_role_permissions(user: Any, role: str | None = None) -> list[str]:
    """
    Sincroniza y asigna los permisos y grupos de Django nativos correspondientes
    a las membresías activas del usuario en Unidades Organizativas (OPERATOR, AUDITOR, ADMIN).
    Garantiza que el usuario tenga acceso a las secciones del panel administrativo según su rol.
    """
    if not user or is_global_admin(user):
        return []

    from django.contrib.auth.models import Group, Permission

    user_roles = set()
    if role:
        user_roles.add(role)
    memberships = UserUOMembership.objects.filter(user=user, is_active=True)
    for m in memberships:
        user_roles.add(m.role)

    if not user_roles:
        user_roles.add(UserUOMembership.Role.OPERATOR)

    assigned_codenames = set()
    for r in user_roles:
        group_name = f"Arcamitte_{r}"
        group, _ = Group.objects.get_or_create(name=group_name)

        role_perms = ROLE_PERMISSIONS_MAP.get(r, [])
        group_permissions = list(
            Permission.objects.filter(
                content_type__app_label="arcamitte",
                codename__in=role_perms,
            )
        )
        group.permissions.set(group_permissions)
        user.groups.add(group)
        assigned_codenames.update(role_perms)

    # Asignar permisos directos en el usuario para resolución garantizada en sesión
    direct_permissions = list(
        Permission.objects.filter(
            content_type__app_label="arcamitte",
            codename__in=assigned_codenames,
        )
    )
    user.user_permissions.add(*direct_permissions)

    return list(assigned_codenames)


def process_batch_import_json(data: Any) -> tuple[int, int, list[str]]:
    """
    Importa masivamente Unidades Organizativas y Usuarios desde un diccionario JSON estructurado.
    Formato esperado:
    {
        "organizational_units": [
            {
                "numeric_code": 1001,
                "alias": "RRHH",
                "name": "Dirección de Recursos Humanos",
                "email": "rrhh@empresa.com",
                "description": "Gestión de personal y talento",
                "is_active": true
            }
        ],
        "users": [
            {
                "username": "mgarcia",
                "email": "mgarcia@empresa.com",
                "first_name": "María",
                "last_name": "García",
                "role": "ADMIN",
                "uo_alias": "RRHH",
                "is_global_admin": false,
                "is_mfa_enforced": false,
                "password": "PasswordOpcional123"
            }
        ]
    }
    """
    if not isinstance(data, dict):
        raise ValidationError(
            _("El contenido JSON debe ser un objeto/diccionario raíz.")
        )

    uo_list = data.get("organizational_units", [])
    user_list = data.get("users", [])

    if not isinstance(uo_list, list) or not isinstance(user_list, list):
        raise ValidationError(
            _("'organizational_units' y 'users' deben ser listas JSON.")
        )

    uos_processed = 0
    users_processed = 0
    feedback_notes = []

    User = get_user_model()

    with transaction.atomic():
        # 1. Procesar Unidades Organizativas
        for uo_data in uo_list:
            if not isinstance(uo_data, dict):
                raise ValidationError(
                    _("Cada entrada en 'organizational_units' debe ser un objeto JSON.")
                )
            code = uo_data.get("numeric_code")
            alias = (uo_data.get("alias") or "").strip().upper()
            name = (uo_data.get("name") or "").strip()
            email = (uo_data.get("email") or "").strip().lower()
            description = (uo_data.get("description") or "").strip()
            uo_is_active = bool(uo_data.get("is_active", True))

            if not code or not alias or not name or not email:
                raise ValidationError(
                    _(
                        "Cada UO debe incluir obligatoriamente 'numeric_code', 'alias', 'name' y 'email'. Entrada inválida: %(data)s"
                    )
                    % {"data": uo_data}
                )

            try:
                code_int = int(code)
            except (ValueError, TypeError):
                raise ValidationError(
                    _(
                        "El campo 'numeric_code' en UO '%(alias)s' debe ser un número entero válido: %(code)s"
                    )
                    % {"alias": alias, "code": code}
                )

            clean_email = validate_safe_email(email)

            uo, created = OrganizationalUnit.objects.update_or_create(
                numeric_code=code_int,
                defaults={
                    "alias": alias,
                    "name": name,
                    "email": clean_email,
                    "description": description,
                    "is_active": uo_is_active,
                },
            )
            uos_processed += 1
            action_desc = "creada" if created else "actualizada"
            feedback_notes.append(
                f"UO [{uo.numeric_code}] {uo.alias} {action_desc} exitosamente."
            )

        # 2. Procesar Usuarios, Membresías y Gobernanza
        for u_data in user_list:
            if not isinstance(u_data, dict):
                raise ValidationError(
                    _("Cada entrada en 'users' debe ser un objeto JSON.")
                )
            username = (u_data.get("username") or "").strip()
            email = (u_data.get("email") or "").strip().lower()
            first_name = (u_data.get("first_name") or "").strip()
            last_name = (u_data.get("last_name") or "").strip()
            user_is_active = bool(u_data.get("is_active", True))

            is_global_admin_flag = bool(u_data.get("is_global_admin", False))
            is_mfa_enforced_flag = bool(u_data.get("is_mfa_enforced", False))
            must_change_pwd_param = u_data.get("must_change_password")

            raw_role = (
                (u_data.get("role") or UserUOMembership.Role.OPERATOR).strip().upper()
            )
            if raw_role == "OPERADOR":
                raw_role = UserUOMembership.Role.OPERATOR
            elif raw_role in ("ADMINISTRADOR", "ADMIN_UO"):
                raw_role = UserUOMembership.Role.ADMIN

            uo_alias = (u_data.get("uo_alias") or "").strip().upper()
            uo_code = u_data.get("uo_numeric_code") or u_data.get("uo_code")
            memberships_data = u_data.get("memberships")
            raw_password = u_data.get("password")

            if not username or not email:
                raise ValidationError(
                    _(
                        "Cada usuario debe incluir obligatoriamente 'username' y 'email'. Entrada inválida: %(data)s"
                    )
                    % {"data": u_data}
                )

            clean_email = validate_safe_email(email)

            # Resolver lista de UOs a vincular (soporta formato plano y lista 'memberships')
            memberships_to_process = []
            if memberships_data and isinstance(memberships_data, list):
                for m_item in memberships_data:
                    if isinstance(m_item, dict):
                        m_alias = (m_item.get("uo_alias") or "").strip().upper()
                        m_code = m_item.get("uo_code") or m_item.get("uo_numeric_code")
                        m_role = (m_item.get("role") or UserUOMembership.Role.OPERATOR).strip().upper()
                        if m_role == "OPERADOR":
                            m_role = UserUOMembership.Role.OPERATOR
                        elif m_role in ("ADMINISTRADOR", "ADMIN_UO"):
                            m_role = UserUOMembership.Role.ADMIN
                        memberships_to_process.append((m_alias, m_code, m_role))
            elif uo_alias or uo_code:
                memberships_to_process.append((uo_alias, uo_code, raw_role))

            # Para usuarios departamentales es obligatorio al menos una UO
            if not is_global_admin_flag and not memberships_to_process:
                raise ValidationError(
                    _(
                        "El usuario departamental '%(username)s' requiere asignar 'uo_alias' o 'uo_numeric_code'."
                    )
                    % {"username": username}
                )

            # Resolver objetos UO
            target_memberships = []
            for m_alias, m_code, m_role in memberships_to_process:
                target_uo = None
                if m_alias:
                    target_uo = OrganizationalUnit.objects.filter(alias=m_alias).first()
                if not target_uo and m_code:
                    try:
                        target_uo = OrganizationalUnit.objects.filter(
                            numeric_code=int(m_code)
                        ).first()
                    except (ValueError, TypeError):
                        target_uo = None

                if not target_uo:
                    raise ValidationError(
                        _(
                            "No se encontró la UO '%(uo)s' asociada al usuario '%(username)s'. Debe definirse previamente."
                        )
                        % {"uo": m_alias or m_code, "username": username}
                    )

                role = (
                    m_role
                    if m_role in UserUOMembership.Role.values
                    else UserUOMembership.Role.OPERATOR
                )
                target_memberships.append((target_uo, role))

            # Desacoplamiento total de Django Admin:
            # Los privilegios se gestionan exclusivamente mediante is_global_admin y roles UO
            user = User.objects.filter(username=username).first()
            user_created = False
            must_change = False
            password_to_record = None

            if not user:
                user = User(
                    username=username,
                    email=clean_email,
                    first_name=first_name,
                    last_name=last_name,
                    is_active=user_is_active,
                    is_staff=False,
                    is_superuser=False,
                )
                if raw_password:
                    if not user.check_password(raw_password):
                        validate_password(raw_password, user=user)
                        user.set_password(raw_password)
                        password_to_record = raw_password
                        must_change = (
                            bool(must_change_pwd_param)
                            if must_change_pwd_param is not None
                            else False
                        )
                else:
                    auto_pass = generate_secure_temporary_password(length=14)
                    validate_password(auto_pass, user=user)
                    user.set_password(auto_pass)
                    password_to_record = auto_pass
                    must_change = (
                        bool(must_change_pwd_param)
                        if must_change_pwd_param is not None
                        else True
                    )
                user.save()
                user_created = True
            else:
                user.email = clean_email
                if first_name:
                    user.first_name = first_name
                if last_name:
                    user.last_name = last_name
                user.is_active = user_is_active
                user.is_staff = False
                user.is_superuser = False
                if raw_password:
                    if not user.check_password(raw_password):
                        validate_password(raw_password, user=user)
                        user.set_password(raw_password)
                        password_to_record = raw_password
                        must_change = (
                            bool(must_change_pwd_param)
                            if must_change_pwd_param is not None
                            else False
                        )
                user.save()

            # Sincronizar directivas de UserProfile
            profile = get_or_create_user_profile(user)
            profile.is_global_admin = is_global_admin_flag
            profile.is_mfa_enforced = is_mfa_enforced_flag
            if must_change_pwd_param is not None or user_created:
                profile.must_change_password = must_change

            profile.save(
                update_fields=[
                    "is_global_admin",
                    "is_mfa_enforced",
                    "must_change_password",
                    "updated_at",
                ]
            )

            if password_to_record:
                record_password_change(user, password_to_record)
                if must_change_pwd_param is not None:
                    profile.must_change_password = bool(must_change_pwd_param)
                    profile.save(update_fields=["must_change_password"])

            # Procesar membresías de UO
            for target_uo, role in target_memberships:
                UserUOMembership.objects.update_or_create(
                    user=user,
                    uo=target_uo,
                    defaults={"role": role, "is_active": True},
                )
                sync_user_role_permissions(user, role)

            users_processed += 1
            action_desc = "creado" if user_created else "actualizado"
            uo_info = (
                ", ".join(f"{t[0].alias} ({t[1]})" for t in target_memberships)
                if target_memberships
                else "Administrador Global (sin UO departamental)"
            )
            feedback_notes.append(
                f"Usuario '{username}' ({clean_email}) {action_desc}: {uo_info}."
            )

    return uos_processed, users_processed, feedback_notes


def generate_secure_temporary_password(length: int = 14) -> str:
    """
    Genera una contraseña temporal criptográficamente robusta utilizando secrets.
    Garantiza la presencia de caracteres en mayúsculas, minúsculas, dígitos y símbolos.
    """
    import string

    length = max(length, 10)

    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%&*+-_="

    pwd_chars = [
        secrets.choice(upper),
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(digits),
        secrets.choice(symbols),
        secrets.choice(symbols),
    ]

    all_chars = upper + lower + digits + symbols
    for _idx in range(length - len(pwd_chars)):
        pwd_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(pwd_chars)
    return "".join(pwd_chars)


def reset_user_password_and_notify(
    user: Any, requested_by: Any = None
) -> tuple[bool, str]:
    """
    Restablece la contraseña de un usuario a una clave temporal generada aleatoriamente,
    activa la exigencia de cambio en el primer acceso (must_change_password = True)
    y remite la credencial temporal a la dirección de correo del usuario.
    """
    if not user or not getattr(user, "is_active", False):
        return False, str(_("El usuario no existe o se encuentra inactivo."))

    if not getattr(user, "email", None):
        return False, str(_("El usuario no tiene una dirección de correo configurada."))

    temp_password = generate_secure_temporary_password(length=14)
    try:
        validate_password(temp_password, user=user)
    except ValidationError:
        pass
    user.set_password(temp_password)
    user.save(update_fields=["password"])

    profile = get_or_create_user_profile(user)
    profile.must_change_password = True
    profile.save(update_fields=["must_change_password", "updated_at"])

    subject = str(_("[Arcamitte] Credenciales de acceso temporal y cambio obligatorio"))
    full_name = user.get_full_name() or user.username
    message = (
        f"Estimado/a {full_name},\n\n"
        f"Se ha generado una clave de acceso temporal para su cuenta en la plataforma Arcamitte.\n\n"
        f"DATOS DE ACCESO TEMPORAL:\n"
        f"• Usuario: {user.username}\n"
        f"• Contraseña temporal: {temp_password}\n\n"
        f"INSTRUCCIONES DE SEGURIDAD:\n"
        f"1. Inicie sesión en la plataforma utilizando estas credenciales temporales.\n"
        f"2. El sistema le exigirá de forma obligatoria establecer una nueva contraseña personal y segura en su primer acceso.\n"
        f"3. Esta clave temporal no debe ser compartida con terceros.\n\n"
        f"Atentamente,\n"
        f"Seguridad y Gobernanza de Acceso - Arcamitte"
    )

    dispatch_email(
        subject=subject,
        message=message,
        recipient_list=[user.email],
        fail_silently=False,
    )

    req_info = (
        getattr(requested_by, "username", "Autoservicio")
        if requested_by
        else "Autoservicio"
    )
    logger.info(
        f"[ARCAMITTE SECURITY] Reseteo de contraseña ejecutado para usuario '{user.username}' por '{req_info}'."
    )
    return True, str(
        _(
            "Se ha restablecido la contraseña y se ha remitido la clave temporal al correo del usuario."
        )
    )


def is_uo_admin(user: Any, uo: OrganizationalUnit) -> bool:
    """
    Verifica si el usuario dispone de privilegios de administración sobre la UO especificada.
    Los superusuarios tienen privilegios sobre todas las UOs.
    """
    if not user or not user.is_authenticated:
        return False
    if is_global_admin(user):
        return True
    return UserUOMembership.objects.filter(
        user=user,
        uo=uo,
        role=UserUOMembership.Role.ADMIN,
        is_active=True,
    ).exists()


def get_user_administered_uos(user: Any) -> Any:
    """
    Retorna el conjunto de Unidades Organizativas donde el usuario tiene rol de Administrador.
    Si es superusuario, retorna todas las UOs del sistema.
    """
    if not user or not user.is_authenticated:
        return OrganizationalUnit.objects.none()
    if is_global_admin(user):
        return OrganizationalUnit.objects.all().order_by("numeric_code")
    return (
        OrganizationalUnit.objects.filter(
            memberships__user=user,
            memberships__role=UserUOMembership.Role.ADMIN,
            memberships__is_active=True,
        )
        .order_by("numeric_code")
        .distinct()
    )


def get_scoped_documents_for_request(
    request: Any,
) -> models.QuerySet[EncryptedDocument]:
    """
    Retorna el QuerySet de documentos confidenciales accesible para la petición dada,
    aplicando estrictamente el principio de Menor Privilegio (Least Privilege) y
    paridad total con las reglas de negocio de la interfaz de usuario:

    1. Si la petición se autentica con APIToken (request.auth):
       - Si el token tiene UO asignada: solo accede a asientos donde origin_uo o target_uo
         coinciden con dicha UO.
       - Si el token no tiene UO y su emisor es Superusuario (Token Maestro): acceso global.
       - En cualquier otro caso: restringido a su emisor o UO.
    2. Si la petición se autentica con usuario Django (request.user):
       - Superusuario: acceso global a toda la malla.
       - Miembro de UO: asientos donde sus UOs activas son origin_uo o target_uo, o subidos por él.
       - Asiento personal sin UO: únicamente asientos subidos personalmente.
    3. No autenticado: QuerySet vacío.
    """
    from arcamitte.models import APIToken, EncryptedDocument

    # 1. Autenticación M2M mediante APIToken
    token = getattr(request, "auth", None)
    if token and isinstance(token, APIToken) and token.is_valid():
        if token.uo:
            return (
                EncryptedDocument.objects.filter(
                    models.Q(origin_uo=token.uo) | models.Q(target_uo=token.uo)
                )
                .select_related("origin_uo", "target_uo", "uploaded_by")
                .distinct()
            )
        if token.created_by and is_global_admin(token.created_by):
            return EncryptedDocument.objects.all().select_related(
                "origin_uo", "target_uo", "uploaded_by"
            )
        if token.created_by:
            return EncryptedDocument.objects.filter(
                uploaded_by=token.created_by
            ).select_related("origin_uo", "target_uo", "uploaded_by")

    # 2. Autenticación interactiva de usuario
    user = getattr(request, "user", None)
    if user and user.is_authenticated:
        if is_global_admin(user):
            return EncryptedDocument.objects.all().select_related(
                "origin_uo", "target_uo", "uploaded_by"
            )

        from arcamitte.models import UserUOMembership

        user_uos = OrganizationalUnit.objects.filter(
            memberships__user=user,
            memberships__is_active=True,
            is_active=True,
        ).distinct()

        return (
            EncryptedDocument.objects.filter(
                models.Q(origin_uo__in=user_uos)
                | models.Q(target_uo__in=user_uos)
                | models.Q(uploaded_by=user)
            )
            .select_related("origin_uo", "target_uo", "uploaded_by")
            .distinct()
        )

    return EncryptedDocument.objects.none()


def can_user_or_token_terminate_document(
    request: Any, document: EncryptedDocument
) -> bool:
    """
    Comprueba si la entidad peticionaria (usuario o token M2M) dispone de potestad
    para terminar/revocar deliberadamente un asiento documental:
    - Superusuario / Token Maestro global: Sí.
    - Token de UO con scope 'documents:terminate': Sí, siempre que origin_uo == token.uo.
    - Usuario de sesión: Sí, si es Superusuario o Administrador de la UO emisora (origin_uo).
    """
    from arcamitte.models import APIToken, UserUOMembership

    token = getattr(request, "auth", None)
    if token and isinstance(token, APIToken) and token.is_valid():
        if not token.has_scope("documents:terminate"):
            return False
        if not token.uo and token.created_by and is_global_admin(token.created_by):
            return True
        return bool(token.uo and document.origin_uo_id == token.uo_id)

    user = getattr(request, "user", None)
    if user and user.is_authenticated:
        if is_global_admin(user):
            return True
        if document.origin_uo_id:
            return UserUOMembership.objects.filter(
                user=user,
                uo_id=document.origin_uo_id,
                role=UserUOMembership.Role.ADMIN,
                is_active=True,
            ).exists()
        # Asiento personal sin UO: el emisor original puede terminarlo
        return document.uploaded_by_id == user.id

    return False


def can_user_or_token_decrypt_for_audit(
    request: Any, document: EncryptedDocument
) -> bool:
    """
    Comprueba si la entidad peticionaria dispone de permiso de descifrado pericial
    para inspección legal / auditoría (sin activar la destrucción por lectura):
    - Superusuario / Token Maestro con scope 'documents:admin_decrypt': Sí.
    - Token de UO con scope 'documents:admin_decrypt': Sí, si su UO es origin_uo o target_uo.
    - Usuario de sesión: Sí, si es Superusuario, o Administrador/Auditor de origin_uo o target_uo.
    """
    from arcamitte.models import APIToken, UserUOMembership

    token = getattr(request, "auth", None)
    if token and isinstance(token, APIToken) and token.is_valid():
        if not token.has_scope("documents:admin_decrypt"):
            return False
        if not token.uo and token.created_by and is_global_admin(token.created_by):
            return True
        return bool(
            token.uo
            and (
                document.origin_uo_id == token.uo_id
                or document.target_uo_id == token.uo_id
            )
        )

    user = getattr(request, "user", None)
    if user and user.is_authenticated:
        if is_global_admin(user):
            return True
        uo_ids = [
            uid
            for uid in (document.origin_uo_id, document.target_uo_id)
            if uid is not None
        ]
        if uo_ids:
            return UserUOMembership.objects.filter(
                user=user,
                uo_id__in=uo_ids,
                role__in=[UserUOMembership.Role.ADMIN, UserUOMembership.Role.AUDITOR],
                is_active=True,
            ).exists()
        return document.uploaded_by_id == user.id

    return False


def get_scoped_audit_logs_for_request(
    request: Any,
) -> models.QuerySet[DocumentAccessLog]:
    """
    Retorna el QuerySet de registros de auditoría accesibles para la petición:
    - Superusuario / Token Maestro sin UO con scope 'audit:read': todos los registros.
    - Token de UO con scope 'audit:read': registros vinculados a documentos de su UO o con origin_uo == token.uo.
    - Usuario en sesión: si es Superusuario ve todo; si es Administrador o Auditor de UO ve los de sus UOs.
    """
    from arcamitte.models import APIToken, DocumentAccessLog, UserUOMembership

    token = getattr(request, "auth", None)
    if token and isinstance(token, APIToken) and token.is_valid():
        if not token.has_scope("audit:read"):
            return DocumentAccessLog.objects.none()
        if not token.uo and token.created_by and is_global_admin(token.created_by):
            return DocumentAccessLog.objects.all().select_related(
                "document", "origin_uo", "target_uo"
            )
        if token.uo:
            return (
                DocumentAccessLog.objects.filter(
                    models.Q(origin_uo=token.uo)
                    | models.Q(target_uo=token.uo)
                    | models.Q(document__origin_uo=token.uo)
                    | models.Q(document__target_uo=token.uo)
                )
                .select_related("document", "origin_uo", "target_uo")
                .distinct()
            )

    user = getattr(request, "user", None)
    if user and user.is_authenticated:
        if is_global_admin(user):
            return DocumentAccessLog.objects.all().select_related(
                "document", "origin_uo", "target_uo"
            )

        administered_or_audited_uos = OrganizationalUnit.objects.filter(
            memberships__user=user,
            memberships__role__in=[
                UserUOMembership.Role.ADMIN,
                UserUOMembership.Role.AUDITOR,
            ],
            memberships__is_active=True,
            is_active=True,
        ).distinct()

        return (
            DocumentAccessLog.objects.filter(
                models.Q(origin_uo__in=administered_or_audited_uos)
                | models.Q(target_uo__in=administered_or_audited_uos)
                | models.Q(document__origin_uo__in=administered_or_audited_uos)
                | models.Q(document__target_uo__in=administered_or_audited_uos)
            )
            .select_related("document", "origin_uo", "target_uo")
            .distinct()
        )

    return DocumentAccessLog.objects.none()


# ==============================================================================
# SERVICIOS DE SEGURIDAD PERIMETRAL, ANTI-FUERZA BRUTA Y NO REPUDIO DE LOGS
# ==============================================================================


def record_failed_login(username: str, client_ip: str | None = None) -> dict[str, Any]:
    """
    Registra un intento fallido de autenticación administrativa en Arcamitte.
    Evalúa umbrales de fuerza bruta defensiva por IP y por cuenta de usuario:
    - IP: Si supera ARCAMITTE_IP_BAN_FAILED_ATTEMPTS_THRESHOLD en la ventana temporal,
      la IP es baneada automáticamente en BannedIP y se envía alerta al SOC.
    - Usuario: Si el usuario existe y acumula ARCAMITTE_USER_MAX_FAILED_LOGINS,
      su cuenta queda bloqueada temporalmente y se remiten notificaciones de seguridad.
    """
    from arcamitte.models import DocumentAccessLog, get_or_create_user_profile
    from django.contrib.auth import get_user_model
    from django.core.cache import cache

    result: dict[str, Any] = {
        "ip_banned": False,
        "user_locked": False,
        "attempts": 0,
        "user_exists": False,
    }

    # 1. Control por IP
    if client_ip:
        ip_cache_key = f"arcamitte_ip_fails_{client_ip}"
        window_secs = getattr(settings, "ARCAMITTE_IP_BAN_WINDOW_MINUTES", 10) * 60
        ip_fails = cache.get(ip_cache_key, 0) + 1
        cache.set(ip_cache_key, ip_fails, timeout=window_secs)

        ip_threshold = getattr(
            settings, "ARCAMITTE_IP_BAN_FAILED_ATTEMPTS_THRESHOLD", 10
        )
        if ip_fails >= ip_threshold:
            duration_hours = getattr(
                settings, "ARCAMITTE_IP_BAN_DEFAULT_DURATION_HOURS", 24
            )
            ban_ip(
                ip_address=client_ip,
                reason=f"Exceso de intentos fallidos de autenticación ({ip_fails} fallos en ventana)",
                duration_hours=duration_hours,
            )
            result["ip_banned"] = True
            logger.warning(
                f"[ARCAMITTE SECURITY] IP {client_ip} baneada automáticamente tras {ip_fails} fallos."
            )

    # 2. Control por Usuario
    clean_username = (username or "").strip()
    if clean_username:
        User = get_user_model()
        user = User.objects.filter(
            models.Q(username__iexact=clean_username)
            | models.Q(email__iexact=clean_username)
        ).first()

        if user:
            result["user_exists"] = True
            profile = get_or_create_user_profile(user)
            failed_count = profile.register_failed_login()
            result["attempts"] = failed_count

            user_threshold = getattr(settings, "ARCAMITTE_USER_MAX_FAILED_LOGINS", 5)
            if failed_count >= user_threshold and not profile.is_locked:
                lockout_min = getattr(
                    settings, "ARCAMITTE_USER_LOCKOUT_DURATION_MINUTES", 30
                )
                profile.lock_account(minutes=lockout_min)
                result["user_locked"] = True

                # Registrar vicisitud en auditoría
                DocumentAccessLog.objects.create(
                    document=None,
                    email=user.email or user.username,
                    action=DocumentAccessLog.Action.BLOQUEO_USUARIO,
                    details=(
                        f"Cuenta del usuario '{user.username}' bloqueada temporalmente ({lockout_min} min) "
                        f"tras {failed_count} intentos fallidos consecutivos desde IP {client_ip or 'desconocida'}."
                    ),
                    ip_address=client_ip,
                )

                # Notificar al usuario afectado y al administrador
                send_security_alert_user_locked(
                    user=user, client_ip=client_ip, lockout_minutes=lockout_min
                )
                send_security_alert_admin(
                    subject=f"[Arcamitte Seguridad] Cuenta de usuario '{user.username}' bloqueada por fuerza bruta",
                    message=(
                        f"Se ha activado el bloqueo de seguridad para la cuenta de usuario '{user.username}'.\n"
                        f"Intentos fallidos: {failed_count}\n"
                        f"IP origen: {client_ip or 'No disponible'}\n"
                        f"Fecha/Hora: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                        f"Duración: {lockout_min} minutos."
                    ),
                    event_type="USER_LOCKOUT",
                    details={
                        "username": user.username,
                        "ip": client_ip,
                        "attempts": failed_count,
                    },
                )
                dispatch_siem_event(
                    event_type="user_lockout",
                    details={
                        "username": user.username,
                        "failed_attempts": failed_count,
                        "lockout_minutes": lockout_min,
                    },
                    actor=user.username,
                    ip=client_ip,
                )
                logger.warning(
                    f"[ARCAMITTE SECURITY] Usuario {user.username} bloqueado por superar {failed_count} fallos."
                )

    return result


def record_successful_login(user: Any, client_ip: str | None = None) -> None:
    """Restablece los contadores de intentos fallidos tras un inicio de sesión exitoso."""
    if not user or not user.is_authenticated:
        return
    from arcamitte.models import get_or_create_user_profile
    from django.core.cache import cache

    profile = get_or_create_user_profile(user)
    profile.reset_failed_logins()

    if client_ip:
        cache.delete(f"arcamitte_ip_fails_{client_ip}")


def ban_ip(
    ip_address: str,
    reason: str = "Bloqueo por actividad sospechosa",
    duration_hours: int | None = 24,
    created_by: Any = None,
) -> Any:
    """
    Incorpora o renueva una dirección IP en la lista negra perimetral BannedIP
    y actualiza la caché para intercepción inmediata con 0 latencia.
    """
    from arcamitte.models import BannedIP, DocumentAccessLog
    from django.core.cache import cache

    clean_ip = ip_address.strip()
    banned_until = (
        timezone.now() + timezone.timedelta(hours=duration_hours)
        if duration_hours and duration_hours > 0
        else None
    )

    banned_obj, _ = BannedIP.objects.update_or_create(
        ip_address=clean_ip,
        defaults={
            "reason": reason,
            "is_active": True,
            "banned_until": banned_until,
            "created_by": created_by,
        },
    )

    ttl = 300
    if banned_until:
        rem = int((banned_until - timezone.now()).total_seconds())
        ttl = max(10, min(ttl, rem))
    cache.set(f"arcamitte_banned_ip_{clean_ip}", "BANNED", timeout=ttl)

    admin_str = getattr(created_by, "username", "Sistema")
    DocumentAccessLog.objects.create(
        document=None,
        email=admin_str,
        action=DocumentAccessLog.Action.BANEO_IP,
        details=f"Dirección IP {clean_ip} incorporada a la lista negra. Motivo: {reason}. Vigencia: {banned_until or 'Permanente'}",
        ip_address=clean_ip,
    )

    send_security_alert_admin(
        subject=f"[Arcamitte Seguridad] Dirección IP {clean_ip} incorporada a lista negra",
        message=(
            f"La dirección IP {clean_ip} ha sido bloqueada perimetralmente.\n"
            f"Motivo: {reason}\n"
            f"Vigencia: {banned_until or 'Indefinida'}\n"
            f"Operador: {admin_str}"
        ),
        event_type="IP_BAN",
        details={
            "ip_address": clean_ip,
            "reason": reason,
            "banned_until": str(banned_until),
            "operator": admin_str,
        },
    )
    dispatch_siem_event(
        event_type="ip_ban",
        details={
            "ip_address": clean_ip,
            "reason": reason,
            "duration_hours": duration_hours,
            "banned_until": banned_until.isoformat() if banned_until else "permanent",
        },
        actor=admin_str,
        ip=clean_ip,
    )
    return banned_obj


def unban_ip(ip_address: str, operator: Any = None) -> bool:
    """Retira una IP de la lista negra y desbloquea su acceso perimetral."""
    from arcamitte.models import BannedIP, DocumentAccessLog
    from django.core.cache import cache

    clean_ip = ip_address.strip()
    banned_entry = BannedIP.objects.filter(ip_address=clean_ip, is_active=True).first()
    if not banned_entry:
        cache.delete(f"arcamitte_banned_ip_{clean_ip}")
        return False

    banned_entry.is_active = False
    banned_entry.save(update_fields=["is_active"])
    cache.set(f"arcamitte_banned_ip_{clean_ip}", "ALLOWED", timeout=60)

    admin_str = getattr(operator, "username", "Sistema")
    DocumentAccessLog.objects.create(
        document=None,
        email=admin_str,
        action=DocumentAccessLog.Action.BANEO_IP,
        details=f"Dirección IP {clean_ip} retirada de la lista negra de seguridad por {admin_str}.",
        ip_address=clean_ip,
    )
    return True


def unlock_user_account(user: Any, operator: Any = None) -> None:
    """Desbloquea inmediatamente la cuenta de un usuario y registra la vicisitud."""
    from arcamitte.models import DocumentAccessLog, get_or_create_user_profile

    profile = get_or_create_user_profile(user)
    profile.unlock_account()

    admin_str = getattr(operator, "username", "Sistema")
    DocumentAccessLog.objects.create(
        document=None,
        email=admin_str,
        action=DocumentAccessLog.Action.BLOQUEO_USUARIO,
        details=f"Cuenta del usuario '{user.username}' reactivada/desbloqueada manualmente por {admin_str}.",
    )


def record_password_change(user: Any, raw_password: str) -> None:
    """
    Registra el cambio de contraseña:
    - Almacena el hash en PasswordHistory.
    - Poda entradas antiguas conservando sólo las últimas N según ARCAMITTE_PASSWORD_HISTORY_LIMIT.
    - Actualiza password_changed_at en UserProfile y restablece must_change_password.
    """
    from arcamitte.models import PasswordHistory, get_or_create_user_profile
    from django.contrib.auth.hashers import make_password

    profile = get_or_create_user_profile(user)
    profile.password_changed_at = timezone.now()
    profile.must_change_password = False
    profile.save(
        update_fields=["password_changed_at", "must_change_password", "updated_at"]
    )

    PasswordHistory.objects.create(
        user=user,
        hashed_password=make_password(raw_password),
    )

    limit = getattr(settings, "ARCAMITTE_PASSWORD_HISTORY_LIMIT", 5)
    old_ids = list(
        PasswordHistory.objects.filter(user=user)
        .order_by("-created_at")
        .values_list("id", flat=True)[limit:]
    )
    if old_ids:
        PasswordHistory.objects.filter(id__in=old_ids).delete()


def verify_audit_log_chain() -> dict[str, Any]:
    """
    Audita la integridad criptográfica de la cadena completa de logs de acceso (Hash Chaining).
    Verifica secuencialmente desde el génesis hasta el último registro que:
    1. El 'previous_hash' coincide exactamente con el 'log_hash' del bloque anterior.
    2. El 'log_hash' recalculado sobre el payload coincide exactamente con el guardado en BD.
    Si se detecta cualquier manipulación, inserción o borrado en la base de datos,
    identifica el ID del registro corrompido.
    """
    from arcamitte.models import DocumentAccessLog

    logs = list(DocumentAccessLog.objects.order_by("id"))
    total = len(logs)
    if total == 0:
        return {"is_valid": True, "total_verified": 0, "head_hash": "0" * 64}

    expected_prev = "0" * 64
    for idx, log in enumerate(logs):
        if idx == 0:
            expected_prev = log.previous_hash or ("0" * 64)

        if log.previous_hash != expected_prev:
            err_msg = (
                f"Ruptura de cadena en registro #{log.id}: previous_hash '{log.previous_hash[:12]}...' "
                f"no coincide con el bloque anterior '{expected_prev[:12]}...'."
            )
            dispatch_siem_event(
                event_type="log_tamper",
                details={"corrupted_log_id": log.id, "error": err_msg},
                actor="Auditor / Sistema",
            )
            return {
                "is_valid": False,
                "total_verified": idx,
                "corrupted_log_id": log.id,
                "error": err_msg,
            }

        recalculated = log.calculate_payload_hash(expected_prev)
        if log.log_hash != recalculated:
            err_msg = (
                f"Manipulación de datos en registro #{log.id}: log_hash '{log.log_hash[:12]}...' "
                f"difiere del hash recalculado sobre el payload '{recalculated[:12]}...'."
            )
            dispatch_siem_event(
                event_type="log_tamper",
                details={"corrupted_log_id": log.id, "error": err_msg},
                actor="Auditor / Sistema",
            )
            return {
                "is_valid": False,
                "total_verified": idx,
                "corrupted_log_id": log.id,
                "error": err_msg,
            }

        expected_prev = log.log_hash

    return {
        "is_valid": True,
        "total_verified": total,
        "head_hash": logs[-1].log_hash,
    }


def create_certified_audit_export(
    user: Any,
    queryset: Any,
    filters: dict[str, Any] | None = None,
    reason: str = "",
    client_ip: str | None = None,
) -> tuple[bytes, Any]:
    """
    Genera un archivo CSV de auditoría certificado con sanitización estricta anti-CSV Injection.
    Calcula el hash SHA-256 exacto del volcado binario, genera el recibo oficial inmutable
    AuditExportReceipt y registra el asiento correspondiente en DocumentAccessLog para
    garantizar el pleno no repudio legal (ENS / eIDAS).
    """
    import csv
    import hashlib
    import io
    import uuid
    from arcamitte.models import AuditExportReceipt, DocumentAccessLog
    from arcamitte.validators import sanitize_csv_cell

    receipt_code = (
        f"ARCA-EXP-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    )
    timestamp_str = timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    operator_str = getattr(user, "username", str(user))
    operator_email = getattr(user, "email", "") or operator_str

    count = queryset.count()
    applied_filters = filters or {}

    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", quoting=csv.QUOTE_MINIMAL)

    # Cabecera Institucional Oficial
    buffer.write(
        f"# ==============================================================================\n"
    )
    buffer.write(
        f"# ARCAMITTE - INFORME OFICIAL CERTIFICADO DE AUDITORÍA Y NO REPUDIO\n"
    )
    buffer.write(
        f"# ==============================================================================\n"
    )
    buffer.write(f"# Identificador de Recibo : {receipt_code}\n")
    buffer.write(f"# Fecha de Generación     : {timestamp_str}\n")
    buffer.write(f"# Operador Responsable    : {operator_str} ({operator_email})\n")
    buffer.write(f"# Dirección IP Solicitud  : {client_ip or 'No registrada'}\n")
    buffer.write(
        f"# Justificación Legal     : {reason or 'Sin justificación declarada'}\n"
    )
    buffer.write(f"# Total de Registros      : {count}\n")
    buffer.write(
        f"# ==============================================================================\n"
    )

    # Columnas CSV
    writer.writerow(
        [
            "ID",
            "Fecha_Hora_UTC",
            "Accion_Codigo",
            "Accion_Descripcion",
            "Documento_Original",
            "Hash_SHA256_Documento",
            "IP_Solicitante",
            "Actor_Correo",
            "Detalles_Foreses",
            "Hash_Bloque_Anterior",
            "Hash_Criptografico_Registro",
        ]
    )

    for log in queryset.iterator():
        doc_filename = log.document.original_filename if log.document else ""
        doc_hash = log.document.file_hash if log.document else ""
        writer.writerow(
            [
                sanitize_csv_cell(log.id),
                sanitize_csv_cell(log.created_at.strftime("%Y-%m-%d %H:%M:%S")),
                sanitize_csv_cell(log.action),
                sanitize_csv_cell(log.get_action_display()),
                sanitize_csv_cell(doc_filename),
                sanitize_csv_cell(doc_hash),
                sanitize_csv_cell(log.ip_address or ""),
                sanitize_csv_cell(log.email or ""),
                sanitize_csv_cell(log.details or ""),
                sanitize_csv_cell(log.previous_hash or ""),
                sanitize_csv_cell(log.log_hash or ""),
            ]
        )

    csv_content = buffer.getvalue()
    csv_bytes = ("\ufeff" + csv_content).encode("utf-8")
    export_hash = hashlib.sha256(csv_bytes).hexdigest()

    # --------------------------------------------------------------------------
    # FASE B: Sellado Criptográfico Cualificado RFC 3161 para Recibo de Exportación
    # --------------------------------------------------------------------------
    timestamp_token_b64 = ""
    tsa_authority = ""
    if getattr(settings, "ARCAMITTE_RFC3161_ENABLED", False):
        from arcamitte.timestamping import (
            request_rfc3161_timestamp,
            token_to_base64,
            TimestampingError,
        )

        try:
            tsr_bytes = request_rfc3161_timestamp(bytes.fromhex(export_hash))
            timestamp_token_b64 = token_to_base64(tsr_bytes)
            tsa_authority = getattr(
                settings, "ARCAMITTE_RFC3161_TSA_URL", "http://timestamp.digicert.com"
            )
        except TimestampingError as ts_exc:
            logger.warning(
                f"[RFC3161] Fallo al solicitar sello de tiempo para el recibo {receipt_code}: {ts_exc}"
            )

    receipt = AuditExportReceipt.objects.create(
        receipt_id=receipt_code,
        export_hash=export_hash,
        exported_by=user,
        records_count=count,
        filter_criteria=applied_filters,
        client_ip=client_ip,
        reason=reason,
        timestamp_token=timestamp_token_b64,
        timestamp_authority=tsa_authority,
        created_at=timezone.now(),
    )

    if timestamp_token_b64:
        DocumentAccessLog.objects.create(
            document=None,
            email=operator_email,
            action=DocumentAccessLog.Action.SELLO_TIEMPO_RFC3161_GENERADO,
            details=f"Sello de tiempo RFC 3161 generado para exportación {receipt_code} con TSA '{tsa_authority}'.",
            ip_address=client_ip,
        )

    DocumentAccessLog.objects.create(
        document=None,
        email=operator_email,
        action=DocumentAccessLog.Action.EXPORTACION_AUDITORIA,
        details=(
            f"Exportación certificada de auditoría [{receipt_code}]. "
            f"Total registros: {count}. Hash SHA-256: {export_hash}. "
            f"Motivo legal: {reason or 'Exportación estándar'}"
        ),
        ip_address=client_ip,
    )

    dispatch_siem_event(
        event_type="audit_export",
        details={
            "receipt_id": receipt_code,
            "records_count": count,
            "export_hash": export_hash,
            "reason": reason,
        },
        actor=operator_email,
        ip=client_ip,
    )

    return csv_bytes, receipt


def verify_export_receipt(
    receipt_id_or_hash: str, file_bytes: bytes | None = None
) -> dict[str, Any]:
    """
    Verifica la autenticidad y el no repudio de una exportación de auditoría.
    Comprueba si existe el recibo en la base de datos y, si se proporcionan los bytes
    del archivo descargado, verifica matemáticamente que el hash coincide al 100%.
    """
    import hashlib
    from arcamitte.models import AuditExportReceipt

    clean_term = (receipt_id_or_hash or "").strip()
    receipt = AuditExportReceipt.objects.filter(
        models.Q(receipt_id__iexact=clean_term)
        | models.Q(export_hash__iexact=clean_term)
    ).first()

    if not receipt:
        return {
            "found": False,
            "is_valid": False,
            "error": str(
                _(
                    "No se encontró ningún recibo oficial con el identificador o hash indicado."
                )
            ),
        }

    computed_hash = None
    hash_match = None
    if file_bytes is not None:
        computed_hash = hashlib.sha256(file_bytes).hexdigest()
        hash_match = computed_hash.lower() == receipt.export_hash.lower()

    # Verificación del sello de tiempo cualificado RFC 3161 si está anclado en el recibo
    timestamp_verification: dict[str, Any] = {"has_timestamp": False}
    if receipt.timestamp_token:
        from arcamitte.timestamping import verify_rfc3161_timestamp, token_from_base64

        try:
            tsr_bytes = token_from_base64(receipt.timestamp_token)
            orig_hash_bytes = bytes.fromhex(receipt.export_hash)
            ts_valid, ts_msg = verify_rfc3161_timestamp(tsr_bytes, orig_hash_bytes)
            timestamp_verification = {
                "has_timestamp": True,
                "is_valid": ts_valid,
                "message": ts_msg,
                "authority": receipt.timestamp_authority,
            }
        except Exception as ts_exc:
            timestamp_verification = {
                "has_timestamp": True,
                "is_valid": False,
                "message": f"Error verificando estructura del sello de tiempo: {ts_exc}",
                "authority": receipt.timestamp_authority,
            }

    return {
        "found": True,
        "is_valid": True if hash_match is None else hash_match,
        "receipt": receipt,
        "hash_match": hash_match,
        "computed_hash": computed_hash,
        "expected_hash": receipt.export_hash,
        "receipt_id": receipt.receipt_id,
        "exported_by": receipt.exported_by.username,
        "created_at": receipt.created_at,
        "records_count": receipt.records_count,
        "reason": receipt.reason,
        "timestamp_verification": timestamp_verification,
    }


def send_security_alert_user_locked(
    user: Any, client_ip: str | None = None, lockout_minutes: int = 30
) -> None:
    """Envía un aviso de seguridad por correo electrónico al usuario cuando su cuenta es bloqueada."""
    if not user or not user.email:
        return
    unlock_time = (
        timezone.now() + timezone.timedelta(minutes=lockout_minutes)
    ).strftime("%H:%M:%S UTC")
    subject = "[Arcamitte Seguridad] Aviso de bloqueo temporal de cuenta por intentos fallidos"
    message = (
        f"Estimado/a {user.get_full_name() or user.username}:\n\n"
        f"Le informamos que su cuenta de acceso en la pasarela confidencial Arcamitte ha sido temporalmente bloqueada "
        f"tras detectarse múltiples intentos fallidos de inicio de sesión consecutivos.\n\n"
        f"Detalles del incidente:\n"
        f"• Dirección IP de origen: {client_ip or 'No disponible'}\n"
        f"• Fecha y hora: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"• Duración del bloqueo: {lockout_minutes} minutos (desbloqueo automático a las {unlock_time})\n\n"
        f"Si usted NO ha intentado iniciar sesión, es posible que un tercero esté intentando acceder a su cuenta. "
        f"Por favor, póngase en contacto inmediato con el Administrador de Seguridad de su Unidad Organizativa "
        f"o restablezca su contraseña al finalizar el periodo de bloqueo.\n\n"
        f"---\nArcamitte Cryptographic Custody Gateway"
    )
    dispatch_email(
        subject=subject,
        message=message,
        recipient_list=[user.email],
        fail_silently=True,
    )


def send_security_alert_admin(
    subject: str,
    message: str,
    event_type: str = "SECURITY_ALERT",
    details: dict[str, Any] | None = None,
) -> None:
    """Envía una alerta de seguridad al buzón de administración/SOC o a los superusuarios."""
    from django.contrib.auth import get_user_model

    admin_email = getattr(settings, "ARCAMITTE_SECURITY_ALERTS_EMAIL", "").strip()
    if not admin_email:
        User = get_user_model()
        recipients = list(
            User.objects.filter(arcamitte_profile__is_global_admin=True, is_active=True)
            .exclude(email="")
            .values_list("email", flat=True)
        )
    else:
        recipients = [admin_email]

    if not recipients:
        return

    dispatch_email(
        subject=subject,
        message=message,
        recipient_list=recipients,
        fail_silently=True,
    )


def dispatch_siem_event(
    event_type: str,
    details: dict[str, Any],
    actor: str = "Sistema",
    ip: str | None = None,
) -> None:
    """
    Despacha un evento de telemetría de seguridad en formato JSON estructurado hacia
    el endpoint SIEM / Webhook configurado (Splunk HEC, Elastic, Sentinel, etc.)
    en un hilo asíncrono no bloqueante (ENS ALTA / NIST SP 800-53 AU-6 / AU-12).
    """
    webhook_url = getattr(settings, "ARCAMITTE_SIEM_WEBHOOK_URL", "")
    if not webhook_url:
        return

    subscribed_events = getattr(settings, "ARCAMITTE_SIEM_WEBHOOK_EVENTS", [])
    if event_type.lower() not in [e.lower() for e in subscribed_events]:
        return

    payload = {
        "timestamp": timezone.now().isoformat(),
        "event": event_type.upper(),
        "actor": actor,
        "client_ip": ip or "127.0.0.1",
        "service": "arcamitte",
        "details": details,
    }

    token = getattr(settings, "ARCAMITTE_SIEM_WEBHOOK_TOKEN", "")

    def _send_webhook() -> None:
        try:
            import json
            import urllib.request

            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Arcamitte-SIEM-Connector/2.0",
            }
            if token:
                headers["Authorization"] = f"Bearer {token}"

            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status not in (200, 201, 202, 204):
                    logger.warning(
                        f"[ARCAMITTE SIEM] Respuesta inusual del webhook SIEM ({resp.status})"
                    )
        except Exception as exc:
            logger.warning(
                f"[ARCAMITTE SIEM] Error al enviar evento de seguridad a {webhook_url}: {exc}"
            )

    executor = get_email_executor()
    if executor:
        executor.submit(_send_webhook)
    else:
        _send_webhook()


def rotate_master_keys(
    new_primary_key: str,
    operator: Any = None,
    client_ip: str | None = None,
) -> dict[str, Any]:
    """
    Ejecuta el recifrado atómico de todas las claves de datos (DEK) de documentos
    y secretos TOTP en base de datos con una nueva clave maestra Fernet primaria
    (NIST SP 800-57 Part 1 Rev. 5 / ENS op.sec.4).
    """
    from arcamitte.models import DocumentAccessLog, EncryptedDocument, UserProfile

    clean_key = new_primary_key.strip()
    try:
        Fernet(clean_key.encode("utf-8"))
    except Exception as exc:
        raise ValidationError(
            f"La clave maestra proporcionada no es una clave Fernet válida: {exc}"
        )

    existing_keys = getattr(
        settings, "ARCAMITTE_FERNET_KEYS", [settings.ARCAMITTE_FERNET_KEY]
    )
    all_keys = [clean_key] + [k for k in existing_keys if k != clean_key]
    rotation_engine = MultiFernet(
        [Fernet(k.encode("utf-8") if isinstance(k, str) else k) for k in all_keys]
    )

    rotated_docs_count = 0
    rotated_profiles_count = 0

    with transaction.atomic():
        # 1. Recifrado de DEKs de documentos
        docs = EncryptedDocument.objects.select_for_update().exclude(encrypted_dek="")
        for doc in docs:
            rotated_dek = rotation_engine.rotate(
                doc.encrypted_dek.encode("utf-8")
            ).decode("utf-8")
            doc.encrypted_dek = rotated_dek
            doc.save(update_fields=["encrypted_dek", "updated_at"])
            rotated_docs_count += 1

        # 2. Recifrado de secretos TOTP de perfiles de usuario
        profiles = UserProfile.objects.select_for_update().exclude(totp_secret="")
        for profile in profiles:
            rotated_totp = rotation_engine.rotate(
                profile.totp_secret.encode("utf-8")
            ).decode("utf-8")
            profile.totp_secret = rotated_totp
            profile.save(update_fields=["totp_secret", "updated_at"])
            rotated_profiles_count += 1

        operator_email = getattr(operator, "email", "") or getattr(
            operator, "username", "Sistema"
        )
        key_fingerprint = hashlib.sha256(clean_key.encode("utf-8")).hexdigest()[:16]

        DocumentAccessLog.objects.create(
            document=None,
            email=operator_email,
            action=DocumentAccessLog.Action.ROTACION_CLAVE_MAESTRA,
            details=(
                f"Rotación de clave maestra completada exitosamente. "
                f"Documentos recifrados: {rotated_docs_count}. Perfiles TOTP recifrados: {rotated_profiles_count}. "
                f"Huella nueva clave maestra (SHA-256): {key_fingerprint}..."
            ),
            ip_address=client_ip,
        )

    dispatch_siem_event(
        event_type="master_key_rotated",
        details={
            "rotated_documents": rotated_docs_count,
            "rotated_profiles": rotated_profiles_count,
            "new_key_fingerprint": key_fingerprint,
        },
        actor=operator_email,
        ip=client_ip,
    )

    return {
        "status": "success",
        "rotated_documents": rotated_docs_count,
        "rotated_profiles": rotated_profiles_count,
        "new_key_fingerprint": key_fingerprint,
    }


def is_totp_required_for_user(user: Any) -> bool:
    """
    Determina si el usuario debe pasar obligatoriamente por el segundo factor (2FA / TOTP).
    Criterios de seguridad estricta (Zero Trust / ENS ALTO):
    1. Si el usuario ya tiene 2FA configurado y activo (is_totp_enabled).
    2. Si es Administrador Global de Seguridad (is_global_admin).
    3. Si cuenta con rol de Administrador de Unidad Organizativa (UserUOMembership.Role.ADMIN).
    4. Si tiene la directiva individual forzada por un administrador (is_mfa_enforced).
    """
    if not user or not user.is_authenticated:
        return False

    profile = getattr(user, "arcamitte_profile", None)
    if profile and profile.is_totp_enabled:
        return True

    from arcamitte.permissions import (
        is_global_admin,
        is_uo_admin,
        is_uo_auditor,
        is_uo_operator,
    )

    # 1. Superusuario Global / Administrador de Seguridad (siempre obligatorio por ENS ALTO)
    if is_global_admin(user):
        return True

    # 2. Administrador de Unidad Organizativa (siempre obligatorio)
    if is_uo_admin(user):
        return True

    # 3. Usuario Estándar con directiva individual forzada por superusuario
    if profile and getattr(profile, "is_mfa_enforced", False):
        return True

    # 4. Directivas dinámicas de rol configuradas por UI (PlatformSecurityPolicy)
    try:
        from arcamitte.models import PlatformSecurityPolicy

        policy = PlatformSecurityPolicy.get_solo()
        if policy.mfa_enforced_for_auditors and is_uo_auditor(user):
            return True
        if policy.mfa_enforced_for_operators and is_uo_operator(user):
            return True
    except Exception:
        pass

    return False


def reset_user_totp(user: Any, operator: Any = None, reason: str = "") -> None:
    """
    Resetea administrativamente las credenciales de segundo factor (2FA / TOTP) de un usuario.
    Permite restaurar el acceso a un operador que haya extraviado su dispositivo móvil o códigos,
    obligándole a vincular un nuevo autenticador en su siguiente inicio de sesión.
    """
    profile = getattr(user, "arcamitte_profile", None)
    if not profile:
        from arcamitte.models import get_or_create_user_profile

        profile = get_or_create_user_profile(user)

    profile.is_totp_enabled = False
    profile.totp_secret = ""
    profile.totp_scratch_codes = []
    profile.save(
        update_fields=[
            "is_totp_enabled",
            "totp_secret",
            "totp_scratch_codes",
            "updated_at",
        ]
    )

    operator_name = getattr(operator, "username", "sistema") if operator else "sistema"
    record_audit_log(
        action=DocumentAccessLog.Action.TOTP_CONFIGURADO,
        email=user.email or user.username,
        details={
            "evento": "2fa_reseteado_administrativamente",
            "operador": operator_name,
            "motivo": reason or "Reseteo administrativo por pérdida de clave",
        },
    )
    logger.info(
        f"[ARCAMITTE AUDIT] 2FA reseteado administrativamente para usuario '{user.username}' por '{operator_name}'."
    )


def verify_user_totp_or_scratch(
    user: Any,
    code: str,
    client_ip: str | None = None,
) -> tuple[bool, str]:
    """
    Valida un código de segundo factor (TOTP de 6 dígitos o código de rescate).
    Retorna (es_valido, tipo_resultado: 'totp' | 'scratch' | 'not_required' | 'invalid').
    """
    from arcamitte.models import DocumentAccessLog, get_or_create_user_profile
    from arcamitte.totp import verify_totp_code

    profile = get_or_create_user_profile(user)
    if not profile.is_totp_enabled:
        return True, "not_required"

    clean_code = (code or "").strip().replace(" ", "")
    if not clean_code:
        return False, "invalid"

    # 1. Comprobar si es un código numérico TOTP de 6 dígitos
    if len(clean_code) == 6 and clean_code.isdigit():
        secret = profile.get_totp_secret()
        if secret and verify_totp_code(secret, clean_code):
            return True, "totp"

    # 2. Comprobar si es un código de rescate (scratch code)
    if profile.consume_scratch_code(clean_code):
        DocumentAccessLog.objects.create(
            document=None,
            email=getattr(user, "email", "") or user.username,
            action=DocumentAccessLog.Action.TOTP_RECUPERACION_USADO,
            details=(
                f"Código de recuperación de emergencia 2FA consumido para '{user.username}'. "
                f"Códigos de rescate restantes: {len(profile.totp_scratch_codes)}."
            ),
            ip_address=client_ip,
        )
        return True, "scratch"

    return False, "invalid"
