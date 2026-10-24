from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import os
import re
import secrets
import sys
from typing import Any

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

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

CHUNK_SIZE: int = 64 * 1024  # 64 KB para lectura segura por bloques anti-DoS (OWASP A04)
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
        logger.error(f"[ARCAMITTE ERROR] Fallo al enviar correo asíncrono a {recipient_list}: {exc}")


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
    sender = from_email or getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@arcamitte.local")
    recipients = recipient_list or []

    if sync is None:
        async_enabled = getattr(settings, "ARCAMITTE_ASYNC_EMAIL", True)
        is_testing = getattr(settings, "TESTING", False) or ("pytest" in sys.modules)
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


def get_uo_recipient_emails(uo: OrganizationalUnit | None, include_members: bool = True) -> list[str]:
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
        member_emails = (
            uo.memberships.filter(is_active=True, user__is_active=True)
            .values_list("user__email", flat=True)
        )
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
            logger.info(f"[ARCAMITTE AUDIT] Shredding físico completado por bloques para: {path}")

        file_field.delete(save=False)
        return True
    except Exception as exc:
        logger.error(f"[ARCAMITTE ERROR] Fallo durante trituración segura de archivo: {exc}")
        try:
            file_field.delete(save=False)
        except Exception:
            pass
        return False


def get_server_fernet_key() -> bytes:
    """Obtiene y normaliza la clave de servidor ARCAMITTE_FERNET_KEY en bytes."""
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
            _("El archivo proporcionado no coincide con el hash SHA-256 del documento original.")
        )

    dek: bytes = Fernet.generate_key()
    fernet_dek = Fernet(dek)

    original_file.seek(0)
    file_bytes = original_file.read()
    encrypted_bytes = fernet_dek.encrypt(file_bytes)

    server_key = get_server_fernet_key()
    server_fernet = Fernet(server_key)
    encrypted_dek_str = server_fernet.encrypt(dek).decode("utf-8")

    # Triturar archivo anterior en disco
    if document.encrypted_file:
        shred_and_delete_file(document.encrypted_file)

    filename = getattr(original_file, "name", document.original_filename) or document.original_filename
    clean_filename = os.path.basename(filename)
    enc_filename = f"{clean_filename}.enc"
    document.encrypted_file.save(enc_filename, ContentFile(encrypted_bytes), save=False)

    normalized_emails = (
        normalize_and_validate_email_list(new_emails) if new_emails is not None else document.allowed_emails
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
    AccessVerificationToken.objects.filter(document=document, is_used=False).update(is_used=True)

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
        return False, _("El asiento ya se encuentra finalizado y el archivo ha sido retirado.")

    user_identifier = getattr(admin_user, "username", str(admin_user))
    user_email = getattr(admin_user, "email", user_identifier) or user_identifier

    with transaction.atomic():
        if document.encrypted_file:
            shred_and_delete_file(document.encrypted_file)

        document.is_consumed = True
        document.consumed_at = timezone.now()
        document.consumed_by = f"Finalizado manualmente por {user_identifier}"
        document.save(update_fields=["is_consumed", "consumed_at", "consumed_by", "updated_at"])

        detail_text = f"Asiento finalizado manualmente por {user_identifier} ({user_email})."
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

    return True, _("Asiento finalizado correctamente. El archivo ha sido destruido físicamente y la vicisitud ha quedado registrada en la auditoría legal.")


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
        doc = EncryptedDocument.objects.select_for_update().filter(pk=document.pk).first()
        if not doc or doc.is_consumed or not doc.is_expired():
            return False

        if doc.encrypted_file:
            shred_and_delete_file(doc.encrypted_file)

        doc.is_consumed = True
        doc.consumed_at = timezone.now()
        doc.consumed_by = "Sistema (Caducidad automática sin acceso en plazo)"
        doc.save(update_fields=["is_consumed", "consumed_at", "consumed_by", "updated_at"])

        expiry_str = doc.expires_at.strftime("%Y-%m-%d %H:%M") if doc.expires_at else "desconocida"
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
    logger.info(f"[ARCAMITTE] Proceso de caducidad completado: {count} documentos cerrados.")
    return count
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

    # Resolución del usuario que sube el archivo
    if uploaded_by is None and admin_user is not None:
        if hasattr(admin_user, "is_authenticated") and admin_user.is_authenticated:
            uploaded_by = admin_user

    # Comprobación de seguridad: El usuario debe pertenecer a la origin_uo si no es superusuario
    if uploaded_by is not None and hasattr(uploaded_by, "is_superuser") and not uploaded_by.is_superuser:
        if origin_uo is not None:
            if not UserUOMembership.objects.filter(user=uploaded_by, uo=origin_uo, is_active=True).exists():
                raise ValidationError(_("El usuario no pertenece a la UO emisora seleccionada."))

    normalized_emails = normalize_and_validate_email_list(allowed_emails)
    file_hash = (precalculated_hash or "").strip().lower() or calculate_file_sha256(original_file)

    existing_doc = EncryptedDocument.objects.filter(file_hash=file_hash).first()
    if existing_doc:
        if reopen_existing:
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
            )
            reactivated._is_reactivated = True
            return reactivated
        raise ValidationError(_("Ya existe un documento registrado con este mismo hash SHA-256."))

    dek: bytes = Fernet.generate_key()
    fernet_dek = Fernet(dek)

    original_file.seek(0)
    original_bytes: bytes = original_file.read()
    ciphertext_bytes: bytes = fernet_dek.encrypt(original_bytes)

    server_key = get_server_fernet_key()
    server_fernet = Fernet(server_key)
    encrypted_dek_str: str = server_fernet.encrypt(dek).decode("utf-8")

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

    document = EncryptedDocument(**doc_kwargs)
    document.encrypted_file.save(encrypted_filename, ContentFile(ciphertext_bytes), save=False)
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
        hashlib.pbkdf2_hmac("sha256", clean_email.encode("utf-8"), b"arcamitte_timing_salt", TIMING_ATTACK_PBKDF2_ITERATIONS)
        return True, GENERIC_ACCESS_MESSAGE

    try:
        normalized_email = validate_safe_email(clean_email)
    except ValidationError:
        hashlib.pbkdf2_hmac("sha256", b"invalid_email", b"arcamitte_timing_salt", TIMING_ATTACK_PBKDF2_ITERATIONS)
        return True, GENERIC_ACCESS_MESSAGE

    document = EncryptedDocument.objects.filter(file_hash=clean_hash).first()

    if not document:
        hashlib.pbkdf2_hmac("sha256", normalized_email.encode("utf-8"), b"arcamitte_timing_salt", TIMING_ATTACK_PBKDF2_ITERATIONS)
        return True, GENERIC_ACCESS_MESSAGE

    # Verificación de autorización previa (Mitigación de enumeración y fuga de metadatos)
    if not document.is_email_authorized(normalized_email):
        hashlib.pbkdf2_hmac("sha256", normalized_email.encode("utf-8"), b"arcamitte_timing_salt", TIMING_ATTACK_PBKDF2_ITERATIONS)
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
        desc_part = f"• Descripción: {document.description}\n" if document.description else ""
        
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
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@arcamitte.local"),
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
        desc_part = f"• Descripción: {document.description}\n" if document.description else ""
        dispatch_email(
            subject=_("Aviso: Copia ya descargada de '%(filename)s'") % {"filename": doc_name},
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
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@arcamitte.local"),
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
        redeem_url = f"{base_url.rstrip('/')}{redeem_path}{query_params}" if base_url else f"{redeem_path}{query_params}"

        policy_note = (
            "El documento permanecerá disponible hasta que todos los destinatarios autorizados hayan completado su descarga."
            if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
            else "Por motivos de seguridad y confidencialidad, el documento dejará de estar disponible una vez completada la primera descarga."
        )

        doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
        desc_part = f"• Descripción: {document.description}\n" if document.description else ""
        email_subject = _("Código de verificación para '%(filename)s' - Arcamitte") % {"filename": doc_name}
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
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@arcamitte.local"),
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
    hashlib.pbkdf2_hmac("sha256", normalized_email.encode("utf-8"), b"arcamitte_timing_salt", TIMING_ATTACK_PBKDF2_ITERATIONS)
    return True, GENERIC_ACCESS_MESSAGE


def generate_corporate_email_text(document: EncryptedDocument, base_url: str | None = None) -> str:
    """
    Genera el texto formal para notificar al destinatario,
    incluyendo nombre del archivo, descripción, identificador SHA-256 e instrucciones de acceso.
    """
    url_root = (base_url or getattr(settings, "ARCAMITTE_BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
    solicitar_url = f"{url_root}/arcamitte/solicitar/?hash={document.file_hash}"
    policy_desc = (
        "El documento permanecerá disponible en la plataforma hasta que todos los destinatarios autorizados hayan completado su descarga."
        if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
        else "Por motivos de seguridad y confidencialidad, el documento dejará de estar disponible una vez completada la primera descarga."
    )
    desc_part = f"\n• Descripción: {document.description}" if document.description else ""

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
        return False, b"", "", _("El código de verificación no es válido o ha expirado.")

    document = token.document

    # Comprobación de caducidad del asiento
    if not document.is_consumed and document.is_expired():
        check_and_expire_document(document, client_ip=client_ip, user_agent=user_agent)
        token.is_used = True
        token.save(update_fields=["is_used"])
        return False, b"", "", _("El plazo de disponibilidad de este documento ha expirado y el archivo ha sido retirado de la plataforma.")

    if document.is_consumed:
        token.is_used = True
        token.save(update_fields=["is_used"])
        return False, b"", "", _("El documento ya no se encuentra disponible para su descarga.")

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
            _("Usted ya ha descargado este documento con anterioridad. Cada destinatario dispone de un único acceso."),
        )

    is_match = secrets.compare_digest(token.otp_code.encode("utf-8"), clean_otp.encode("utf-8"))

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
                _("Ha superado el número máximo de intentos permitidos. El acceso ha sido bloqueado por seguridad."),
            )
        else:
            remaining = 3 - token.failed_attempts
            return (
                False,
                b"",
                "",
                _("Código de verificación incorrecto. Intentos restantes: %(remaining)d.")
                % {"remaining": remaining},
            )

    try:
        with transaction.atomic():
            token.is_used = True
            token.save(update_fields=["is_used"])

            server_key = get_server_fernet_key()
            server_fernet = Fernet(server_key)
            dek_bytes = server_fernet.decrypt(document.encrypted_dek.encode("utf-8"))

            if not document.encrypted_file:
                return False, b"", "", _("El archivo cifrado no está disponible en el servidor.")

            document.encrypted_file.seek(0)
            encrypted_file_bytes = document.encrypted_file.read()

            dek_fernet = Fernet(dek_bytes)
            decrypted_bytes = dek_fernet.decrypt(encrypted_file_bytes)

            consumed_list = list(document.consumed_recipients or [])
            if token.email not in [e.strip().lower() for e in consumed_list if isinstance(e, str)]:
                consumed_list.append(token.email)
            document.consumed_recipients = consumed_list

            should_burn = False
            if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
                if document.are_all_recipients_consumed():
                    should_burn = True
                    document.consumed_by = f"todos los destinatarios autorizados ({len(consumed_list)}/{len(document.allowed_emails)})"
                else:
                    should_burn = False
                    document.consumed_by = f"Parcial: {len(consumed_list)}/{len(document.allowed_emails)}"
            else:
                should_burn = True
                document.consumed_by = token.email

            if should_burn:
                shred_and_delete_file(document.encrypted_file)
                document.is_consumed = True
                document.consumed_at = timezone.now()
                document.save(update_fields=["is_consumed", "consumed_by", "consumed_at", "consumed_recipients"])
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

        return True, decrypted_bytes, document.original_filename, _("Documento descifrado con éxito.")

    except Exception as exc:
        logger.error(f"[ARCAMITTE ERROR] Fallo durante descifrado y canje del documento: {exc}")
        return False, b"", "", _("Se produjo un error al procesar el descifrado del documento.")


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
    if document.is_consumed:
        return False, b"", "", _("El documento ya ha sido consumido y destruido del servidor.")

    if not document.encrypted_file:
        return False, b"", "", _("El archivo cifrado no está disponible.")

    if (
        admin_user
        and hasattr(admin_user, "is_authenticated")
        and admin_user.is_authenticated
        and not getattr(admin_user, "is_superuser", False)
    ):
        user_uos = list(
            UserUOMembership.objects.filter(
                user=admin_user,
                is_active=True,
                role__in=[UserUOMembership.Role.AUDITOR, UserUOMembership.Role.ADMIN],
            ).values_list("uo_id", flat=True)
        )
        is_authorized_uo = False
        if document.origin_uo_id and document.origin_uo_id in user_uos or document.target_uo_id and document.target_uo_id in user_uos:
            is_authorized_uo = True
        elif not document.origin_uo_id and not document.target_uo_id:
            # Documento sin UO asignada (legado / staging)
            is_authorized_uo = True

        if not is_authorized_uo:
            return False, b"", "", _("No tiene permisos de auditoría en la UO asociada a este documento.")

    try:
        server_key = get_server_fernet_key()
        server_fernet = Fernet(server_key)
        dek_bytes = server_fernet.decrypt(document.encrypted_dek.encode("utf-8"))

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
            origin_uo=document.origin_uo,
            target_uo=document.target_uo,
            ip_address=client_ip,
            user_agent=user_agent,
        )

        logger.info(
            f"[ARCAMITTE AUDIT] Descarga administrativa preservada realizada por '{admin_identifier}' "
            f"para documento {document.file_hash[:12]}..."
        )
        return True, decrypted_bytes, document.original_filename, _("Descarga de auditoría completada.")

    except Exception as exc:
        logger.error(f"[ARCAMITTE ERROR] Error en descarga de auditoría administrativa: {exc}")
        return False, b"", "", _("Error al descifrar el documento para auditoría.")


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
    if not user or getattr(user, "is_superuser", False):
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

    if not user.is_staff:
        user.is_staff = True
        user.save(update_fields=["is_staff"])

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
                "description": "Gestión de personal y talento"
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
                "is_staff": true,
                "password": "PasswordOpcional123"
            }
        ]
    }
    """
    if not isinstance(data, dict):
        raise ValidationError(_("El contenido JSON debe ser un objeto/diccionario raíz."))

    uo_list = data.get("organizational_units", [])
    user_list = data.get("users", [])

    if not isinstance(uo_list, list) or not isinstance(user_list, list):
        raise ValidationError(_("'organizational_units' y 'users' deben ser listas JSON."))

    uos_processed = 0
    users_processed = 0
    feedback_notes = []

    User = get_user_model()

    with transaction.atomic():
        # 1. Procesar Unidades Organizativas
        for uo_data in uo_list:
            if not isinstance(uo_data, dict):
                raise ValidationError(_("Cada entrada en 'organizational_units' debe ser un objeto JSON."))
            code = uo_data.get("numeric_code")
            alias = (uo_data.get("alias") or "").strip().upper()
            name = (uo_data.get("name") or "").strip()
            email = (uo_data.get("email") or "").strip().lower()
            description = (uo_data.get("description") or "").strip()

            if not code or not alias or not name or not email:
                raise ValidationError(
                    _(f"Cada UO debe incluir obligatoriamente 'numeric_code', 'alias', 'name' y 'email'. Entrada inválida: {uo_data}")
                )

            try:
                code_int = int(code)
            except (ValueError, TypeError):
                raise ValidationError(
                    _(f"El campo 'numeric_code' en UO '{alias}' debe ser un número entero válido: {code}")
                )

            clean_email = validate_safe_email(email)

            uo, created = OrganizationalUnit.objects.update_or_create(
                numeric_code=code_int,
                defaults={
                    "alias": alias,
                    "name": name,
                    "email": clean_email,
                    "description": description,
                    "is_active": True,
                },
            )
            uos_processed += 1
            action_desc = "creada" if created else "actualizada"
            feedback_notes.append(f"UO [{uo.numeric_code}] {uo.alias} {action_desc} exitosamente.")

        # 2. Procesar Usuarios y Membresías
        for u_data in user_list:
            if not isinstance(u_data, dict):
                raise ValidationError(_("Cada entrada en 'users' debe ser un objeto JSON."))
            username = (u_data.get("username") or "").strip()
            email = (u_data.get("email") or "").strip().lower()
            first_name = (u_data.get("first_name") or "").strip()
            last_name = (u_data.get("last_name") or "").strip()
            raw_role = (u_data.get("role") or UserUOMembership.Role.OPERATOR).strip().upper()
            uo_alias = (u_data.get("uo_alias") or "").strip().upper()
            uo_code = u_data.get("uo_numeric_code")
            is_staff = bool(u_data.get("is_staff", True))
            raw_password = u_data.get("password")

            if not username or not email:
                raise ValidationError(
                    _(f"Cada usuario debe incluir obligatoriamente 'username' y 'email'. Entrada inválida: {u_data}")
                )

            clean_email = validate_safe_email(email)

            # Buscar UO de destino
            target_uo = None
            if uo_alias:
                target_uo = OrganizationalUnit.objects.filter(alias=uo_alias).first()
            if not target_uo and uo_code:
                try:
                    target_uo = OrganizationalUnit.objects.filter(numeric_code=int(uo_code)).first()
                except (ValueError, TypeError):
                    target_uo = None

            if not target_uo:
                raise ValidationError(
                    _(f"No se encontró la UO '{uo_alias or uo_code}' asociada al usuario '{username}'. Debe definirse previamente.")
                )

            role = raw_role if raw_role in UserUOMembership.Role.values else UserUOMembership.Role.OPERATOR

            user = User.objects.filter(username=username).first()
            user_created = False
            if not user:
                user = User(
                    username=username,
                    email=clean_email,
                    first_name=first_name,
                    last_name=last_name,
                    is_staff=is_staff,
                )
                if raw_password:
                    user.set_password(raw_password)
                else:
                    user.set_password(secrets.token_urlsafe(16))
                user.save()
                user_created = True
            else:
                user.email = clean_email
                if first_name:
                    user.first_name = first_name
                if last_name:
                    user.last_name = last_name
                user.is_staff = is_staff
                if raw_password:
                    user.set_password(raw_password)
                user.save()

            UserUOMembership.objects.update_or_create(
                user=user,
                uo=target_uo,
                defaults={"role": role, "is_active": True},
            )
            sync_user_role_permissions(user, role)
            users_processed += 1
            action_desc = "creado" if user_created else "actualizado"
            feedback_notes.append(
                f"Usuario '{username}' ({clean_email}) {action_desc} y asignado a UO {target_uo.alias} con rol {role}."
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


def reset_user_password_and_notify(user: Any, requested_by: Any = None) -> tuple[bool, str]:
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

    req_info = getattr(requested_by, "username", "Autoservicio") if requested_by else "Autoservicio"
    logger.info(
        f"[ARCAMITTE SECURITY] Reseteo de contraseña ejecutado para usuario '{user.username}' por '{req_info}'."
    )
    return True, str(_("Se ha restablecido la contraseña y se ha remitido la clave temporal al correo del usuario."))


def is_uo_admin(user: Any, uo: OrganizationalUnit) -> bool:
    """
    Verifica si el usuario dispone de privilegios de administración sobre la UO especificada.
    Los superusuarios tienen privilegios sobre todas las UOs.
    """
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser:
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
    if user.is_superuser:
        return OrganizationalUnit.objects.all().order_by("numeric_code")
    return OrganizationalUnit.objects.filter(
        memberships__user=user,
        memberships__role=UserUOMembership.Role.ADMIN,
        memberships__is_active=True,
    ).order_by("numeric_code").distinct()


class DocumentManagementService:
    """
    Clase de servicio unificada para operaciones sobre documentos confidenciales.
    """

    def upload_and_encrypt_document(
        self,
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
        **kwargs: Any,
    ) -> EncryptedDocument:
        return upload_and_encrypt_document(
            original_file=original_file,
            allowed_emails=allowed_emails,
            burn_policy=burn_policy,
            description=description,
            reopen_existing=reopen_existing,
            origin_uo=origin_uo,
            target_uo=target_uo,
            uploaded_by=uploaded_by,
            admin_user=admin_user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def reactivate_document(
        self,
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
    ) -> EncryptedDocument:
        return reactivate_document(
            document=document,
            original_file=original_file,
            new_emails=new_emails,
            burn_policy=burn_policy,
            new_description=new_description,
            origin_uo=origin_uo,
            target_uo=target_uo,
            uploaded_by=uploaded_by,
            admin_user=admin_user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def generate_corporate_email_text(
        self,
        document: EncryptedDocument,
        base_url: str | None = None,
    ) -> str:
        return generate_corporate_email_text(document=document, base_url=base_url)

    def request_document_access(
        self,
        file_hash: str,
        email: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
        base_url: str | None = None,
        **kwargs: Any,
    ) -> tuple[bool, str]:
        return request_document_access(
            file_hash=file_hash,
            email=email,
            client_ip=client_ip,
            user_agent=user_agent,
            base_url=base_url,
        )

    def consume_document_with_otp(
        self,
        file_hash: str,
        email: str,
        entered_otp: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[bool, bytes, str, str]:
        return consume_document_with_otp(
            file_hash=file_hash,
            email=email,
            entered_otp=entered_otp,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def admin_decrypt_document(
        self,
        document: EncryptedDocument,
        admin_user: Any = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[bool, bytes, str, str]:
        return admin_decrypt_document(
            document=document,
            admin_user=admin_user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def terminate_document_manually(
        self,
        document: EncryptedDocument,
        admin_user: Any,
        client_ip: str | None = None,
        user_agent: str | None = None,
        reason: str = "",
    ) -> tuple[bool, str]:
        return terminate_document_manually(
            document=document,
            admin_user=admin_user,
            client_ip=client_ip,
            user_agent=user_agent,
            reason=reason,
        )

    def check_and_expire_document(
        self,
        document: EncryptedDocument,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> bool:
        return check_and_expire_document(
            document=document,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def process_expired_documents(self) -> int:
        return process_expired_documents()

    def shred_and_delete_file(self, file_field: Any) -> bool:
        return shred_and_delete_file(file_field)
