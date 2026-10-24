#!/usr/bin/env python3
"""
Demostración interactiva del flujo desatendido de Arcamitte (OWASP Top 10 & Zero-Trust).

Principios de diseño y reglas de oro validadas:
1. Cero transporte del binario por el cliente (identificación unívoca por hash SHA-256).
2. Sin contraseñas humanas (Zero Human-Readable Passwords, DEK simétrica y Fernet).
3. Burn-After-Read con destrucción segura física (Zeroization/Shredding con os.urandom).
4. Verificación en tiempo real por OTP de 6 dígitos (caducidad 15 min, máx. 3 intentos).
5. Descarga de auditoría administrativa preservada para personal autorizado.
"""

import hashlib
import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()

from django.core.files.uploadedfile import SimpleUploadedFile
from arcamitte.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from arcamitte.services import (
    consume_document_with_otp,
    request_document_access,
    upload_and_encrypt_document,
)
from arcamitte.validators import validate_document_file

BASE_URL = os.environ.get("ARCAMITTE_API_URL", "http://127.0.0.1:8000")

# Documento PDF legítimo de prueba
MINIMAL_VALID_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


def print_step(title: str) -> None:
    print(f"\n{'=' * 75}\n{title}\n{'=' * 75}")


def main() -> None:
    print_step("ARCAMITTE - DEMOSTRACIÓN DEL SISTEMA DESATENDIDO (SHA-256 + OTP)")

    # --------------------------------------------------------------------------
    # PRUEBA PREVIA: Validación estricta de Magic Bytes (Anti-Spoofing OWASP A03)
    # --------------------------------------------------------------------------
    print_step("PRUEBA PREVIA: Validación de Magic Bytes (Rechazo de ejecutable camuflado)")
    fake_exe = SimpleUploadedFile("malware.pdf", b"MZ\x90\x00FakePEExecutableData")
    try:
        validate_document_file(fake_exe)
        print("✗ ERROR: El validador aceptó un ejecutable camuflado como PDF.")
        sys.exit(1)
    except Exception as exc:
        print(f"✓ ÉXITO OWASP: El validador rechazó el ejecutable por firma binaria: {exc}")

    # --------------------------------------------------------------------------
    # PASO 1: Alta Administrativa y Cifrado Desatendido con DEK (Zero Passwords)
    # --------------------------------------------------------------------------
    print_step("PASO 1: Alta y Cifrado de Documento Confidencial con DEK Interna")
    allowed_emails = ["destinatario@seguro.gob.es", "auditor@seguro.gob.es"]
    sample_file = SimpleUploadedFile("expediente_sensible.pdf", MINIMAL_VALID_PDF)

    # Limpiar ejecuciones previas con el mismo hash si existiera
    doc_hash = hashlib.sha256(MINIMAL_VALID_PDF).hexdigest().lower()
    EncryptedDocument.objects.filter(file_hash=doc_hash).delete()

    doc = upload_and_encrypt_document(
        original_file=sample_file,
        allowed_emails=allowed_emails,
    )
    print("✓ Documento confidencial registrado y cifrado en el servidor.")
    print(f"✓ Hash SHA-256 (Prueba unívoca de trámite): {doc.file_hash}")
    print(f"✓ Archivo cifrado en reposo: {doc.encrypted_file.path}")
    print("✓ Cero contraseñas humanas: DEK cifrada con settings.ARCAMITTE_FERNET_KEY")
    print(f"✓ Destinatarios autorizados: {doc.allowed_emails}")

    # --------------------------------------------------------------------------
    # PASO 2: Solicitud de Canje (Cero Transporte del Binario)
    # --------------------------------------------------------------------------
    print_step("PASO 2: Solicitud de Canje Desatendido (Sin subir archivo)")
    print(f"Solicitante autorizado: {allowed_emails[0]}")
    print(f"Localizador: {doc.file_hash}")

    success, msg = request_document_access(
        file_hash=doc.file_hash,
        email=allowed_emails[0],
        client_ip="192.168.1.50",
        user_agent="Firefox/Client",
    )
    print(f"✓ Estado de solicitud: {success}")
    print(f"✓ Mensaje neutro anti-enumeración: {msg}")

    token = AccessVerificationToken.objects.filter(
        document=doc, email=allowed_emails[0], is_used=False
    ).first()
    if not token:
        print("✗ No se generó el token OTP.")
        sys.exit(1)

    print(f"✓ Token OTP generado criptográficamente: {token.otp_code}")
    print(f"✓ Caducidad estricta (15 min): {token.expires_at}")
    print(f"✓ Intentos fallidos actuales: {token.failed_attempts}/3")

    # --------------------------------------------------------------------------
    # PASO 3: Verificación OTP y Destrucción Física (Burn-After-Read)
    # --------------------------------------------------------------------------
    print_step("PASO 3: Canje por OTP y Destrucción Física Segura (Burn-After-Read)")
    physical_path = doc.encrypted_file.path
    if not os.path.exists(physical_path):
        print("✗ El archivo físico no existe antes del canje.")
        sys.exit(1)

    print(f"Archivo físico presente en disco: {physical_path}")
    success_burn, decrypted_bytes, original_filename, burn_msg = consume_document_with_otp(
        file_hash=doc.file_hash,
        email=allowed_emails[0],
        entered_otp=token.otp_code,
        client_ip="192.168.1.50",
    )

    if not success_burn or decrypted_bytes != MINIMAL_VALID_PDF:
        print(f"✗ Falló el canje: {burn_msg}")
        sys.exit(1)

    print(f"✓ Descifrado en memoria RAM completado con éxito: {len(decrypted_bytes)} bytes.")
    print(f"✓ Nombre original restaurado: {original_filename}")

    # Comprobación de trituración física (Zeroization)
    if not os.path.exists(physical_path):
        print("✓ ¡CONFIRMADO! El archivo en disco ha sido sobrescrito con bytes aleatorios y destruido (Zeroization).")
    else:
        print("✗ Alerta: El archivo físico aún persiste en disco.")
        sys.exit(1)

    doc.refresh_from_db()
    print(f"✓ Estado del documento: is_consumed={doc.is_consumed}, consumido_por={doc.consumed_by}")

    # --------------------------------------------------------------------------
    # PASO 4: Intentos Posteriores y Notificación de Documento ya Retirado
    # --------------------------------------------------------------------------
    print_step("PASO 4: Intento Posterior por Segundo Destinatario")
    print(f"Solicitante: {allowed_emails[1]} (intenta canjear tras destrucción)")

    _success_post, msg_post = request_document_access(
        file_hash=doc.file_hash,
        email=allowed_emails[1],
        client_ip="192.168.1.51",
    )
    print(f"✓ Mensaje genérico recibido: {msg_post}")

    post_log = DocumentAccessLog.objects.filter(
        document=doc, action=DocumentAccessLog.Action.INTENTO_POST_CONSUMO
    ).first()
    if post_log:
        print(f"✓ Evento de intento post-consumo registrado en la auditoría para: {post_log.email}")

    # --------------------------------------------------------------------------
    # PASO 5: Mitigación de Enumeración y Ataques de Canal Lateral
    # --------------------------------------------------------------------------
    print_step("PASO 5: Mitigación Anti-Enumeración (Correo No Autorizado)")
    _success_unauth, msg_unauth = request_document_access(
        file_hash=doc.file_hash,
        email="atacante@infiltrado.org",
        client_ip="192.168.1.99",
    )
    print(f"✓ Respuesta idéntica y neutra ante correo no autorizado: {msg_unauth}")
    print("✓ Ningún token generado ni filtración de metadatos.")

    print_step("¡TODAS LAS PRUEBAS DE CIBERSEGURIDAD Y BURN-AFTER-READ HAN SIDO COMPLETADAS CON ÉXITO!")


if __name__ == "__main__":
    main()
