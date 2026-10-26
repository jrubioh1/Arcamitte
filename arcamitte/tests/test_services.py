import hashlib
import io
import os
import shutil
import tempfile
import zipfile
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone

from arcamitte.apps import ArcamitteConfig
from arcamitte.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from arcamitte.services import (
    admin_decrypt_document,
    consume_document_with_otp,
    generate_corporate_email_text,
    reactivate_document,
    request_document_access,
    shred_and_delete_file,
    upload_and_encrypt_document,
)
from arcamitte.validators import validate_document_file, validate_safe_email

User = get_user_model()
TEST_FERNET_KEY = Fernet.generate_key().decode()

MINIMAL_TEST_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


def create_minimal_odt_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        zf.writestr("content.xml", "<document-content></document-content>")
    return buf.getvalue()


def create_minimal_docx_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<document></document>")
    return buf.getvalue()


@override_settings(ARCAMITTE_FERNET_KEY=TEST_FERNET_KEY)
class ArcamitteSecurityAndServicesTestCase(TestCase):
    """
    Suite exhaustiva de pruebas unitarias de Ciberseguridad para Arcamitte:
    - Validación de firmas binarias (Magic Bytes).
    - Cifrado de sobre (Envelope Encryption con DEK).
    - Verificación desatendida y OTP en tiempo real.
    - Destrucción segura física (Zeroization / Shredding).
    - Auditoría legal y protección contra Timing Attacks.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._temp_media = tempfile.mkdtemp()
        cls._media_override = override_settings(MEDIA_ROOT=cls._temp_media)
        cls._media_override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._media_override.disable()
        shutil.rmtree(cls._temp_media, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        from django.conf import settings

        settings.ARCAMITTE_FERNET_KEY = TEST_FERNET_KEY
        self.test_content = MINIMAL_TEST_PDF
        self.expected_sha256 = hashlib.sha256(self.test_content).hexdigest().lower()
        self.allowed_email = "destinatario@seguro.gob.es"
        self.other_email = "atacante@malicioso.com"

        self.admin_user = User.objects.create_superuser(
            username="admin_auditor",
            email="admin@arcamitte.local",
            password="StrongPassword#2026",
        )

    # --------------------------------------------------------------------------
    # 1. VALIDACIÓN EN ARRANQUE (arcamitte/apps.py)
    # --------------------------------------------------------------------------
    def test_startup_validation_valid_key(self):
        """Valida que una clave Fernet url-safe válida de 32 bytes pase la verificación."""
        import arcamitte
        config = ArcamitteConfig("arcamitte", arcamitte)
        with override_settings(ARCAMITTE_FERNET_KEY=Fernet.generate_key().decode()):
            # No debe lanzar excepción
            config.ready()

    def test_startup_validation_missing_key(self):
        """Si falta ARCAMITTE_FERNET_KEY, debe lanzar ImproperlyConfigured."""
        import arcamitte
        config = ArcamitteConfig("arcamitte", arcamitte)
        with override_settings(ARCAMITTE_FERNET_KEY=None):
            with self.assertRaises(ImproperlyConfigured):
                config.ready()

    def test_startup_validation_invalid_length_key(self):
        """Si la clave no decodifica a 32 bytes, debe lanzar ImproperlyConfigured."""
        import arcamitte
        config = ArcamitteConfig("arcamitte", arcamitte)
        with override_settings(ARCAMITTE_FERNET_KEY="invalid-short-key"):
            with self.assertRaises(ImproperlyConfigured):
                config.ready()

    # --------------------------------------------------------------------------
    # 2. VALIDACIONES DE ARCHIVO Y EMAIL (OWASP A03 / A08)
    # --------------------------------------------------------------------------
    def test_format_validation_pdf_and_office(self):
        """Formatos válidos PDF, ODT y DOCX deben ser admitidos."""
        pdf_file = SimpleUploadedFile("expediente.pdf", self.test_content)
        self.assertIsNotNone(validate_document_file(pdf_file))

        odt_file = SimpleUploadedFile("expediente.odt", create_minimal_odt_bytes())
        self.assertIsNotNone(validate_document_file(odt_file))

        docx_file = SimpleUploadedFile("expediente.docx", create_minimal_docx_bytes())
        self.assertIsNotNone(validate_document_file(docx_file))

    def test_format_validation_spoofed_executable_rejected(self):
        """Un ejecutable (.exe / .sh) camuflado como PDF debe ser bloqueado por Magic Bytes."""
        fake_pdf = SimpleUploadedFile("malware.pdf", b"MZ\x90\x00\x03\x00\x00\x00malicious binary content")
        with self.assertRaises(ValidationError):
            validate_document_file(fake_pdf)

    def test_safe_email_crlf_injection(self):
        """Intento de inyección CRLF en cabecera de correo debe ser bloqueado."""
        with self.assertRaises(ValidationError):
            validate_safe_email("user@corp.com\r\nBcc: spy@evil.org")

    # --------------------------------------------------------------------------
    # 3. REGISTRO Y CIFRADO DESATENDIDO (upload_and_encrypt_document)
    # --------------------------------------------------------------------------
    def test_upload_and_encrypt_document_success(self):
        """El documento original debe cifrarse con una DEK única y guardarse en disco."""
        upload_file = SimpleUploadedFile("contrato.pdf", self.test_content)
        doc = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=[self.allowed_email, "OTRO@SEGURO.GOB.ES "],
        )

        self.assertEqual(doc.file_hash, self.expected_sha256)
        self.assertEqual(doc.original_filename, "contrato.pdf")
        self.assertFalse(doc.is_consumed)
        self.assertIn(self.allowed_email, doc.allowed_emails)
        self.assertIn("otro@seguro.gob.es", doc.allowed_emails)

        # El contenido en disco debe estar cifrado (no contener la firma PDF en claro)
        doc.encrypted_file.seek(0)
        cipher_bytes = doc.encrypted_file.read()
        self.assertNotEqual(cipher_bytes, self.test_content)
        self.assertNotIn(b"%PDF-1.4", cipher_bytes)

        # La DEK interna debe estar cifrada con ARCAMITTE_FERNET_KEY
        server_fernet = Fernet(TEST_FERNET_KEY.encode())
        decrypted_dek = server_fernet.decrypt(doc.encrypted_dek.encode())
        self.assertEqual(len(decrypted_dek), 44)  # Clave Fernet base64 url-safe

    def test_upload_duplicate_hash_rejected(self):
        """No debe permitirse registrar dos veces un archivo con el mismo hash SHA-256."""
        file1 = SimpleUploadedFile("doc1.pdf", self.test_content)
        upload_and_encrypt_document(file1, [self.allowed_email])

        file2 = SimpleUploadedFile("doc2.pdf", self.test_content)
        with self.assertRaises(ValidationError):
            upload_and_encrypt_document(file2, [self.allowed_email])

    # --------------------------------------------------------------------------
    # 4. SOLICITUD DE ACCESO Y OTP (request_document_access)
    # --------------------------------------------------------------------------
    def test_request_access_authorized_email_sends_otp(self):
        """Un correo autorizado recibe un código OTP numérico de 6 dígitos."""
        upload_file = SimpleUploadedFile("secreto.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])

        mail.outbox.clear()
        success, message = request_document_access(
            file_hash=doc.file_hash,
            email=self.allowed_email,
            client_ip="192.168.1.100",
            user_agent="Mozilla/5.0 Test",
            base_url="https://arcamitte.example.com",
        )

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        self.assertIn(self.allowed_email, sent_email.to)

        # Buscar el token generado
        token = AccessVerificationToken.objects.filter(document=doc, email=self.allowed_email).first()
        self.assertIsNotNone(token)
        self.assertTrue(token.is_valid())
        self.assertEqual(len(token.otp_code), 6)
        self.assertTrue(token.otp_code.isdigit())
        self.assertIn(token.otp_code, sent_email.body)

        # Auditoría legal: debe registrarse action='otp_enviado'
        log = DocumentAccessLog.objects.filter(document=doc, action=DocumentAccessLog.Action.OTP_ENVIADO).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.email, self.allowed_email)
        self.assertEqual(log.ip_address, "192.168.1.100")

    def test_request_access_unauthorized_email_anti_enumeration(self):
        """Un correo no autorizado recibe respuesta genérica neutra sin emitir OTP."""
        upload_file = SimpleUploadedFile("secreto.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])

        mail.outbox.clear()
        success, message = request_document_access(
            file_hash=doc.file_hash,
            email=self.other_email,
            client_ip="192.168.1.101",
        )

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(AccessVerificationToken.objects.filter(email=self.other_email).count(), 0)

    def test_request_access_nonexistent_hash_anti_enumeration(self):
        """Un hash inexistente devuelve respuesta genérica neutra."""
        dummy_hash = "a" * 64
        mail.outbox.clear()
        success, message = request_document_access(
            file_hash=dummy_hash,
            email=self.allowed_email,
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 0)

    def test_request_access_post_consumed_notification(self):
        """Si el documento ya fue consumido, envía notificación informativa y audita."""
        upload_file = SimpleUploadedFile("doc_consumido.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])
        doc.is_consumed = True
        doc.consumed_by = "primero@seguro.gob.es"
        doc.consumed_at = timezone.now()
        doc.save()

        mail.outbox.clear()
        success, message = request_document_access(
            file_hash=doc.file_hash,
            email=self.allowed_email,
        )

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        self.assertIn(doc.file_hash, body)
        self.assertIn("ya fue retirado", body)
        self.assertIn("primero@seguro.gob.es", body)

        # Auditoría legal: intento_post_consumo
        log = DocumentAccessLog.objects.filter(document=doc, action=DocumentAccessLog.Action.INTENTO_POST_CONSUMO).first()
        self.assertIsNotNone(log)

    # --------------------------------------------------------------------------
    # 5. CANJE, DESCIFRADO Y BURN-AFTER-READ (consume_document_with_otp)
    # --------------------------------------------------------------------------
    def test_consume_document_with_otp_success_and_shredding(self):
        """Canje exitoso descifra en RAM y tritura de disco físicamente."""
        upload_file = SimpleUploadedFile("confidencial.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])
        physical_path = doc.encrypted_file.path
        self.assertTrue(os.path.exists(physical_path))

        request_document_access(doc.file_hash, self.allowed_email)
        token = AccessVerificationToken.objects.get(document=doc, email=self.allowed_email)

        success, decrypted_bytes, filename, msg = consume_document_with_otp(
            file_hash=doc.file_hash,
            email=self.allowed_email,
            entered_otp=token.otp_code,
            client_ip="192.168.1.105",
            user_agent="Firefox Secure",
        )

        self.assertTrue(success)
        self.assertEqual(decrypted_bytes, self.test_content)
        self.assertEqual(filename, "confidencial.pdf")

        # Comprobación de destrucción física (Burn-After-Read)
        self.assertFalse(os.path.exists(physical_path))

        # Estado del documento actualizado
        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)
        self.assertEqual(doc.consumed_by, self.allowed_email)
        self.assertIsNotNone(doc.consumed_at)

        # Token revocado
        token.refresh_from_db()
        self.assertTrue(token.is_used)

        # Auditoría legal: descifrado_exitoso_burn
        log = DocumentAccessLog.objects.filter(document=doc, action=DocumentAccessLog.Action.DESCIFRADO_EXITOSO_BURN).first()
        self.assertIsNotNone(log)

    def test_consume_document_wrong_otp_attempts_and_lock(self):
        """Código OTP erróneo descuenta intentos y se bloquea al 3er fallo."""
        upload_file = SimpleUploadedFile("expediente.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])

        request_document_access(doc.file_hash, self.allowed_email)
        token = AccessVerificationToken.objects.get(document=doc, email=self.allowed_email)

        # 1er fallo
        success1, _, _, msg1 = consume_document_with_otp(doc.file_hash, self.allowed_email, "999999")
        self.assertFalse(success1)
        self.assertIn("2", msg1)

        # 2do fallo
        success2, _, _, msg2 = consume_document_with_otp(doc.file_hash, self.allowed_email, "888888")
        self.assertFalse(success2)
        self.assertIn("1", msg2)

        # 3er fallo: bloqueo definitivo
        success3, _, _, msg3 = consume_document_with_otp(doc.file_hash, self.allowed_email, "777777")
        self.assertFalse(success3)
        self.assertIn("bloqueado", msg3.lower())

        token.refresh_from_db()
        self.assertTrue(token.is_used)
        self.assertEqual(token.failed_attempts, 3)

        # Auditoría legal: otp_invalido_bloqueado
        log = DocumentAccessLog.objects.filter(document=doc, action=DocumentAccessLog.Action.OTP_INVALIDO_BLOQUEADO).first()
        self.assertIsNotNone(log)

    # --------------------------------------------------------------------------
    # 6. DESCARGA DE AUDITORÍA ADMINISTRATIVA PRESERVADA
    # --------------------------------------------------------------------------
    def test_admin_decrypt_document_preserves_file(self):
        """La auditoría administrativa descifra en memoria sin destruir el archivo."""
        upload_file = SimpleUploadedFile("auditoria.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])
        physical_path = doc.encrypted_file.path

        success, decrypted_bytes, filename, msg = admin_decrypt_document(
            document=doc,
            admin_user=self.admin_user,
            client_ip="10.0.0.1",
        )

        self.assertTrue(success)
        self.assertEqual(decrypted_bytes, self.test_content)
        self.assertEqual(filename, "auditoria.pdf")

        # El archivo físico NO debe ser destruido
        self.assertTrue(os.path.exists(physical_path))

        # El documento NO debe estar marcado como consumido
        doc.refresh_from_db()
        self.assertFalse(doc.is_consumed)

        # Auditoría legal: admin_descarga_preservada
        log = DocumentAccessLog.objects.filter(
            document=doc, action=DocumentAccessLog.Action.ADMIN_DESCARGA_PRESERVADA
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.email, self.admin_user.email)

    def test_admin_decrypt_fails_if_already_consumed(self):
        """La descarga de auditoría no puede realizarse si el documento ya fue consumido."""
        upload_file = SimpleUploadedFile("doc.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])
        doc.is_consumed = True
        doc.save()

        success, _, _, msg = admin_decrypt_document(doc, admin_user=self.admin_user)
        self.assertFalse(success)
        self.assertIn("consumido", msg.lower())

    # --------------------------------------------------------------------------
    # 7. FUNCIÓN SHRED_AND_DELETE_FILE
    # --------------------------------------------------------------------------
    def test_shred_and_delete_file_zeroization(self):
        """Prueba de sobrescritura de archivo con bytes aleatorios y eliminación."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"DOCUMENTO_CONFIDENCIAL_DATOS_SENSIBLES_123456789")
            temp_path = f.name

        class MockFileField:
            path = temp_path
            def delete(self, save=False):
                pass

        result = shred_and_delete_file(MockFileField())
        self.assertTrue(result)
        self.assertFalse(os.path.exists(temp_path))

    # --------------------------------------------------------------------------
    # 8. POLÍTICA DE DESTRUCCIÓN Y REACTIVACIÓN DE DOCUMENTOS
    # --------------------------------------------------------------------------
    def test_burn_policy_all_recipients_partial_and_final_shredding(self):
        """
        En política ALL_RECIPIENTS:
        - El canje por el primer usuario no destruye el archivo físico en disco.
        - Se registra DESCIFRADO_PARCIAL_PRESERVADO y se anota en consumed_recipients.
        - Un segundo intento del mismo usuario es notificado de que ya retiró su copia.
        - Cuando el último destinatario consume, el archivo es triturado y se marca is_consumed=True.
        """
        user1 = "user1@seguro.gob.es"
        user2 = "user2@seguro.gob.es"
        upload_file = SimpleUploadedFile("expediente_multiple.pdf", self.test_content)
        doc = upload_and_encrypt_document(
            upload_file,
            allowed_emails=[user1, user2],
            burn_policy=EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
        )
        physical_path = doc.encrypted_file.path
        self.assertTrue(os.path.exists(physical_path))

        # 1. Primer usuario solicita y canjea
        request_document_access(doc.file_hash, user1)
        token1 = AccessVerificationToken.objects.get(document=doc, email=user1, is_used=False)
        success1, data1, name1, msg1 = consume_document_with_otp(
            file_hash=doc.file_hash,
            email=user1,
            entered_otp=token1.otp_code,
        )
        self.assertTrue(success1)
        self.assertEqual(data1, self.test_content)

        doc.refresh_from_db()
        # El documento aún NO está consumido del todo y el archivo sigue en disco
        self.assertFalse(doc.is_consumed)
        self.assertIn(user1, doc.consumed_recipients)
        self.assertTrue(os.path.exists(physical_path))

        # Registro de auditoría parcial
        self.assertTrue(
            DocumentAccessLog.objects.filter(
                document=doc,
                email=user1,
                action=DocumentAccessLog.Action.DESCIFRADO_PARCIAL_PRESERVADO,
            ).exists()
        )

        # Re-intento del primer usuario: recibe aviso de copia ya descargada
        mail.outbox.clear()
        request_document_access(doc.file_hash, user1)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("ya ha descargado previamente", mail.outbox[0].body)

        # 2. Segundo usuario (último) solicita y canjea
        request_document_access(doc.file_hash, user2)
        token2 = AccessVerificationToken.objects.get(document=doc, email=user2, is_used=False)
        success2, data2, name2, msg2 = consume_document_with_otp(
            file_hash=doc.file_hash,
            email=user2,
            entered_otp=token2.otp_code,
        )
        self.assertTrue(success2)
        self.assertEqual(data2, self.test_content)

        doc.refresh_from_db()
        # Ahora sí debe estar consumido y destruido físicamente
        self.assertTrue(doc.is_consumed)
        self.assertIn(user2, doc.consumed_recipients)
        self.assertFalse(os.path.exists(physical_path))

        # Registro de auditoría final
        self.assertTrue(
            DocumentAccessLog.objects.filter(
                document=doc,
                email=user2,
                action=DocumentAccessLog.Action.DESCIFRADO_EXITOSO_BURN,
            ).exists()
        )

    def test_reactivate_document_success(self):
        """
        Reactivación de un documento previamente consumido:
        - Re-cifra con una nueva DEK.
        - Restablece el estado is_consumed=False y limpia destinatarios consumidos.
        - Invalida tokens previos pendientes.
        - Registra evento de auditoría REACTIVACION_DOCUMENTO.
        """
        upload_file = SimpleUploadedFile("expediente_reactivar.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])
        original_dek = doc.encrypted_dek

        # Consumir el documento
        request_document_access(doc.file_hash, self.allowed_email)
        token = AccessVerificationToken.objects.get(document=doc, email=self.allowed_email, is_used=False)
        consume_document_with_otp(doc.file_hash, self.allowed_email, token.otp_code)

        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)

        # Reactivar con nuevo correo y archivo idéntico
        reupload_file = SimpleUploadedFile("expediente_reactivar.pdf", self.test_content)
        new_email = "nuevo_destinatario@seguro.gob.es"
        reactivated = reactivate_document(
            document=doc,
            original_file=reupload_file,
            new_emails=[new_email],
            admin_user=self.admin_user,
        )

        self.assertFalse(reactivated.is_consumed)
        self.assertIsNone(reactivated.consumed_by)
        self.assertIsNone(reactivated.consumed_at)
        self.assertEqual(reactivated.consumed_recipients, [])
        self.assertEqual(reactivated.allowed_emails, [new_email])
        self.assertNotEqual(reactivated.encrypted_dek, original_dek)
        self.assertTrue(os.path.exists(reactivated.encrypted_file.path))

        # Auditoría registrada
        self.assertTrue(
            DocumentAccessLog.objects.filter(
                document=reactivated,
                action=DocumentAccessLog.Action.REACTIVACION_DOCUMENTO,
            ).exists()
        )

    def test_upload_duplicate_hash_with_reopen_existing_true(self):
        """Si reopen_existing=True, subir el mismo archivo reactiva el documento automáticamente."""
        file1 = SimpleUploadedFile("doc1.pdf", self.test_content)
        doc1 = upload_and_encrypt_document(file1, [self.allowed_email])

        new_email = "segundo@seguro.gob.es"
        file2 = SimpleUploadedFile("doc2.pdf", self.test_content)
        doc2 = upload_and_encrypt_document(
            file2,
            [new_email],
            reopen_existing=True,
            admin_user=self.admin_user,
        )

        self.assertEqual(doc1.pk, doc2.pk)
        self.assertTrue(getattr(doc2, "_is_reactivated", False))
        self.assertIn(new_email, doc2.allowed_emails)

    def test_email_content_includes_filename_description_and_hash(self):
        """Los correos de verificación y avisos deben incluir nombre de archivo, descripción y hash SHA-256."""
        custom_desc = "Informe pericial confidencial de auditoría externa ejercicio 2026."
        upload_file = SimpleUploadedFile("informe_pericial.pdf", self.test_content)
        doc = upload_and_encrypt_document(
            upload_file,
            allowed_emails=[self.allowed_email],
            description=custom_desc,
        )

        mail.outbox.clear()
        success, _ = request_document_access(doc.file_hash, self.allowed_email)
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)

        sent_mail = mail.outbox[0]
        self.assertIn("informe_pericial.pdf", sent_mail.subject)
        self.assertIn("informe_pericial.pdf", sent_mail.body)
        self.assertIn(custom_desc, sent_mail.body)
        self.assertIn(doc.file_hash, sent_mail.body)

    def test_generate_corporate_email_text(self):
        """La función generate_corporate_email_text genera el formato corporativo con todos los datos necesarios."""
        custom_desc = "Documentación fiscal sensible para entrega confidencial."
        upload_file = SimpleUploadedFile("declaracion_renta.pdf", self.test_content)
        doc = upload_and_encrypt_document(
            upload_file,
            allowed_emails=[self.allowed_email],
            description=custom_desc,
        )

        text = generate_corporate_email_text(doc)
        self.assertIn("declaracion_renta.pdf", text)
        self.assertIn(custom_desc, text)
        self.assertIn(doc.file_hash, text)
        self.assertIn(f"/arcamitte/solicitar/?hash={doc.file_hash}", text)
        self.assertIn("Servicio de Entrega Segura - Arcamitte", text)

    def test_reactivate_document_updates_description(self):
        """Al reactivar un documento, se permite actualizar la descripción y ésta persiste."""
        upload_file = SimpleUploadedFile("doc_reactivar_desc.pdf", self.test_content)
        doc = upload_and_encrypt_document(
            upload_file,
            allowed_emails=[self.allowed_email],
            description="Descripción inicial",
        )
        self.assertEqual(doc.description, "Descripción inicial")

        reupload = SimpleUploadedFile("doc_reactivar_desc.pdf", self.test_content)
        new_desc = "Descripción completamente renovada para la nueva fase."
        reactivated = reactivate_document(
            document=doc,
            original_file=reupload,
            new_emails=["nuevo@seguro.gob.es"],
            new_description=new_desc,
            admin_user=self.admin_user,
        )

        self.assertEqual(reactivated.description, new_desc)
        doc.refresh_from_db()
        self.assertEqual(doc.description, new_desc)

    def test_dispatch_email_sync_and_async(self):
        """dispatch_email soporta despacho síncrono y asíncrono no bloqueante vía worker pool."""
        from arcamitte.services import dispatch_email
        from django.core import mail

        mail.outbox.clear()

        # 1. Despacho síncrono explícito
        fut_sync = dispatch_email(
            subject="Test Síncrono",
            message="Contenido de prueba síncrono",
            from_email="no-reply@arcamitte.local",
            recipient_list=["sync_test@empresa.com"],
            sync=True,
        )
        self.assertIsNone(fut_sync)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Test Síncrono")

        # 2. Despacho asíncrono explícito
        fut_async = dispatch_email(
            subject="Test Asíncrono",
            message="Contenido de prueba asíncrono",
            from_email="no-reply@arcamitte.local",
            recipient_list=["async_test@empresa.com"],
            sync=False,
        )
        self.assertIsNotNone(fut_async)
        # Esperamos a que el worker complete la ejecución
        fut_async.result(timeout=5)
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(mail.outbox[1].subject, "Test Asíncrono")

    def test_purge_expired_tokens_command(self):
        """El comando purge_expired_tokens elimina tokens caducados o usados conservando los válidos."""
        from io import StringIO
        from django.core.management import call_command
        from django.utils import timezone
        from arcamitte.models import AccessVerificationToken

        upload_file = SimpleUploadedFile("purge_test.pdf", self.test_content)
        doc = upload_and_encrypt_document(upload_file, [self.allowed_email])

        now = timezone.now()
        # 1. Token caducado
        tok_expired = AccessVerificationToken.objects.create(
            document=doc,
            email="expired@test.com",
            otp_code="111111",
            expires_at=now - timezone.timedelta(minutes=30),
            is_used=False,
        )
        # 2. Token usado
        tok_used = AccessVerificationToken.objects.create(
            document=doc,
            email="used@test.com",
            otp_code="222222",
            expires_at=now + timezone.timedelta(minutes=30),
            is_used=True,
        )
        # 3. Token activo válido
        tok_valid = AccessVerificationToken.objects.create(
            document=doc,
            email="valid@test.com",
            otp_code="333333",
            expires_at=now + timezone.timedelta(minutes=15),
            is_used=False,
        )

        # Probar con --dry-run
        out = StringIO()
        call_command("purge_expired_tokens", "--dry-run", stdout=out)
        self.assertIn("[DRY-RUN]", out.getvalue())
        self.assertTrue(AccessVerificationToken.objects.filter(pk=tok_expired.pk).exists())
        self.assertTrue(AccessVerificationToken.objects.filter(pk=tok_used.pk).exists())
        self.assertTrue(AccessVerificationToken.objects.filter(pk=tok_valid.pk).exists())

        # Ejecución real
        out_real = StringIO()
        call_command("purge_expired_tokens", stdout=out_real)
        self.assertIn("Purga completada con éxito", out_real.getvalue())

        # Verificar que se eliminaron los caducados y usados, y se mantuvo el válido
        self.assertFalse(AccessVerificationToken.objects.filter(pk=tok_expired.pk).exists())
        self.assertFalse(AccessVerificationToken.objects.filter(pk=tok_used.pk).exists())
        self.assertTrue(AccessVerificationToken.objects.filter(pk=tok_valid.pk).exists())

    def test_setup_staging_command(self):
        """El comando setup_staging inicializa el sandbox desatendido con UOs, superusuario y documentos descifrables."""
        from io import StringIO
        from pathlib import Path
        from django.conf import settings
        from django.core.management import call_command
        from arcamitte.models import OrganizationalUnit, EncryptedDocument

        ini_path = Path(settings.BASE_DIR) / "arcamitte.ini"
        ini_existed = ini_path.exists()
        ini_backup = ini_path.read_bytes() if ini_existed else None

        out = StringIO()
        try:
            call_command("setup_staging", stdout=out)
            output = out.getvalue()

            self.assertIn("ENTORNO DE STAGING SANDBOX MONTADO EXITOSAMENTE", output)
            self.assertTrue(OrganizationalUnit.objects.filter(alias="RRHH").exists())
            self.assertTrue(OrganizationalUnit.objects.filter(alias="LEGAL").exists())

            doc_rrhh = EncryptedDocument.objects.filter(original_filename="expediente_laboral_confidencial.pdf").first()
            doc_legal = EncryptedDocument.objects.filter(original_filename="acuerdo_confidencial_junta.pdf").first()
            self.assertIsNotNone(doc_rrhh)
            self.assertIsNotNone(doc_legal)

            # Verificar que los documentos precargados en staging pueden descifrarse en memoria sin InvalidToken
            ok_rrhh, decrypted_rrhh, _, msg_rrhh = admin_decrypt_document(doc_rrhh, admin_user=self.admin_user)
            ok_legal, decrypted_legal, _, msg_legal = admin_decrypt_document(doc_legal, admin_user=self.admin_user)
            self.assertTrue(ok_rrhh, msg_rrhh)
            self.assertTrue(ok_legal, msg_legal)
            self.assertTrue(decrypted_rrhh.startswith(b"%PDF-1.4"))
            self.assertTrue(decrypted_legal.startswith(b"%PDF-1.4"))
        finally:
            settings.ARCAMITTE_FERNET_KEY = TEST_FERNET_KEY
            if ini_existed and ini_backup is not None:
                ini_path.write_bytes(ini_backup)
            elif not ini_existed and ini_path.exists():
                ini_path.unlink()

    def test_arcamitte_ini_template_integrity(self):
        """Valida que la plantilla arcamitte.ini.template contenga todas las secciones requeridas."""
        import configparser
        from pathlib import Path
        from django.conf import settings

        template_path = Path(settings.BASE_DIR) / "arcamitte.ini.template"
        self.assertTrue(template_path.exists(), "La plantilla arcamitte.ini.template debe existir en la raíz.")

        cfg = configparser.ConfigParser()
        cfg.read(template_path, encoding="utf-8")
        self.assertTrue(cfg.has_section("django"))
        self.assertTrue(cfg.has_section("database"))
        self.assertTrue(cfg.has_section("security"))
        self.assertTrue(cfg.has_section("email"))
        self.assertTrue(cfg.has_section("throttling"))
        self.assertEqual(cfg.get("security", "fernet_key"), "cambiame-cambiame-cambiame-cambiame-cambiame=")

    def test_fernet_key_production_enforcement(self):
        """Valida que en entornos con clave placeholder o inválida, ArcamitteConfig.ready() impida el arranque."""
        import arcamitte
        from arcamitte.apps import ArcamitteConfig

        config = ArcamitteConfig("arcamitte", arcamitte)
        with override_settings(ARCAMITTE_FERNET_KEY="cambiame-cambiame-cambiame-cambiame-cambiame="):
            with self.assertRaises(ImproperlyConfigured):
                config.ready()


