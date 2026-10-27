"""
Batería de Pruebas Automatizadas de Seguridad Avanzada - FASE B:
1. Marca de Agua Forense Dinámica en Descargas PDF (Dynamic Forensic PDF Watermarking).
2. Motor Antivirus ClamAV en Memoria (Stream In-Memory Scanner zINSTREAM).
3. Sellado Criptográfico Cualificado de Tiempo (RFC 3161 TSA Protocol).

Cumplimiento Normativo:
- ENS (Nivel ALTO) / NIST SP 800-53 Rev. 5 (SI-3, AC-21, AU-10) / eIDAS (Reglamento UE 910/2014).
"""

from __future__ import annotations

import io
import socket
from unittest.mock import MagicMock, patch
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
import pypdf

from arcamitte.antivirus import (
    AntivirusConnectionError,
    AntivirusError,
    ping_clamav,
    scan_file_stream,
)
from arcamitte.models import (
    AccessVerificationToken,
    AuditExportReceipt,
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
)
from arcamitte.services import (
    admin_decrypt_document,
    consume_document_with_otp,
    create_certified_audit_export,
    upload_and_encrypt_document,
    verify_export_receipt,
)
from arcamitte.timestamping import (
    build_rfc3161_request,
    request_rfc3161_timestamp,
    token_from_base64,
    token_to_base64,
    verify_rfc3161_timestamp,
    TimestampingError,
)
from arcamitte.watermark import (
    WatermarkError,
    apply_pdf_watermark,
    _build_watermark_page_bytes,
)

User = get_user_model()


def _create_minimal_pdf_bytes(title: str = "Documento Confidencial", pages: int = 1) -> bytes:
    """Genera un archivo PDF válido en memoria para testing con pypdf."""
    writer = pypdf.PdfWriter()
    for i in range(pages):
        page = writer.add_blank_page(width=595.0, height=842.0)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _create_mock_tsr_bytes(hash_bytes: bytes, status: int = 0) -> bytes:
    """Genera una respuesta ASN.1 DER TimeStampResp simulada con el hash incrustado."""
    # SEQUENCE { PKIStatusInfo { INTEGER status }, ContentInfo { ... hash_bytes ... } }
    # PKIStatusInfo: 30 03 02 01 status
    status_info = b"\x30\x03\x02\x01" + bytes([status])
    # ContentInfo simulado con OID CMS (1.2.840.113549.1.7.2) y el hash de 32 bytes
    content_body = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" + b"\x04\x20" + hash_bytes
    content_info = b"\x30" + bytes([len(content_body)]) + content_body
    body = status_info + content_info
    tsr = b"\x30" + bytes([len(body)]) + body
    return tsr


class AdvancedSecurityPhaseBTests(TestCase):
    """Batería de pruebas unitarias y de abuso para las defensas de la Fase B."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            username="auditor_test",
            email="auditor@arcamitte.local",
            password="TestPassword123!Safe",
        )
        self.uo = OrganizationalUnit.objects.create(
            name="División de Ciberseguridad",
            alias="CIBER",
            numeric_code=2001,
        )
        UserUOMembership.objects.create(
            user=self.user,
            uo=self.uo,
            role=UserUOMembership.Role.AUDITOR,
            is_active=True,
        )

    # ==========================================================================
    # 1. PRUEBAS DE MARCA DE AGUA FORENSE DINÁMICA (PDF WATERMARKING)
    # ==========================================================================

    def test_watermark_page_bytes_generation(self) -> None:
        """Verifica que la generación de la página de marca de agua produce un PDF válido."""
        wm_pdf = _build_watermark_page_bytes(
            width=595.0,
            height=842.0,
            lines=["CONFIDENCIAL", "DESTINATARIO: test@arcamitte.local"],
            opacity=0.20,
        )
        self.assertTrue(wm_pdf.startswith(b"%PDF-1.4"))
        reader = pypdf.PdfReader(io.BytesIO(wm_pdf))
        self.assertEqual(len(reader.pages), 1)
        extracted = reader.pages[0].extract_text()
        self.assertIn("CONFIDENCIAL", extracted)
        self.assertIn("test@arcamitte.local", extracted)

    def test_apply_pdf_watermark_single_page(self) -> None:
        """Verifica el estampado forense en un documento PDF de una sola página."""
        pdf_bytes = _create_minimal_pdf_bytes(pages=1)
        watermarked = apply_pdf_watermark(
            pdf_content=pdf_bytes,
            recipient_email="agente01@gob.es",
            client_ip="192.168.1.100",
            doc_hash="a" * 64,
        )
        self.assertGreater(len(watermarked), len(pdf_bytes))
        reader = pypdf.PdfReader(io.BytesIO(watermarked))
        self.assertEqual(len(reader.pages), 1)
        text = reader.pages[0].extract_text()
        self.assertIn("agente01@gob.es", text)
        self.assertIn("192.168.1.100", text)
        self.assertIn("ARCAMITTE AUDIT TRAIL", text)

    def test_apply_pdf_watermark_multi_page(self) -> None:
        """Verifica que todas las páginas de un PDF multi-página reciben el estampado forense."""
        pdf_bytes = _create_minimal_pdf_bytes(pages=3)
        watermarked = apply_pdf_watermark(
            pdf_content=pdf_bytes,
            recipient_email="auditor@entidad.es",
            client_ip="10.0.50.25",
            doc_hash="b" * 64,
        )
        reader = pypdf.PdfReader(io.BytesIO(watermarked))
        self.assertEqual(len(reader.pages), 3)
        for page in reader.pages:
            text = page.extract_text()
            self.assertIn("auditor@entidad.es", text)
            self.assertIn("10.0.50.25", text)

    def test_apply_pdf_watermark_invalid_file_raises_error(self) -> None:
        """Verifica que un archivo binario corrupto o no-PDF lanza WatermarkError."""
        with self.assertRaises(WatermarkError):
            apply_pdf_watermark(
                pdf_content=b"NO_ES_UN_PDF_VALIDO",
                recipient_email="test@test.es",
                client_ip="1.2.3.4",
            )

    def test_watermark_applied_on_otp_consume(self) -> None:
        """Verifica que al canjear un PDF con OTP, los bytes retornados están marcados forensemente."""
        pdf_bytes = _create_minimal_pdf_bytes()
        uploaded_file = SimpleUploadedFile(
            "informe_secreto.pdf", pdf_bytes, content_type="application/pdf"
        )
        doc = upload_and_encrypt_document(
            original_file=uploaded_file,
            allowed_emails=["receptor@gob.es"],
            origin_uo=self.uo,
            uploaded_by=self.user,
        )

        token = AccessVerificationToken.objects.create(
            document=doc,
            email="receptor@gob.es",
            otp_code="123456",
            expires_at=timezone.now() + timezone.timedelta(minutes=10),
        )

        success, decrypted, filename, msg = consume_document_with_otp(
            file_hash=doc.file_hash,
            email="receptor@gob.es",
            entered_otp="123456",
            client_ip="185.20.30.40",
        )
        self.assertTrue(success)
        self.assertTrue(decrypted.startswith(b"%PDF"))
        # Comprobar que contiene la marca forense
        reader = pypdf.PdfReader(io.BytesIO(decrypted))
        text = reader.pages[0].extract_text()
        self.assertIn("receptor@gob.es", text)
        self.assertIn("185.20.30.40", text)

        # Verificar registro en auditoría de la marca aplicada
        wm_log = DocumentAccessLog.objects.filter(
            action=DocumentAccessLog.Action.MARCA_AGUA_APLICADA,
            email="receptor@gob.es",
        ).first()
        self.assertIsNotNone(wm_log)

    def test_watermark_applied_on_admin_decrypt(self) -> None:
        """Verifica que en descargas de auditoría administrativa también se aplica la marca forense."""
        pdf_bytes = _create_minimal_pdf_bytes()
        uploaded_file = SimpleUploadedFile(
            "acta_confidencial.pdf", pdf_bytes, content_type="application/pdf"
        )
        doc = upload_and_encrypt_document(
            original_file=uploaded_file,
            allowed_emails=["personal@gob.es"],
            origin_uo=self.uo,
            uploaded_by=self.user,
        )

        success, decrypted, filename, msg = admin_decrypt_document(
            document=doc,
            admin_user=self.user,
            client_ip="10.20.30.40",
        )
        self.assertTrue(success)
        reader = pypdf.PdfReader(io.BytesIO(decrypted))
        text = reader.pages[0].extract_text()
        self.assertIn("auditor@arcamitte.local", text)
        self.assertIn("10.20.30.40", text)

    # ==========================================================================
    # 2. PRUEBAS DE INTEGRACIÓN CON MOTOR ANTIVIRUS CLAMAV (zINSTREAM)
    # ==========================================================================

    @patch("arcamitte.antivirus._open_clamav_socket")
    def test_scan_clean_stream(self, mock_socket_open: MagicMock) -> None:
        """Verifica que un archivo limpio retorna is_clean=True."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"stream: OK\x00", b""]
        mock_socket_open.return_value = mock_sock

        data = io.BytesIO(b"Archivo completamente inofensivo y legal.")
        is_clean, status = scan_file_stream(data)
        self.assertTrue(is_clean)
        self.assertEqual(status, "OK")
        mock_sock.sendall.assert_any_call(b"zINSTREAM\x00")

    @patch("arcamitte.antivirus._open_clamav_socket")
    def test_scan_infected_stream_and_memory_trample(self, mock_socket_open: MagicMock) -> None:
        """Verifica que un archivo con firma de malware es detectado y el búfer sobrescrito."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"stream: Win.Trojan.Generic-999 FOUND\n", b""]
        mock_socket_open.return_value = mock_sock

        raw_buffer = bytearray(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        data = io.BytesIO(raw_buffer)

        is_clean, threat = scan_file_stream(data)
        self.assertFalse(is_clean)
        self.assertEqual(threat, "Win.Trojan.Generic-999")
        # Verificar sobrescritura del búfer en memoria (trampling)
        data.seek(0)
        self.assertEqual(data.read(10), b"\x00" * 10)

    @patch("arcamitte.antivirus.scan_file_stream")
    @patch("arcamitte.services.dispatch_siem_event")
    @override_settings(ARCAMITTE_CLAMAV_ENABLED=True)
    def test_upload_blocks_infected_file_and_alerts_siem(
        self, mock_siem: MagicMock, mock_scan: MagicMock
    ) -> None:
        """Verifica que la subida de un archivo infectado es bloqueada con ValidationError y alerta al SIEM."""
        mock_scan.return_value = (False, "Eicar-Test-Signature")

        pdf_bytes = _create_minimal_pdf_bytes()
        malware_file = SimpleUploadedFile(
            "malware.pdf", pdf_bytes, content_type="application/pdf"
        )

        with self.assertRaises(ValidationError) as ctx:
            upload_and_encrypt_document(
                original_file=malware_file,
                allowed_emails=["test@test.es"],
                origin_uo=self.uo,
                uploaded_by=self.user,
                client_ip="198.51.100.23",
            )
        self.assertIn("Amenaza de malware detectada", str(ctx.exception))

        # Verificar registro en auditoría legal
        log_entry = DocumentAccessLog.objects.filter(
            action=DocumentAccessLog.Action.MALWARE_DETECTADO
        ).first()
        self.assertIsNotNone(log_entry)
        self.assertIn("Eicar-Test-Signature", log_entry.details)

        # Verificar emisión de evento SIEM
        mock_siem.assert_called_once()
        call_kwargs = mock_siem.call_args[1]
        self.assertEqual(call_kwargs.get("event_type"), "malware_detected")
        self.assertEqual(call_kwargs.get("ip_address"), "198.51.100.23")

    @patch("arcamitte.antivirus._open_clamav_socket")
    def test_clamav_fail_closed_by_default(self, mock_socket_open: MagicMock) -> None:
        """Verifica política Fail-Secure: si ClamAV cae, se lanza excepción y se bloquea."""
        mock_socket_open.side_effect = AntivirusConnectionError("Connection refused")
        stream = io.BytesIO(b"dummy")
        with self.assertRaises(AntivirusConnectionError):
            scan_file_stream(stream, fail_open=False)

    @patch("arcamitte.antivirus._open_clamav_socket")
    def test_clamav_fail_open_when_configured(self, mock_socket_open: MagicMock) -> None:
        """Verifica política Fail-Open cuando está explícitamente activada."""
        mock_socket_open.side_effect = AntivirusConnectionError("Connection refused")
        stream = io.BytesIO(b"dummy")
        is_clean, status = scan_file_stream(stream, fail_open=True)
        self.assertTrue(is_clean)
        self.assertIn("FAIL_OPEN", status)

    @patch("arcamitte.antivirus._open_clamav_socket")
    def test_ping_clamav(self, mock_socket_open: MagicMock) -> None:
        """Verifica ping de salud al demonio clamd."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"PONG\x00"
        mock_socket_open.return_value = mock_sock
        self.assertTrue(ping_clamav())

        mock_socket_open.side_effect = Exception("Down")
        self.assertFalse(ping_clamav())

    # ==========================================================================
    # 3. PRUEBAS DE SELLADO CRIPTOGRÁFICO CUALIFICADO DE TIEMPO (RFC 3161)
    # ==========================================================================

    def test_build_rfc3161_request_asn1_der(self) -> None:
        """Verifica que build_rfc3161_request genera una estructura ASN.1 DER válida."""
        sample_hash = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        req_der = build_rfc3161_request(sample_hash, nonce=123456789, cert_req=True)
        self.assertEqual(req_der[0], 0x30)  # SEQUENCE
        self.assertIn(sample_hash, req_der)  # MessageImprint contiene el hash
        # OID SHA-256: 2.16.840.1.101.3.4.2.1
        self.assertIn(b"\x60\x86\x48\x01\x65\x03\x04\x02\x01", req_der)

    def test_build_rfc3161_request_invalid_hash_raises_error(self) -> None:
        """Verifica que un hash que no mida exactamente 32 bytes es rechazado."""
        with self.assertRaises(ValueError):
            build_rfc3161_request(b"corto")

    def test_verify_rfc3161_timestamp(self) -> None:
        """Verifica la validación de una respuesta TimeStampResp ASN.1 DER."""
        target_hash = bytes.fromhex("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
        valid_tsr = _create_mock_tsr_bytes(target_hash, status=0)

        # 1. Validación positiva
        is_valid, msg = verify_rfc3161_timestamp(valid_tsr, target_hash)
        self.assertTrue(is_valid)

        # 2. Validación negativa: discrepancia de hash (manipulación)
        tampered_hash = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        is_valid, msg = verify_rfc3161_timestamp(valid_tsr, tampered_hash)
        self.assertFalse(is_valid)
        self.assertIn("no coincide", msg)

        # 3. Validación negativa: estado rechazado por la TSA (status = 2)
        rejected_tsr = _create_mock_tsr_bytes(target_hash, status=2)
        is_valid, msg = verify_rfc3161_timestamp(rejected_tsr, target_hash)
        self.assertFalse(is_valid)
        self.assertIn("rechazó", msg)

    @patch("arcamitte.timestamping.urllib.request.urlopen")
    @override_settings(ARCAMITTE_RFC3161_ENABLED=True)
    def test_audit_export_receipt_with_rfc3161_timestamp(self, mock_urlopen: MagicMock) -> None:
        """Verifica que al generar una exportación de auditoría se ancla el sello RFC 3161 en el recibo."""
        # Simulamos respuesta TSA
        def mock_response(req, timeout=10):
            # Extraer el hash del request DER para simular un TSR válido
            data = req.data
            # En build_rfc3161_request, el hash de 32 bytes está en los offsets [24:56]
            hash_bytes = data[24:56]
            resp = MagicMock()
            resp.read.return_value = _create_mock_tsr_bytes(hash_bytes, status=0)
            resp.__enter__.return_value = resp
            return resp

        mock_urlopen.side_effect = mock_response

        # Crear registros de prueba
        DocumentAccessLog.objects.create(
            email="test@arcamitte.local",
            action=DocumentAccessLog.Action.SOLICITUD_OTP,
            details="Registro de auditoría de prueba",
        )

        csv_bytes, receipt = create_certified_audit_export(
            user=self.user,
            queryset=DocumentAccessLog.objects.all(),
            reason="Inspección judicial oficial",
            client_ip="192.0.2.1",
        )

        self.assertIsNotNone(receipt.timestamp_token)
        self.assertTrue(len(receipt.timestamp_token) > 0)
        self.assertEqual(receipt.timestamp_authority, "http://timestamp.digicert.com")

        # Verificar que el servicio verify_export_receipt convalida el sello RFC 3161
        verification = verify_export_receipt(receipt.receipt_id, file_bytes=csv_bytes)
        self.assertTrue(verification["found"])
        self.assertTrue(verification["is_valid"])
        self.assertTrue(verification["timestamp_verification"]["has_timestamp"])
        self.assertTrue(verification["timestamp_verification"]["is_valid"])

    def test_audit_receipt_tsr_download_view(self) -> None:
        """Verifica que la vista de descarga .tsr entrega el archivo binario DER con MIME correcto."""
        sample_hash = bytes.fromhex("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        mock_tsr = _create_mock_tsr_bytes(sample_hash)
        b64_token = token_to_base64(mock_tsr)

        receipt = AuditExportReceipt.objects.create(
            receipt_id="ARCA-EXP-20261026-TEST0001",
            export_hash=sample_hash.hex(),
            exported_by=self.user,
            records_count=10,
            timestamp_token=b64_token,
            timestamp_authority="http://timestamp.digicert.com",
        )

        self.client.force_login(self.user)
        url = reverse("dashboard:audit_receipt_tsr", kwargs={"receipt_id": receipt.receipt_id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/timestamp-reply")
        self.assertIn(".tsr", response["Content-Disposition"])
        self.assertEqual(response.content, mock_tsr)
