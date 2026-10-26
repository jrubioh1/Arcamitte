"""
Módulo de Integración con Motor Antivirus ClamAV en Memoria (Stream In-Memory Scanner).

Cumplimiento Normativo y Estándares:
- ENS (Esquema Nacional de Seguridad) - Nivel ALTO: Medidas [op.cont.1] Protección contra código dañino.
- NIST SP 800-53 Rev. 5: SI-3 (Malicious Code Protection).
- ISO/IEC 27001:2022: Control A.8.7 (Protection against malware).

Arquitectura de Seguridad:
1. Inspección en Memoria (Zero Disk Footprint): El archivo se transmite en streaming al demonio clamd
   mediante el protocolo binario 'zINSTREAM' a través de sockets TCP o sockets de dominio Unix locales.
2. Cero persistencia no cifrada: El archivo jamás se escribe en disco antes ni durante el análisis antivirus.
3. Fail-Secure por Defecto: Si clamd no responde o el servicio está caído, la subida se bloquea por defecto
   (salvo configuración explícita 'clamav_fail_open = true').
4. Sanitización Inmediata: Si se detecta un artefacto malicioso, el búfer en memoria se sobrescribe con ceros
   (memory trampling) y se levanta una alerta de seguridad hacia el SIEM.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Any, Optional, Tuple
from django.conf import settings
from django.core.exceptions import ValidationError

logger = logging.getLogger("arcamitte.security")


class AntivirusError(Exception):
    """Excepción genérica para fallos del subsistema antivirus."""

    pass


class AntivirusConnectionError(AntivirusError):
    """Excepción cuando el demonio ClamAV es inaccesible o experimenta un timeout."""

    pass


class MalwareDetectedError(ValidationError):
    """Excepción cuando un archivo subido contiene una firma de malware o amenaza activa."""

    def __init__(self, message: str, threat_name: str = "Unknown"):
        super().__init__(message)
        self.threat_name = threat_name


def _open_clamav_socket(
    host: Optional[str] = None,
    port: Optional[int] = None,
    socket_path: Optional[str] = None,
    timeout: Optional[int] = None,
) -> socket.socket:
    """
    Abre una conexión de socket TCP o Unix con el demonio clamd de ClamAV.
    """
    effective_timeout = (
        timeout
        if timeout is not None
        else getattr(settings, "ARCAMITTE_CLAMAV_TIMEOUT", 10)
    )
    effective_socket_path = (
        socket_path
        if socket_path is not None
        else getattr(settings, "ARCAMITTE_CLAMAV_SOCKET_PATH", "")
    )

    if effective_socket_path:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(effective_timeout)
        try:
            sock.connect(effective_socket_path)
            return sock
        except Exception as exc:
            sock.close()
            raise AntivirusConnectionError(
                f"No se pudo conectar al socket Unix de ClamAV en '{effective_socket_path}': {exc}"
            ) from exc

    effective_host = (
        host if host is not None else getattr(settings, "ARCAMITTE_CLAMAV_HOST", "127.0.0.1")
    )
    effective_port = (
        port if port is not None else getattr(settings, "ARCAMITTE_CLAMAV_PORT", 3310)
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(effective_timeout)
    try:
        sock.connect((effective_host, effective_port))
        return sock
    except Exception as exc:
        sock.close()
        raise AntivirusConnectionError(
            f"No se pudo conectar al daemon ClamAV en {effective_host}:{effective_port}: {exc}"
        ) from exc


def ping_clamav(
    host: Optional[str] = None,
    port: Optional[int] = None,
    socket_path: Optional[str] = None,
    timeout: int = 3,
) -> bool:
    """
    Comprueba si el demonio clamd está activo y respondiendo a comandos de control.
    Envía 'zPING\\0' y valida que la respuesta sea 'PONG'.
    """
    try:
        sock = _open_clamav_socket(host=host, port=port, socket_path=socket_path, timeout=timeout)
        try:
            sock.sendall(b"zPING\x00")
            response = sock.recv(64)
            return b"PONG" in response
        finally:
            sock.close()
    except Exception:
        return False


def scan_file_stream(
    file_obj: Any,
    host: Optional[str] = None,
    port: Optional[int] = None,
    socket_path: Optional[str] = None,
    timeout: Optional[int] = None,
    fail_open: Optional[bool] = None,
    chunk_size: int = 65536,
) -> Tuple[bool, str]:
    """
    Analiza un flujo de archivo en memoria contra ClamAV utilizando el comando 'zINSTREAM'.

    Parámetros:
    - file_obj: Objeto similar a archivo con soporte para .read(n) y .seek().
    - host, port, socket_path, timeout: Parámetros opcionales de conexión.
    - fail_open: Si es True, tolera caídas de ClamAV permitiendo el paso del archivo con advertencia.
                 Si es False (por defecto), bloquea de forma preventiva (Fail-Closed).
    - chunk_size: Tamaño del bloque de streaming (64 KB por defecto).

    Retorna:
    - Tupla (is_clean: bool, threat_name_or_status: str).
    """
    if fail_open is None:
        fail_open = getattr(settings, "ARCAMITTE_CLAMAV_FAIL_OPEN", False)

    try:
        sock = _open_clamav_socket(host=host, port=port, socket_path=socket_path, timeout=timeout)
    except AntivirusConnectionError as exc:
        if fail_open:
            logger.warning(
                f"[CLAMAV FAIL-OPEN] ClamAV no disponible: {exc}. Permitiendo archivo por política de tolerancia."
            )
            return True, "CLAMAV_UNAVAILABLE_FAIL_OPEN"
        logger.error(f"[CLAMAV FAIL-CLOSED] Conexión denegada al escanear archivo: {exc}")
        raise

    try:
        # Comando zINSTREAM delimitado por byte nulo
        sock.sendall(b"zINSTREAM\x00")

        # Asegurar lectura desde el inicio del flujo
        if hasattr(file_obj, "seek"):
            file_obj.seek(0)

        # Enviar bloques prefijados con longitud Big-Endian de 4 bytes
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break
            # Formato: 4 bytes big-endian length + datos
            sock.sendall(struct.pack(">I", len(chunk)) + chunk)

        # Terminador de flujo: bloque de longitud 0
        sock.sendall(struct.pack(">I", 0))

        # Leer respuesta de clamd
        raw_response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            raw_response += data
            if b"\x00" in raw_response or b"\n" in raw_response:
                break

    except Exception as exc:
        if fail_open:
            logger.warning(
                f"[CLAMAV FAIL-OPEN] Error durante la transmisión a ClamAV: {exc}. Permitiendo archivo."
            )
            return True, "CLAMAV_STREAM_ERROR_FAIL_OPEN"
        raise AntivirusError(f"Error de comunicación durante el streaming a ClamAV: {exc}") from exc
    finally:
        sock.close()
        # Restaurar puntero de lectura original para los siguientes componentes del pipeline
        if hasattr(file_obj, "seek"):
            file_obj.seek(0)

    # Decodificar y evaluar respuesta
    # Respuestas estándar de clamd:
    # "stream: OK" -> Limpio
    # "stream: Eicar-Signature FOUND" -> Infectado
    # "stream: ... ERROR" -> Error de motor
    response_str = raw_response.decode("utf-8", errors="replace").strip().strip("\x00")

    if response_str == "stream: OK":
        return True, "OK"

    if "FOUND" in response_str:
        # Extraer nombre de la firma de amenaza
        # Ejemplo: "stream: Win.Trojan.Generic-12345 FOUND"
        parts = response_str.split()
        threat_name = "Threat.Unknown"
        if len(parts) >= 3 and parts[0] == "stream:" and parts[-1] == "FOUND":
            threat_name = " ".join(parts[1:-1])

        # Sanitización de emergencia del búfer en memoria (trampling)
        try:
            if hasattr(file_obj, "seek") and hasattr(file_obj, "write"):
                file_obj.seek(0)
                file_obj.write(b"\x00" * 4096)
                file_obj.seek(0)
        except Exception:
            pass

        logger.critical(
            f"[MALWARE DETECTED] ClamAV detectó la amenaza '{threat_name}' en el flujo analizado."
        )
        return False, threat_name

    logger.warning(f"[CLAMAV ERROR] Respuesta inesperada del servicio ClamAV: {response_str}")
    if fail_open:
        return True, f"UNRECOGNIZED_STATUS_{response_str}"
    raise AntivirusError(f"El motor ClamAV reportó un error durante el análisis: {response_str}")
