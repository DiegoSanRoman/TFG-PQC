"""
sonda_pqc_final.py
-----------------------
Sonda para pruebas de conectividad con algoritmos post-cuánticos (PQC).
Utiliza OpenSSL con soporte PQC para probar diferentes grupos de cifrado
híbridos y puros contra servidores HTTPS.
"""
from __future__ import annotations

# Importaciones necesarias
import subprocess                                           # Para ejecutar comandos del sistema
import json                                                 # Para guardar resultados en JSON
import os                                                   # Para operaciones del sistema
import sys                                                  # Para manipular sys.path
import time                                                 # Para medir tiempo de conexión
import csv                                                  # Para leer y escribir archivos CSV
import hashlib                                              # Para fingerprint SHA256 de certificados
import statistics                                           # Para cálculos estadísticos
import logging                                              # Para logging
import argparse                                             # Para argumentos CLI
import socket                                               # Para pre-check TCP
import dns.resolver                                         # Para pre-check DNS con dnspython
import dns.exception                                        # Para capturar excepciones de dnspython
import re                                                   # Para parseo de salida
import random                                               # Para aleatorizar orden de grupos
import threading                                            # Para semáforo de procesos
from cryptography import x509 as _x509_lib                  # Para parseo de certificados sin subprocess
from cryptography.hazmat.primitives import serialization as _serialization  # Para codificar cert a DER
from datetime import datetime, timezone                     # Para timestamps y zona horaria
from pathlib import Path                                    # Para rutas
from concurrent.futures import ThreadPoolExecutor, as_completed  # Para concurrencia
from tqdm import tqdm                                       # Para barras de progreso
from dataclasses import dataclass                               # Para ProbeResults
from typing import List, Dict, Any, Optional                # Para type hints

# Importar constantes y utilidades compartidas desde scripts/
_SCRIPTS_DIR = Path(__file__).parent.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from constants import (                                     # noqa: E402
    ERROR_DNS,
    ERROR_TCP_REFUSED,
    ERROR_TCP_TIMEOUT,
    ERROR_TCP_OTHER,
    ERROR_TLS_TIMEOUT,
    ERROR_TLS_ALERT,
    ERROR_UNKNOWN,
    CONNECTION_ACCEPTED,
    CONNECTION_REJECTED,
)
from utils import es_hostname_valido, configurar_logging, _build_result_dict  # noqa: E402
from exceptions import (                                     # noqa: E402
    PQCValidationError,
)

# Configurar logging
logger = logging.getLogger(__name__)

# ============================================
# CONSTANTES DE RUTAS
# ============================================
# Timeouts para el subproceso OpenSSL.
# 8 s es suficiente para X25519, ML-KEM y Kyber768 híbridos.
# Algoritmos con intercambio de claves grande (FrodoKEM: ~15 KB; BIKE; HQC) pueden
# agotar este límite en redes reales: un 0 % de aceptación con ERROR_TLS_TIMEOUT indica
# overhead de red excesivo, NO rechazo activo del servidor.
TIMEOUT_TLS_INTERNET_S = 8
TIMEOUT_TLS_LOCALHOST_S = 30
TIMEOUT_TLS_INTERNET_LENTO_S = 30
GRUPOS_LENTOS = frozenset({"frodo640aes", "bikel1", "x25519_bikel1", "x25519_hqc128"})

BASE_DIR = Path(__file__).parent.parent.parent         # Directorio raíz del proyecto
DATA_DIR = BASE_DIR / "data"                    # Directorio de datos
RESULTADOS_DIR = BASE_DIR / "resultados"        # Directorio de resultados
CSV_DEFECTO = DATA_DIR / "majestic_million.csv"           # Archivo CSV de input por defecto
LOG_DEFECTO = RESULTADOS_DIR / "sonda_pqc.log"  # Archivo de log por defecto



# ============================================
# FUNCIONES AUXILIARES
# ============================================

def leer_hostnames_csv(ruta_csv: Path, longitud_max: int, domain_column: Optional[int] = None) -> List[str]:
    '''
    Lee los hostnames desde un archivo CSV con autodetección de columna
    :param ruta_csv: Ruta al archivo CSV (Path object)
    :param longitud_max: Número máximo de hostnames a leer
    :param domain_column: Índice de columna explícito (None para autodetectar)
    :return: Lista de hostnames
    '''
    hostnames = []  # Lista para almacenar los hostnames
    # Leer el archivo CSV
    try:
        with ruta_csv.open('r', encoding='utf-8') as archivo:
            lector = csv.reader(archivo)
            primera_fila = next(lector, None)
            
            # Verificar si el archivo está vacío
            if not primera_fila:
                logger.error("El archivo CSV está vacío: %s", ruta_csv)
                return hostnames
            
            # Autodetección de columna si no se especifica
            if domain_column is None:
                # Verificar si la primera fila tiene encabezados conocidos
                encabezados_lower = [col.lower() for col in primera_fila]
                
                if 'domain' in encabezados_lower:
                    # Majestic Million: buscar columna "Domain"
                    domain_column = encabezados_lower.index('domain')
                    logger.info("Detectado formato Majestic Million (columna %d: %s)", domain_column, primera_fila[domain_column])
                    # Saltar la fila de encabezados
                elif primera_fila[0].isdigit() and len(primera_fila) >= 2:
                    # Tranco: columna B (índice 1) sin encabezados
                    domain_column = 1
                    logger.info("Detectado formato Tranco (columna B, índice 1)")
                    # La primera fila es dato, procesar
                    if len(primera_fila) > domain_column and primera_fila[domain_column]:
                        _h = primera_fila[domain_column].strip()
                        if es_hostname_valido(_h):
                            hostnames.append(_h)
                else:
                    # Default: columna B (compatibilidad con Tranco)
                    domain_column = 1
                    logger.warning("Formato desconocido, usando columna B por defecto")
                    if len(primera_fila) > domain_column and primera_fila[domain_column]:
                        _h = primera_fila[domain_column].strip()
                        if es_hostname_valido(_h):
                            hostnames.append(_h)
            else:
                # Columna especificada manualmente
                logger.info("Usando columna especificada: %d", domain_column)
                # Verificar si primera fila son encabezados
                if not primera_fila[0].isdigit():
                    logger.info("Saltando fila de encabezados")
                else:
                    if len(primera_fila) > domain_column and primera_fila[domain_column]:
                        _h = primera_fila[domain_column].strip()
                        if es_hostname_valido(_h):
                            hostnames.append(_h)

            # Leer el resto de filas
            for fila in lector:
                # Comprobar límite antes de procesar para evitar off-by-one cuando
                # la primera fila ya aportó un hostname (formato Tranco/default).
                if len(hostnames) >= longitud_max:
                    break
                if len(fila) > domain_column and fila[domain_column]:
                    _h = fila[domain_column].strip()
                    if es_hostname_valido(_h):
                        hostnames.append(_h)
                    else:
                        logger.debug("Hostname ignorado (inválido): %s", fila[domain_column])
    except Exception as e:
        logger.error("Error al leer el archivo CSV %s: %s", ruta_csv, e)
    
    return hostnames


def parse_trace_bytes(trace_output: str) -> Dict[str, Any]:  # noqa: C901
    '''
    Parsea bytes de handshake TLS desde la salida de OpenSSL con -trace.
    :param trace_output: Salida de stderr + stdout de OpenSSL con -trace
                :return: Dict con:
                        - bytes_sent/bytes_received/handshake_overhead: métricas de registros TLS visibles en trace
                            (Handshake/CCS/Alert/ApplicationData). En TLS 1.3 esto incluye el handshake cifrado
                            posterior a ServerHello (p.ej. EncryptedExtensions/Certificate/CertificateVerify/Finished).
            - handshake_total_bytes_sent/handshake_total_bytes_received/handshake_total_overhead: métricas de handshake total reportadas por OpenSSL
            - measurement_method / measurement_method_total: calidad/fuente de medición
    '''
    bytes_sent = 0
    bytes_received = 0
    measurement_method = "unknown"  # "traced", "partial", "unknown"
    handshake_content_types = {"handshake", "changecipherspec", "alert", "application_data"}
    # Umbral máximo razonable para descartar registros de datos de aplicación
    max_record_length = 20000

    def _extract_record_bytes(lines: list, start_idx: int) -> int:
        '''
        Escanea las líneas siguientes a un encabezado "Sent/Received TLS Record" buscando
        Content Type y Length. Devuelve (Length + 5 bytes de cabecera TLS) si el registro
        es de tipo handshake; 0 si no aplica o no se encuentran los campos.
        Los +5 son: 1 byte tipo + 2 bytes versión + 2 bytes longitud.
        '''
        content_type = None
        for j in range(start_idx + 1, min(start_idx + 10, len(lines))):
            ct_match = re.search(r'^\s*Content\s*Type\s*=\s*(.+)$', lines[j], re.IGNORECASE)
            if ct_match:
                content_type = ct_match.group(1).strip().lower()
            len_match = re.search(r'^\s*Length\s*=\s*(\d+)', lines[j])
            if len_match:
                length = int(len_match.group(1))
                if (length <= max_record_length and content_type
                        and any(token in content_type for token in handshake_content_types)):
                    return length + 5
                break  # Length encontrado pero no cumple criterios
        return 0

    # Parsear desde -trace buscando patrones "Length = N" después de "Sent/Received TLS Record"
    # Formato OpenSSL:
    #   Sent TLS Record
    #   Header:
    #     Version = ...
    #     Content Type = ...
    #     Length = 1560    <-- Este es el valor que necesitamos
    lines = trace_output.split('\n')

    for i, line in enumerate(lines):
        if ('Sent' in line and 'Record' in line) or 'Sent TLS Record' in line:
            record_bytes = _extract_record_bytes(lines, i)
            if record_bytes:
                bytes_sent += record_bytes
                measurement_method = "traced"
        elif ('Received' in line and 'Record' in line) or 'Received TLS Record' in line:
            record_bytes = _extract_record_bytes(lines, i)
            if record_bytes:
                bytes_received += record_bytes
                measurement_method = "traced"
    
    # Si solo capturamos uno de los dos (enviado o recibido), marcar como "partial"
    if (bytes_sent > 0 and bytes_received == 0) or (bytes_sent == 0 and bytes_received > 0):
        measurement_method = "partial"
        logger.debug("Medición parcial de bytes: sent=%d, received=%d", bytes_sent, bytes_received)
    
    # Si no capturamos nada, dejar en 0 y marcar como "unknown"
    # NO usar valores estimados hardcodeados
    if bytes_sent == 0 and bytes_received == 0:
        measurement_method = "unknown"
    
    handshake_overhead = bytes_sent + bytes_received if measurement_method != "unknown" else 0

    # Métrica de handshake total reportada por OpenSSL (incluye mensajes cifrados en TLS 1.3)
    # Formato típico: "SSL handshake has read 3587 bytes and written 1204 bytes"
    handshake_total_bytes_received = None
    handshake_total_bytes_sent = None
    handshake_total_overhead = None
    measurement_method_total = "unknown"

    match_total = re.search(
        r"SSL\s+handshake\s+has\s+read\s+(\d+)\s+bytes\s+and\s+written\s+(\d+)\s+bytes",
        trace_output,
        re.IGNORECASE
    )
    if match_total:
        handshake_total_bytes_received = int(match_total.group(1))
        handshake_total_bytes_sent = int(match_total.group(2))
        handshake_total_overhead = handshake_total_bytes_sent + handshake_total_bytes_received
        measurement_method_total = "openssl_summary"
    
    return {
        'bytes_sent': bytes_sent if measurement_method != "unknown" else None,
        'bytes_received': bytes_received if measurement_method != "unknown" else None,
        'handshake_overhead': handshake_overhead if measurement_method != "unknown" else None,
        'measurement_method': measurement_method,
        'handshake_total_bytes_sent': handshake_total_bytes_sent,
        'handshake_total_bytes_received': handshake_total_bytes_received,
        'handshake_total_overhead': handshake_total_overhead,
        'measurement_method_total': measurement_method_total
    }


class TLSOutputParser:
    """
    Encapsula el análisis de la salida ``-trace`` de OpenSSL en métricas de bytes TLS.

    La lógica de parseo reside en ``parse_trace_bytes``; esta clase la envuelve
    proporcionando una interfaz orientada a objetos con resultado cacheado y un
    método de fábrica conveniente para salidas de subproceso.

    Uso típico::

        parser = TLSOutputParser.from_subprocess(stdout, stderr)
        metrics = parser.parse()
        print(metrics["bytes_sent"])
    """

    def __init__(self, trace_output: str) -> None:
        self._trace_output = trace_output
        self._result: Optional[Dict[str, Any]] = None

    def parse(self) -> Dict[str, Any]:
        """
        Parsea la salida y devuelve las métricas de bytes TLS.
        El resultado se cachea: llamadas sucesivas no repiten el trabajo.
        """
        if self._result is None:
            self._result = parse_trace_bytes(self._trace_output)
        return self._result

    @staticmethod
    def from_subprocess(stdout: str, stderr: str) -> "TLSOutputParser":
        """
        Crea un parser combinando stdout y stderr de un proceso OpenSSL.

        :param stdout: Salida estándar del proceso OpenSSL.
        :param stderr: Salida de error del proceso OpenSSL.
        """
        return TLSOutputParser(stdout + "\n" + stderr)


# ============================================
# FUNCIONES PRINCIPALES
# ============================================

# Alias para compatibilidad con el resto del módulo y los tests existentes.
# La implementación canónica vive en utils._build_result_dict.
_build_result = _build_result_dict

# Regex para detectar alertas TLS reales en la salida de OpenSSL.
# Evita falsos positivos en líneas que mencionen "alert" en otro contexto
# (e.g. cabeceras HTTP, logs de aplicación, etc.).
_TLS_ALERT_RE = re.compile(
    r"\b(?:SSL|TLS)\b.*\balert\b|\balert\b.*\b(?:write|read|fatal|warning)\b",
    re.IGNORECASE,
)


def sonda_pqc(  # noqa: C901
    hostname: str,
    group: Optional[str] = None,
    openssl_bin: Optional[str] = None,
    proc_semaphore: Optional[threading.Semaphore] = None,
) -> Dict[str, Any]:
    '''
    Función que intenta conectarse a un servidor HTTPS usando OpenSSL con soporte para cifrados post-cuánticos (híbridos y puros).
    :param hostname: El nombre del host o dominio del servidor HTTPS a escanear (puede incluir puerto: "hostname:puerto")
    :param group: El grupo de cifrado a usar (None deja que OpenSSL negocie libremente)
    :param openssl_bin: Ruta al binario de OpenSSL personalizado con soporte PQC (opcional)
    :param proc_semaphore: Semáforo para limitar concurrencia de procesos (opcional)
    :return: Diccionario con el resultado de la conexión
    '''

    # Ruta al binario de OpenSSL personalizado con soporte PQC
    openssl_bin = openssl_bin or "/opt/openssl/bin/openssl"
    
    # Parsear hostname y puerto (formato: "hostname:puerto" o "hostname")
    if ':' in hostname and not hostname.startswith('['):  # No confundir con IPv6
        parts = hostname.rsplit(':', 1)
        base_hostname = parts[0]
        puerto = parts[1]
    else:
        base_hostname = hostname
        puerto = "443"
    
    # Comando base con -trace para capturar el tamaño real de los mensajes TLS
    # Activamos explícitamente el provider OQS para compatibilidad
    # Habilitamos -trace para todas las conexiones incluyendo localhost
    # NOTA METODOLÓGICA: no se añade -verify_return_error ni se fuerza verificación
    # de cadena PKI. El objetivo es medir compatibilidad y latencia de negociación,
    # no validar certificados. En producción, la verificación añadiría tiempo adicional.
    cmd = [
        openssl_bin,                                # Ruta al binario de OpenSSL personalizado con soporte PQC
        "s_client",                                 # Modo cliente para probar conexiones TLS
        "-connect", f"{base_hostname}:{puerto}",    # Host y puerto a conectar
        "-servername", base_hostname,               # SNI para el hostname (importante para servidores con múltiples certificados)
        "-trace",                                   # Habilitar trace para capturar detalles de bytes enviados/recibidos
        "-provider", "oqsprovider",                 # Usar el provider OQS para soporte PQC
        "-provider", "default"                      # Incluir el provider default para compatibilidad con grupos tradicionales
    ]
    
    # Si se especifica un grupo, forzamos TLS 1.3 y el grupo PQC
    # Si no, es una conexión normal (sin forzar TLS 1.3 ni grupos)
    if group:
        cmd += ["-tls1_3", "-groups", group]
    
    logger.debug("Probando %s con grupo %s", hostname, group)
    
    # Pre-check DNS para separar fallos de infraestructura de PQC.
    # No se abre una conexión TCP extra: evita consumir slots en servidores con
    # rate-limiting y garantiza que OpenSSL usa exactamente la misma IP (fijada
    # vía -connect más abajo), sin riesgo de rotación anycast entre resoluciones.
    dns_time_ms = None
    ip_resuelta = None
    ip_familia = None
    sni_usado = base_hostname

    try:
        dns_inicio = time.perf_counter()
        # Usar dnspython (mismo resolver que las sondas ECH) para coherencia metodológica.
        # Evita la caché del SO y el resolver síncrono bloqueante de socket.getaddrinfo.
        _res = dns.resolver.Resolver()
        try:
            _ans = _res.resolve(base_hostname, 'A')
            ip_resuelta = str(_ans[0])
            ip_familia = "IPv4"
        except dns.resolver.NoAnswer:
            _ans = _res.resolve(base_hostname, 'AAAA')
            ip_resuelta = str(_ans[0])
            ip_familia = "IPv6"
        dns_time_ms = round((time.perf_counter() - dns_inicio) * 1000, 2)
    except dns.exception.DNSException as e:
        logger.debug("Pre-check DNS falló para %s: %s", hostname, e)
        return _build_result(
            error_category=ERROR_DNS,
            connection_result=None,
            res=str(e),
            dns_time_ms=dns_time_ms,
            ip=None,
            ip_familia=None,
            sni_usado=sni_usado,
        )

    # Fijar destino de conexión para comparaciones justas entre grupos:
    # - Si tenemos IP resuelta en pre-check, conectar a esa IP.
    # - Mantener SNI con hostname original (-servername) para no romper validación/certificados.
    # Esto evita que distintos grupos terminen en nodos CDN/anycast distintos.
    connect_host = ip_resuelta if ip_resuelta else base_hostname
    if connect_host and ":" in connect_host and not connect_host.startswith("["):
        connect_host = f"[{connect_host}]"

    try:
        idx_connect = cmd.index("-connect")
        cmd[idx_connect + 1] = f"{connect_host}:{puerto}"
    except (ValueError, IndexError):
        pass

    # Ejecutamos OpenSSL para probar el handshake TLS/PQC y capturamos la salida
    try:
        # Ejecutamos con Popen (Process open) para controlar mejor timeouts y limpieza
        stdout_bytes = b""
        stderr_bytes = b""
        openssl_subprocess_time_ms = None
        return_code = None

        if proc_semaphore:
            proc_semaphore.acquire()
        try:
            tiempo_inicio = time.perf_counter()
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True
            )
            # Iniciamos el timer DESPUÉS de Popen para excluir el overhead de fork/exec
            intento_inicio = time.perf_counter()

            try:
                if "localhost" in base_hostname or "127.0.0.1" in base_hostname:
                    timeout_seconds = TIMEOUT_TLS_LOCALHOST_S
                elif group in GRUPOS_LENTOS:
                    timeout_seconds = TIMEOUT_TLS_INTERNET_LENTO_S
                else:
                    timeout_seconds = TIMEOUT_TLS_INTERNET_S
                # Handshake puro: no enviamos tráfico de aplicación (sin GET)
                stdout_bytes, stderr_bytes = process.communicate(input=b"", timeout=timeout_seconds)
                openssl_subprocess_time_ms = round((time.perf_counter() - intento_inicio) * 1000, 2)
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout_bytes, stderr_bytes = process.communicate()
                openssl_subprocess_time_ms = round((time.perf_counter() - intento_inicio) * 1000, 2)
                return_code = process.returncode
                logger.warning("Timeout en %s con grupo %s", hostname, group)
                return _build_result(
                    error_category=ERROR_TLS_TIMEOUT,
                    connection_result=None,
                    res="Timeout durante handshake TLS",
                    dns_time_ms=dns_time_ms,
                    ip=ip_resuelta,
                    ip_familia=ip_familia,
                    sni_usado=sni_usado,
                )
        finally:
            if proc_semaphore:
                proc_semaphore.release()

        # Medimos el tiempo final
        tiempo_fin = time.perf_counter()
        tiempo_conexion_segundos = round(tiempo_fin - tiempo_inicio, 3)

        # Decodificamos la salida
        stdout = stdout_bytes.decode(errors='ignore') if stdout_bytes else ""
        stderr = stderr_bytes.decode(errors='ignore') if stderr_bytes else ""

        # Detectar errores de conexión TCP en la salida de OpenSSL.
        # Estos ocurren cuando DNS resuelve pero el servidor rechaza o no responde a TCP.
        _combined = stderr + " " + stdout
        _tcp_refused_markers = ("Connection refused", "connect: ECONNREFUSED", "Connection reset by peer")
        _tcp_timeout_markers = ("Connection timed out", "connect: ETIMEDOUT", "Operation timed out",
                                "connect: Connection timed out")
        _tcp_ctx = dict(dns_time_ms=dns_time_ms, openssl_subprocess_time_ms=openssl_subprocess_time_ms,
                        ip=ip_resuelta, ip_familia=ip_familia, sni_usado=sni_usado)
        if any(m in _combined for m in _tcp_refused_markers):
            return _build_result(
                error_category=ERROR_TCP_REFUSED,
                connection_result=None,
                res="TCP: conexión rechazada por el servidor",
                **_tcp_ctx,
            )
        if any(m in _combined for m in _tcp_timeout_markers):
            return _build_result(
                error_category=ERROR_TCP_TIMEOUT,
                connection_result=None,
                res="TCP: timeout de conexión",
                **_tcp_ctx,
            )

        # Parsear los bytes reales del handshake TLS desde la salida de -trace
        trace_metrics = TLSOutputParser.from_subprocess(stdout, stderr).parse()
        
        # Métricas reales del tráfico de red
        bytes_sent = trace_metrics['bytes_sent']
        bytes_received = trace_metrics['bytes_received']
        handshake_overhead = trace_metrics['handshake_overhead']
        measurement_method = trace_metrics['measurement_method']
        handshake_total_bytes_sent = trace_metrics['handshake_total_bytes_sent']
        handshake_total_bytes_received = trace_metrics['handshake_total_bytes_received']
        handshake_total_overhead = trace_metrics['handshake_total_overhead']
        measurement_method_total = trace_metrics['measurement_method_total']
        
        # Log de advertencia si no se pudieron medir bytes
        if measurement_method == "unknown":
            logger.debug("No se pudieron medir bytes desde trace para %s (grupo %s)", 
                        hostname, group)

        # Parseo de TLS: versión, cipher y ALPN
        tls_version = None
        cipher_suite = None
        alpn = None

        # Buscar la versión TLS en la salida (puede variar según la versión de OpenSSL y el formato de salida)
        match_protocol = re.search(r"^\s*Protocol\s*:\s*(.+)$", stdout, re.MULTILINE)
        if match_protocol:
            tls_version = match_protocol.group(1).strip()

        match_cipher = re.search(r"^\s*Cipher\s*:\s*(.+)$", stdout, re.MULTILINE)
        if match_cipher:
            cipher_suite = match_cipher.group(1).strip()
        elif "Cipher is" in stdout:
            match_cipher = re.search(r"Cipher is\s*(.+)$", stdout, re.MULTILINE)
            if match_cipher:
                cipher_suite = match_cipher.group(1).strip()

        # Buscar ALPN (Application Layer Protocol Negotiation) negociado (puede aparecer como "ALPN protocol" o "ALPN selected" dependiendo de la versión de OpenSSL)
        match_alpn = re.search(r"^\s*ALPN[\s,]+protocol[:\s]+(.+)$", stdout, re.MULTILINE | re.IGNORECASE)
        if not match_alpn:
            match_alpn = re.search(r"ALPN[\s,]+selected[:\s]+(.+)$", stdout, re.MULTILINE | re.IGNORECASE)
        if match_alpn:
            alpn = match_alpn.group(1).strip()

        # TLS alert específico (si aparece)
        tls_alert = None
        for line in (stderr + "\n" + stdout).split("\n"):
            if _TLS_ALERT_RE.search(line):
                tls_alert = line.strip()
                break

        # Extraer primer certificado en PEM (servidor)
        cert_pem = None
        # Buscar desde Certificate chain o desde el primer BEGIN hasta el primer END
        cert_match = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            stdout,
            re.DOTALL
        )
        if cert_match:
            cert_pem = cert_match.group(0)
        
        # Fallback: intentar desde stderr si stdout no tiene certificado
        if not cert_pem and stderr:
            cert_match = re.search(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                stderr,
                re.DOTALL
            )
            if cert_match:
                cert_pem = cert_match.group(0)

        # Si tenemos el certificado en PEM, extraemos información relevante usando OpenSSL x509
        cert_issuer = None
        cert_not_before = None
        cert_not_after = None
        cert_san = None
        cert_fingerprint_sha256 = None

        if cert_pem:
            # Parseamos el certificado con la librería cryptography (ya dependencia del proyecto)
            # en lugar de lanzar un segundo subproceso openssl x509, que escaparía al semáforo.
            try:
                _cert = _x509_lib.load_pem_x509_certificate(cert_pem.encode())
                cert_issuer = _cert.issuer.rfc4514_string()
                cert_not_before = _cert.not_valid_before_utc.isoformat()
                cert_not_after = _cert.not_valid_after_utc.isoformat()
                _der = _cert.public_bytes(_serialization.Encoding.DER)
                _fp = hashlib.sha256(_der).hexdigest().upper()
                cert_fingerprint_sha256 = ":".join(_fp[i:i + 2] for i in range(0, len(_fp), 2))
                try:
                    _san_ext = _cert.extensions.get_extension_for_class(
                        _x509_lib.SubjectAlternativeName
                    )
                    _dns_names = [n.value for n in _san_ext.value
                                  if isinstance(n, _x509_lib.DNSName)]
                    cert_san = ", ".join(f"DNS:{n}" for n in _dns_names) if _dns_names else None
                except _x509_lib.ExtensionNotFound:
                    cert_san = None
            except Exception as _cert_err:
                logger.debug("No se pudo parsear certificado PEM para %s: %s", hostname, _cert_err)

        # Detectar fallos reales de handshake
        handshake_failed = False
        tls_alert_lower = tls_alert.lower() if tls_alert else ""
        fatal_alert_markers = [
            "handshake failure",
            "protocol version",
            "illegal parameter",
            "decode error",
            "internal error",
            "unexpected message",
            "bad record mac",
            "decrypt error"
        ]
        has_fatal_alert = any(marker in tls_alert_lower for marker in fatal_alert_markers)

        if has_fatal_alert:
            handshake_failed = True

        # Cipher (NONE) significa que no se negoció nada
        if cipher_suite and "(NONE)" in cipher_suite:
            handshake_failed = True

        # Return code distinto de 0 con cierre anómalo del servidor (ej. sin GET).
        # Solo se considera fallo si además no se negoció un cipher válido,
        # porque openssl frecuentemente devuelve 1 tras un handshake exitoso
        # cuando el servidor cierra la conexión sin datos de aplicación.
        valid_cipher = cipher_suite and "(NONE)" not in cipher_suite
        if return_code not in (0, None) and not valid_cipher:
            handshake_failed = True

        # Contexto TLS compartido por todos los returns de la fase post-subprocess
        _tls_ctx: Dict[str, Any] = dict(
            tiempo_conexion_segundos=tiempo_conexion_segundos,
            dns_time_ms=dns_time_ms,
            openssl_subprocess_time_ms=openssl_subprocess_time_ms,
            ip=ip_resuelta,
            ip_familia=ip_familia,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            alpn=alpn,
            tls_alert=tls_alert,
            cert_issuer=cert_issuer,
            cert_not_before=cert_not_before,
            cert_not_after=cert_not_after,
            cert_san=cert_san,
            cert_fingerprint_sha256=cert_fingerprint_sha256,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            handshake_overhead=handshake_overhead,
            measurement_method=measurement_method,
            handshake_total_bytes_sent=handshake_total_bytes_sent,
            handshake_total_bytes_received=handshake_total_bytes_received,
            handshake_total_overhead=handshake_total_overhead,
            measurement_method_total=measurement_method_total,
            sni_usado=sni_usado,
        )

        # Si hay fallo de handshake confirmado, es RECHAZADO
        if handshake_failed:
            logger.debug("Rechazado (handshake failed): %s - %s", hostname, group)
            return _build_result(
                error_category=ERROR_TLS_ALERT,
                connection_result=CONNECTION_REJECTED,
                res=tls_alert if tls_alert else "Handshake failed",
                **_tls_ctx,
            )

        # Buscar el grupo negociado en la línea Server Temp Key
        negotiated_line = None
        for line in stdout.split("\n"):
            if line.lstrip().startswith("Server Temp Key:"):
                negotiated_line = line.strip()
                break

        # Éxito real: hay Server Temp Key Y (hay certificado O cipher válido).
        # openssl s_client devuelve 1 cuando cierra limpiamente sin datos HTTP; ambos
        # son señal de handshake exitoso cuando hay cipher negociado.
        if return_code in (0, 1) and negotiated_line and (cert_issuer or (cipher_suite and "(NONE)" not in cipher_suite)):
            logger.debug("Éxito: %s - %s - %s", hostname, group, negotiated_line)
            return _build_result(
                error_category=None,
                connection_result=CONNECTION_ACCEPTED,
                res=negotiated_line,
                **_tls_ctx,
            )

        # Fallback: conexión exitosa si hay cipher válido Y certificado
        if return_code in (0, 1) and cipher_suite and "(NONE)" not in cipher_suite and cert_issuer:
            logger.debug("Éxito: %s - %s - Conectado (TLS 1.3)", hostname, group)
            return _build_result(
                error_category=None,
                connection_result=CONNECTION_ACCEPTED,
                res=f"Conectado - {cipher_suite}",
                **_tls_ctx,
            )

        # Si hay un error específico de incompatibilidad de protocolo/draft
        logger.debug("Rechazado: %s - %s - %s", hostname, group, stderr.strip())
        return _build_result(
            error_category=ERROR_TLS_ALERT,
            connection_result=CONNECTION_REJECTED,
            res="Incompatibilidad de protocolo/draft",
            **_tls_ctx,
        )

    # Capturamos cualquier excepción (timeout, fallo, etc.)
    except Exception as e:
        logger.warning("Error en %s con grupo %s: %s", hostname, group, str(e))
        return _build_result(
            error_category=ERROR_UNKNOWN,
            connection_result=None,
            res=str(e),
            dns_time_ms=dns_time_ms,
            ip=ip_resuelta,
            ip_familia=ip_familia,
            sni_usado=sni_usado,
        )


def escanear_servidor_pqc(hostname: str, grupos: List[str], openssl_bin: str, proc_semaphore: threading.Semaphore, repeticiones: int = 3) -> Dict[str, Any]:
    '''
    Escanea un servidor con múltiples grupos PQC y retorna los resultados
    :param hostname: Nombre del host a escanear
    :param grupos: Lista de grupos a probar
    :param openssl_bin: Ruta al binario de OpenSSL
    :param proc_semaphore: Semáforo para controlar procesos concurrentes
    :param repeticiones: Número de repeticiones por grupo (default: 3)
    :return: Diccionario con los resultados del escaneo
    '''
    # Diccionario para almacenar resultados por hostname
    resultado_host = {
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pruebas": []
    }
    
    # Aleatorizar el orden de grupos para evitar sesgos por rate-limiting o caché del servidor
    grupos_aleatorios = list(grupos)
    random.shuffle(grupos_aleatorios)

    # Probar cada grupo
    for g in grupos_aleatorios:
        label = g

        # Realizar múltiples repeticiones
        intentos = []
        for i in range(repeticiones):
            resultado = sonda_pqc(hostname, g, openssl_bin=openssl_bin, proc_semaphore=proc_semaphore)
            resultado["grupo"] = label
            resultado["repeticion"] = i + 1
            intentos.append(resultado)
        
        # Guardar cada repetición individualmente para preservar variabilidad
        resultado_host["pruebas"].extend(intentos)
    
    # Retornar resultados del host
    return resultado_host


def generar_estadisticas_por_grupo(lista_resultados: List[Dict[str, Any]], grupos: List[str]) -> List[Dict[str, Any]]:
    '''
    Genera estadísticas agregadas por grupo de cifrado
    :param lista_resultados: Lista de resultados de todos los hosts
    :param grupos: Lista de grupos probados
    :return: Lista de diccionarios con estadísticas por grupo
    '''
    # Agrupar resultados por grupo y calcular estadísticas
    estadisticas_grupos = []
    
    # Para cada grupo, recolectar todas las pruebas y calcular métricas
    for grupo in grupos:
        label = grupo
        
        # Recolectar todas las pruebas de este grupo
        pruebas_grupo = []
        for host_resultado in lista_resultados:
            for prueba in host_resultado.get("pruebas", []):
                if prueba.get("grupo") == label:
                    pruebas_grupo.append(prueba)
        
        if not pruebas_grupo:
            continue
        
        # Contar aceptados — distinguiendo timeout de rechazo activo:
        # - timeout: el handshake no terminó en el tiempo límite (puede ser latencia del algoritmo)
        # - rechazado: el servidor envió un TLS alert explícito (no soporta el algoritmo)
        # Mezclarlos daría la falsa impresión de que todos los fallos son rechazos activos.
        total_pruebas = len(pruebas_grupo)
        aceptados  = sum(1 for p in pruebas_grupo if p.get("connection_result") == CONNECTION_ACCEPTED)
        rechazados = sum(1 for p in pruebas_grupo if p.get("connection_result") == CONNECTION_REJECTED)
        timeouts   = sum(1 for p in pruebas_grupo if p.get("error_category") == ERROR_TLS_TIMEOUT)
        errores    = total_pruebas - aceptados - rechazados - timeouts

        # Calcular porcentajes
        porcentaje_aceptacion = round((aceptados  / total_pruebas * 100) if total_pruebas else 0, 2)
        porcentaje_rechazo    = round((rechazados / total_pruebas * 100) if total_pruebas else 0, 2)
        porcentaje_timeout    = round((timeouts   / total_pruebas * 100) if total_pruebas else 0, 2)
        porcentaje_error      = round((errores    / total_pruebas * 100) if total_pruebas else 0, 2)
        
        # Recolectar métricas numéricas solo de conexiones exitosas
        # Creamos las listas para cada métrica que queremos analizar
        handshake_times = []
        dns_times = []
        bytes_sent_list = []
        bytes_received_list = []
        handshake_overhead_list = []
        handshake_total_overhead_list = []
        
        for prueba in pruebas_grupo:
            if prueba.get("connection_result") == CONNECTION_ACCEPTED:
                if prueba.get("openssl_subprocess_time_ms") is not None:
                    handshake_times.append(prueba["openssl_subprocess_time_ms"])
                if prueba.get("dns_time_ms") is not None:
                    dns_times.append(prueba["dns_time_ms"])
                if prueba.get("bytes_sent") is not None:
                    bytes_sent_list.append(prueba["bytes_sent"])
                if prueba.get("bytes_received") is not None:
                    bytes_received_list.append(prueba["bytes_received"])
                if prueba.get("handshake_overhead") is not None:
                    handshake_overhead_list.append(prueba["handshake_overhead"])
                if prueba.get("handshake_total_overhead") is not None:
                    handshake_total_overhead_list.append(prueba["handshake_total_overhead"])
        
        # Calcular estadísticas.
        # La métrica primaria para comparaciones es la MEDIANA (robusta ante outliers
        # de red). La media se exporta como referencia complementaria pero NO debe
        # usarse como métrica principal al comparar grupos.
        def calc_stats(valores):
            if not valores:
                return {"media": None, "mediana": None, "desv_std": None, "min": None, "max": None}
            return {
                "media": round(statistics.mean(valores), 2),
                "mediana": round(statistics.median(valores), 2),
                "desv_std": round(statistics.stdev(valores), 2) if len(valores) > 1 else 0,
                "min": round(min(valores), 2),
                "max": round(max(valores), 2)
            }
        
        stats_handshake = calc_stats(handshake_times)
        stats_dns = calc_stats(dns_times)
        stats_bytes_sent = calc_stats(bytes_sent_list)
        stats_bytes_received = calc_stats(bytes_received_list)
        stats_handshake_overhead = calc_stats(handshake_overhead_list)
        stats_handshake_total_overhead = calc_stats(handshake_total_overhead_list)
        
        # Contar categorías de error
        error_categories = {}
        for prueba in pruebas_grupo:
            cat = prueba.get("error_category")
            if cat:
                error_categories[cat] = error_categories.get(cat, 0) + 1    # Contar cada categoría de error
        
        estadisticas_grupos.append({
            "grupo": label,
            "total_pruebas": total_pruebas,
            "aceptados": aceptados,
            "rechazados": rechazados,
            "timeouts": timeouts,
            "errores": errores,
            "porcentaje_aceptacion": porcentaje_aceptacion,
            "porcentaje_rechazo": porcentaje_rechazo,
            "porcentaje_timeout": porcentaje_timeout,
            "porcentaje_error": porcentaje_error,
            "openssl_subprocess_time_ms": stats_handshake,
            "dns_time_ms": stats_dns,
            "bytes_sent": stats_bytes_sent,
            "bytes_received": stats_bytes_received,
            "handshake_overhead": stats_handshake_overhead,
            "handshake_total_overhead": stats_handshake_total_overhead,
            "categorias_error": error_categories
        })
    
    return estadisticas_grupos


def _flatten_stats_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    '''
    Aplana una entrada de estadísticas en un dict plano apto para CSV.

    Los campos escalares se copian directamente. Los campos que son dicts
    de sub-métricas (p.ej. openssl_subprocess_time_ms → {media, mediana, ...}) se
    expanden como ``campo_submetrica``. El campo ``categorias_error`` se omite
    porque su estructura es variable (un dict de claves dinámicas) y no encaja
    en una fila tabular fija.

    :param entry: Diccionario de estadísticas de un grupo.
    :return: Dict plano con todas las columnas derivadas.
    '''
    flat: Dict[str, Any] = {}
    for key, value in entry.items():
        if key == "categorias_error":
            # Serializar como JSON compacto para preservar la información en el CSV.
            flat[key] = json.dumps(value, ensure_ascii=False) if value else ""
            continue
        if isinstance(value, dict):
            for sub_key, sub_val in value.items():
                flat[f"{key}_{sub_key}"] = sub_val
        else:
            flat[key] = value
    return flat


def exportar_estadisticas_csv(estadisticas_grupos: List[Dict[str, Any]], output_path: Path) -> None:
    '''
    Exporta estadísticas por grupo a un archivo CSV con headers derivados
    dinámicamente de la estructura de datos, sin listas hardcodeadas.

    Si se añaden nuevas métricas a ``generar_estadisticas_por_grupo``, este
    método las incluirá automáticamente en el CSV sin necesidad de modificación.

    :param estadisticas_grupos: Lista de estadísticas calculadas por grupo.
    :param output_path: Ruta donde guardar el CSV.
    '''
    if not estadisticas_grupos:
        logger.warning("No hay estadísticas para exportar a CSV")
        return

    filas = [_flatten_stats_entry(e) for e in estadisticas_grupos]
    # Los headers se derivan de la primera fila; todas las filas tienen la misma estructura
    headers = list(filas[0].keys())

    with output_path.open('w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(filas)

    logger.info("Estadísticas por grupo exportadas a %s", output_path)



# ============================================
# CLASES DE ALTO NIVEL: ProbeResults / PQCProbe
# ============================================

@dataclass
class ProbeResults:
    """
    Resultado tipado de una sonda PQC individual.

    Envuelve el diccionario devuelto por ``sonda_pqc()`` proporcionando
    acceso por atributo a los campos más usados y garantizando que el
    esquema de datos permanece coherente.

    Ejemplo::

        probe = PQCProbe()
        result = probe.run("example.com", group="X25519MLKEM768")
        if result.is_accepted:
            print(result.tls_version)
    """

    data: Dict[str, Any]

    # ------------------------------------------------------------------
    # Propiedades de acceso rápido
    # ------------------------------------------------------------------

    @property
    def connection_result(self) -> Optional[str]:
        """``CONNECTION_ACCEPTED`` / ``CONNECTION_REJECTED`` / None."""
        return self.data.get("connection_result")

    @property
    def error_category(self) -> Optional[str]:
        """Categoría de error (ERROR_DNS, ERROR_TCP_REFUSED, …) o None si no hubo error."""
        return self.data.get("error_category")

    @property
    def is_accepted(self) -> bool:
        """True si el handshake TLS/PQC fue aceptado por el servidor."""
        return self.connection_result == CONNECTION_ACCEPTED

    @property
    def tls_version(self) -> Optional[str]:
        return self.data.get("tls_version")

    @property
    def cipher_suite(self) -> Optional[str]:
        return self.data.get("cipher_suite")

    @property
    def handshake_time_ms(self) -> Optional[float]:
        return self.data.get("openssl_subprocess_time_ms")

    # ------------------------------------------------------------------
    # Compatibilidad con acceso por clave (dict-like)
    # ------------------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        """Devuelve una copia del diccionario de resultados subyacente."""
        return dict(self.data)


class PQCProbe:
    """
    Encapsula la configuración y ejecución de una sonda PQC para un host.

    Centraliza la validación de entradas y la creación del resultado tipado,
    delegando la lógica de conexión a ``sonda_pqc()``.

    Ejemplo::

        probe = PQCProbe(openssl_bin="/opt/openssl/bin/openssl")
        result = probe.run("example.com", group="X25519MLKEM768")
        print(result.is_accepted, result.tls_version)
    """

    def __init__(
        self,
        openssl_bin: str = "/opt/openssl/bin/openssl",
        proc_semaphore: Optional[threading.Semaphore] = None,
    ) -> None:
        """
        :param openssl_bin: Ruta al binario OpenSSL con soporte PQC.
        :param proc_semaphore: Semáforo opcional para limitar la concurrencia de procesos.
        """
        self.openssl_bin = openssl_bin
        self.proc_semaphore = proc_semaphore

    def run(self, hostname: str, group: Optional[str] = None) -> ProbeResults:
        """
        Ejecuta la sonda PQC para un hostname y grupo dado.

        :param hostname: Nombre del host objetivo (p.ej. ``"example.com"``).
        :param group:    Grupo de cifrado PQC (p.ej. ``"X25519MLKEM768"``); None deja que OpenSSL negocie libremente.
        :raises PQCValidationError: Si el hostname no es un nombre de dominio válido.
        :return: :class:`ProbeResults` con el resultado de la conexión.
        """
        if not es_hostname_valido(hostname):
            raise PQCValidationError(f"Hostname inválido: {hostname!r}")
        result = sonda_pqc(
            hostname,
            group,
            openssl_bin=self.openssl_bin,
            proc_semaphore=self.proc_semaphore,
        )
        return ProbeResults(data=result)


# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

if __name__ == "__main__":
    # Parseo de argumentos CLI
    parser = argparse.ArgumentParser(description="Sonda PQC: escaneo concurrente de servidores HTTPS con algoritmos post-cuánticos")
    parser.add_argument("--input-csv", type=Path, default=CSV_DEFECTO, help="Ruta del archivo CSV de entrada con hostnames")
    parser.add_argument("--max-hostnames", type=int, default=100, help="Número máximo de hostnames a escanear")
    parser.add_argument("--max-workers", type=int, default=20, help="Número de hilos en paralelo")
    parser.add_argument("--domain-column", type=int, default=None, help="Índice de columna con dominios (None para autodetectar)")
    parser.add_argument("--log-level", default="INFO", help="Nivel de log: DEBUG, INFO, WARNING, ERROR (solo archivo)")
    parser.add_argument("--log-file", type=Path, default=LOG_DEFECTO, help="Ruta del archivo de log")
    parser.add_argument(
        "--openssl-bin",
        default=os.getenv("OPENSSL_BIN", "/opt/openssl/bin/openssl"),
        help="Ruta al binario OpenSSL (o variable de entorno OPENSSL_BIN)"
    )
    parser.add_argument(
        "--max-openssl-procs",
        type=int,
        default=min(12, os.cpu_count() or 1),
        help="Límite de procesos OpenSSL concurrentes"
    )
    parser.add_argument(
        "--repeticiones",
        type=int,
        default=3,
        help="Número de repeticiones por grupo para promediar métricas (default: 3)"
    )
    parser.add_argument(
        "--timeout-total",
        type=float,
        default=None,
        metavar="SEGUNDOS",
        help="Tiempo máximo total de escaneo en segundos. Cancela hosts pendientes al agotarse (default: sin límite)"
    )
    args = parser.parse_args()

    # Configurar logging
    configurar_logging(args.log_file, args.log_level)
    
    # Loguear configuración inicial
    logger.info("Iniciando sonda PQC con OpenSSL personalizado")
    logger.info("Binario OpenSSL: %s", args.openssl_bin)
    logger.info("Límite de procesos OpenSSL: %s", args.max_openssl_procs)
    logger.info("Repeticiones por grupo: %s", args.repeticiones)

    # Verificar que el binario OpenSSL existe antes de iniciar el escaneo
    if not os.path.exists(args.openssl_bin):
        logger.error("El binario OpenSSL no se encontro: %s", args.openssl_bin)
        raise SystemExit(1)

    # Probamos diferentes protocolos, desde automático (None) hasta algunos híbridos y algunos puros PQC
    grupos = [
        # --- Clásico ---
        "X25519",               # 1. Clásico (Control)
        # --- Híbridos con soporte real en producción ---
        "X25519MLKEM768",       # 2. Estándar NIST (FIPS 203, ML-KEM-768). Codepoint 0x11ec, distinto de x25519_kyber768 (draft OQS, 0x6399)
        "x25519_kyber768",      # 4. Draft experimental OQS (híbrido pre-estándar, nunca estandarizado)
        # --- Puros ---
        "mlkem768",             # 5. Puro Moderno
        "kyber768",             # 6. Puro Viejo
        # --- Variantes Híbridas (Para maximizar compatibilidad) ---
        "p256_kyber768",        # 7. Híbrido con curva P-256
        "SecP256r1MLKEM768",    # 8. [NUEVO] Versión P-256 del estándar moderno (Nombre exacto de tu lista)
        # --- Variantes de Tamaño (Nivel 1 - Más rápidos) ---
        "x25519_mlkem512",      # 9. [NUEVO] Híbrido Nivel 1 Moderno
        "x25519_kyber512",      # 10. [NUEVO] Híbrido Nivel 1 Viejo (Cloudflare a veces usa este)
        # --- Algoritmos Alternativos (valor experimental; NO seleccionados por NIST) ---
        "frodo640aes",          # 11. LWE genérico (FrodoKEM, muy conservador, extremadamente lento en TLS real)
        "bikel1",               # 12. Code-based Puro
        "x25519_bikel1",        # 13. [NUEVO] Híbrido BIKE (Más probable que conecte que el puro)
        "x25519_hqc128"         # 14. [NUEVO] Híbrido HQC (Code-based, muy robusto)
    ]

    # Leer hostnames desde el archivo CSV
    ruta_csv = args.input_csv
    hostnames = leer_hostnames_csv(ruta_csv, args.max_hostnames, args.domain_column)
    
    # Verificar que se han leído hostnames
    if not hostnames:
        logger.error("No se encontraron hostnames en %s", ruta_csv)
        raise SystemExit(1)
    
    logger.info("Se han cargado %s hostnames desde %s", len(hostnames), ruta_csv)
    logger.info("Grupos PQC a probar: %s", ", ".join(grupos))
    
    # Lista para almacenar todos los resultados
    lista_resultados = []

    # Definimos el número de hilos (trabajadores en paralelo)
    MAX_WORKERS = args.max_workers

    logger.info("Iniciando escaneo concurrente con %s hilos...", MAX_WORKERS)
    
    # Tiempo de inicio
    tiempo_inicio_total = time.time()
    deadline = tiempo_inicio_total + args.timeout_total if args.timeout_total is not None else None

    # Semáforo para limitar procesos OpenSSL concurrentes
    proc_semaphore = threading.BoundedSemaphore(args.max_openssl_procs)

    # Usamos ThreadPoolExecutor para concurrencia
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Lanzamos todas las tareas
        futuros = {executor.submit(escanear_servidor_pqc, host, grupos, args.openssl_bin, proc_semaphore, args.repeticiones): host for host in hostnames}

        # Conforme vayan terminando, recogemos los resultados con barra de progreso
        with tqdm(total=len(hostnames), desc="Escaneo PQC", unit="host") as pbar:
            for futuro in as_completed(futuros):
                if deadline is not None and time.time() > deadline:
                    pendientes = sum(1 for f in futuros if not f.done())
                    logger.warning(
                        "Timeout total de %.0f s alcanzado. Cancelando %d hosts pendientes.",
                        args.timeout_total, pendientes
                    )
                    for f in futuros:
                        f.cancel()
                    break
                host = futuros[futuro]
                try:
                    datos_host = futuro.result()
                    lista_resultados.append(datos_host)
                    
                    # Contar cuántas pruebas fueron exitosas
                    exitosos = sum(1 for prueba in datos_host["pruebas"] if prueba.get("connection_result") == CONNECTION_ACCEPTED)
                    total_pruebas = len(datos_host["pruebas"])
                    
                    # Loguear el resultado del host
                    if exitosos > 0:
                        logger.debug("Escaneo completado: %s (%d/%d pruebas exitosas)", host, exitosos, total_pruebas)
                    else:
                        logger.warning("Escaneo sin éxitos para %s (0/%d pruebas exitosas)", host, total_pruebas)
                except Exception as e:
                    logger.error("Error inesperado procesando %s: %s", host, e)
                finally:
                    pbar.update(1)  # Actualizar barra de progreso

    # Calcular tiempo total
    tiempo_total = time.time() - tiempo_inicio_total

    # Calcular estadísticas
    total_hosts = len(lista_resultados)
    hosts_con_exito = 0
    total_pruebas = 0
    pruebas_exitosas = 0
    
    # Recorrer resultados para estadísticas
    for resultado in lista_resultados:
        pruebas = resultado.get("pruebas", [])
        total_pruebas += len(pruebas)
        exitosos_host = sum(1 for p in pruebas if p.get("connection_result") == CONNECTION_ACCEPTED)
        pruebas_exitosas += exitosos_host
        if exitosos_host > 0:
            hosts_con_exito += 1
    
    # Generar resumen
    resumen = {
        "estadisticas": {
            "timestamp_finalizacion": datetime.now(timezone.utc).isoformat(),
            "tiempo_total_segundos": round(tiempo_total, 2),
            "total_hostnames": total_hosts,
            "hosts_con_al_menos_un_exito": hosts_con_exito,
            "total_pruebas": total_pruebas,
            "pruebas_exitosas": pruebas_exitosas,
            "tasa_exito_hosts_percent": round((hosts_con_exito / total_hosts * 100) if total_hosts else 0, 2),
            "tasa_exito_pruebas_percent": round((pruebas_exitosas / total_pruebas * 100) if total_pruebas else 0, 2),
            "grupos_probados": grupos
        }
    }

    # Calcular estadísticas agregadas por grupo
    estadisticas_grupos = generar_estadisticas_por_grupo(lista_resultados, grupos)
    
    # Guardar resultados
    RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)
    resultados_path = RESULTADOS_DIR / "resultados_sonda_pqc.json"
    csv_path = RESULTADOS_DIR / "resumen_por_grupo.csv"
    
    datos_finales = {
        "resumen": resumen["estadisticas"],
        "datos": lista_resultados
    }
    
    with resultados_path.open("w", encoding="utf-8") as f:
        json.dump(datos_finales, f, indent=4, ensure_ascii=False)
    
    # Exportar estadísticas por grupo a CSV
    exportar_estadisticas_csv(estadisticas_grupos, csv_path)

    logger.info("="*70)
    logger.info("Escaneo PQC completado")
    logger.info("Tiempo total: %.2f segundos", tiempo_total)
    logger.info("Hosts con al menos un éxito: %d/%d (%.2f%%)", 
                hosts_con_exito, total_hosts, resumen["estadisticas"]["tasa_exito_hosts_percent"])
    logger.info("Pruebas exitosas: %d/%d (%.2f%%)", 
                pruebas_exitosas, total_pruebas, resumen["estadisticas"]["tasa_exito_pruebas_percent"])
    logger.info("Resultados guardados en %s", resultados_path)
    logger.info("Resumen CSV guardado en %s", csv_path)
    logger.info("="*70)