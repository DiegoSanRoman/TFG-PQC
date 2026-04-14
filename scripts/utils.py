"""
utils.py
--------
Módulo de utilidades compartidas entre las sondas del proyecto TFG-PQC.

Contiene funciones reutilizables de resolución DNS, análisis de certificados X.509
y detección de versiones TLS soportadas. Todas estas funciones estaban duplicadas
en sonda_base.py y hostname_conexion.py; se centralizan aquí para evitar divergencias.
"""

import hashlib
import logging
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

logger = logging.getLogger(__name__)


# ============================================
# RESOLUCIÓN DNS
# ============================================

def resolver_dns(hostname: str) -> Tuple[Optional[str], Optional[float]]:
    """
    Resuelve el DNS de un hostname y mide la latencia.

    :param hostname: Nombre del host a resolver
    :return: Tupla (ip, latencia_ms) o (None, None) si falla
    """
    try:
        inicio = time.perf_counter()
        respuesta = dns.resolver.resolve(hostname, 'A')
        latencia = (time.perf_counter() - inicio) * 1000
        ip = str(respuesta[0]) if respuesta else None
        if not ip:
            return None, None
        return ip, round(latencia, 2)
    except Exception as e:
        logger.debug("Error al resolver DNS para %s: %s", hostname, e)
        return None, None


# ============================================
# ANÁLISIS DE CERTIFICADOS X.509
# ============================================

def extraer_san(cert) -> List[str]:
    """
    Extrae los Subject Alternative Names (SAN) del certificado X.509.

    :param cert: Certificado X.509 (objeto cryptography)
    :return: Lista de nombres DNS en los SANs
    """
    san_list = []
    try:
        san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_extension.value:
            if isinstance(name, x509.DNSName):
                san_list.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return san_list


def obtener_informacion_clave(cert) -> Dict[str, Any]:
    """
    Extrae información sobre la clave pública del certificado.

    :param cert: Certificado X.509 (objeto cryptography)
    :return: Diccionario con 'algoritmo', 'tamaño_bits' y 'curva' (None si no aplica)
    """
    public_key = cert.public_key()
    info: Dict[str, Any] = {
        "algoritmo": None,
        "tamaño_bits": None,
        "curva": None,
    }
    if isinstance(public_key, rsa.RSAPublicKey):
        info["algoritmo"] = "RSA"
        info["tamaño_bits"] = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        info["algoritmo"] = "ECDSA"
        info["tamaño_bits"] = public_key.key_size
        info["curva"] = public_key.curve.name
    elif isinstance(public_key, dsa.DSAPublicKey):
        info["algoritmo"] = "DSA"
        info["tamaño_bits"] = public_key.key_size
    return info


def obtener_cadena_certificados(sock, hostname: str) -> List[Dict[str, Any]]:
    """
    Obtiene información del certificado del servidor desde un socket SSL conectado.

    :param sock: Socket SSL/TLS ya conectado (con getpeercert disponible)
    :param hostname: Nombre del host (usado solo para logging)
    :return: Lista con un dict de información del certificado (posición 0)
    """
    cadena: List[Dict[str, Any]] = []
    try:
        peer_cert_der = sock.getpeercert(binary_form=True)
        if peer_cert_der:
            cert = x509.load_der_x509_certificate(peer_cert_der)
            cadena.append({
                "posicion": 0,
                "sujeto": cert.subject.rfc4514_string(),
                "emisor": cert.issuer.rfc4514_string(),
                "numero_serie": cert.serial_number,
                "valido_desde": cert.not_valid_before_utc.isoformat(),
                "valido_hasta": cert.not_valid_after_utc.isoformat(),
                "algoritmo_firma": cert.signature_algorithm_oid._name,
                "hash_sha256": hashlib.sha256(peer_cert_der).hexdigest(),
                "hash_sha1": hashlib.sha1(peer_cert_der).hexdigest(),
                "es_autofirmado": cert.issuer == cert.subject,
                "subject_alternative_names": extraer_san(cert),
                "clave_publica": obtener_informacion_clave(cert),
            })
    except Exception as e:
        logger.debug("Error al obtener cadena de certificados para %s: %s", hostname, e)
    return cadena


# ============================================
# VALIDACIÓN DE HOSTNAMES
# ============================================

def es_hostname_valido(hostname: str) -> bool:
    """
    Comprueba si un string es un hostname DNS plausible.

    Reglas aplicadas (ligeras, para filtrar basura en CSVs):
    - No vacío tras strip
    - Contiene al menos un punto (descarta etiquetas sueltas como "localhost")
    - Sin espacios internos
    - Longitud máxima de 253 caracteres (límite DNS)
    - Solo caracteres permitidos en DNS: letras, dígitos, guiones y puntos

    :param hostname: String a validar
    :return: True si parece un hostname válido, False en caso contrario
    """
    if not hostname or not isinstance(hostname, str):
        return False
    h = hostname.strip()
    if not h or '.' not in h or ' ' in h or len(h) > 253:
        return False
    # Caracteres permitidos en DNS (RFC 1123): a-z, A-Z, 0-9, '-', '.'
    if not re.fullmatch(r'[a-zA-Z0-9.\-]+', h):
        return False
    return True


# ============================================
# DETECCIÓN DE VERSIONES TLS
# ============================================

def obtener_versiones_tls_soportadas(hostname: str, ip: str) -> Dict[str, bool]:
    """
    Prueba diferentes versiones de TLS para ver cuáles soporta el servidor.

    :param hostname: Nombre del host (usado como SNI)
    :param ip: Dirección IP del servidor
    :return: Diccionario {versión: soportada}, p.ej. {"TLS1.2": True, "TLS1.3": True}
    """
    versiones_soportadas: Dict[str, bool] = {}
    versiones_a_probar = [
        ("TLS1.0", ssl.TLSVersion.TLSv1),
        ("TLS1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS1.3", ssl.TLSVersion.TLSv1_3),
    ]
    for nombre_version, tls_version in versiones_a_probar:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((ip, 443), timeout=2) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    versiones_soportadas[nombre_version] = True
                    logger.debug("Versión %s soportada para %s", nombre_version, hostname)
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
            versiones_soportadas[nombre_version] = False
            logger.debug("Versión %s NO soportada para %s: %s", nombre_version, hostname, type(e).__name__)
        except Exception:
            versiones_soportadas[nombre_version] = False
    return versiones_soportadas
