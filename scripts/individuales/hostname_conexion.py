"""
Script para conectar a un hostname específico y obtener toda la información posible sobre la conexión, el certificado y el protocolo TLS/SSL utilizado. 
El resultado se guarda en un JSON único por hostname en la carpeta "resultados/". Además, se registra un log general de conexiones exitosas y errores en "resultados/hostnames.log".

El proceso se divide en tres etapas principales:
1. Conexión y recopilación de datos: Se conecta al hostname, se mide la latencia DNS, se realiza el handshake TLS/SSL y se extrae toda la información relevante del certificado y la conexión.
2. Almacenamiento de resultados: Se guarda toda la información recopilada en un JSON estructurado por hostname y se registra un log general de conexiones.
3. Manejo de errores: Se capturan y registran errores de conexión, resolución DNS o problemas con el certificado, asegurando que el script sea robusto y no se detenga ante fallos en un hostname específico.

Se ejecuta fuera del entorno de la sonda, permitiendo realizar pruebas puntuales a hosts específicos sin necesidad de escanear un dominio completo.
Ejemplo de uso:
python hostname_conexion.py --hostname www.ejemplo.com

Nota: Este script requiere permisos de red y acceso a Internet para funcionar correctamente. Asegúrate de tener las dependencias necesarias instaladas (ssl, cryptography, dns.resolver, etc.) y de ejecutar el script en un entorno con acceso a la red.
"""

# Imports necesarios para la conexión, manejo de certificados, resolución DNS, y almacenamiento de resultados
import argparse
import logging
from pathlib import Path
import socket
import ssl
import json
import time
import hashlib
import dns.resolver
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

# Configuración del logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# CONSTANTES DE RUTAS
# ============================================
BASE_DIR = Path(__file__).parent.parent.parent  # Directorio raíz del proyecto (3 niveles arriba)
RESULTADOS_DIR = BASE_DIR / "resultados"

# Crear el directorio de resultados si no existe
RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================
# FUNCIONES AUXILIARES
# ============================================

def resolver_dns(hostname: str):
    """
    Resuelve el DNS y mide la latencia.
    Devuelve la IP resuelta y la latencia en milisegundos.
    """
    try:
        inicio = time.perf_counter()
        respuesta = dns.resolver.resolve(hostname, 'A')
        latencia_dns = (time.perf_counter() - inicio) * 1000
        ip = str(respuesta[0]) if respuesta else None
        if not ip:
            return None, None
        return ip, round(latencia_dns, 2)
    except Exception as e:
        logger.error(f"Error al resolver DNS para {hostname}: {e}")
        return None, None

def obtener_versiones_tls_soportadas(hostname: str, ip: str):
    """
    Prueba diferentes versiones de TLS para ver cuáles soporta el servidor.
    Devuelve un diccionario con el resultado de cada versión.
    """
    versiones_soportadas = {}
    versiones_a_probar = [
        ("TLS1.0", ssl.TLSVersion.TLSv1),
        ("TLS1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS1.3", ssl.TLSVersion.TLSv1_3),
    ]
    
    # Para cada versión, intentamos establecer una conexión TLS específica y vemos si es exitosa o no
    for nombre_version, tls_version in versiones_a_probar:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            
            with socket.create_connection((ip, 443), timeout=2) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    versiones_soportadas[nombre_version] = True
                    logger.debug(f"Versión {nombre_version} soportada para {hostname}")
        except Exception:
            versiones_soportadas[nombre_version] = False
    
    return versiones_soportadas

def extraer_san(cert):
    """
    Extrae los Subject Alternative Names del certificado.
    Devuelve una lista de SANs encontrados.
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

def obtener_informacion_clave(cert):
    """
    Extrae información sobre la clave pública.
    Devuelve un diccionario con detalles de la clave.
    """
    public_key = cert.public_key()
    info = {
        "algoritmo": None,
        "tamaño_bits": None,
        "curva": None
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

def obtener_cadena_certificados(sock, hostname):
    """
    Obtiene la cadena completa de certificados.
    Devuelve una lista con la información de cada certificado.
    """
    cadena = []
    try:
        # Obtener el certificado del peer
        peer_cert_der = sock.getpeercert(binary_form=True)
        if peer_cert_der:
            cert = x509.load_der_x509_certificate(peer_cert_der)
            cert_info = {
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
                "pem": "-----BEGIN CERTIFICATE-----\n" + 
                       hashlib.sha256(peer_cert_der).hexdigest() + 
                       "\n-----END CERTIFICATE-----"
            }
            cadena.append(cert_info)
    except Exception as e:
        logger.debug(f"Error al obtener cadena de certificados: {e}")
    
    return cadena

def conectar_a_host(hostname: str):
    """
    Conecta a un host y obtiene toda la información posible.
    Realiza la conexión, obtiene información del certificado, protocolos soportados, y guarda los resultados en un JSON.
    """
    # Resuelve el DNS y mide la latencia
    ip, latencia_dns = resolver_dns(hostname)
    if not ip:
        logger.error(f"No se pudo resolver el hostname: {hostname}")
        return

    # Inicia la conexión SSL/TLS
    contexto_ssl = ssl.create_default_context()
    contexto_ssl.check_hostname = False
    contexto_ssl.verify_mode = ssl.CERT_NONE

    try:
        tiempo_inicio = time.perf_counter()
        
        # Conexión TCP
        with socket.create_connection((ip, 443), timeout=5) as sock:
            tiempo_tcp = time.perf_counter() - tiempo_inicio
            
            # Handshake TLS/SSL
            tiempo_handshake_inicio = time.perf_counter()
            with contexto_ssl.wrap_socket(sock, server_hostname=hostname) as ssock:
                tiempo_handshake = time.perf_counter() - tiempo_handshake_inicio
                tiempo_conexion_total = time.perf_counter() - tiempo_inicio

                # Información de la conexión y protocolo
                cipher_suite = ssock.cipher()
                tls_version = ssock.version()
                
                # Obtener información del certificado
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der)
                
                # Calcular días válido
                ahora = datetime.now(timezone.utc)
                valido_desde = cert.not_valid_before_utc
                valido_hasta = cert.not_valid_after_utc
                
                if ahora < valido_desde:
                    dias_valido = (valido_hasta - valido_desde).days
                    estado_validez = "no_valido_aun"
                elif ahora > valido_hasta:
                    dias_valido = 0
                    estado_validez = "caducado"
                else:
                    dias_valido = (valido_hasta - ahora).days
                    estado_validez = "valido"
                
                # Compilar todos los datos
                datos_completos = {
                    "hostname": hostname,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "conexion": {
                        "ip": ip,
                        "latencia_dns_ms": latencia_dns,
                        "tiempo_tcp_ms": round(tiempo_tcp * 1000, 2),
                        "tiempo_handshake_tls_ms": round(tiempo_handshake * 1000, 2),
                        "tiempo_total_ms": round(tiempo_conexion_total * 1000, 2)
                    },
                    "protocolo": {
                        "version_tls": tls_version,
                        "cipher_suite": cipher_suite[0],
                        "cipher_suite_protocolo": cipher_suite[1],
                        "cipher_suite_bits": cipher_suite[2],
                        "versiones_soportadas": obtener_versiones_tls_soportadas(hostname, ip)
                    },
                    "certificado_principal": {
                        "sujeto": cert.subject.rfc4514_string(),
                        "emisor": cert.issuer.rfc4514_string(),
                        "numero_serie": cert.serial_number,
                        "algoritmo_firma": cert.signature_algorithm_oid._name,
                        "valido_desde": valido_desde.isoformat(),
                        "valido_hasta": valido_hasta.isoformat(),
                        "dias_valido": dias_valido,
                        "estado_validez": estado_validez,
                        "hash_sha256": hashlib.sha256(cert_der).hexdigest(),
                        "hash_sha1": hashlib.sha1(cert_der).hexdigest(),
                        "es_autofirmado": cert.issuer == cert.subject,
                        "subject_alternative_names": extraer_san(cert),
                        "clave_publica": obtener_informacion_clave(cert)
                    },
                    "cadena_certificados": obtener_cadena_certificados(ssock, hostname)
                }
                
                # Guardar resultados en un JSON único por hostname
                json_file = RESULTADOS_DIR / f"{hostname}.json"
                RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)
                with json_file.open('w') as f:
                    json.dump(datos_completos, f, default=str, ensure_ascii=False, indent=2)
                    logger.info(f"Datos completos guardados en {json_file}")

                # Guardar en el log general
                log_file = RESULTADOS_DIR / "hostnames.log"
                with log_file.open('a') as f:
                    f.write(f"[{datetime.now().isoformat()}] Conexión exitosa a {hostname} (IP: {ip}, TLS: {tls_version}, Tiempo: {tiempo_conexion_total:.2f}s)\n")

                logger.info(f"✓ Conexión exitosa a {hostname}")
                logger.info(f"  IP: {ip}")
                logger.info(f"  TLS Version: {tls_version}")
                logger.info(f"  Cipher Suite: {cipher_suite[0]}")
                logger.info(f"  Issuer: {cert.issuer.rfc4514_string()}")

    except Exception as e:
        logger.error(f"Error al conectar a {hostname}: {e}")
        # Registrar error en el log
        log_file = RESULTADOS_DIR / "hostnames.log"
        RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)
        with log_file.open('a') as f:
            f.write(f"[{datetime.now().isoformat()}] ERROR al conectar a {hostname}: {e}\n")


# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Conexión a un hostname específico.')
    parser.add_argument('--hostname', type=str, required=True, help='El hostname al que conectarse.')
    args = parser.parse_args()
    conectar_a_host(args.hostname)