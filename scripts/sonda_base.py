"""
sonda_base.py
En esta primera versión de la sonda, nos conectamos a servidores HTTPS de diferentes hostnames
y extraemos información básica del protocolo TLS y del certificado.
No verificamos la validez del certificado para poder conectarnos a servidores
con certificados autofirmados o caducados (lo hice asi porque el certificado de la uc3m no me dejaba continuar).
"""

# Importaciones necesarias
import socket                                                   # Para conexiones TCP
import ssl                                                      # Para capa SSL/TLS 
import json                                                     # Para guardar resultados en JSON
import time                                                     # Para medir tiempo de conexión
import hashlib                                                  # Para calcular hashes de certificados
import dns.resolver                                             # Para medir latencia DNS
from cryptography import x509                                   # Para manejar certificados X.509
from cryptography.hazmat.primitives import serialization        # Para manejar claves públicas
from datetime import datetime, timezone                         # Para timestamps y zona horaria
from datetime import timedelta                                  # Para cálculos de tiempo
import os                                                       # Para variables de entorno
import csv                                                      # Para leer archivos CSV
from concurrent.futures import ThreadPoolExecutor, as_completed # Para concurrencia
from pathlib import Path                                        # Para rutas
import argparse                                                 # Para argumentos CLI
import logging                                                  # Para logging

logger = logging.getLogger(__name__)


# ============================================
# FUNCIONES AUXILIARES
# ============================================

def leer_hostnames_csv(ruta_csv, longitud_max):
    '''
    Lee los hostnames desde un archivo CSV (columna B)
    :param ruta_csv: Ruta al archivo CSV
    :param longitud_max: Número máximo de hostnames a leer
    :return: Lista de hostnames
    '''
    hostnames = []
    try:
        ruta = Path(ruta_csv)
        with ruta.open('r', encoding='utf-8') as archivo:
            lector = csv.reader(archivo)
            for fila in lector:
                # La columna B es el índice 1 (columna A es índice 0)
                if len(fila) >= 2 and fila[1]:  # Verificar que existe columna B y no está vacía
                    hostnames.append(fila[1])
                    # Detener si alcanzamos el límite
                    if len(hostnames) >= longitud_max:
                        break
    except Exception as e:
        logger.error("Error al leer el archivo CSV: %s", e)
    return hostnames


def resolver_dns(hostname):
    '''
    Resuelve el DNS y mide la latencia en milisegundos
    :param hostname: El nombre del host o dominio a resolver
    :return: Tupla (ip, latencia_ms) o (None, None) si falla
    '''

    try:
        inicio = time.time()
        respuesta = dns.resolver.resolve(hostname, 'A')
        latencia = (time.time() - inicio) * 1000  # Convertir a ms
        ip = str(respuesta[0]) if respuesta else None
        if not ip:
            return None, None
        return ip, round(latencia, 2)
    except Exception:
        return None, None


def extraer_san(cert):
    '''
    Extrae los Subject Alternative Names (SAN) del certificado
    :param cert: Certificado X.509
    :return: Lista de Subject Alternative Names
    '''

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
    '''
    Extrae información sobre la clave pública
    :param cert: Certificado X.509
    :return: Diccionario con tipo y tamaño de clave
    '''

    public_key = cert.public_key()
    info = {
        "algoritmo": None,
        "tamaño_bits": None
    }
    
    # Determinar tipo de clave
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    
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
    '''
    Obtiene la cadena completa de certificados
    :param sock: Socket SSL/TLS conectado
    :param hostname: Nombre del host o dominio
    :return: Lista de certificados en la cadena
    '''
    cadena = []
    try:
        # Intentar obtener la cadena de certificados del servidor
        # Nota: Esto es limitado sin validación, así que lo intentamos con SSLContext
        peer_cert_der = sock.getpeercert(binary_form=True)
        if peer_cert_der:
            cert = x509.load_der_x509_certificate(peer_cert_der)
            cadena.append({
                "sujeto": cert.subject.rfc4514_string(),
                "emisor": cert.issuer.rfc4514_string(),
                "posicion": 0
            })
    except Exception:
        pass
    
    return cadena


def es_cipher_debil(cipher_name):
    '''
    Determina si una suite de cifrado es débil
    :param cipher_name: Nombre de la suite de cifrado
    :return: True si es débil, False si no
    '''

    debiles = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'ADH']
    return any(debil in cipher_name for debil in debiles)


def tiene_pfs(cipher_name):
    '''
    Determina si una suite de cifrado tiene Perfect Forward Secrecy
    :param cipher_name: Nombre de la suite de cifrado
    :return: True si tiene PFS, False si no
    '''

    return 'ECDHE' in cipher_name or 'DHE' in cipher_name


def en_contenedor():
    try:
        if Path("/.dockerenv").exists():
            return True
        with open("/proc/1/cgroup", "r", encoding="utf-8") as f:
            contenido = f.read()
            return "docker" in contenido or "containerd" in contenido
    except Exception:
        return False


def crear_contexto_ssl(modo_compatible=False):
    # Cargamos la configuración por defecto de SSL del sistema
    ctx = ssl.create_default_context()

    # Desactivamos la validación del nombre del host (permite conectar aunque el cert sea para otro dominio)
    ctx.check_hostname = False

    # Desactivamos la verificación del certificado (permite certs caducados, autofirmados o no fiables)
    ctx.verify_mode = ssl.CERT_NONE

    # En entornos OQS (OpenSSL modificado) a veces falla TLS 1.3 con servidores clásicos
    if modo_compatible:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except Exception:
            pass

    return ctx


def conectar_y_extraer(hostname, ip, ctx, resultado, latencia_dns):
    # --- MEDICIÓN DE TIEMPO ---
    tiempo_inicio = time.time()

    try:
        # --- ESTABLECIMIENTO DE LA CONEXIÓN ---
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Extraemos una tupla con (nombre_cifrado, version_protocolo, bits_usados)
                detalles = ssock.cipher()

                # Obtenemos el certificado del servidor en formato binario (DER)
                cert_der = ssock.getpeercert(binary_form=True)

                # Usamos la librería cryptography para convertir esos bytes "en bruto" en un objeto manejable
                cert = x509.load_der_x509_certificate(cert_der)

                # Registramos el momento final después de completar la conexión y obtener el certificado
                tiempo_fin = time.time()
                tiempo_conexion = tiempo_fin - tiempo_inicio

                # --- EXTRACCIÓN Y ORGANIZACIÓN DE DATOS ---

                # Información de la clave pública
                info_clave = obtener_informacion_clave(cert)

                # Nombres alternativos (SAN)
                san_list = extraer_san(cert)

                # Fechas de validez
                valido_desde = cert.not_valid_before_utc
                valido_hasta = cert.not_valid_after_utc
                ahora = datetime.now(timezone.utc)

                # Cálculo de días válido
                if ahora < valido_desde:
                    dias_valido = (valido_hasta - valido_desde).days
                    estado_validez = "no_valido_aun"
                elif ahora > valido_hasta:
                    dias_valido = 0
                    estado_validez = "caducado"
                else:
                    dias_valido = (valido_hasta - ahora).days
                    estado_validez = "valido"

                # Hash del certificado
                hash_sha256 = hashlib.sha256(cert_der).hexdigest()
                hash_sha1 = hashlib.sha1(cert_der).hexdigest()

                # Suite de cifrado analizada
                cipher_name = detalles[0]
                tiene_pfs_socket = tiene_pfs(cipher_name)
                es_debil = es_cipher_debil(cipher_name)

                # Información de seguridad
                tamaño_clave = info_clave.get("tamaño_bits")
                clave_debil = tamaño_clave is not None and tamaño_clave < 2048 if info_clave.get("algoritmo") == "RSA" else False

                resultado["estado"] = "exito"
                resultado["datos"] = {
                    "conexion": {
                        "tiempo_conexion_segundos": round(tiempo_conexion, 3),
                        "latencia_dns_ms": latencia_dns
                    },
                    "protocolo": {
                        "version": ssock.version(),         
                        "suite_cifrado": cipher_name,       
                        "bits_clave": detalles[2],          
                        "perfect_forward_secrecy": tiene_pfs_socket,
                        "suite_debil": es_debil
                    },
                    "certificado": {
                        # Información básica
                        "sujeto": cert.subject.rfc4514_string(),
                        "emisor": cert.issuer.rfc4514_string(),
                        "numero_serie": cert.serial_number,
                        "algoritmo_firma": cert.signature_algorithm_oid._name,

                        # Fechas de validez
                        "valido_desde": valido_desde.isoformat(),
                        "valido_hasta": valido_hasta.isoformat(),
                        "dias_valido": dias_valido,
                        "estado_validez": estado_validez,

                        # Nombres alternativos
                        "subject_alternative_names": san_list,

                        # Información de clave pública
                        "clave_publica": {
                            "algoritmo": info_clave.get("algoritmo"),
                            "tamaño_bits": tamaño_clave,
                            "clave_debil": clave_debil
                        },

                        # Hashes
                        "hash": {
                            "sha256": hash_sha256,
                            "sha1": hash_sha1
                        },

                        # Cadena de certificados
                        "cadena_certificados": obtener_cadena_certificados(ssock, hostname),

                        # Información adicional
                        "es_autofirmado": cert.issuer == cert.subject
                    }
                }
    except socket.timeout:
        raise RuntimeError(f"Timeout conectando a {ip}:443 para {hostname}")
    except ConnectionRefusedError:
        raise RuntimeError(f"Conexión rechazada por {ip}:443")
    except (socket.error, OSError) as e:
        raise RuntimeError(f"Error de conexión de red a {ip}:443 - {type(e).__name__}: {e}")
    except ssl.SSLError as e:
        raise  # Re-raise SSL errors para que sean manejados arriba
    except Exception as e:
        raise RuntimeError(f"Error inesperado en conexión: {type(e).__name__}: {e}")


# ============================================
# FUNCION PRINCIPAL DE LA SONDA
# ============================================

def escanear_servidor(hostname):
    '''
    Escanea un servidor HTTPS y extrae información TLS y del certificado
    :param hostname: El nombre del host o dominio del servidor HTTPS a escanear
    :return: Diccionario con los resultados del escaneo
    '''

    # Estructura base del json que tendrá el resultado
    resultado = {
        "hostname": hostname,
        "timestamp": datetime.now().isoformat(),
        "estado": "error",
        "datos": None,
        "error": None,
        "entorno": {
            "openssl_version": ssl.OPENSSL_VERSION,
            "fallback_tls12": False
        }
    }
    
    try:
        # --- RESOLUCIÓN DNS Y LATENCIA ---
        ip, latencia_dns = resolver_dns(hostname)
        if not ip:
            logger.warning("No se pudo resolver DNS para %s", hostname)
            raise RuntimeError(f"No se pudo resolver DNS para {hostname}")
        
        logger.debug("DNS resuelto para %s -> %s (latencia: %.2f ms)", hostname, ip, latencia_dns)

        try:
            contexto = crear_contexto_ssl(modo_compatible=False)
            conectar_y_extraer(hostname, ip, contexto, resultado, latencia_dns)
        except RuntimeError as e:
            # Errores de red (timeout, conexión rechazada, etc.)
            logger.warning("Error de red para %s: %s", hostname, e)
            raise
        except ssl.SSLError as e:
            # Errores de TLS/SSL
            logger.debug("Error SSL inicial para %s: %s", hostname, e)
            # Solo reintentamos en modo compatible si el OpenSSL es OQS
            if "oqs" in ssl.OPENSSL_VERSION.lower():
                logger.debug("Reintentando con fallback TLS 1.2 para %s", hostname)
                resultado["entorno"]["fallback_tls12"] = True
                contexto = crear_contexto_ssl(modo_compatible=True)
                try:
                    conectar_y_extraer(hostname, ip, contexto, resultado, latencia_dns)
                except RuntimeError as e:
                    logger.warning("Error de red en fallback para %s: %s", hostname, e)
                    raise
                except ssl.SSLError as e:
                    logger.error("Error SSL persistente en fallback para %s: %s", hostname, e)
                    raise
            else:
                logger.error("Error SSL para %s (OpenSSL no es OQS): %s", hostname, e)
                raise

    except Exception as e:
        # Si algo falla, guardamos el mensaje de error
        resultado["error"] = str(e)
        logger.debug("Escaneo fallido para %s: %s", hostname, resultado["error"])
    
    # Devolvemos el resultado completo
    return resultado


# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Sonda TLS: escaneo concurrente de servidores HTTPS")
    parser.add_argument("--max-workers", type=int, default=50, help="Número de hilos en paralelo")
    parser.add_argument("--log-level", default="INFO", help="Nivel de log: DEBUG, INFO, WARNING, ERROR")
    parser.add_argument("--log-file", default="resultados/sonda_base.log", help="Ruta del archivo de log")
    args = parser.parse_args()

    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler()
        ]
    )

    # Evita ejecutar con OpenSSL OQS (contenedor) por defecto.
    # Para forzar ejecución en OQS, exporta: ALLOW_OQS=1
    if en_contenedor() and os.getenv("ALLOW_CONTAINER") != "1":
        logger.error("Contenedor detectado. Ejecuta esta sonda fuera de Docker para usar el OpenSSL del sistema.")
        logger.error("Si quieres forzar en contenedor, usa: ALLOW_CONTAINER=1")
        raise SystemExit(1)

    if "oqs" in ssl.OPENSSL_VERSION.lower() and os.getenv("ALLOW_OQS") != "1":
        logger.error("OpenSSL OQS detectado. Ejecuta esta sonda fuera del contenedor para usar el OpenSSL del sistema.")
        logger.error("Si quieres forzar en OQS, usa: ALLOW_OQS=1")
        raise SystemExit(1)
    
    # Leer hostnames desde el archivo CSV
    ruta_csv = Path("data/tranco.csv")
    hostnames = leer_hostnames_csv(ruta_csv, 100)
    
    if not hostnames:
        logger.error("No se encontraron hostnames en %s", ruta_csv)
        raise SystemExit(1)
    
    logger.info("Se han cargado %s hostnames desde %s", len(hostnames), ruta_csv)
    
    lista_resultados = []

    # Definimos el número de hilos (trabajadores en paralelo)
    MAX_WORKERS = args.max_workers 

    logger.info("Iniciando escaneo concurrente con %s hilos...", MAX_WORKERS)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Lanzamos todas las tareas
        futuros = {executor.submit(escanear_servidor, host): host for host in hostnames}
        
        # Conforme vayan terminando, recogemos los resultados
        for i, futuro in enumerate(as_completed(futuros)):
            host = futuros[futuro]
            try:
                datos_host = futuro.result()
                lista_resultados.append(datos_host)
                if datos_host.get("estado") == "exito":
                    logger.debug("[%s/%s] Escaneo exitoso: %s", i, len(hostnames), host)
                else:
                    logger.warning("[%s/%s] Escaneo fallido para %s: %s", i, len(hostnames), host, datos_host.get("error"))
                if i % 10 == 0: # Feedback visual cada 10 hosts
                    logger.info("[%s/%s] Progreso", i, len(hostnames))
            except Exception as e:
                logger.error("Error inesperado procesando %s: %s", host, e)

    # Guardar resultados
    resultados_dir = Path("resultados")
    resultados_dir.mkdir(parents=True, exist_ok=True)
    resultados_path = resultados_dir / "resultados_sonda_base.json"
    with resultados_path.open("w", encoding="utf-8") as f:
        json.dump(lista_resultados, f, indent=4, ensure_ascii=False)

    logger.info("Listo. Se han guardado los datos de %s servidores en %s.", len(hostnames), resultados_path)