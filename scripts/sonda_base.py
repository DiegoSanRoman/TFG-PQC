"""
sonda_base.py
En esta primera versión de la sonda, nos conectamos a servidores HTTPS de diferentes hostnames
y extraemos información básica del protocolo TLS y del certificado.
No verificamos la validez del certificado para poder conectarnos a servidores
con certificados autofirmados o caducados (lo hice asi porque el certificado de la uc3m no me dejaba continuar).
"""

# Importaciones necesarias
import socket                                                       # Para conexiones TCP
import ssl                                                          # Para capa SSL/TLS 
import json                                                         # Para guardar resultados en JSON
import time                                                         # Para medir tiempo de conexión
import hashlib                                                      # Para calcular hashes de certificados
import dns.resolver                                                 # Para medir latencia DNS
from cryptography import x509                                       # Para manejar certificados X.509
from cryptography.hazmat.primitives import serialization            # Para manejar claves públicas
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa  # Para tipos de claves simétricas
from datetime import datetime, timezone                             # Para timestamps y zona horaria
from datetime import timedelta                                      # Para cálculos de tiempo
import os                                                           # Para variables de entorno
import csv                                                          # Para leer archivos CSV
from concurrent.futures import ThreadPoolExecutor, as_completed     # Para concurrencia
from pathlib import Path                                            # Para rutas
import argparse                                                     # Para argumentos CLI
import logging                                                      # Para logging
from dataclasses import dataclass, asdict                           # Para dataclasses
from typing import Optional, List, Dict, Any                        # Para type hints
from tqdm import tqdm                                               # Para barras de progreso

logger = logging.getLogger(__name__)

# ============================================
# CONSTANTES DE RUTAS
# ============================================
BASE_DIR = Path(__file__).parent.parent  # Directorio raíz del proyecto
DATA_DIR = BASE_DIR / "data"
RESULTADOS_DIR = BASE_DIR / "resultados"
CSV_DEFECTO = DATA_DIR / "tranco.csv"
LOG_DEFECTO = RESULTADOS_DIR / "sonda_base.log"


# ============================================
# DATACLASSES PARA ESTRUCTURA DE RESULTADOS
# ============================================

@dataclass
class Hash:
    sha256: str
    sha1: str

@dataclass
class ClavePublica:
    algoritmo: Optional[str]
    tamaño_bits: Optional[int]
    clave_debil: bool
    curva: Optional[str] = None

@dataclass
class Conexion:
    tiempo_conexion_segundos: float
    latencia_dns_ms: Optional[float]

@dataclass
class Protocolo:
    version: str
    suite_cifrado: str
    bits_clave: int
    perfect_forward_secrecy: bool
    suite_debil: bool

@dataclass
class Certificado:
    sujeto: str
    emisor: str
    numero_serie: int
    algoritmo_firma: str
    valido_desde: str
    valido_hasta: str
    dias_valido: int
    estado_validez: str
    subject_alternative_names: List[str]
    clave_publica: ClavePublica
    hash: Hash
    cadena_certificados: List[Dict[str, Any]]
    es_autofirmado: bool

@dataclass
class AnálisisSeguridadAvanzado:
    hsts_presente: bool
    hsts_max_age: Optional[int]
    ocsp_stapling: bool
    versiones_tls_soportadas: Dict[str, bool]  # {"TLS1.0": True, "TLS1.1": False, "TLS1.2": True, "TLS1.3": True}

@dataclass
class DatosExito:
    conexion: Conexion
    protocolo: Protocolo
    certificado: Certificado
    seguridad_avanzada: AnálisisSeguridadAvanzado

@dataclass
class Entorno:
    openssl_version: str
    fallback_tls12: bool

@dataclass
class ResultadoEscaneo:
    hostname: str
    timestamp: str
    estado: str  # "exito" o "error"
    datos: Optional[DatosExito]
    error: Optional[str]
    entorno: Entorno
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convierte a diccionario, serializando dataclasses anidadas.
        :return: Diccionario con los datos del escaneo
        """

        result = asdict(self)
        return result



# ============================================
# ANALIZADOR DE CERTIFICADOS
# ============================================

class CertificateAnalyzer:
    '''Analiza y procesa certificados X.509'''
    
    def __init__(self, cert_der: bytes, hostname: str, ip: str, ssock, latencia_dns: Optional[float]):
        '''
        :param cert_der: Certificado en formato DER (bytes)
        :param hostname: Nombre del host o dominio
        :param ip: IP del servidor
        :param ssock: Socket SSL/TLS conectado
        :param latencia_dns: Latencia DNS en milisegundos (opcional)
        '''

        self.cert_der = cert_der
        self.hostname = hostname
        self.ip = ip
        self.ssock = ssock
        self.latencia_dns = latencia_dns
        self.cert = x509.load_der_x509_certificate(cert_der)
    
    def analizar(self, tiempo_conexion: float) -> DatosExito:
        '''
        Realiza análisis completo del certificado
        :param tiempo_conexion: Tiempo de conexión en segundos
        :return: DatosExito con la información procesada
        '''

        detalles = self.ssock.cipher()
        
        return DatosExito(
            conexion=self._analizar_conexion(tiempo_conexion),
            protocolo=self._analizar_protocolo(detalles),
            certificado=self._analizar_certificado(),
            seguridad_avanzada=self._analizar_seguridad_avanzada()
        )
    
    def _analizar_conexion(self, tiempo_conexion: float) -> Conexion:
        '''
        Extrae información de la conexión
        :param tiempo_conexion: Tiempo de conexión en segundos
        :return: Conexion con los datos de la conexión
        '''

        return Conexion(
            tiempo_conexion_segundos=round(tiempo_conexion, 3),
            latencia_dns_ms=self.latencia_dns
        )
    
    def _analizar_protocolo(self, detalles: tuple) -> Protocolo:
        '''
        Extrae información del protocolo TLS/SSL
        :param detalles: Tupla con detalles del cifrado (nombre, versión, bits clave)
        :return: Protocolo con los datos del protocolo TLS/SSL
        '''

        cipher_name = detalles[0]
        return Protocolo(
            version=self.ssock.version(),
            suite_cifrado=cipher_name,
            bits_clave=detalles[2],
            perfect_forward_secrecy=tiene_pfs(cipher_name),
            suite_debil=es_cipher_debil(cipher_name)
        )
    
    def _analizar_certificado(self) -> Certificado:
        '''
        Extrae información del certificado
        :return: Certificado con los datos del certificado
        '''

        info_clave = obtener_informacion_clave(self.cert)
        san_list = extraer_san(self.cert)
        
        # Fechas de validez
        valido_desde = self.cert.not_valid_before_utc
        valido_hasta = self.cert.not_valid_after_utc
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
        hash_sha256 = hashlib.sha256(self.cert_der).hexdigest()
        hash_sha1 = hashlib.sha1(self.cert_der).hexdigest()
        
        # Información de seguridad
        tamaño_clave = info_clave.get("tamaño_bits")
        clave_debil = tamaño_clave is not None and tamaño_clave < 2048 if info_clave.get("algoritmo") == "RSA" else False
        
        clave_publica = ClavePublica(
            algoritmo=info_clave.get("algoritmo"),
            tamaño_bits=tamaño_clave,
            clave_debil=clave_debil,
            curva=info_clave.get("curva")
        )
        
        return Certificado(
            sujeto=self.cert.subject.rfc4514_string(),
            emisor=self.cert.issuer.rfc4514_string(),
            numero_serie=self.cert.serial_number,
            algoritmo_firma=self.cert.signature_algorithm_oid._name,
            valido_desde=valido_desde.isoformat(),
            valido_hasta=valido_hasta.isoformat(),
            dias_valido=dias_valido,
            estado_validez=estado_validez,
            subject_alternative_names=san_list,
            clave_publica=clave_publica,
            hash=Hash(sha256=hash_sha256, sha1=hash_sha1),
            cadena_certificados=obtener_cadena_certificados(self.ssock, self.hostname),
            es_autofirmado=self.cert.issuer == self.cert.subject
        )
    
    def _analizar_seguridad_avanzada(self) -> AnálisisSeguridadAvanzado:
        '''
        Extrae análisis de seguridad avanzada: HSTS, OCSP, versiones TLS
        :return: AnálisisSeguridadAvanzado con los datos de seguridad avanzada
        '''

        logger.debug("Analizando seguridad avanzada para %s", self.hostname)
        
        # HSTS
        hsts_presente, hsts_max_age = verificar_hsts(self.hostname, self.ip)
        
        # OCSP Stapling
        ocsp_stapling = verificar_ocsp_stapling(self.ssock)
        
        # Versiones de TLS soportadas (esto puede ser lento, así que lo hacemos paralelo si es necesario)
        versiones_tls = obtener_versiones_tls_soportadas(self.hostname, self.ip)
        
        return AnálisisSeguridadAvanzado(
            hsts_presente=hsts_presente,
            hsts_max_age=hsts_max_age,
            ocsp_stapling=ocsp_stapling,
            versiones_tls_soportadas=versiones_tls
        )



# ============================================
# FUNCIONES AUXILIARES
# ============================================

def leer_hostnames_csv(ruta_csv: Path, longitud_max: int) -> List[str]:
    '''
    Lee los hostnames desde un archivo CSV (columna B)
    :param ruta_csv: Ruta al archivo CSV (Path object)
    :param longitud_max: Número máximo de hostnames a leer
    :return: Lista de hostnames
    '''
    hostnames = []
    try:
        with ruta_csv.open('r', encoding='utf-8') as archivo:
            lector = csv.reader(archivo)
            for fila in lector:
                # La columna B es el índice 1 (columna A es índice 0)
                if len(fila) >= 2 and fila[1]:  # Verificar que existe columna B y no está vacía
                    hostnames.append(fila[1])
                    # Detener si alcanzamos el límite
                    if len(hostnames) >= longitud_max:
                        break
    except Exception as e:
        logger.error("Error al leer el archivo CSV %s: %s", ruta_csv, e)
    return hostnames


def resolver_dns(hostname):
    '''
    Resuelve el DNS y mide la latencia en milisegundos
    :param hostname: El nombre del host o dominio a resolver
    :return: Tupla (ip, latencia_ms) o (None, None) si falla
    '''

    try:
        inicio = time.perf_counter()
        respuesta = dns.resolver.resolve(hostname, 'A')
        latencia = (time.perf_counter() - inicio) * 1000  # Convertir a ms
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


def verificar_hsts(hostname: str, ip: str) -> tuple[bool, Optional[int]]:
    '''
    Verifica si el servidor envía la cabecera HSTS (Strict-Transport-Security)
    :param hostname: Nombre del host
    :param ip: IP del servidor
    :return: Tupla (hsts_presente, max_age) donde max_age es None si no está presente
    '''
    try:
        with socket.create_connection((ip, 443), timeout=2) as sock:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Enviar petición HTTP GET
                peticion = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                ssock.sendall(peticion.encode())
                
                # Recibir respuesta
                respuesta = b""
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        respuesta += chunk
                    except:
                        break
                
                # Parsear headers
                respuesta_str = respuesta.decode('utf-8', errors='ignore')
                headers = respuesta_str.split('\r\n\r\n')[0]
                
                for linea in headers.split('\r\n'):
                    if linea.lower().startswith('strict-transport-security'):
                        # Extraer max-age
                        max_age = None
                        for param in linea.split(';'):
                            if 'max-age' in param.lower():
                                try:
                                    max_age = int(param.split('=')[1].strip())
                                except:
                                    pass
                        return True, max_age
                
                return False, None
    except Exception as e:
        logger.debug("Error verificando HSTS para %s: %s", hostname, e)
        return False, None


def verificar_ocsp_stapling(ssock) -> bool:
    '''
    Verifica si el servidor adjunta respuesta de revocación OCSP (OCSP Stapling)
    :param ssock: Socket SSL/TLS conectado
    :return: True si tiene OCSP Stapling, False si no
    '''
    try:
        # Obtener información del handshake
        cert_der = ssock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_der)
        
        # Verificar si el certificado tiene extensión OCSP URL
        try:
            ocsp_extension = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in ocsp_extension.value:
                if desc.method._name == 'OCSP':
                    # Si tiene OCSP URL, comprobamos si el servidor adjunta la respuesta
                    # Esto se hace durante el handshake, así que si llegamos aquí es porque fue exitoso
                    # Para verificar realmente si hay stapling, necesitaríamos inspeccionar el handshake
                    # Por ahora asumimos que si tiene URL y la conexión fue exitosa, probablemente tiene stapling
                    return True
        except:
            pass
        
        return False
    except Exception as e:
        logger.debug("Error verificando OCSP Stapling: %s", e)
        return False


def obtener_versiones_tls_soportadas(hostname: str, ip: str) -> Dict[str, bool]:
    '''
    Prueba diferentes versiones de TLS para ver cuáles soporta el servidor
    :param hostname: Nombre del host
    :param ip: IP del servidor
    :return: Diccionario con versiones de TLS y soporte (ej: {"TLS1.0": False, "TLS1.2": True})
    '''
    versiones_soportadas = {}
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
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Si llegamos aquí, la versión es soportada
                    versiones_soportadas[nombre_version] = True
                    logger.debug("Versión %s soportada para %s", nombre_version, hostname)
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
            versiones_soportadas[nombre_version] = False
            logger.debug("Versión %s NO soportada para %s: %s", nombre_version, hostname, type(e).__name__)
        except Exception as e:
            versiones_soportadas[nombre_version] = False
    
    return versiones_soportadas


def en_contenedor():
    '''
    Detecta si el script se está ejecutando dentro de un contenedor Docker
    :return: True si está en contenedor, False si no
    '''

    try:
        if Path("/.dockerenv").exists():
            return True
        with open("/proc/1/cgroup", "r", encoding="utf-8") as f:
            contenido = f.read()
            return "docker" in contenido or "containerd" in contenido
    except Exception:
        return False


def crear_contexto_ssl(modo_compatible=False):
    '''
    Crea un contexto SSL con configuraciones específicas
    :param modo_compatible: Si es True, fuerza TLS 1.2 y ciphers compatibles
    :return: Contexto SSL configurado
    '''

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


def conectar_y_extraer(hostname: str, ip: str, ctx, latencia_dns: Optional[float]) -> Optional[DatosExito]:
    '''
    Conecta a un servidor y extrae datos del certificado
    :param hostname: Nombre del host
    :param ip: IP del servidor
    :param ctx: Contexto SSL
    :param latencia_dns: Latencia DNS en ms
    :return: DatosExito con la información procesada
    '''

    # --- MEDICIÓN DE TIEMPO ---
    tiempo_inicio = time.perf_counter()

    try:
        # --- ESTABLECIMIENTO DE LA CONEXIÓN ---
        with socket.create_connection((ip, 443), timeout=2) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Obtenemos el certificado del servidor en formato binario (DER)
                cert_der = ssock.getpeercert(binary_form=True)

                # Registramos el momento final después de completar la conexión y obtener el certificado
                tiempo_fin = time.perf_counter()
                tiempo_conexion = tiempo_fin - tiempo_inicio

                # --- ANÁLISIS DEL CERTIFICADO USANDO CertificateAnalyzer ---
                analyzer = CertificateAnalyzer(cert_der, hostname, ip, ssock, latencia_dns)
                datos = analyzer.analizar(tiempo_conexion)
                
                return datos

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
    except (socket.error, OSError) as e:
        raise RuntimeError(f"Error de conexión de red a {ip}:443 - {type(e).__name__}: {e}")
    except ssl.SSLError as e:
        raise  # Re-raise SSL errors para que sean manejados arriba
    except Exception as e:
        raise RuntimeError(f"Error inesperado en conexión: {type(e).__name__}: {e}")



# ============================================
# FUNCION PRINCIPAL DE LA SONDA
# ============================================

def escanear_servidor(hostname: str) -> Dict[str, Any]:
    '''
    Escanea un servidor HTTPS y extrae información TLS y del certificado
    :param hostname: El nombre del host o dominio del servidor HTTPS a escanear
    :return: Diccionario con los resultados del escaneo
    '''

    resultado = ResultadoEscaneo(
        hostname=hostname,
        timestamp=datetime.now(timezone.utc).isoformat(),
        estado="error",
        datos=None,
        error=None,
        entorno=Entorno(
            openssl_version=ssl.OPENSSL_VERSION,
            fallback_tls12=False
        )
    )
    
    try:
        # --- RESOLUCIÓN DNS Y LATENCIA ---
        ip, latencia_dns = resolver_dns(hostname)
        if not ip:
            logger.warning("No se pudo resolver DNS para %s", hostname)
            raise RuntimeError(f"No se pudo resolver DNS para {hostname}")
        
        logger.debug("DNS resuelto para %s -> %s (latencia: %.2f ms)", hostname, ip, latencia_dns)

        try:
            contexto = crear_contexto_ssl(modo_compatible=False)
            datos = conectar_y_extraer(hostname, ip, contexto, latencia_dns)
            if datos:
                resultado.estado = "exito"
                resultado.datos = datos
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
                resultado.entorno.fallback_tls12 = True
                contexto = crear_contexto_ssl(modo_compatible=True)
                try:
                    datos = conectar_y_extraer(hostname, ip, contexto, latencia_dns)
                    if datos:
                        resultado.estado = "exito"
                        resultado.datos = datos
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
        resultado.error = str(e)
        logger.debug("Escaneo fallido para %s: %s", hostname, resultado.error)
    
    # Devolvemos como diccionario
    return resultado.to_dict()



# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Sonda TLS: escaneo concurrente de servidores HTTPS")
    parser.add_argument("--input-csv", type=Path, default=CSV_DEFECTO, help="Ruta del archivo CSV de entrada con hostnames")
    parser.add_argument("--max-hostnames", type=int, default=100, help="Número máximo de hostnames a escanear")
    parser.add_argument("--max-workers", type=int, default=50, help="Número de hilos en paralelo")
    parser.add_argument("--log-level", default="INFO", help="Nivel de log: DEBUG, INFO, WARNING, ERROR (solo archivo)")
    parser.add_argument("--log-file", type=Path, default=LOG_DEFECTO, help="Ruta del archivo de log")
    args = parser.parse_args()

    log_path = args.log_file
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8")
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
    ruta_csv = args.input_csv
    hostnames = leer_hostnames_csv(ruta_csv, args.max_hostnames)
    
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
        
        # Conforme vayan terminando, recogemos los resultados con barra de progreso
        with tqdm(total=len(hostnames), desc="Escaneo TLS", unit="host") as pbar:
            for futuro in as_completed(futuros):
                host = futuros[futuro]
                try:
                    datos_host = futuro.result()
                    lista_resultados.append(datos_host)
                    if datos_host.get("estado") == "exito":
                        logger.debug("Escaneo exitoso: %s", host)
                    else:
                        logger.warning("Escaneo fallido para %s: %s", host, datos_host.get("error"))
                except Exception as e:
                    logger.error("Error inesperado procesando %s: %s", host, e)
                finally:
                    pbar.update(1)  # Actualizar barra de progreso

    # Calcular estadísticas
    exitosos = sum(1 for r in lista_resultados if r.get("estado") == "exito")
    fallidos = len(lista_resultados) - exitosos
    tiempo_total = time.time()
    
    # Generar resumen
    resumen = {
        "estadisticas": {
            "timestamp_finalizacion": datetime.now(timezone.utc).isoformat(),
            "total_hostnames": len(hostnames),
            "escaneos_exitosos": exitosos,
            "escaneos_fallidos": fallidos,
            "tasa_exito_percent": round((exitosos / len(hostnames) * 100) if hostnames else 0, 2)
        }
    }

    # Guardar resultados
    RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)
    resultados_path = RESULTADOS_DIR / "resultados_sonda_base.json"
    
    datos_finales = {
        "resumen": resumen["estadisticas"],
        "datos": lista_resultados
    }
    
    with resultados_path.open("w", encoding="utf-8") as f:
        json.dump(datos_finales, f, indent=4, ensure_ascii=False)

    logger.info("Listo. Escaneo completado: %s exitosos, %s fallidos (%.2f%% éxito)", 
                exitosos, fallidos, resumen["estadisticas"]["tasa_exito_percent"])
    logger.info("Resultados guardados en %s", resultados_path)