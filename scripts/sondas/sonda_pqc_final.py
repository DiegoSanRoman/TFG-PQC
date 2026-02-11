"""
sonda_pqc_final.py
-----------------------
Sonda para pruebas de conectividad con algoritmos post-cuánticos (PQC).
Utiliza OpenSSL con soporte PQC para probar diferentes grupos de cifrado
híbridos y puros contra servidores HTTPS.
"""

# Importaciones necesarias
import subprocess                                           # Para ejecutar comandos del sistema
import json                                                 # Para guardar resultados en JSON
import os                                                   # Para operaciones del sistema  
import time                                                 # Para medir tiempo de conexión
import csv                                                  # Para leer archivos CSV
import logging                                              # Para logging
import argparse                                             # Para argumentos CLI
import socket                                               # Para pre-check TCP
import re                                                   # Para parseo de salida
import threading                                            # Para semáforo de procesos
from datetime import datetime, timezone                     # Para timestamps y zona horaria
from pathlib import Path                                    # Para rutas
from concurrent.futures import ThreadPoolExecutor, as_completed  # Para concurrencia
from tqdm import tqdm                                       # Para barras de progreso
from typing import List, Dict, Any, Optional                # Para type hints

# Configurar logging
logger = logging.getLogger(__name__)

# ============================================
# CONSTANTES DE RUTAS
# ============================================
BASE_DIR = Path(__file__).parent.parent.parent         # Directorio raíz del proyecto
DATA_DIR = BASE_DIR / "data"                    # Directorio de datos
RESULTADOS_DIR = BASE_DIR / "resultados"        # Directorio de resultados
CSV_DEFECTO = DATA_DIR / "prueba.csv"           # Archivo CSV de input por defecto
LOG_DEFECTO = RESULTADOS_DIR / "sonda_pqc.log"  # Archivo de log por defecto



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
    hostnames = []  # Lista para almacenar los hostnames
    # Leer el archivo CSV
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



# ============================================
# FUNCION PRINCIPAL
# ============================================

def sonda_pqc(hostname, group=None, openssl_bin=None, proc_semaphore=None):
    '''
    Función que intenta conectarse a un servidor HTTPS usando OpenSSL con soporte para cifrados post-cuánticos (híbridos y puros).
    :param hostname: El nombre del host o dominio del servidor HTTPS a escanear
    :param group: El grupo de cifrado a usar (None para automático)
    :return: Diccionario con el resultado de la conexión
    '''

    # Ruta al binario de OpenSSL personalizado con soporte PQC
    openssl_bin = openssl_bin or "/opt/openssl/bin/openssl"
    
    # Comando base
    cmd = [openssl_bin, "s_client", "-connect", f"{hostname}:443", "-servername", hostname, "-ign_eof"]
    
    # Si se especifica un grupo, forzamos TLS 1.3 y el grupo PQC
    # Si no, es una conexión normal (sin forzar TLS 1.3 ni grupos)
    if group:
        cmd += ["-tls1_3", "-groups", group]
    
    logger.debug("Probando %s con grupo %s", hostname, group if group else "Automático")
    
    # Pre-check DNS/TCP para separar fallos de infraestructura de PQC
    dns_time_ms = None
    tcp_time_ms = None
    ip_resuelta = None
    ip_familia = None
    sni_usado = hostname
    sni_difiere = False
    retried = False

    try:
        dns_inicio = time.time()
        addrinfos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        dns_time_ms = round((time.time() - dns_inicio) * 1000, 2)

        if not addrinfos:
            raise socket.gaierror("Sin resultados de DNS")

        family, socktype, proto, canonname, sockaddr = addrinfos[0]
        ip_resuelta = sockaddr[0]
        ip_familia = "IPv6" if family == socket.AF_INET6 else "IPv4"

        tcp_inicio = time.time()
        with socket.socket(family, socktype, proto) as sock:
            sock.settimeout(3)
            sock.connect(sockaddr)
        tcp_time_ms = round((time.time() - tcp_inicio) * 1000, 2)
    except socket.gaierror:
        logger.warning("DNS fallo para %s", hostname)
        return {
            "status": "ERROR",
            "res": "DNS no resolvió",
            "tiempo_conexion_segundos": None,
            "dns_time_ms": dns_time_ms,
            "tcp_time_ms": tcp_time_ms,
            "handshake_time_ms": None,
            "ip": ip_resuelta,
            "ip_familia": ip_familia,
            "tls_version": None,
            "cipher_suite": None,
            "alpn": None,
            "tls_alert": None,
            "cert_issuer": None,
            "cert_not_before": None,
            "cert_not_after": None,
            "cert_san": None,
            "cert_fingerprint_sha256": None,
            "response_size_bytes": None,
            "sni_usado": sni_usado,
            "sni_difiere": sni_difiere,
            "retry": retried
        }
    except ConnectionRefusedError:
        logger.warning("Conexión rechazada para %s:443", hostname)
        return {
            "status": "ERROR",
            "res": "Puerto 443 cerrado o rechazado",
            "tiempo_conexion_segundos": None,
            "dns_time_ms": dns_time_ms,
            "tcp_time_ms": tcp_time_ms,
            "handshake_time_ms": None,
            "ip": ip_resuelta,
            "ip_familia": ip_familia,
            "tls_version": None,
            "cipher_suite": None,
            "alpn": None,
            "tls_alert": None,
            "cert_issuer": None,
            "cert_not_before": None,
            "cert_not_after": None,
            "cert_san": None,
            "cert_fingerprint_sha256": None,
            "response_size_bytes": None,
            "sni_usado": sni_usado,
            "sni_difiere": sni_difiere,
            "retry": retried
        }
    except socket.timeout:
        logger.warning("Timeout TCP para %s:443", hostname)
        return {
            "status": "ERROR",
            "res": "Timeout TCP 443",
            "tiempo_conexion_segundos": None,
            "dns_time_ms": dns_time_ms,
            "tcp_time_ms": tcp_time_ms,
            "handshake_time_ms": None,
            "ip": ip_resuelta,
            "ip_familia": ip_familia,
            "tls_version": None,
            "cipher_suite": None,
            "alpn": None,
            "tls_alert": None,
            "cert_issuer": None,
            "cert_not_before": None,
            "cert_not_after": None,
            "cert_san": None,
            "cert_fingerprint_sha256": None,
            "response_size_bytes": None,
            "sni_usado": sni_usado,
            "sni_difiere": sni_difiere,
            "retry": retried
        }
    except OSError as e:
        logger.warning("Error TCP para %s: %s", hostname, e)
        return {
            "status": "ERROR",
            "res": f"Error TCP: {e}",
            "tiempo_conexion_segundos": None,
            "dns_time_ms": dns_time_ms,
            "tcp_time_ms": tcp_time_ms,
            "handshake_time_ms": None,
            "ip": ip_resuelta,
            "ip_familia": ip_familia,
            "tls_version": None,
            "cipher_suite": None,
            "alpn": None,
            "tls_alert": None,
            "cert_issuer": None,
            "cert_not_before": None,
            "cert_not_after": None,
            "cert_san": None,
            "cert_fingerprint_sha256": None,
            "response_size_bytes": None,
            "sni_usado": sni_usado,
            "sni_difiere": sni_difiere,
            "retry": retried
        }

    # Ejecutamos el comando y capturamos la salida
    try:
        # Medimos el tiempo de conexión
        tiempo_inicio = time.time()

        # Ejecutamos con Popen para controlar mejor timeouts y limpieza
        stdout_bytes = b""
        stderr_bytes = b""
        handshake_inicio = time.time()

        max_attempts = 2
        for intento in range(1, max_attempts + 1):
            if proc_semaphore:
                proc_semaphore.acquire()
            try:
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True
                )

                try:
                    stdout_bytes, stderr_bytes = process.communicate(input=b"HEAD / HTTP/1.0\n\n", timeout=8)
                    break
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout_bytes, stderr_bytes = process.communicate()
                    if intento < max_attempts:
                        retried = True
                        continue
                    logger.warning("Timeout en %s con grupo %s", hostname, group if group else "Automático")
                    return {
                        "status": "ERROR",
                        "res": "Timeout en s_client",
                        "tiempo_conexion_segundos": None,
                        "dns_time_ms": dns_time_ms,
                        "tcp_time_ms": tcp_time_ms,
                        "handshake_time_ms": None,
                        "ip": ip_resuelta,
                        "ip_familia": ip_familia,
                        "tls_version": None,
                        "cipher_suite": None,
                        "alpn": None,
                        "tls_alert": None,
                        "cert_issuer": None,
                        "cert_not_before": None,
                        "cert_not_after": None,
                        "cert_san": None,
                        "cert_fingerprint_sha256": None,
                        "response_size_bytes": None,
                        "sni_usado": sni_usado,
                        "sni_difiere": sni_difiere,
                        "retry": retried
                    }
            finally:
                if proc_semaphore:
                    proc_semaphore.release()

        handshake_time_ms = round((time.time() - handshake_inicio) * 1000, 2)

        # Medimos el tiempo final
        tiempo_fin = time.time()
        tiempo_conexion_segundos = round(tiempo_fin - tiempo_inicio, 3)

        # Decodificamos la salida
        stdout = stdout_bytes.decode(errors='ignore') if stdout_bytes else ""
        stderr = stderr_bytes.decode(errors='ignore') if stderr_bytes else ""
        response_size_bytes = (len(stdout_bytes) if stdout_bytes else 0) + (len(stderr_bytes) if stderr_bytes else 0)

        # Parseo de TLS: versión, cipher y ALPN
        tls_version = None
        cipher_suite = None
        alpn = None

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

        match_alpn = re.search(r"^\s*ALPN[\s,]+protocol[:\s]+(.+)$", stdout, re.MULTILINE | re.IGNORECASE)
        if not match_alpn:
            match_alpn = re.search(r"ALPN[\s,]+selected[:\s]+(.+)$", stdout, re.MULTILINE | re.IGNORECASE)
        if match_alpn:
            alpn = match_alpn.group(1).strip()

        # TLS alert específico (si aparece)
        tls_alert = None
        for line in (stderr + "\n" + stdout).split("\n"):
            if "alert" in line.lower():
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

        cert_issuer = None
        cert_not_before = None
        cert_not_after = None
        cert_san = None
        cert_fingerprint_sha256 = None

        if cert_pem:
            x509 = subprocess.run(
                [openssl_bin, "x509", "-noout", "-issuer", "-dates", "-ext", "subjectAltName", "-fingerprint", "-sha256"],
                input=cert_pem.encode(),
                capture_output=True
            )
            x509_out = x509.stdout.decode(errors="ignore")
            for line in x509_out.split("\n"):
                if line.startswith("issuer="):
                    cert_issuer = line.replace("issuer=", "").strip()
                elif line.startswith("notBefore="):
                    cert_not_before = line.replace("notBefore=", "").strip()
                elif line.startswith("notAfter="):
                    cert_not_after = line.replace("notAfter=", "").strip()
                elif "Fingerprint=" in line or "fingerprint=" in line.lower():
                    # Captura SHA256 Fingerprint=..., sha256 Fingerprint=..., Fingerprint=...
                    cert_fingerprint_sha256 = re.sub(r"^.*[Ff]ingerprint\s*=\s*", "", line).strip()
                elif "Subject Alternative Name" in line:
                    continue
                elif "DNS:" in line:
                    cert_san = line.strip()

        # Detectar fallos reales de handshake
        handshake_failed = False
        if tls_alert and ("handshake failure" in tls_alert.lower() or 
                          "protocol version" in tls_alert.lower() or
                          "illegal parameter" in tls_alert.lower()):
            handshake_failed = True
        
        # Cipher (NONE) significa que no se negoció nada
        if cipher_suite and "(NONE)" in cipher_suite:
            handshake_failed = True
        
        # Si hay fallo de handshake confirmado, es RECHAZADO
        if handshake_failed:
            logger.debug("Rechazado (handshake failed): %s - %s", hostname, group if group else "Automático")
            return {
                "status": "RECHAZADO",
                "res": tls_alert if tls_alert else "Handshake failed",
                "tiempo_conexion_segundos": tiempo_conexion_segundos,
                "dns_time_ms": dns_time_ms,
                "tcp_time_ms": tcp_time_ms,
                "handshake_time_ms": handshake_time_ms,
                "ip": ip_resuelta,
                "ip_familia": ip_familia,
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "alpn": alpn,
                "tls_alert": tls_alert,
                "cert_issuer": cert_issuer,
                "cert_not_before": cert_not_before,
                "cert_not_after": cert_not_after,
                "cert_san": cert_san,
                "cert_fingerprint_sha256": cert_fingerprint_sha256,
                "response_size_bytes": response_size_bytes,
                "sni_usado": sni_usado,
                "sni_difiere": sni_difiere,
                "retry": retried
            }

        # Buscar el grupo negociado en la línea Server Temp Key
        negotiated_line = None
        for line in stdout.split("\n"):
            if line.lstrip().startswith("Server Temp Key:"):
                negotiated_line = line.strip()
                break

        # Éxito real: hay Server Temp Key Y (hay certificado O cipher válido)
        if negotiated_line and (cert_issuer or (cipher_suite and "(NONE)" not in cipher_suite)):
            logger.debug("Éxito: %s - %s - %s", hostname, group if group else "Automático", negotiated_line)
            return {
                "status": "ACEPTADO",
                "res": negotiated_line,
                "tiempo_conexion_segundos": tiempo_conexion_segundos,
                "dns_time_ms": dns_time_ms,
                "tcp_time_ms": tcp_time_ms,
                "handshake_time_ms": handshake_time_ms,
                "ip": ip_resuelta,
                "ip_familia": ip_familia,
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "alpn": alpn,
                "tls_alert": tls_alert,
                "cert_issuer": cert_issuer,
                "cert_not_before": cert_not_before,
                "cert_not_after": cert_not_after,
                "cert_san": cert_san,
                "cert_fingerprint_sha256": cert_fingerprint_sha256,
                "response_size_bytes": response_size_bytes,
                "sni_usado": sni_usado,
                "sni_difiere": sni_difiere,
                "retry": retried
            }

        # Fallback: conexión exitosa si hay cipher válido Y certificado
        if cipher_suite and "(NONE)" not in cipher_suite and cert_issuer:
            logger.debug("Éxito: %s - %s - Conectado (TLS 1.3)", hostname, group if group else "Automático")
            return {
                "status": "ACEPTADO",
                "res": f"Conectado - {cipher_suite}",
                "tiempo_conexion_segundos": tiempo_conexion_segundos,
                "dns_time_ms": dns_time_ms,
                "tcp_time_ms": tcp_time_ms,
                "handshake_time_ms": handshake_time_ms,
                "ip": ip_resuelta,
                "ip_familia": ip_familia,
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "alpn": alpn,
                "tls_alert": tls_alert,
                "cert_issuer": cert_issuer,
                "cert_not_before": cert_not_before,
                "cert_not_after": cert_not_after,
                "cert_san": cert_san,
                "cert_fingerprint_sha256": cert_fingerprint_sha256,
                "response_size_bytes": response_size_bytes,
                "sni_usado": sni_usado,
                "sni_difiere": sni_difiere,
                "retry": retried
            }

        # Si hay un error específico de incompatibilidad de protocolo/draft
        logger.debug("Rechazado: %s - %s - %s", hostname, group if group else "Automático", stderr.strip())
        return {
            "status": "RECHAZADO",
            "res": "Incompatibilidad de protocolo/draft",
            "tiempo_conexion_segundos": tiempo_conexion_segundos,
            "dns_time_ms": dns_time_ms,
            "tcp_time_ms": tcp_time_ms,
            "handshake_time_ms": handshake_time_ms,
            "ip": ip_resuelta,
            "ip_familia": ip_familia,
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "alpn": alpn,
            "tls_alert": tls_alert,
            "cert_issuer": cert_issuer,
            "cert_not_before": cert_not_before,
            "cert_not_after": cert_not_after,
            "cert_san": cert_san,
            "cert_fingerprint_sha256": cert_fingerprint_sha256,
            "response_size_bytes": response_size_bytes,
            "sni_usado": sni_usado,
            "sni_difiere": sni_difiere,
            "retry": retried
        }

    # Capturamos cualquier excepción (timeout, fallo, etc.)
    except Exception as e:
        logger.warning("Error en %s con grupo %s: %s", hostname, group if group else "Automático", str(e))
        return {
            "status": "ERROR",
            "res": str(e),
            "tiempo_conexion_segundos": None,
            "dns_time_ms": dns_time_ms,
            "tcp_time_ms": tcp_time_ms,
            "handshake_time_ms": None,
            "ip": ip_resuelta,
            "ip_familia": ip_familia,
            "tls_version": None,
            "cipher_suite": None,
            "alpn": None,
            "tls_alert": None,
            "cert_issuer": None,
            "cert_not_before": None,
            "cert_not_after": None,
            "cert_san": None,
            "cert_fingerprint_sha256": None,
            "response_size_bytes": None,
            "sni_usado": sni_usado,
            "sni_difiere": sni_difiere,
            "retry": retried
        }


def escanear_servidor_pqc(hostname: str, grupos: List[Optional[str]], openssl_bin: str, proc_semaphore) -> Dict[str, Any]:
    '''
    Escanea un servidor con múltiples grupos PQC y retorna los resultados
    :param hostname: Nombre del host a escanear
    :param grupos: Lista de grupos a probar (None para automático)
    :return: Diccionario con los resultados del escaneo
    '''
    # Diccionario para almacenar resultados por hostname
    resultado_host = {
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pruebas": []
    }
    
    # Probar cada grupo
    for g in grupos:
        label = g if g else "Automático"
        resultado = sonda_pqc(hostname, g, openssl_bin=openssl_bin, proc_semaphore=proc_semaphore)
        resultado["grupo"] = label
        resultado_host["pruebas"].append(resultado)
    
    # Retornar resultados del host
    return resultado_host



# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

if __name__ == "__main__":
    # Parseo de argumentos CLI
    parser = argparse.ArgumentParser(description="Sonda PQC: escaneo concurrente de servidores HTTPS con algoritmos post-cuánticos")
    parser.add_argument("--input-csv", type=Path, default=CSV_DEFECTO, help="Ruta del archivo CSV de entrada con hostnames")
    parser.add_argument("--max-hostnames", type=int, default=100, help="Número máximo de hostnames a escanear")
    parser.add_argument("--max-workers", type=int, default=20, help="Número de hilos en paralelo")
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
        default=min(8, os.cpu_count() or 1),
        help="Límite de procesos OpenSSL concurrentes"
    )
    args = parser.parse_args()

    # Configurar logging
    log_path = args.log_file
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8")
        ]
    )

    logger.info("Iniciando sonda PQC con OpenSSL personalizado")
    logger.info("Binario OpenSSL: %s", args.openssl_bin)
    logger.info("Límite de procesos OpenSSL: %s", args.max_openssl_procs)

    # Probamos diferentes protocolos, desde automático (None) hasta algunos híbridos y algunos puros PQC
    grupos = [None, "prime256v1", "x25519_mlkem768", "p256_kyber768", "kyber768", "frodo640aes", "sikep434"]
    # - None representa el modo automático por defecto de OpenSSL
    # - prime256v1 es un grupo ECDSA clásico
    # - x25519_mlkem768 es un grupo híbrido X25519 + Kyber768
    # - p256_kyber768 es un grupo híbrido P-256 + Kyber768
    # - kyber768 es un grupo puro Kyber768
    # - frodo640aes es un grupo puro FrodoKEM-640-AES
    # - sikep434 es un grupo puro SIKEp434

    # Leer hostnames desde el archivo CSV
    ruta_csv = args.input_csv
    hostnames = leer_hostnames_csv(ruta_csv, args.max_hostnames)
    
    # Verificar que se han leído hostnames
    if not hostnames:
        logger.error("No se encontraron hostnames en %s", ruta_csv)
        raise SystemExit(1)
    
    logger.info("Se han cargado %s hostnames desde %s", len(hostnames), ruta_csv)
    logger.info("Grupos PQC a probar: %s", ", ".join([g if g else "Automático" for g in grupos]))
    
    # Lista para almacenar todos los resultados
    lista_resultados = []

    # Definimos el número de hilos (trabajadores en paralelo)
    MAX_WORKERS = args.max_workers

    logger.info("Iniciando escaneo concurrente con %s hilos...", MAX_WORKERS)
    
    # Tiempo de inicio
    tiempo_inicio_total = time.time()
    
    # Semáforo para limitar procesos OpenSSL concurrentes
    proc_semaphore = threading.BoundedSemaphore(args.max_openssl_procs)

    # Usamos ThreadPoolExecutor para concurrencia
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Lanzamos todas las tareas
        futuros = {executor.submit(escanear_servidor_pqc, host, grupos, args.openssl_bin, proc_semaphore): host for host in hostnames}
        
        # Conforme vayan terminando, recogemos los resultados con barra de progreso
        with tqdm(total=len(hostnames), desc="Escaneo PQC", unit="host") as pbar:
            for futuro in as_completed(futuros):
                host = futuros[futuro]
                try:
                    datos_host = futuro.result()
                    lista_resultados.append(datos_host)
                    
                    # Contar cuántas pruebas fueron exitosas
                    exitosos = sum(1 for prueba in datos_host["pruebas"] if prueba.get("status") == "ACEPTADO")
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
        exitosos_host = sum(1 for p in pruebas if p.get("status") == "ACEPTADO")
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
            "grupos_probados": [g if g else "Automático" for g in grupos]
        }
    }

    # Guardar resultados
    RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)
    resultados_path = RESULTADOS_DIR / "resultados_sonda_pqc.json"
    
    datos_finales = {
        "resumen": resumen["estadisticas"],
        "datos": lista_resultados
    }
    
    with resultados_path.open("w", encoding="utf-8") as f:
        json.dump(datos_finales, f, indent=4, ensure_ascii=False)

    logger.info("="*70)
    logger.info("Escaneo PQC completado")
    logger.info("Tiempo total: %.2f segundos", tiempo_total)
    logger.info("Hosts con al menos un éxito: %d/%d (%.2f%%)", 
                hosts_con_exito, total_hosts, resumen["estadisticas"]["tasa_exito_hosts_percent"])
    logger.info("Pruebas exitosas: %d/%d (%.2f%%)", 
                pruebas_exitosas, total_pruebas, resumen["estadisticas"]["tasa_exito_pruebas_percent"])
    logger.info("Resultados guardados en %s", resultados_path)
    logger.info("="*70)