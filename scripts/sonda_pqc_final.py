"""
sonda_pqc_final.py
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
from datetime import datetime, timezone                     # Para timestamps y zona horaria
from pathlib import Path                                    # Para rutas
from concurrent.futures import ThreadPoolExecutor, as_completed  # Para concurrencia
from tqdm import tqdm                                       # Para barras de progreso
from typing import List, Dict, Any, Optional                # Para type hints

logger = logging.getLogger(__name__)

# ============================================
# CONSTANTES DE RUTAS
# ============================================
BASE_DIR = Path(__file__).parent.parent  # Directorio raíz del proyecto
DATA_DIR = BASE_DIR / "data"
RESULTADOS_DIR = BASE_DIR / "resultados"
CSV_DEFECTO = DATA_DIR / "tranco.csv"
LOG_DEFECTO = RESULTADOS_DIR / "sonda_pqc.log"

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


# ============================================
# FUNCION PRINCIPAL
# ============================================

def sonda_pqc(hostname, group=None, openssl_bin=None):
    '''
    Función que intenta conectarse a un servidor HTTPS usando OpenSSL con soporte para cifrados post-cuánticos (híbridos y puros).
    :param hostname: El nombre del host o dominio del servidor HTTPS a escanear
    :param group: El grupo de cifrado a usar (None para automático)
    :return: Diccionario con el resultado de la conexión
    '''

    # Ruta al binario de OpenSSL personalizado con soporte PQC
    openssl_bin = openssl_bin or "/opt/openssl/bin/openssl"
    
    # Comando con flags de compatibilidad máxima
    cmd = [openssl_bin, "s_client", "-connect", f"{hostname}:443", "-servername", hostname, "-tls1_3", "-ign_eof"]
    
    # Si se especifica un grupo, lo añadimos al comando. Si no, se usará el modo automático por defecto.
    if group:
        cmd += ["-groups", group]
    
    logger.debug("Probando %s con grupo %s", hostname, group if group else "Automático")
    
    # Pre-check TCP para separar fallos de infraestructura de PQC
    try:
        with socket.create_connection((hostname, 443), timeout=3):
            pass
    except socket.gaierror:
        logger.warning("DNS fallo para %s", hostname)
        return {"status": "ERROR", "res": "DNS no resolvió", "tiempo_conexion_segundos": None}
    except ConnectionRefusedError:
        logger.warning("Conexión rechazada para %s:443", hostname)
        return {"status": "ERROR", "res": "Puerto 443 cerrado o rechazado", "tiempo_conexion_segundos": None}
    except socket.timeout:
        logger.warning("Timeout TCP para %s:443", hostname)
        return {"status": "ERROR", "res": "Timeout TCP 443", "tiempo_conexion_segundos": None}
    except OSError as e:
        logger.warning("Error TCP para %s: %s", hostname, e)
        return {"status": "ERROR", "res": f"Error TCP: {e}", "tiempo_conexion_segundos": None}

    # Ejecutamos el comando y capturamos la salida
    try:
        # Medimos el tiempo de conexión
        tiempo_inicio = time.time()

        # Ejecutamos con Popen para controlar mejor timeouts y limpieza
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True
        )

        try:
            stdout_bytes, stderr_bytes = process.communicate(input=b"HEAD / HTTP/1.0\n\n", timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout_bytes, stderr_bytes = process.communicate()
            logger.warning("Timeout en %s con grupo %s", hostname, group if group else "Automático")
            return {"status": "ERROR", "res": "Timeout en s_client", "tiempo_conexion_segundos": None}

        # Medimos el tiempo final
        tiempo_fin = time.time()
        tiempo_conexion_segundos = round(tiempo_fin - tiempo_inicio, 3)

        # Decodificamos la salida
        stdout = stdout_bytes.decode(errors='ignore') if stdout_bytes else ""
        stderr = stderr_bytes.decode(errors='ignore') if stderr_bytes else ""

        # Buscar el grupo negociado en la línea Server Temp Key
        negotiated_line = None
        for line in stdout.split("\n"):
            if line.lstrip().startswith("Server Temp Key:"):
                negotiated_line = line.strip()
                break

        if negotiated_line:
            logger.debug("Éxito: %s - %s - %s", hostname, group if group else "Automático", negotiated_line)
            return {"status": "ACEPTADO", "res": negotiated_line, "tiempo_conexion_segundos": tiempo_conexion_segundos}

        # Fallback: si no hay Server Temp Key, usamos indicadores de handshake
        if "Cipher is" in stdout or "New, " in stdout:
            logger.debug("Éxito: %s - %s - Conectado (TLS 1.3)", hostname, group if group else "Automático")
            return {"status": "ACEPTADO", "res": "Conectado (TLS 1.3)", "tiempo_conexion_segundos": tiempo_conexion_segundos}

        # Si hay un error específico de incompatibilidad de protocolo/draft
        logger.debug("Rechazado: %s - %s - %s", hostname, group if group else "Automático", stderr.strip())
        return {"status": "RECHAZADO", "res": "Incompatibilidad de protocolo/draft", "tiempo_conexion_segundos": tiempo_conexion_segundos}

    # Capturamos cualquier excepción (timeout, fallo, etc.)
    except Exception as e:
        logger.warning("Error en %s con grupo %s: %s", hostname, group if group else "Automático", str(e))
        return {"status": "ERROR", "res": str(e), "tiempo_conexion_segundos": None}


def escanear_servidor_pqc(hostname: str, grupos: List[Optional[str]], openssl_bin: str) -> Dict[str, Any]:
    '''
    Escanea un servidor con múltiples grupos PQC y retorna los resultados
    :param hostname: Nombre del host a escanear
    :param grupos: Lista de grupos a probar (None para automático)
    :return: Diccionario con los resultados del escaneo
    '''
    resultado_host = {
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pruebas": []
    }
    
    for g in grupos:
        label = g if g else "Automático"
        resultado = sonda_pqc(hostname, g, openssl_bin=openssl_bin)
        resultado["grupo"] = label
        resultado_host["pruebas"].append(resultado)
    
    return resultado_host


# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

if __name__ == "__main__":
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
    
    if not hostnames:
        logger.error("No se encontraron hostnames en %s", ruta_csv)
        raise SystemExit(1)
    
    logger.info("Se han cargado %s hostnames desde %s", len(hostnames), ruta_csv)
    logger.info("Grupos PQC a probar: %s", ", ".join([g if g else "Automático" for g in grupos]))
    
    lista_resultados = []

    # Definimos el número de hilos (trabajadores en paralelo)
    MAX_WORKERS = args.max_workers

    logger.info("Iniciando escaneo concurrente con %s hilos...", MAX_WORKERS)
    
    # Tiempo de inicio
    tiempo_inicio_total = time.time()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Lanzamos todas las tareas
        futuros = {executor.submit(escanear_servidor_pqc, host, grupos, args.openssl_bin): host for host in hostnames}
        
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