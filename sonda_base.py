"""
sonda_base.py
En esta primera versión de la sonda, nos conectamos a servidores HTTPS de diferentes hostnames
y extraemos información básica del protocolo TLS y del certificado.
No verificamos la validez del certificado para poder conectarnos a servidores
con certificados autofirmados o caducados (lo hice asi porque el certificado de la uc3m no me dejaba continuar).
"""

# Importaciones necesarias
import socket                       # Para conexiones TCP
import ssl                          # Para capa SSL/TLS 
import json                         # Para guardar resultados en JSON
import time                         # Para medir tiempo de conexión
from cryptography import x509       # Para manejar certificados X.509
from datetime import datetime       # Para timestamps


def escanear_servidor(hostname):
    '''
    Conectarse a un servidor HTTPS y extraer información del protocolo TLS y del certificado.
    :param hostname: El nombre del host o dominio del servidor HTTPS a escanear
    '''

    # Estructura base del resultado
    resultado = {
        "hostname": hostname,
        "timestamp": datetime.now().isoformat(),
        "estado": "error",
        "datos": None,
        "error": None
    }
    
    
    # --- CONFIGURACIÓN DEL ENTORNO SSL ---
    # Cargamos la configuración por defecto de SSL del sistema
    context = ssl.create_default_context()
    
    # Desactivamos la validación del nombre del host (permite conectar aunque el cert sea para otro dominio)
    context.check_hostname = False
    
    # Desactivamos la verificación del certificado (permite certs caducados, autofirmados o no fiables)
    context.verify_mode = ssl.CERT_NONE
    
    # Ejecutamos el comando y capturamos la salida
    try:
        # --- MEDICIÓN DE TIEMPO ---
        # Registramos el momento inicial antes de establecer la conexión
        tiempo_inicio = time.time()
        
        # --- ESTABLECIMIENTO DE LA CONEXIÓN ---
        # Creamos una conexión TCP estándar (socket) al puerto 443 con un máximo de 5 segundos de espera
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            
            # "Envolvemos" el socket TCP con la capa de seguridad SSL/TLS usando nuestro contexto configurado
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                
                # Extraemos una tupla con (nombre_cifrado, version_protocolo, bits_usados)
                detalles = ssock.cipher()
                
                # Obtenemos el certificado del servidor en formato binario (DER). 
                # Es necesario usar binary_form=True porque al no verificar el cert, ssock.getpeercert() vendría vacío
                cert_der = ssock.getpeercert(binary_form=True)
                
                # Usamos la librería cryptography para convertir esos bytes "en bruto" en un objeto manejable
                cert = x509.load_der_x509_certificate(cert_der)
                
                # Registramos el momento final después de completar la conexión y obtener el certificado
                tiempo_fin = time.time()
                tiempo_conexion = tiempo_fin - tiempo_inicio

                # --- EXTRACCIÓN Y ORGANIZACIÓN DE DATOS ---
                resultado["estado"] = "exito"
                resultado["datos"] = {
                    "tiempo_conexion_segundos": round(tiempo_conexion, 3),
                    "protocolo": {
                        "version": ssock.version(),         # Ej: TLSv1.3
                        "suite_cifrado": detalles[0],       # Ej: ECDHE-RSA-AES256-GCM-SHA384
                        "bits_clave": detalles[2]           # Ej: 256
                    },
                    "certificado": {
                        # Convertimos el Sujeto y Emisor a formato string estándar (RFC4514)
                        "sujeto": cert.subject.rfc4514_string(),
                        "emisor": cert.issuer.rfc4514_string(),
                        "algoritmo_firma": cert.signature_algorithm_oid._name,
                        # Extraemos fechas de validez en formato ISO para el JSON
                        "valido_desde": cert.not_valid_before_utc.isoformat(),
                        "valido_hasta": cert.not_valid_after_utc.isoformat()
                    }
                }
    except Exception as e:
        # Si algo falla, guardamos el mensaje de error
        resultado["error"] = str(e)
    
    return resultado

if __name__ == "__main__":
    
    # Lista de hostnames a escanear (se puede modificar)
    hostnames = [
        "cosec.inf.uc3m.es",
        "www.uc3m.es",
        "www.google.com",
        "www.facebook.com"
    ]
    
    lista_resultados = []

    print("Iniciando escaneo y recolección de datos...")
    for host in hostnames:
        print(f" -> Analizando: {host}")
        datos_host = escanear_servidor(host)
        lista_resultados.append(datos_host)
    
    # Guardamos toda la lista de diccionarios en un único archivo JSON bien formateado
    with open("resultados/resultados_sonda_base.json", "w", encoding="utf-8") as f:
        json.dump(lista_resultados, f, indent=4, ensure_ascii=False)
    
    print(f"\n[!] Listo. Se han guardado los datos de {len(hostnames)} servidores en resultados/resultados_sonda_base.json.")