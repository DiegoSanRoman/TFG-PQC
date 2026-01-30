"""
sonda_base.py
En esta primera versión de la sonda, nos conectamos a servidores HTTPS de diferentes hostnames
y extraemos información básica del protocolo TLS y del certificado.
No verificamos la validez del certificado para poder conectarnos a servidores
con certificados autofirmados o caducados (lo hice asi porque el certificado de la uc3m no me dejaba continuar).
"""

# Importaciones necesarias
import socket                                               # Para conexiones TCP
import ssl                                                  # Para capa SSL/TLS 
import json                                                 # Para guardar resultados en JSON
import time                                                 # Para medir tiempo de conexión
import hashlib                                              # Para calcular hashes de certificados
import dns.resolver                                         # Para medir latencia DNS
from cryptography import x509                               # Para manejar certificados X.509
from cryptography.hazmat.primitives import serialization    # Para manejar claves públicas
from datetime import datetime, timezone                     # Para timestamps y zona horaria
from datetime import timedelta                              # Para cálculos de tiempo


# ============================================
# FUNCIONES AUXILIARES
# ============================================

def obtener_latencia_dns(hostname):
    '''
    Mide el tiempo de resolución DNS en milisegundos
    :param hostname: El nombre del host o dominio a resolver
    :return: Latencia en ms o None si falla
    '''

    try:
        inicio = time.time()
        dns.resolver.resolve(hostname, 'A')
        latencia = (time.time() - inicio) * 1000  # Convertir a ms
        return round(latencia, 2)
    except Exception:
        return None


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
        "error": None
    }
    
    try:
        # --- MEDICIÓN DE LATENCIA DNS ---
        latencia_dns = obtener_latencia_dns(hostname)
        
        # --- CONFIGURACIÓN DEL ENTORNO SSL ---
        # Cargamos la configuración por defecto de SSL del sistema
        context = ssl.create_default_context()
        
        # Desactivamos la validación del nombre del host (permite conectar aunque el cert sea para otro dominio)
        context.check_hostname = False
        
        # Desactivamos la verificación del certificado (permite certs caducados, autofirmados o no fiables)
        context.verify_mode = ssl.CERT_NONE
        
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

    except Exception as e:
        # Si algo falla, guardamos el mensaje de error
        resultado["error"] = str(e)
    
    # Devolvemos el resultado completo
    return resultado


# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

if __name__ == "__main__":
    
    # Lista de hostnames a escanear (se puede modificar)
    hostnames = [
        "cosec.inf.uc3m.es",
        "www.uc3m.es",
        "www.google.com",
        "www.facebook.com",
        "cloudflare.com", 
        "expired.badssl.com",
        "self-signed.badssl.com"
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