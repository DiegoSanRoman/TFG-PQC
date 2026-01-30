"""
sonda_base.py
En esta primera versión de la sonda, nos conectamos a servidores HTTPS de diferentes hostnames
y extraemos información básica del protocolo TLS y del certificado.
No verificamos la validez del certificado para poder conectarnos a servidores
con certificados autofirmados o caducados (lo hice asi porque el certificado de la uc3m no me dejaba continuar).
"""

# Importaciones necesarias
import subprocess                   # Para ejecutar comandos del sistema
import json                         # Para guardar resultados en JSON
import os                           # Para operaciones del sistema  
import time                         # Para medir tiempo de conexión
from datetime import datetime       # Para timestamps

def sonda_pqc(hostname, group=None):
    '''
    Conectarse a un servidor HTTPS usando OpenSSL y probar compatibilidad con TLS 1
    :param hostname: El nombre del host o dominio del servidor HTTPS a escanear
    :param group: El grupo de cifrado a usar (None para automático)
    '''
    # Ruta al binario de OpenSSL personalizado con soporte PQC
    openssl_bin = "/opt/openssl/bin/openssl"
    
    # Comando con flags de compatibilidad máxima
    cmd = [openssl_bin, "s_client", "-connect", f"{hostname}:443", "-servername", hostname, "-tls1_3", "-ign_eof"]
    
    # Si se especifica un grupo, lo añadimos al comando
    if group:
        cmd += ["-groups", group]
    
    # Ejecutamos el comando y capturamos la salida
    try:
        # Medimos el tiempo de conexión
        tiempo_inicio = time.time()
        
        # Ejecutamos capturando el error detallado
        process = subprocess.run(cmd, input=b"HEAD / HTTP/1.0\n\n", capture_output=True, timeout=8)
        
        # Medimos el tiempo final
        tiempo_fin = time.time()
        tiempo_conexion_segundos = round(tiempo_fin - tiempo_inicio, 3)
        
        # Decodificamos la salida
        stdout = process.stdout.decode(errors='ignore')
        stderr = process.stderr.decode(errors='ignore')
        
        # Si vemos que se ha elegido un Cifrado, es que ha habido éxito
        if "Cipher is" in stdout or "New, " in stdout:
            # Extraer el grupo negociado
            for line in stdout.split('\n'):
                if "Server Temp Key" in line or "Key Exchange" in line:
                    return {"status": "ACEPTADO ✅", "res": line.strip(), "tiempo_conexion_segundos": tiempo_conexion_segundos}
            return {"status": "ACEPTADO ✅", "res": "Conectado (TLS 1.3)", "tiempo_conexion_segundos": tiempo_conexion_segundos}
        
        # Si hay un error específico de incompatibilidad de protocolo/draft
        return {"status": "RECHAZADO ❌", "res": "Incompatibilidad de protocolo/draft", "tiempo_conexion_segundos": tiempo_conexion_segundos}
    
    # Capturamos cualquier excepción (timeout, fallo, etc.)
    except Exception as e:
        return {"status": "ERROR", "res": str(e), "tiempo_conexion_segundos": None}

if __name__ == "__main__":
    # Prueba con varios servidores y grupos
    targets = ["cosec.inf.uc3m.es", "www.uc3m.es", "www.google.com", "cloudflare.com", "www.facebook.com"]
    # Probamos diferentes protocolos, desde automático (None) hasta algunos híbridos y algunos puros PQC
    grupos = [None, "prime256v1", "x25519_mlkem768", "p256_kyber768", "kyber768", "frodo640aes", "sikep434"]
    # - None representa el modo automático por defecto de OpenSSL
    # - prime256v1 es un grupo ECDSA clásico
    # - x25519_mlkem768 es un grupo híbrido X25519 + Kyber768
    # - p256_kyber768 es un grupo híbrido P-256 + Kyber768
    # - kyber768 es un grupo puro Kyber768
    # - frodo640aes es un grupo puro FrodoKEM-640-AES
    # - sikep434 es un grupo puro SIKEp434

    lista_resultados = []
    
    # Iteramos sobre cada target y cada grupo, almacenando los resultados
    for host in targets:
        print(f"Analizando host: {host}")
        resultado_host = {
            "hostname": host,
            "timestamp": datetime.now().isoformat(),
            "pruebas": []
        }
        
        for g in grupos:
            label = g if g else "Automático"
            resultado = sonda_pqc(host, g)
            
            resultado["grupo"] = label
            resultado_host["pruebas"].append(resultado)
        
        lista_resultados.append(resultado_host)
    
    # Guardamos toda la lista de diccionarios en un único archivo JSON
    with open("resultados/resultados_sonda_pqc.json", "w", encoding="utf-8") as f:
        json.dump(lista_resultados, f, indent=4, ensure_ascii=False)
    
    print(f"[!] Listo. Se han guardado los datos en resultados/resultados_sonda_pqc.json.")