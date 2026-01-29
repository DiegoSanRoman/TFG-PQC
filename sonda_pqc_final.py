import subprocess
import json
import os

def sonda_emergencia(hostname, group=None):
    openssl_bin = "/opt/openssl/bin/openssl"
    
    # Comando con flags de compatibilidad máxima
    cmd = [openssl_bin, "s_client", "-connect", f"{hostname}:443", "-servername", hostname, "-tls1_3", "-ign_eof"]
    
    if group:
        cmd += ["-groups", group]
    
    try:
        # Ejecutamos capturando el error detallado
        process = subprocess.run(cmd, input=b"HEAD / HTTP/1.0\n\n", capture_output=True, timeout=8)
        stdout = process.stdout.decode(errors='ignore')
        stderr = process.stderr.decode(errors='ignore')
        
        # Si vemos que se ha elegido un Cifrado, es que ha habido éxito
        if "Cipher is" in stdout or "New, " in stdout:
            # Extraer el grupo negociado
            for line in stdout.split('\n'):
                if "Server Temp Key" in line or "Key Exchange" in line:
                    return {"status": "ACEPTADO ✅", "res": line.strip()}
            return {"status": "ACEPTADO ✅", "res": "Conectado (TLS 1.3)"}
        
        return {"status": "RECHAZADO ❌", "res": "Incompatibilidad de protocolo/draft"}
            
    except Exception as e:
        return {"status": "ERROR", "res": str(e)}

if __name__ == "__main__":
    # Prueba solo con Google y Cloudflare para ir rápido
    targets = ["cosec.inf.uc3m.es", "www.uc3m.es", "www.google.com", "cloudflare.com", "www.facebook.com"]
    # Probamos el nombre más moderno (mlkem768) y el clásico
    grupos = [None, "prime256v1", "x25519_mlkem768", "p256_kyber768"]
    
    print("🔍 Analizando interoperabilidad PQC...")
    for host in targets:
        print(f"\nServidor: {host}")
        for g in grupos:
            label = g if g else "Automático"
            resultado = sonda_emergencia(host, g)
            print(f"  - {label:15}: {resultado['status']} -> {resultado['res']}")