#!/usr/bin/env python3
"""
Sonda de prevalencia ECH (Encrypted Client Hello) a gran escala.

Objetivos:
- Descubrir registros HTTPS (RR tipo 65) y extraer el parámetro `ech`. RR significa que el dominio anuncia soporte ECH, pero no garantiza que esté bien configurado o activo.   
- Decodificar ECHConfigList para obtener KEM/HPKE/public_name (Outer SNI).
- Intentar negociación TLS 1.3 con/ sin soporte ECH según cliente disponible.
- Medir longitud del ClientHello y detectar patrones de padding.
- Exportar resultados por dominio en JSON y CSV.
"""

# Imports necesarios para el script.
from __future__ import annotations
import argparse
import asyncio
import base64
import csv
import json
import re
import shutil
import socket
import statistics
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver

# Configuración por defecto y constantes.
DEFAULT_JSON_OUTPUT = "resultados/resultados_ech_prevalencia.json"
DEFAULT_CSV_OUTPUT = "resultados/resultados_ech_prevalencia.csv"

STATUS_SIN_HTTPS_RR = "SIN_HTTPS_RR"
STATUS_SIN_ECH = "HTTPS_RR_SIN_ECH"
STATUS_CLIENTE_SIN_SOPORTE = "CLIENTE_SIN_SOPORTE_ECH"
STATUS_EXITO_OUTER_CH = "EXITO_OUTER_CLIENT_HELLO"
STATUS_FALLBACK = "FALLBACK_SNI_EN_CLARO"
STATUS_NEGOCIACION_OK_SIN_CONFIRMAR = "NEGOCIACION_TLS_OK_SIN_CONFIRMACION_ECH"
STATUS_FALLO_NEGOCIACION = "FALLO_NEGOCIACION_ECH"
STATUS_ERROR_TIMEOUT_TLS = "ERROR_TIMEOUT_TLS"


# Estructura de datos para almacenar resultados por dominio.
@dataclass
class DominioECHResultado:
    domain: str
    https_rr_present: bool
    has_ech_param: bool
    outer_sni: Optional[str]
    provider: str
    tls_client_used: str
    ech_negotiation_status: str
    handshake_completed: bool
    tls_connected: bool
    client_hello_length: Optional[int]
    padding_detected: bool
    padding_profile: Optional[str]
    ech_version: Optional[str]
    kem_id: Optional[int]
    hpke_suites: List[str]
    ech_config_id: Optional[int]
    public_key_length: Optional[int]
    dns_error: Optional[str]
    tls_error: Optional[str]
    notes: Optional[str]

# Funciones auxiliares para procesamiento de ECH, negociación TLS, y análisis de resultados.

def _limpiar_valor_ech(value: str) -> str:
    """
    Normaliza el valor textual de `ech=` para poder decodificar base64.
    Esto incluye eliminar espacios, comillas, y manejar escapes comunes.
        Input: `ech="base64value=="` o `ech=base64value==` con posibles espacios.
        Output: `base64value==` listo para decodificar.
    """
    cleaned = value.strip().strip('"').strip("'")
    cleaned = cleaned.replace("\\\"", "")
    cleaned = cleaned.replace(" ", "")
    return cleaned


def _decode_ech_base64(value: str) -> bytes:
    """
    Decodifica base64 estándar o URL-safe con padding flexible.
        Input: valor de `ech` limpio, p.ej. `base64value==` o `base64value` (sin padding).
        Output: bytes decodificados de la ECHConfigList.
    """
    payload = _limpiar_valor_ech(value)
    payload = payload.replace("-", "+").replace("_", "/")
    payload += "=" * ((4 - (len(payload) % 4)) % 4)
    return base64.b64decode(payload)


def _normalizar_target(value: str) -> str:
    """
    Limpia una entrada de dominio leída desde CSV.
    Esto incluye eliminar esquemas URL, rutas, espacios, y comillas.
        Input: `https://example.com/path` o `  "example.com"  `
        Output: `example.com`
    """
    candidate = value.strip()
    if not candidate:
        return ""
    candidate = re.sub(r"^https?://", "", candidate, flags=re.IGNORECASE)
    candidate = candidate.split("/")[0]
    candidate = candidate.strip().strip('"').strip("'")
    return candidate


def _target_parece_dominio(value: str) -> bool:
    """
    Heurística simple para decidir si un campo parece hostname/dominio.
        Input: cadena de texto representando un posible nombre de host.
        Output: True si parece un nombre de dominio, False en caso contrario.
    """
    if not value:
        return False
    if value.isdigit():
        return False
    return bool(re.search(r"[A-Za-z]", value) and ("." in value or ":" in value or value == "localhost"))


def _split_host_port(target: str) -> Tuple[str, int]:
    """
    Soporta entradas `host` o `host:puerto` (sin IPv6 bracket para simplicidad).
    Si no se especifica puerto, asume 443 por defecto.
        Input: `example.com` o `example.com:8443`
        Output: (`example.com`, 443) o (`example.com`, 8443)
    """
    if ":" in target and target.count(":") == 1:
        host, port_text = target.rsplit(":", 1)
        if port_text.isdigit():
            return host.strip(), int(port_text)
    return target, 443


def _parse_ech_config_contents(contents: bytes, version: int) -> Dict[str, Any]:
    """
    Parsea una ECHConfig (draft TLS ECH) de forma segura y tolerante a errores.
    La estructura de ECHConfig es compleja y tiene múltiples campos con longitudes variables.
    Esta función extrae los campos principales y maneja casos de datos truncados o malformados.
        Input: bytes de una ECHConfig individual (sin encabezado de longitud) y su versión.
        Output: diccionario con campos extraídos como config_id, kem_id, hpke_suites, public_name, etc.
        En caso de datos malformados, lanza ValueError con descripción del problema.
        Esta función no asume que los datos son correctos y valida cada paso del parseo.
        Se enfoca en extraer información relevante para el estudio de prevalencia ECH sin requerir parseo completo de cada campo.
    """
    index = 0
    if len(contents) < 8:
        raise ValueError("ECHConfig demasiado corta")

    config_id = contents[index]
    index += 1

    kem_id = int.from_bytes(contents[index:index + 2], "big")
    index += 2

    pk_len = int.from_bytes(contents[index:index + 2], "big")
    index += 2
    if index + pk_len > len(contents):
        raise ValueError("Longitud de clave pública inválida")
    public_key = contents[index:index + pk_len]
    index += pk_len

    suites_len = int.from_bytes(contents[index:index + 2], "big")
    index += 2
    if suites_len % 4 != 0 or index + suites_len > len(contents):
        raise ValueError("Lista HPKE inválida")

    hpke_suites: List[str] = []
    suites_end = index + suites_len
    while index < suites_end:
        kdf_id = int.from_bytes(contents[index:index + 2], "big")
        index += 2
        aead_id = int.from_bytes(contents[index:index + 2], "big")
        index += 2
        hpke_suites.append(f"kdf=0x{kdf_id:04x}/aead=0x{aead_id:04x}")

    _maximum_name_length = contents[index]
    index += 1

    public_name_len = contents[index]
    index += 1
    if index + public_name_len > len(contents):
        raise ValueError("public_name inválido")
    public_name = contents[index:index + public_name_len].decode("utf-8", errors="replace")
    index += public_name_len

    extensions_len = int.from_bytes(contents[index:index + 2], "big")
    index += 2
    if index + extensions_len > len(contents):
        raise ValueError("Extensiones ECH inválidas")

    return {
        "version": f"0x{version:04x}",
        "config_id": config_id,
        "kem_id": kem_id,
        "hpke_suites": hpke_suites,
        "public_name": public_name,
        "public_key_length": len(public_key),
    }


def parse_ech_config_list(raw_ech: bytes) -> List[Dict[str, Any]]:
    """
    Parsea ECHConfigList (vector con prefijo de longitud de 2 bytes).
    ECHConfigList es una estructura que contiene una lista de ECHConfig, cada una con su propia longitud. Esta función maneja el parseo de esta estructura, validando las longitudes y extrayendo cada ECHConfig individualmente para luego parsearla con `_parse_ech_config_contents`. Se asegura de manejar casos donde los datos pueden estar truncados o malformados, lanzando errores descriptivos en caso de problemas.
        Input: bytes de la ECHConfigList completa (incluyendo prefijo de longitud).
        Output: lista de diccionarios con campos extraídos de cada ECHConfig dentro de la lista.
         En caso de datos malformados, lanza ValueError con descripción del problema.
         Esta función no asume que los datos son correctos y valida cada paso del parseo.
    """
    # Validamos que la ECHConfigList tenga al menos 2 bytes para la longitud total, y luego iteramos sobre el blob de configs extrayendo cada una según su longitud declarada. Para cada ECHConfig extraída, llamamos a `_parse_ech_config_contents` para obtener los campos relevantes. Si en cualquier punto encontramos inconsistencias en las longitudes o datos malformados, lanzamos un ValueError con una descripción clara del problema.
    if len(raw_ech) < 2:
        raise ValueError("ECHConfigList sin longitud")

    # Leemos la longitud total de la lista de configs, y luego iteramos sobre el blob de configs extrayendo cada una según su longitud declarada. Para cada ECHConfig extraída, llamamos a `_parse_ech_config_contents` para obtener los campos relevantes. Si en cualquier punto encontramos inconsistencias en las longitudes o datos malformados, lanzamos un ValueError con una descripción clara del problema.
    total_len = int.from_bytes(raw_ech[0:2], "big")
    if total_len > len(raw_ech) - 2:
        raise ValueError("Longitud ECHConfigList inconsistente")

    # Iteramos sobre el blob de configs extrayendo cada una según su longitud declarada. Para cada ECHConfig extraída, llamamos a `_parse_ech_config_contents` para obtener los campos relevantes. Si en cualquier punto encontramos inconsistencias en las longitudes o datos malformados, lanzamos un ValueError con una descripción clara del problema.
    configs_blob = raw_ech[2:2 + total_len]
    index = 0
    parsed_configs: List[Dict[str, Any]] = []

    #  Iteramos sobre el blob de configs extrayendo cada una según su longitud declarada. Para cada ECHConfig extraída, llamamos a `_parse_ech_config_contents` para obtener los campos relevantes. Si en cualquier punto encontramos inconsistencias en las longitudes o datos malformados, lanzamos un ValueError con una descripción clara del problema.
    while index < len(configs_blob):
        if index + 4 > len(configs_blob):
            raise ValueError("Cabecera ECHConfig incompleta")
        version = int.from_bytes(configs_blob[index:index + 2], "big")
        index += 2

        config_len = int.from_bytes(configs_blob[index:index + 2], "big")
        index += 2

        if index + config_len > len(configs_blob):
            raise ValueError("Longitud ECHConfig fuera de rango")
        config_contents = configs_blob[index:index + config_len]
        index += config_len

        parsed_configs.append(_parse_ech_config_contents(config_contents, version))

    # Devolvemos la lista de configs parseadas, cada una con sus campos relevantes extraídos. Esta función maneja múltiples casos de datos malformados y asegura que solo se devuelvan configs válidas, lanzando errores descriptivos en caso de problemas.
    return parsed_configs


def clasificar_proveedor(outer_sni: Optional[str]) -> str:
    """
    Clasifica proveedor CDN/infra a partir de public_name (Outer SNI).
        Input: valor de Outer SNI extraído de ECHConfig (p.ej. "cloudflare.com", "fastly.net", etc.) o None si no se pudo extraer.
        Output: etiqueta de proveedor clasificada ("Cloudflare", "Fastly", "DEfO", "OTRO", o "DESCONOCIDO"). Esta función utiliza heurísticas simples basadas en la presencia de ciertas palabras clave en el Outer SNI para clasificar el proveedor, lo que puede ayudar a identificar patrones comunes de despliegue ECH asociados a ciertos proveedores de CDN o infraestructura, aunque no es infalible y se basa en suposiciones razonables sobre los nombres de host utilizados en las configuraciones ECH.
    """
    if not outer_sni:
        return "DESCONOCIDO"
    value = outer_sni.lower()
    if "cloudflare" in value:
        return "Cloudflare"
    if "fastly" in value:
        return "Fastly"
    if "defo" in value:
        return "DEfO"
    return "OTRO"


def detectar_padding(client_hello_len: Optional[int], provider: str) -> Tuple[bool, Optional[str]]:
    """
    Detecta tamaños de padding estandarizados observados en despliegues ECH.
    Algunos proveedores usan tamaños de ClientHello específicos o rangos estrechos para facilitar la detección de ECH, lo que puede ser un indicador indirecto de su uso. Esta función identifica patrones comunes de padding basados en la longitud del ClientHello y el proveedor asociado, devolviendo si se detectó padding y una etiqueta descriptiva del perfil de padding identificado.
        Input: longitud de ClientHello (si se pudo medir) y proveedor clasificado.
        Output: tupla indicando si se detectó padding, y etiqueta del perfil de padding (p.ej. "PADDING_1925", "PADDING_RANGO_CLOUDFLARE", etc.) o None si no se detectó ningún patrón de padding conocido. Esta función ayuda a identificar casos donde el cliente TLS está usando un tamaño de ClientHello que coincide con patrones de padding conocidos asociados a despliegues ECH, lo que puede ser un indicador indirecto de su uso incluso si no se negocia ECH exitosamente.
    """
    # Detectamos tamaños de padding estandarizados observados en despliegues ECH. Algunos proveedores usan tamaños de ClientHello específicos o rangos estrechos para facilitar la detección de ECH, lo que puede ser un indicador indirecto de su uso. Identificamos patrones comunes de padding basados en la longitud del ClientHello y el proveedor asociado, devolviendo si se detectó padding y una etiqueta descriptiva del perfil de padding identificado.
    if client_hello_len is None:
        return False, None
    if client_hello_len == 1925:
        return True, "PADDING_1925"
    if client_hello_len == 1920:
        return True, "PADDING_1920"

    if provider == "Cloudflare" and 1918 <= client_hello_len <= 1930:
        return True, "PADDING_RANGO_CLOUDFLARE"
    if provider == "DEfO" and 1916 <= client_hello_len <= 1924:
        return True, "PADDING_RANGO_DEFO"
    return False, None


def extraer_longitud_client_hello(output: str) -> Optional[int]:
    """
    Extrae longitud de ClientHello desde salida textual de OpenSSL/BoringSSL.
        Input: salida combinada de stdout/stderr del cliente TLS.
        Output: longitud de ClientHello si se encuentra, o None si no se pudo extraer. Esta función maneja múltiples formatos de salida que pueden variar entre versiones y configuraciones de los clientes TLS, buscando patrones comunes que indiquen la longitud del ClientHello, ya sea en decimal o hexadecimal. Si no se encuentra ningún patrón reconocible, devuelve None.
    """
    # Buscamos múltiples patrones comunes en la salida textual que puedan indicar la longitud del ClientHello, ya sea en decimal o hexadecimal, y manejamos ambos casos para extraer el valor numérico. Si no se encuentra ningún patrón reconocible, devolvemos None.
    patterns = [
        r"ClientHello\s*,\s*Length\s*=\s*(\d+)",
        r"\[length\s+([0-9a-fA-F]+)\]\s*,\s*ClientHello",
        r"ClientHello[^\n]*\[length\s+([0-9a-fA-F]+)\]",
        r"ClientHello[^\n]*Length\s*[=:]\s*(\d+)",
        r"client_hello_length\s*[=:]\s*(\d+)",
    ]
    # Iteramos sobre los patrones y buscamos coincidencias en la salida. 
    # Si encontramos una coincidencia, intentamos convertir el valor extraído a un número entero, manejando tanto formatos decimales como hexadecimales. Si la conversión es exitosa, devolvemos la longitud del ClientHello. Si no se encuentra ningún patrón o si la conversión falla, devolvemos None.
    for pat in patterns:
        match = re.search(pat, output, flags=re.IGNORECASE)
        if not match:
            continue
        value = match.group(1)
        if re.fullmatch(r"[0-9]+", value):
            return int(value)
        return int(value, 16)
    return None


def detectar_handshake_completo(output: str, return_code: int) -> bool:
    """
    Detecta si el handshake TLS terminó correctamente (no solo conexión TCP).
    Esto es importante para clasificar correctamente casos donde el handshake falla por razones no relacionadas con ECH, evitando clasificaciones erróneas de fallo de negociación ECH cuando en realidad el handshake ni siquiera se completó. Se buscan indicadores comunes en la salida textual que sugieran que el handshake TLS se completó exitosamente, como mensajes de verificación, protocolo negociado, o confirmación de handshake completo. Si el código de retorno indica un error general (no timeout), se asume que el handshake no se completó.
        Input: salida combinada de stdout/stderr del cliente TLS y código de retorno del proceso.
        Output: True si hay indicadores claros de que el handshake TLS se completó, False en caso contrario. Esta función ayuda a mejorar la precisión de la clasificación de resultados de negociación ECH al considerar el resultado general del handshake TLS, evitando clasificaciones erróneas en casos donde el handshake falla por razones no relacionadas con ECH.
    """
    # Si el código de retorno indica un error general (no timeout), se asume que el handshake no se completó. Luego, se buscan indicadores comunes en la salida textual que sugieran que el handshake TLS se completó exitosamente, como mensajes de verificación, protocolo negociado, o confirmación de handshake completo. Si encontramos alguno de estos indicadores, consideramos que el handshake TLS se completó correctamente.
    if return_code != 0:
        return False

    # Buscamos indicadores comunes en la salida textual que sugieran que el handshake TLS se completó exitosamente, como mensajes de verificación, protocolo negociado, o confirmación de handshake completo. Si encontramos alguno de estos indicadores, consideramos que el handshake TLS se completó correctamente.
    text = output.lower()
    markers = [
        "verification: ok",
        "verify return code:",
        "ssl-session:",
        "protocol  : tlsv1.3",
        "handshake complete",
        "handshake done.",
        "new, tlsv1.3",
    ]
    return any(marker in text for marker in markers)


def clasificar_estado_negociacion(output: str, return_code: int, client_mode: str) -> Tuple[str, bool, bool]:
    """
    Clasifica el resultado de negociación TLS/ECH con reglas robustas.
        - Si el cliente TLS no soporta ECH real (p.ej. OpenSSL), siempre se clasifica como "CLIENTE_SIN_SOPORTE_ECH" aunque el handshake TLS pueda ser exitoso, ya que el objetivo es medir ClientHello base sin negociar ECH real.
        - Para clientes con soporte ECH real (p.ej. BoringSSL), se analizan indicadores claros de aceptación o rechazo de ECH en la salida textual, pero también se considera el resultado general del handshake TLS para clasificar correctamente casos donde el handshake falla por razones no relacionadas con ECH.
        - Si no hay indicadores claros de ECH pero el handshake TLS se completa, se clasifica como "NEGOCIACION_TLS_OK_SIN_CONFIRMACION_ECH" para reflejar que aunque TLS funcionó, no se pudo confirmar si ECH fue negociado o no.
            Input: salida combinada de stdout/stderr del cliente TLS, código de retorno del proceso, y tipo de cliente TLS usado.
            Output: estado de negociación ECH clasificado, si TLS se conectó, y si el handshake se completó. Esta función maneja múltiples escenarios de salida y códigos de retorno para proporcionar una clasificación lo más precisa posible del resultado de la negociación ECH, considerando las limitaciones de cada cliente TLS.
    """
    # Primero, determinamos si el handshake TLS se completó correctamente usando indicadores comunes en la salida del cliente TLS. Esto nos da una base para clasificar el resultado de ECH, ya que un handshake fallido generalmente indica que no se negoció ECH exitosamente, aunque también puede fallar por otras razones. Luego, analizamos la salida textual para buscar indicadores específicos de aceptación o rechazo de ECH, pero siempre considerando el resultado general del handshake TLS para evitar clasificaciones erróneas.
    text = output.lower()
    handshake_completed = detectar_handshake_completo(output, return_code)
    tls_ok = return_code == 0 and (
        handshake_completed or "handshake" in text or "protocol" in text or "connected" in text
    )

    # Si el cliente TLS es OpenSSL, no negocia ECH real, por lo que clasificamos directamente como "CLIENTE_SIN_SOPORTE_ECH" independientemente del resultado del handshake, ya que el objetivo de usar OpenSSL en este estudio es medir ClientHello base sin negociar ECH real. Esto refleja la realidad de que OpenSSL no implementa ECH real, y aunque pueda completar un handshake TLS exitoso, no se puede considerar que negoció ECH.
    if client_mode == "openssl":
        # OpenSSL estándar no negocia ECH real. Incluso si falla el handshake,
        # el estado correcto para el estudio ECH es "cliente sin soporte".
        return STATUS_CLIENTE_SIN_SOPORTE, tls_ok, handshake_completed

    # Diferentes indicadores de aceptación o rechazo de ECH en la salida textual, pero siempre considerando el resultado general del handshake TLS para clasificar correctamente casos donde el handshake falla por razones no relacionadas con ECH. Si no hay indicadores claros de ECH pero el handshake TLS se completa, se clasifica como "NEGOCIACION_TLS_OK_SIN_CONFIRMACION_ECH" para reflejar que aunque TLS funcionó, no se pudo confirmar si ECH fue negociado o no.
    if "encrypted clienthello: yes" in text:
        return STATUS_EXITO_OUTER_CH, True, handshake_completed
    if "encrypted clienthello: no" in text:
        return STATUS_FALLBACK, tls_ok, handshake_completed

    if "ech accepted" in text or "encrypted client hello accepted" in text or "ech: accepted" in text:
        if tls_ok:
            return STATUS_EXITO_OUTER_CH, True, handshake_completed
        return STATUS_FALLO_NEGOCIACION, False, handshake_completed
    if "ech rejected" in text or "retry configs" in text or "fallback" in text or "ech required" in text:
        return STATUS_FALLBACK, tls_ok, handshake_completed
    if tls_ok:
        return STATUS_NEGOCIACION_OK_SIN_CONFIRMAR, True, handshake_completed
    return STATUS_FALLO_NEGOCIACION, False, handshake_completed


async def run_command(command: List[str], timeout: float, input_data: bytes = b"") -> Tuple[int, str, str]:
    """
    Ejecuta comando asíncrono capturando stdout/stderr y timeout.
        Input: lista de argumentos del comando, timeout en segundos, y datos opcionales para stdin.
        Output: tupla con código de retorno, stdout decodificado, y stderr decodificado. Si ocurre un timeout, el código de retorno es 124 y stderr incluye "TIMEOUT". Esta función maneja la ejecución del proceso de forma segura, asegurándose de matar el proceso si excede el timeout, y captura cualquier salida generada hasta ese momento para reportarla adecuadamente.
    """
    # Ejecutamos el comando usando asyncio.create_subprocess_exec, lo que nos permite manejar la ejecución de forma asíncrona y capturar stdout y stderr. Usamos asyncio.wait_for para imponer un timeout, y si se excede, matamos el proceso y capturamos cualquier salida generada hasta ese momento para reportar un error de timeout de manera clara.
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # Si se proporciona input_data, lo enviamos al proceso. Luego esperamos a que termine o a que se exceda el timeout. Si ocurre un timeout, matamos el proceso y capturamos cualquier salida generada hasta ese momento para reportar un error de timeout de manera clara.
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(input_data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        stdout, stderr = await proc.communicate()
        stdout_text = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace")
        if stderr_text:
            stderr_text = f"{stderr_text}\nTIMEOUT"
        else:
            stderr_text = "TIMEOUT"
        return 124, stdout_text, stderr_text

    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def resolver_ips_ipv4(domain: str, port: int) -> List[str]:
    """
    Resuelve IPs IPv4 del dominio para reintentos de conexión TLS.
        Input: dominio a resolver y puerto (para compatibilidad con getaddrinfo).
        Output: lista de direcciones IPv4 únicas asociadas al dominio, o lista vacía si no se pudieron resolver. Esta función maneja errores de resolución y simplemente devuelve una lista vacía en caso de cualquier problema, para que el proceso principal pueda decidir si reintentar o no sin fallar por completo.
    """
    #  Usamos getaddrinfo para resolver el dominio a IPv4, ya que es una función estándar que maneja múltiples casos de resolución y es compatible con la mayoría de entornos. Si ocurre cualquier error durante la resolución (como NXDOMAIN, timeout, o problemas de red), capturamos la excepción y devolvemos una lista vacía, lo que indica que no se pudieron resolver IPs para ese dominio.
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(domain, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except Exception:
        return []

    # Extraemos las IPs únicas de la información de direcciones. La función getaddrinfo puede devolver múltiples entradas para el mismo dominio, incluyendo duplicados o múltiples interfaces. Usamos un conjunto para asegurarnos de que solo obtenemos IPs únicas, y luego las devolvemos como una lista.
    ips: List[str] = []
    seen = set()
    for item in addr_info:
        ip = item[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


async def medir_clienthello_len_openssl(domain: str, port: int, timeout: float) -> Optional[int]:
    """
    Mide longitud de ClientHello con OpenSSL como fallback cuando bssl no la expone.
        Input: dominio, puerto, y timeout para la conexión TLS.
        Output: longitud de ClientHello reportada por OpenSSL, o None si no se pudo medir. Esta función asume que OpenSSL está disponible y se puede ejecutar, pero maneja casos donde no lo está devolviendo None.    
    """
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        return None

    cmd = [
        openssl_path,
        "s_client",
        "-connect",
        f"{domain}:{port}",
        "-servername",
        domain,
        "-tls1_3",
        "-brief",
        "-msg",
    ]
    return_code, stdout, stderr = await run_command(cmd, timeout=max(timeout, 8), input_data=b"Q\n")
    if return_code not in (0, 124):
        return None

    output = f"{stdout}\n{stderr}"
    return extraer_longitud_client_hello(output)


async def descubrir_https_rr(
    resolver: dns.asyncresolver.Resolver,
    domain: str,
    dns_timeout: float,
) -> Tuple[bool, Optional[str], Optional[List[Dict[str, Any]]], Optional[str]]:
    """
    Consulta RR HTTPS y devuelve valor ech + parseo de configs si existe.
        Input: resolver DNS asíncrono, dominio a consultar, y timeout para la consulta.
        Output: tupla indicando si RR HTTPS existe, valor ech encontrado (si hay), lista de configs parseadas (si hay), y error DNS si ocurrió.
    """
    # Intentamos resolver el RR HTTPS del dominio. Si no existe o hay un error de resolución, indicamos que no hay RR HTTPS. Si existe pero no tiene `ech=`, indicamos que hay RR HTTPS pero sin ECH. Si tiene `ech=`, intentamos decodificarlo y parsearlo, y capturamos cualquier error en el proceso para reportarlo.
    try:
        answer = await resolver.resolve(domain, "HTTPS", raise_on_no_answer=False, lifetime=dns_timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        return False, None, None, str(exc)
    except dns.resolver.NoAnswer:
        return False, None, None, None
    except Exception as exc:
        return False, None, None, f"ERROR_DNS:{exc}"

    #  Si no hay RR HTTPS, indicamos que no existe. Si hay RR pero no tiene `ech=`, indicamos que hay RR pero sin ECH. Si tiene `ech=`, intentamos decodificarlo y parsearlo, y capturamos cualquier error en el proceso para reportarlo.
    if not answer.rrset:
        return False, None, None, None

    #  Si hay RR HTTPS, intentamos extraer el valor de `ech=`.
    ech_value = None
    for rdata in answer:
        text_rr = rdata.to_text()
        match = re.search(r"\bech\s*=\s*([^\s]+)", text_rr, flags=re.IGNORECASE)
        if match:
            ech_value = match.group(1)
            break

    if not ech_value:
        return True, None, None, None

    # Si encontramos un valor `ech=`, intentamos decodificarlo y parsearlo. Si ocurre cualquier error en este proceso, lo capturamos para reportarlo, pero indicamos que el RR HTTPS existe y tiene un valor `ech` aunque no se pudo procesar correctamente.
    try:
        raw_ech = _decode_ech_base64(ech_value)
        parsed = parse_ech_config_list(raw_ech)
        return True, ech_value, parsed, None
    except Exception as exc:
        return True, ech_value, None, f"ECH_PARSE_ERROR:{exc}"


def _buscar_bssl_local() -> Optional[str]:
    """
    Busca un binario bssl local dentro del repositorio.
        Input: ninguno.
        Output: ruta al ejecutable bssl si se encuentra, o None si no se encuentra.    
    """
    # Buscamos en rutas comunes dentro del proyecto donde se podría compilar bssl.
    project_root = Path(__file__).resolve().parents[2]
    # Estas rutas son típicas para una compilación local de bssl.
    candidatos = [
        project_root / "tools" / "boringssl" / "build" / "bssl",
        project_root / "tools" / "boringssl" / "build" / "tool" / "bssl",
    ]
    for ruta in candidatos:
        if ruta.exists() and ruta.is_file():
            return str(ruta)
    return None


def resolver_cliente_tls(mode: str, bssl_path_override: Optional[str] = None) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Selecciona cliente TLS real según modo solicitado y disponibilidad local.
        Input: modo TLS deseado ("bssl", "openssl", "auto") y ruta opcional a bssl.
        Output: tupla con tipo de cliente seleccionado, ruta al ejecutable, y nota adicional si hubo fallback o falta de soporte.
    """
    # Intentamos localizar bssl según orden de preferencia: ruta override > PATH > búsqueda local. Esto permite flexibilidad para usar una versión específica de bssl si se desea, o confiar en el PATH, o usar una copia incluida en el proyecto.
    bssl_path = None
    if bssl_path_override:
        ruta = Path(bssl_path_override)
        if ruta.exists() and ruta.is_file():
            bssl_path = str(ruta)

    # Si no se encontró bssl con la ruta override, intentamos localizarlo en el PATH del sistema. Esto es útil para usuarios que tengan bssl instalado globalmente o en su entorno virtual.
    if not bssl_path:
        bssl_path = shutil.which("bssl")
    if not bssl_path:
        bssl_path = _buscar_bssl_local()

    # Resolver según modo solicitado, con lógica de fallback. Si el modo es "openssl", usamos OpenSSL sin importar la disponibilidad de bssl, ya que el objetivo es medir ClientHello base. Si el modo es "bssl", intentamos usar bssl y solo si no está disponible, hacemos fallback a OpenSSL para medir ClientHello base, pero con una nota indicando que no se negoció ECH real. Si el modo es "auto", preferimos bssl si está disponible, pero caemos a OpenSSL si no lo está, para asegurar que al menos se mida ClientHello aunque no se negocie ECH real.
    if mode == "openssl":
        return "openssl", shutil.which("openssl"), None
    if mode == "bssl":
        if bssl_path:
            return "bssl", bssl_path, None
        openssl_path = shutil.which("openssl")
        if openssl_path:
            return "openssl", openssl_path, "bssl no disponible; fallback a openssl"
        return "bssl", None, "bssl no disponible"

    if bssl_path:
        return "bssl", bssl_path, None
    return "openssl", shutil.which("openssl"), None


async def simular_tls_ech(
    domain: str,
    port: int,
    ech_value: Optional[str],
    outer_sni: Optional[str],
    tls_mode: str,
    tls_timeout: float,
    bssl_path_override: Optional[str] = None,
) -> Tuple[str, bool, bool, Optional[int], Optional[str], str, Optional[str]]:
    """
    Ejecuta handshake TLS 1.3 y evalúa estado ECH + longitud ClientHello.
        - Usa cliente TLS según `tls_mode` (bssl, openssl, auto).
        - Si `ech_value` está presente y el cliente soporta ECH real, lo configura para intentar negociación ECH.
        - Mide longitud de ClientHello desde salida del cliente TLS.
        - Clasifica resultado en categorías como éxito ECH, fallback, negociación sin confirmar, fallo, o timeout.
            - Devuelve estado de negociación, si se conectó TLS, si handshake se completó, longitud de ClientHello, error TLS si existe, cliente usado, y nota adicional.
            Input: dominio, puerto, valor ech del RR, outer SNI, modo TLS, timeout, y ruta opcional a bssl.
            Output: estado negociación ECH, si TLS se conectó, si handshake se completó, longitud ClientHello, error TLS, cliente usado, y nota.
    """
    # Resolver el cliente TLS según el modo solicitado
    client_kind, client_path, note = resolver_cliente_tls(tls_mode, bssl_path_override=bssl_path_override)
    if not client_path:
        return STATUS_CLIENTE_SIN_SOPORTE, False, False, None, "Cliente TLS no encontrado", client_kind, note

    # Si tenemos valor ech y el cliente soporta ECH real, preparamos configuración temporal para el cliente.
    ech_temp_file: Optional[str] = None

    # Función para construir el comando TLS según cliente y host de conexión (dominio o IP).
    def construir_cmd(connect_host: str) -> List[str]:
        """
        Construye el comando de cliente TLS según el tipo de cliente y host de conexión.
            - Para OpenSSL, el comando es fijo y no soporta configuración ECH real, pero se incluye para medir ClientHello base.
            - Para BoringSSL, se construye el comando con opción de configuración ECH si está disponible.
                Input: host al que conectar (dominio o IP).
                Output: lista de argumentos para ejecutar el cliente TLS con la configuración adecuada.
        """
        # Para openssl
        if client_kind == "openssl":
            return [
                client_path,
                "s_client",
                "-connect",
                f"{connect_host}:{port}",
                "-servername",
                domain,
                "-tls1_3",
                "-brief",   # Salida más concisa, pero aún con información de handshake y protocolo.
                "-msg",     # Muestra mensajes de handshake para intentar extraer longitud de ClientHello.
            ]

        # Para bssl
        cmd_local = [
            client_path,
            "client",
            "-connect",
            f"{connect_host}:{port}",
            "-server-name",
            domain,
            "-debug",
        ]
        if ech_temp_file:
            cmd_local.extend(["-ech-config-list", ech_temp_file])
            return cmd_local

    # Para BoringSSL
    if client_kind == "bssl" and ech_value:
        try:
            raw_ech = _decode_ech_base64(ech_value)
            temp_handle = tempfile.NamedTemporaryFile(prefix="ech_config_", suffix=".bin", delete=False)
            temp_handle.write(raw_ech)
            temp_handle.flush()
            temp_handle.close()
            ech_temp_file = temp_handle.name
        except Exception as exc:
            return STATUS_FALLO_NEGOCIACION, False, False, None, f"ECH_CONFIG_FILE_ERROR:{exc}", client_kind, note

    # Ejecutar el cliente TLS y analizar resultados. Para OpenSSL, el input_data es "Q\n" para salir rápido después de recibir mensajes de handshake, ya que no negocia ECH real. Para BoringSSL, no se necesita input adicional.
    input_data = b"Q\n" if client_kind == "openssl" else b""
    attempted_hosts = [domain]
    try:
        # Ejecutamos el cliente TLS con el host de conexión inicial (dominio) y analizamos la salida para clasificar el resultado de negociación ECH y medir longitud de ClientHello.
        cmd = construir_cmd(domain)
        return_code, stdout, stderr = await run_command(cmd, timeout=tls_timeout, input_data=input_data)
        if return_code == 124:
            retry_timeout = max(tls_timeout * 1.5, tls_timeout + 2)
            return_code, stdout, stderr = await run_command(cmd, timeout=retry_timeout, input_data=input_data)

        combined_output = f"{stdout}\n{stderr}"
        client_hello_len = extraer_longitud_client_hello(combined_output)
        status, tls_connected, handshake_completed = clasificar_estado_negociacion(combined_output, return_code, client_kind)

        tls_error = None
        if return_code != 0 and stderr.strip():
            tls_error = stderr.strip().splitlines()[-1][:400]
        elif return_code == 124:
            tls_error = "TIMEOUT"

        if tls_error == "TIMEOUT":
            status = STATUS_ERROR_TIMEOUT_TLS
            tls_connected = False
            handshake_completed = False

        if client_hello_len is None and client_kind == "bssl":
            baseline_len = await medir_clienthello_len_openssl(domain, port, tls_timeout)
            if baseline_len is not None:
                client_hello_len = baseline_len
                note = (note + "; " if note else "") + "clienthello_len_base_openssl"

        # Reintento por IP para reducir falsos negativos por timeout/ruta DNS.
        if client_kind == "bssl" and status == STATUS_ERROR_TIMEOUT_TLS:
            ips = await resolver_ips_ipv4(domain, port)
            for ip in ips[:3]:
                if ip in attempted_hosts:
                    continue
                attempted_hosts.append(ip)
                cmd_ip = construir_cmd(ip)
                return_code_ip, stdout_ip, stderr_ip = await run_command(cmd_ip, timeout=max(tls_timeout, 10), input_data=input_data)
                combined_ip = f"{stdout_ip}\n{stderr_ip}"
                len_ip = extraer_longitud_client_hello(combined_ip)
                status_ip, tls_ok_ip, hs_ip = clasificar_estado_negociacion(combined_ip, return_code_ip, client_kind)

                tls_error_ip = None
                if return_code_ip != 0 and stderr_ip.strip():
                    tls_error_ip = stderr_ip.strip().splitlines()[-1][:400]
                elif return_code_ip == 124:
                    tls_error_ip = "TIMEOUT"

                if tls_error_ip == "TIMEOUT":
                    status_ip = STATUS_ERROR_TIMEOUT_TLS
                    tls_ok_ip = False
                    hs_ip = False

                if status_ip in (STATUS_EXITO_OUTER_CH, STATUS_FALLBACK, STATUS_NEGOCIACION_OK_SIN_CONFIRMAR):
                    status, tls_connected, handshake_completed = status_ip, tls_ok_ip, hs_ip
                    client_hello_len = len_ip
                    tls_error = tls_error_ip
                    note = (note + "; " if note else "") + f"reintento_ip_ok:{ip}"
                    break

                # Si no mejoró pero ya no es timeout, conservamos para no etiquetar como timeout puro.
                if status == STATUS_ERROR_TIMEOUT_TLS and status_ip != STATUS_ERROR_TIMEOUT_TLS:
                    status, tls_connected, handshake_completed = status_ip, tls_ok_ip, hs_ip
                    client_hello_len = len_ip
                    tls_error = tls_error_ip
                    note = (note + "; " if note else "") + f"reintento_ip:{ip}"
    finally:
        if ech_temp_file:
            try:
                Path(ech_temp_file).unlink(missing_ok=True)
            except Exception:
                pass
    
    # Ajuste de estado para OpenSSL, que no negocia ECH real pero es útil para medir ClientHello base. Si el cliente es OpenSSL y no se detectó soporte ECH, etiquetamos como "cliente sin soporte" incluso si hubo conexión TLS, para reflejar la realidad de que no se negoció ECH real.
    if client_kind == "openssl" and status == STATUS_CLIENTE_SIN_SOPORTE and note is None and tls_mode in ("bssl", "auto"):
        note = "sin bssl, se midió ClientHello base con openssl (sin ECH real)"

    return status, tls_connected, handshake_completed, client_hello_len, tls_error, client_kind, note


def cargar_dominios_csv(csv_path: Path, max_dominios: int) -> List[str]:
    """
    Carga dominios desde CSV con autodetección simple de columna.
        Input: ruta a CSV y número máximo de dominios a cargar.
        Output: lista de dominios normalizados extraídos del CSV, con heurística para detectar la columna correcta.
        El CSV puede tener o no encabezado. Si tiene encabezado, se busca preferentemente columnas con nombres relacionados a dominio/host. Si no tiene encabezado, se analiza cada celda para encontrar la que parece un dominio.
         Se detiene al alcanzar el número máximo de dominios o al finalizar el archivo.
    """
    # Si el archivo no existe, lanzamos error inmediatamente para evitar confusión.
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV no encontrado: {csv_path}")

    # Heurística para detectar la columna de dominio: buscamos nombres comunes en el encabezado, o si no hay encabezado, analizamos cada celda para encontrar la que parece un dominio.
    domains: List[str] = []
    preferred_cols = {"domain", "dominio", "hostname", "host"}

    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        sample = handle.read(2048)
        handle.seek(0)

        try:
            has_header = csv.Sniffer().has_header(sample)
        except csv.Error:
            has_header = True

        reader = csv.DictReader(handle) if has_header else csv.reader(handle)

        # Si hay encabezado, buscamos la columna que mejor se ajuste a nombres relacionados con dominio. Si no hay encabezado, analizamos cada celda para encontrar la que parece un dominio, y nos detenemos al alcanzar el número máximo de dominios.
        if has_header:
            assert isinstance(reader, csv.DictReader)
            fieldnames = [field.strip().lower() for field in (reader.fieldnames or [])]
            selected_col = None
            for col in fieldnames:
                if col in preferred_cols:
                    selected_col = col
                    break
            selected_col = selected_col or (fieldnames[0] if fieldnames else None)
            
            # Si la columna seleccionada no parece contener dominios, intentamos analizar cada fila para encontrar celdas que parezcan dominios, y nos detenemos al alcanzar el número máximo de dominios.
            for row in reader:
                value = _normalizar_target((row.get(selected_col) or "").strip()) if selected_col else ""
                if not _target_parece_dominio(value):
                    for cell in row.values():
                        candidate = _normalizar_target(cell or "")
                        if _target_parece_dominio(candidate):
                            value = candidate
                            break
                if _target_parece_dominio(value):
                    domains.append(value)
                if len(domains) >= max_dominios:
                    break
        # Si no hay encabezado, analizamos cada celda de cada fila para encontrar la que parece un dominio, y nos detenemos al alcanzar el número máximo de dominios.
        else:
            assert not isinstance(reader, csv.DictReader)
            for row in reader:
                if not row:
                    continue
                selected = ""
                for cell in row:
                    candidate = _normalizar_target(cell or "")
                    if _target_parece_dominio(candidate):
                        selected = candidate
                        break
                if selected and selected.lower() != "domain":
                    domains.append(selected)
                if len(domains) >= max_dominios:
                    break
    
    return domains


async def procesar_dominio(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
    dns_timeout: float,
    tls_timeout: float,
    tls_mode: str,
    bssl_path_override: Optional[str] = None,
) -> DominioECHResultado:
    """
    Pipeline por dominio: DNS -> parseo ECH -> handshake TLS -> padding.
        Input: dominio a procesar, resolver DNS asíncrono, semáforo para control de concurrencia, timeouts, modo TLS, y ruta opcional a bssl.
        Output: instancia de DominioECHResultado con todos los campos llenados según resultados de cada etapa, incluyendo manejo robusto de errores y casos especiales.
    """
    # El semáforo limita la concurrencia para evitar sobrecargar recursos locales o remotos.
    async with semaphore:
        # Separamos host y puerto para consultas DNS y conexiones TLS, soportando formato `host:puerto` en el CSV.
        lookup_domain, tls_port = _split_host_port(domain)

        # Primero descubrimos RR HTTPS y extraemos el valor de `ech` si está presente, junto con el parseo de configuraciones ECHConfigList. También capturamos cualquier error DNS que ocurra durante esta etapa.
        https_present, ech_value, parsed_configs, dns_error = await descubrir_https_rr(
            resolver=resolver,
            domain=lookup_domain,
            dns_timeout=dns_timeout,
        )

        # Si no hay RR HTTPS, no podemos negociar ECH. Retornamos resultado con campos relevantes llenados para este caso específico, incluyendo el error DNS si existió.
        if not https_present:
            return DominioECHResultado(
                domain=domain,
                https_rr_present=False,
                has_ech_param=False,
                outer_sni=None,
                provider="DESCONOCIDO",
                tls_client_used="none",
                ech_negotiation_status=STATUS_SIN_HTTPS_RR,
                handshake_completed=False,
                tls_connected=False,
                client_hello_length=None,
                padding_detected=False,
                padding_profile=None,
                ech_version=None,
                kem_id=None,
                hpke_suites=[],
                ech_config_id=None,
                public_key_length=None,
                dns_error=dns_error,
                tls_error=None,
                notes="No se encontró RR HTTPS",
            )
        
        # Si el RR HTTPS está presente pero no se pudo extraer un valor de `ech` utilizable (ya sea porque no existe o porque el parseo falló), retornamos resultado indicando que aunque hay RR HTTPS, no hay ECH utilizable, incluyendo detalles del error de parseo si existió.
        if not ech_value or not parsed_configs:
            return DominioECHResultado(
                domain=domain,
                https_rr_present=True,
                has_ech_param=bool(ech_value),
                outer_sni=None,
                provider="DESCONOCIDO",
                tls_client_used="none",
                ech_negotiation_status=STATUS_SIN_ECH,
                handshake_completed=False,
                tls_connected=False,
                client_hello_length=None,
                padding_detected=False,
                padding_profile=None,
                ech_version=None,
                kem_id=None,
                hpke_suites=[],
                ech_config_id=None,
                public_key_length=None,
                dns_error=dns_error,
                tls_error=None,
                notes="RR HTTPS presente pero sin ECH utilizable",
            )

        # Si tenemos configuraciones ECHConfig parseadas, procedemos a simular el handshake TLS con soporte ECH, extrayendo el Outer SNI para clasificar el proveedor y luego ejecutando la simulación TLS. Finalmente, analizamos la longitud del ClientHello para detectar posibles patrones de padding asociados a despliegues conocidos.
        primary = parsed_configs[0]
        outer_sni = primary.get("public_name")
        provider = clasificar_proveedor(outer_sni)

        # Simulamos el handshake TLS con el cliente seleccionado, pasando la configuración ECH si está disponible, y capturando el estado de negociación, si se logró conectar, si el handshake se completó, la longitud del ClientHello, y cualquier error TLS que ocurra durante esta etapa.
        status, tls_connected, handshake_completed, client_hello_len, tls_error, tls_client_used, tls_note = await simular_tls_ech(
            domain=lookup_domain,
            port=tls_port,
            ech_value=ech_value,
            outer_sni=outer_sni,
            tls_mode=tls_mode,
            tls_timeout=tls_timeout,
            bssl_path_override=bssl_path_override,
        )

        padding_detected, padding_profile = detectar_padding(client_hello_len, provider)

        # Finalmente, retornamos una instancia de DominioECHResultado con todos los campos llenados según los resultados obtenidos en cada etapa del pipeline, proporcionando una visión completa del estado ECH, la negociación TLS, y cualquier error encontrado.
        return DominioECHResultado(
            domain=domain,
            https_rr_present=True,
            has_ech_param=True,
            outer_sni=outer_sni,
            provider=provider,
            tls_client_used=tls_client_used,
            ech_negotiation_status=status,
            handshake_completed=handshake_completed,
            tls_connected=tls_connected,
            client_hello_length=client_hello_len,
            padding_detected=padding_detected,
            padding_profile=padding_profile,
            ech_version=primary.get("version"),
            kem_id=primary.get("kem_id"),
            hpke_suites=primary.get("hpke_suites", []),
            ech_config_id=primary.get("config_id"),
            public_key_length=primary.get("public_key_length"),
            dns_error=dns_error,
            tls_error=tls_error,
            notes=tls_note,
        )


def calcular_variabilidad_por_proveedor(resultados: List[DominioECHResultado]) -> Dict[str, Dict[str, Any]]:
    """
    Calcula variabilidad de longitud de ClientHello por proveedor.
            Input: lista de resultados por dominio con campos completos.
            Output: diccionario con estadísticas de count, min, max, mean, stddev, y rango de ClientHello por proveedor.
    """
    # Agrupamos longitudes de ClientHello por proveedor, ignorando casos sin longitud válida.
    grouped: Dict[str, List[int]] = {}
    for row in resultados:
        if row.client_hello_length is None:
            continue
        grouped.setdefault(row.provider, []).append(row.client_hello_length)

    stats: Dict[str, Dict[str, Any]] = {}
    for provider, lengths in grouped.items():
        if not lengths:
            continue
        stats[provider] = {
            "count": len(lengths),
            "min": min(lengths),
            "max": max(lengths),
            "mean": round(statistics.mean(lengths), 2),
            "stddev": round(statistics.pstdev(lengths), 2) if len(lengths) > 1 else 0.0,
            "range": max(lengths) - min(lengths),
        }
    return stats


def exportar_csv(resultados: List[DominioECHResultado], csv_path: Path) -> None:
    """
    Guarda CSV plano con columnas principales de investigación.
        Input: lista de resultados por dominio con campos completos.
        Output: archivo CSV con columnas clave para análisis, incluyendo estado ECH, proveedor, TLS, padding, y errores.
    """
    # Aseguramos que el directorio de salida exista antes de escribir el archivo CSV.
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    # Definimos campos clave para el CSV, seleccionando los más relevantes para análisis y filtrado posterior.
    fields = [
        "domain",
        "https_rr_present",
        "has_ech_param",
        "outer_sni",
        "provider",
        "tls_client_used",
        "ech_negotiation_status",
        "handshake_completed",
        "tls_connected",
        "client_hello_length",
        "padding_detected",
        "padding_profile",
        "ech_version",
        "kem_id",
        "hpke_suites",
        "ech_config_id",
        "public_key_length",
        "dns_error",
        "tls_error",
        "notes",
    ]

    # Guardamos el CSV con codificación UTF-8 y manejo adecuado de nuevas líneas, escribiendo una fila por dominio con los campos seleccionados.
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in resultados:
            data = asdict(row)
            data["hpke_suites"] = ";".join(data["hpke_suites"])
            writer.writerow(data)


def exportar_json(
    resultados: List[DominioECHResultado],
    provider_variability: Dict[str, Dict[str, Any]],
    json_path: Path,
    args: argparse.Namespace,
) -> None:
    """
    Guarda JSON estructurado con configuración, resumen y resultados detallados.
        Input: lista de resultados por dominio, estadísticas de variabilidad por proveedor, configuración de entrada.
        Output: archivo JSON con campos de metadata, resumen estadístico, variabilidad por proveedor, y lista completa de resultados por dominio con todos los campos.
    """
    # Aseguramos que el directorio de salida exista antes de escribir el archivo JSON.
    json_path.parent.mkdir(parents=True, exist_ok=True)

    # Construimos el payload JSON con estructura clara y campos detallados para cada resultado de dominio.
    payload = {
        "metadata": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "input_csv": str(args.input_csv),
            "max_dominios": args.max_dominios,
            "max_concurrency": args.max_concurrency,
            "dns_timeout": args.dns_timeout,
            "tls_timeout": args.tls_timeout,
            "tls_client_mode": args.tls_client,
        },
        "summary": {
            "total_dominios": len(resultados),
            "con_https_rr": sum(1 for r in resultados if r.https_rr_present),
            "con_ech": sum(1 for r in resultados if r.has_ech_param),
            "exito_outer_client_hello": sum(1 for r in resultados if r.ech_negotiation_status == STATUS_EXITO_OUTER_CH),
            "fallback_sni": sum(1 for r in resultados if r.ech_negotiation_status == STATUS_FALLBACK),
            "cliente_sin_soporte": sum(1 for r in resultados if r.ech_negotiation_status == STATUS_CLIENTE_SIN_SOPORTE),
            "errores_timeout_tls": sum(1 for r in resultados if r.ech_negotiation_status == STATUS_ERROR_TIMEOUT_TLS),
            "padding_detectado": sum(1 for r in resultados if r.padding_detected),
        },
        "provider_variability": provider_variability,
        "results": [asdict(r) for r in resultados], # Convertimos cada resultado de dominio a diccionario para JSON, manteniendo todos los campos detallados.
    }

    # Guardamos el JSON con indentación para legibilidad y sin escapar caracteres Unicode.
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def imprimir_resumen_consola(resultados: List[DominioECHResultado]) -> None:
    """
    Imprime un resumen corto y legible del estado final de la sonda.
        Input: lista de resultados por dominio con campos completos.
        Output: impresión formateada en consola con conteos y porcentajes de estados relevantes.
    """
    # Obtenemos conteos clave para el resumen
    total = len(resultados)
    con_https_rr = sum(1 for row in resultados if row.https_rr_present)
    con_ech = sum(1 for row in resultados if row.has_ech_param)
    handshake_completo = sum(1 for row in resultados if row.handshake_completed)
    clienthello_medido = sum(1 for row in resultados if row.client_hello_length is not None)
    padding_detectado = sum(1 for row in resultados if row.padding_detected)

    # Imprimimos resumen formateado
    print("\n--- Resumen rápido de la sonda ECH ---")
    print(f"Dominios procesados:      {total}")
    print(f"Con HTTPS RR:             {con_https_rr}")
    print(f"Con parámetro ECH:        {con_ech}")
    print(f"Handshake completado:     {handshake_completo}")
    print(f"ClientHello con longitud: {clienthello_medido}")
    print(f"Padding detectado:        {padding_detectado}")

    # Detalle de estados de negociación
    estados_principales = [
        STATUS_EXITO_OUTER_CH,
        STATUS_FALLBACK,
        STATUS_CLIENTE_SIN_SOPORTE,
        STATUS_ERROR_TIMEOUT_TLS,
        STATUS_FALLO_NEGOCIACION,
    ]
    print("Estado negociación (clave):")
    for estado in estados_principales:
        count = sum(1 for row in resultados if row.ech_negotiation_status == estado)
        print(f"- {estado}: {count}")


async def ejecutar_estudio(args: argparse.Namespace) -> int:
    """
    Coordina el estudio completo y exporta artefactos de salida.
        - Carga dominios desde CSV con validación.
        - Ejecuta tareas asíncronas para cada dominio con control de concurrencia.
        - Agrega manejo robusto de excepciones para evitar fallos globales.
        - Calcula estadísticas de variabilidad por proveedor.
        - Exporta resultados a CSV y JSON con estructura detallada.
        Input: argumentos de configuración desde CLI.
        Output: archivos CSV y JSON con resultados, y resumen en consola.
    """
    # Paso 1: Cargar dominios desde CSV con validación
    domains = cargar_dominios_csv(Path(args.input_csv), max_dominios=args.max_dominios)
    if not domains:
        print("No se encontraron dominios válidos en el CSV de entrada.")
        return 1

    # Paso 2: Configurar resolver DNS asíncrono y semáforo para control de concurrencia
    resolver = dns.asyncresolver.Resolver()
    semaphore = asyncio.Semaphore(args.max_concurrency)

    # Paso 3: Ejecutar tareas asíncronas para cada dominio
    tasks = [
        procesar_dominio(
            domain=domain,
            resolver=resolver,
            semaphore=semaphore,
            dns_timeout=args.dns_timeout,
            tls_timeout=args.tls_timeout,
            tls_mode=args.tls_client,
            bssl_path_override=args.bssl_path,
        )
        for domain in domains
    ]

    # Paso 4: Recopilar resultados con manejo robusto de excepciones para evitar fallos globales
    resultados: List[DominioECHResultado] = []
    for i, task in enumerate(asyncio.as_completed(tasks), start=1):
        try:
            resultados.append(await task)
        except Exception as exc:
            resultados.append(
                DominioECHResultado(
                    domain=f"<error_{i}>",
                    https_rr_present=False,
                    has_ech_param=False,
                    outer_sni=None,
                    provider="DESCONOCIDO",
                    tls_client_used="none",
                    ech_negotiation_status=STATUS_FALLO_NEGOCIACION,
                    handshake_completed=False,
                    tls_connected=False,
                    client_hello_length=None,
                    padding_detected=False,
                    padding_profile=None,
                    ech_version=None,
                    kem_id=None,
                    hpke_suites=[],
                    ech_config_id=None,
                    public_key_length=None,
                    dns_error=None,
                    tls_error=str(exc),
                    notes="Excepción no controlada durante procesamiento",
                )
            )

        if i % 100 == 0 or i == len(tasks):
            print(f"Progreso: {i}/{len(tasks)} dominios procesados")

    # Paso 5: Calcular estadísticas de variabilidad por proveedor
    provider_variability = calcular_variabilidad_por_proveedor(resultados)
    exportar_csv(resultados, Path(args.output_csv))
    exportar_json(resultados, provider_variability, Path(args.output_json), args)
    imprimir_resumen_consola(resultados)

    # Paso 6: Imprimir resumen en consola y finalizar
    print("\nEstudio ECH completado")
    print(f"- JSON: {args.output_json}")
    print(f"- CSV:  {args.output_csv}")
    return 0


def construir_parser() -> argparse.ArgumentParser:
    """
    Define CLI de la herramienta con valores por defecto prácticos.
    Permite configurar entrada, concurrencia, timeouts y cliente TLS para adaptarse a diferentes entornos de ejecución.
    """
    parser = argparse.ArgumentParser(description="Sonda de prevalencia ECH (TLS 1.3)")
    parser.add_argument("--input-csv", default="data/majestic_million.csv", help="CSV de entrada con dominios")
    parser.add_argument("--max-dominios", type=int, default=1000, help="Máximo de dominios a procesar")
    parser.add_argument("--max-concurrency", type=int, default=200, help="Concurrencia asyncio")
    parser.add_argument("--dns-timeout", type=float, default=4.0, help="Timeout DNS en segundos")
    parser.add_argument("--tls-timeout", type=float, default=8.0, help="Timeout TLS en segundos")
    parser.add_argument(
        "--tls-client",
        choices=["auto", "bssl", "openssl"],
        default="auto",
        help="Cliente TLS para simulación ECH",
    )
    parser.add_argument(
        "--bssl-path",
        default=None,
        help="Ruta explícita al binario bssl (opcional)",
    )
    parser.add_argument("--output-json", default=DEFAULT_JSON_OUTPUT, help="Ruta de salida JSON")
    parser.add_argument("--output-csv", default=DEFAULT_CSV_OUTPUT, help="Ruta de salida CSV")
    return parser


# Función principal para ejecución asíncrona del estudio completo
def main() -> int:
    parser = construir_parser()
    args = parser.parse_args()
    return asyncio.run(ejecutar_estudio(args))  # Ejecuta la función principal asíncrona


# Punto de entrada principal para ejecución directa
if __name__ == "__main__":
    raise SystemExit(main())
