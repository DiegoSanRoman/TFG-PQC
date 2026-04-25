"""
tls_utils.py
------------
Helpers de subproceso y parseo TLS compartidos entre las sondas de latencia
(sonda_latencia_ech y sonda_latencia_pqc).

Centralizar aquí evita que sonda_latencia_pqc importe funciones privadas de
sonda_latencia_ech, desacoplando los dos módulos.
"""
from __future__ import annotations

import asyncio
import statistics
from typing import List, Optional, Tuple


async def run_cmd(
    command: List[str],
    timeout: float,
    input_data: bytes = b"",
) -> Tuple[int, str, str]:
    """Ejecuta un subproceso con stdin=PIPE para que EOF cierre el proceso correctamente."""
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input_data), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        stdout, stderr = await proc.communicate()
        return 124, stdout.decode(errors="replace"), stderr.decode(errors="replace") + "\nTIMEOUT"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def parsear_bssl(stderr: str) -> Tuple[Optional[str], Optional[bool]]:
    """
    Extrae cipher suite y confirmación ECH del stderr de bssl.
    Devuelve (cipher, ech_aceptado).
    """
    cipher: Optional[str] = None
    ech_aceptado: Optional[bool] = None
    for line in stderr.splitlines():
        stripped = line.strip()
        if stripped.startswith("Cipher:"):
            cipher = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Encrypted ClientHello:"):
            val = stripped.split(":", 1)[1].strip().lower()
            ech_aceptado = val == "yes"
    return cipher, ech_aceptado


def extraer_error(stdout: str, stderr: str, rc: int) -> str:
    if rc == 124:
        return "TIMEOUT"
    lines = (stderr.strip() or stdout.strip()).splitlines()
    relevant = [l for l in lines if any(k in l.lower() for k in ("error", "fail", "alert", "reject", "unable"))]
    if relevant:
        return " | ".join(relevant[-3:])[:400]
    return " | ".join(lines[-3:])[:400] if lines else "HANDSHAKE_FALLIDO"


def agregar(latencias: List[float]) -> Tuple[Optional[float], Optional[float]]:
    """Calcula media y stddev de una lista de latencias."""
    if not latencias:
        return None, None
    media = round(statistics.mean(latencias), 2)
    stddev = round(statistics.stdev(latencias), 2) if len(latencias) > 1 else 0.0
    return media, stddev
