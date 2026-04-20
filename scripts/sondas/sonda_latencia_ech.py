#!/usr/bin/env python3
"""
Sonda de latencia ECH: compara el tiempo de handshake TLS con y sin ECH.

Para cada hostname:
  1. Mide latencia DNS de la consulta HTTPS RR.
  2. Conecta N veces con ECH (bssl + ech-config-list) y recoge latencias.
  3. Si ECH tiene éxito, conecta N veces sin ECH (bssl sin config) y recoge latencias.
  4. Agrega media ± stddev, confirma si ECH fue realmente aceptado, y captura cipher suite.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import random
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import dns.asyncresolver
from tqdm import tqdm

_SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from utils import configurar_logging
from sondas.sonda_ech_prevalencia import (
    _decode_ech_base64,
    _split_host_port,
    cargar_dominios_csv,
    descubrir_https_rr,
    detectar_handshake_completo,
    resolver_cliente_tls,
)

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_CSV    = str(BASE_DIR / "data" / "hostnames_ech.csv")
DEFAULT_OUTPUT_CSV   = str(BASE_DIR / "resultados" / "resultados_latencia_ech.csv")
DEFAULT_LOG_FILE     = str(BASE_DIR / "resultados" / "sonda_latencia_ech.log")

DEFAULT_DNS_TIMEOUT   = 5.0
DEFAULT_TLS_TIMEOUT   = 10.0
DEFAULT_CONCURRENCY   = 10
DEFAULT_MAX_HOSTNAMES = 10_000
DEFAULT_REPETICIONES  = 3


@dataclass
class ResultadoLatenciaECH:
    hostname: str
    timestamp: str
    ech_config_disponible: bool
    conexion_ech_exitosa: bool
    conexion_sin_ech_exitosa: bool
    ech_aceptado: Optional[bool]
    cipher_con_ech: Optional[str]
    cipher_sin_ech: Optional[str]
    latencia_dns_ms: Optional[float]
    n_mediciones: int
    latencia_con_ech_media_ms: Optional[float]
    latencia_con_ech_stddev_ms: Optional[float]
    latencia_sin_ech_media_ms: Optional[float]
    latencia_sin_ech_stddev_ms: Optional[float]
    delta_medio_ms: Optional[float]
    cliente_tls: str
    outer_sni: Optional[str]
    error_ech: Optional[str]
    error_sin_ech: Optional[str]
    dns_error: Optional[str]


# ---------------------------------------------------------------------------
# Helpers de subproceso y parseo
# ---------------------------------------------------------------------------

async def _run_cmd(
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


def _parsear_bssl(stderr: str) -> Tuple[Optional[str], Optional[bool]]:
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


def _extraer_error(stdout: str, stderr: str, rc: int) -> str:
    if rc == 124:
        return "TIMEOUT"
    lines = (stderr.strip() or stdout.strip()).splitlines()
    relevant = [l for l in lines if any(k in l.lower() for k in ("error", "fail", "alert", "reject", "unable"))]
    if relevant:
        return " | ".join(relevant[-3:])[:400]
    return " | ".join(lines[-3:])[:400] if lines else "HANDSHAKE_FALLIDO"


# ---------------------------------------------------------------------------
# Mediciones TLS
# ---------------------------------------------------------------------------

async def _una_medicion_con_ech(
    domain: str,
    port: int,
    tmp_path: str,
    bssl_path: str,
    timeout: float,
) -> Tuple[bool, Optional[float], Optional[str], Optional[bool], Optional[str]]:
    """Una sola medición con ECH. Devuelve (ok, latencia_ms, error, ech_aceptado, cipher)."""
    cmd = [
        bssl_path, "client",
        "-connect", f"{domain}:{port}",
        "-server-name", domain,
        "-ech-config-list", tmp_path,
        "-debug",
    ]
    t0 = time.perf_counter()
    rc, stdout, stderr = await _run_cmd(cmd, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    combined = f"{stdout}\n{stderr}"
    ok = detectar_handshake_completo(combined, rc)
    if not ok:
        return False, None, _extraer_error(stdout, stderr, rc), None, None

    cipher, ech_aceptado = _parsear_bssl(stderr)
    return True, round(elapsed_ms, 2), None, ech_aceptado, cipher


async def _medir_con_ech(
    domain: str,
    port: int,
    ech_value: str,
    bssl_path: str,
    timeout: float,
    repeticiones: int,
) -> Tuple[bool, List[float], Optional[str], Optional[bool], Optional[str]]:
    """
    Realiza `repeticiones` mediciones con ECH.
    Devuelve (alguna_ok, latencias_validas, error_ultimo, ech_aceptado, cipher).
    """
    try:
        raw_ech = _decode_ech_base64(ech_value)
        tmp = tempfile.NamedTemporaryFile(prefix="ech_", suffix=".bin", delete=False)
        tmp.write(raw_ech)
        tmp.flush()
        tmp.close()
        tmp_path = tmp.name
    except Exception as exc:
        return False, [], f"ECH_DECODE_ERROR:{exc}", None, None

    latencias: List[float] = []
    ultimo_error: Optional[str] = None
    ech_aceptado: Optional[bool] = None
    cipher: Optional[str] = None

    try:
        for _ in range(repeticiones):
            ok, lat, err, ea, ci = await _una_medicion_con_ech(
                domain, port, tmp_path, bssl_path, timeout
            )
            if ok and lat is not None:
                latencias.append(lat)
                if ech_aceptado is None:
                    ech_aceptado = ea
                if cipher is None:
                    cipher = ci
            else:
                ultimo_error = err
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return bool(latencias), latencias, ultimo_error, ech_aceptado, cipher


async def _medir_sin_ech(
    domain: str,
    port: int,
    bssl_path: str,
    timeout: float,
    repeticiones: int,
) -> Tuple[bool, List[float], Optional[str], Optional[str]]:
    """
    Realiza `repeticiones` mediciones sin ECH (bssl sin config).
    Devuelve (alguna_ok, latencias_validas, error_ultimo, cipher).
    """
    cmd = [
        bssl_path, "client",
        "-connect", f"{domain}:{port}",
        "-server-name", domain,
        "-debug",
    ]

    latencias: List[float] = []
    ultimo_error: Optional[str] = None
    cipher: Optional[str] = None

    for _ in range(repeticiones):
        t0 = time.perf_counter()
        rc, stdout, stderr = await _run_cmd(cmd, timeout=timeout)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        combined = f"{stdout}\n{stderr}"
        ok = detectar_handshake_completo(combined, rc)
        if ok:
            latencias.append(round(elapsed_ms, 2))
            if cipher is None:
                cipher, _ = _parsear_bssl(stderr)
        else:
            ultimo_error = _extraer_error(stdout, stderr, rc)

    return bool(latencias), latencias, ultimo_error, cipher


def _agregar(latencias: List[float]) -> Tuple[Optional[float], Optional[float]]:
    """Calcula media y stddev de una lista de latencias."""
    if not latencias:
        return None, None
    media = round(statistics.mean(latencias), 2)
    stddev = round(statistics.pstdev(latencias), 2) if len(latencias) > 1 else 0.0
    return media, stddev


# ---------------------------------------------------------------------------
# Pipeline por hostname
# ---------------------------------------------------------------------------

async def procesar_hostname(
    hostname: str,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
    dns_timeout: float,
    tls_timeout: float,
    repeticiones: int,
) -> ResultadoLatenciaECH:
    ts = datetime.now(timezone.utc).isoformat()

    async with semaphore:
        domain, port = _split_host_port(hostname)

        # 1. Consulta DNS con medición de latencia
        t_dns = time.perf_counter()
        https_present, ech_value, parsed_configs, dns_error = await descubrir_https_rr(
            resolver=resolver,
            domain=domain,
            dns_timeout=dns_timeout,
        )
        latencia_dns_ms = round((time.perf_counter() - t_dns) * 1000, 2)

        outer_sni: Optional[str] = None
        if parsed_configs:
            outer_sni = parsed_configs[0].get("public_name")

        def _sin_ech_config(motivo: str) -> ResultadoLatenciaECH:
            return ResultadoLatenciaECH(
                hostname=hostname, timestamp=ts,
                ech_config_disponible=False,
                conexion_ech_exitosa=False, conexion_sin_ech_exitosa=False,
                ech_aceptado=None, cipher_con_ech=None, cipher_sin_ech=None,
                latencia_dns_ms=latencia_dns_ms, n_mediciones=0,
                latencia_con_ech_media_ms=None, latencia_con_ech_stddev_ms=None,
                latencia_sin_ech_media_ms=None, latencia_sin_ech_stddev_ms=None,
                delta_medio_ms=None, cliente_tls="none", outer_sni=outer_sni,
                error_ech=motivo, error_sin_ech=None, dns_error=dns_error,
            )

        if not https_present or not ech_value or not parsed_configs:
            if not https_present:
                motivo = "Sin HTTPS RR"
            elif not ech_value:
                motivo = "Sin parámetro ECH en HTTPS RR"
            else:
                motivo = dns_error if dns_error else "ECH_PARSE_ERROR"
            logger.info("Sin config ECH para %s: %s", hostname, motivo)
            return _sin_ech_config(motivo)

        _, bssl_path, _ = resolver_cliente_tls("bssl")
        if not bssl_path:
            logger.warning("bssl no disponible para %s", hostname)
            return _sin_ech_config("bssl no disponible")

        # 2+3. Mediciones con y sin ECH en orden aleatorio para evitar sesgo de calentamiento
        medir_ech_primero = random.random() < 0.5

        if medir_ech_primero:
            ech_ok, lats_ech, err_ech, ech_aceptado, cipher_ech = await _medir_con_ech(
                domain, port, ech_value, bssl_path, tls_timeout, repeticiones
            )
            sin_ech_ok, lats_sin_ech, err_sin_ech, cipher_sin_ech = await _medir_sin_ech(
                domain, port, bssl_path, tls_timeout, repeticiones
            )
        else:
            sin_ech_ok, lats_sin_ech, err_sin_ech, cipher_sin_ech = await _medir_sin_ech(
                domain, port, bssl_path, tls_timeout, repeticiones
            )
            ech_ok, lats_ech, err_ech, ech_aceptado, cipher_ech = await _medir_con_ech(
                domain, port, ech_value, bssl_path, tls_timeout, repeticiones
            )

        if not ech_ok:
            logger.debug("ECH fallido para %s: %s", hostname, err_ech)
            return ResultadoLatenciaECH(
                hostname=hostname, timestamp=ts,
                ech_config_disponible=True,
                conexion_ech_exitosa=False, conexion_sin_ech_exitosa=sin_ech_ok,
                ech_aceptado=None, cipher_con_ech=None, cipher_sin_ech=cipher_sin_ech,
                latencia_dns_ms=latencia_dns_ms, n_mediciones=len(lats_sin_ech),
                latencia_con_ech_media_ms=None, latencia_con_ech_stddev_ms=None,
                latencia_sin_ech_media_ms=_agregar(lats_sin_ech)[0],
                latencia_sin_ech_stddev_ms=_agregar(lats_sin_ech)[1],
                delta_medio_ms=None, cliente_tls="bssl", outer_sni=outer_sni,
                error_ech=err_ech, error_sin_ech=err_sin_ech, dns_error=dns_error,
            )

        media_ech, stddev_ech       = _agregar(lats_ech)
        media_sin_ech, stddev_sin_ech = _agregar(lats_sin_ech)

        delta: Optional[float] = None
        if media_ech is not None and media_sin_ech is not None:
            delta = round(media_sin_ech - media_ech, 2)

        n = max(len(lats_ech), len(lats_sin_ech))

        return ResultadoLatenciaECH(
            hostname=hostname, timestamp=ts,
            ech_config_disponible=True,
            conexion_ech_exitosa=(ech_aceptado is True), conexion_sin_ech_exitosa=sin_ech_ok,
            ech_aceptado=ech_aceptado,
            cipher_con_ech=cipher_ech, cipher_sin_ech=cipher_sin_ech,
            latencia_dns_ms=latencia_dns_ms, n_mediciones=n,
            latencia_con_ech_media_ms=media_ech, latencia_con_ech_stddev_ms=stddev_ech,
            latencia_sin_ech_media_ms=media_sin_ech, latencia_sin_ech_stddev_ms=stddev_sin_ech,
            delta_medio_ms=delta, cliente_tls="bssl", outer_sni=outer_sni,
            error_ech=None, error_sin_ech=err_sin_ech, dns_error=dns_error,
        )


# ---------------------------------------------------------------------------
# Exportación y resumen
# ---------------------------------------------------------------------------

def exportar_csv(resultados: List[ResultadoLatenciaECH], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(ResultadoLatenciaECH.__dataclass_fields__.keys())
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for r in resultados:
            writer.writerow(asdict(r))


def imprimir_resumen(resultados: List[ResultadoLatenciaECH]) -> None:
    total     = len(resultados)
    con_ech   = sum(1 for r in resultados if r.ech_config_disponible)
    ech_ok    = sum(1 for r in resultados if r.conexion_ech_exitosa)
    ech_conf  = sum(1 for r in resultados if r.ech_aceptado is True)
    sin_ok    = sum(1 for r in resultados if r.conexion_sin_ech_exitosa)
    deltas    = [r.delta_medio_ms for r in resultados if r.delta_medio_ms is not None]

    print(f"\n--- Resultados latencia ECH ---")
    print(f"Hostnames procesados:            {total}")
    print(f"Con configuración ECH:           {con_ech}")
    print(f"Conexión ECH exitosa:            {ech_ok}")
    print(f"ECH confirmado por servidor:     {ech_conf}")
    print(f"Conexión sin ECH exitosa:        {sin_ok}")

    if deltas:
        avg = round(sum(deltas) / len(deltas), 2)
        print(f"Delta medio (noECH-ECH) ms:      {avg}  (n={len(deltas)})")
        print(f"  min={min(deltas)} ms  max={max(deltas)} ms")

    print("\nDetalle por hostname:")
    for r in sorted(resultados, key=lambda x: x.hostname):
        if r.conexion_ech_exitosa:
            ech_str = f"{r.latencia_con_ech_media_ms}±{r.latencia_con_ech_stddev_ms} ms"
            if r.conexion_sin_ech_exitosa:
                sin_str = f"{r.latencia_sin_ech_media_ms}±{r.latencia_sin_ech_stddev_ms} ms"
            else:
                sin_str = f"FALLIDO({r.error_sin_ech})"
            conf = "✓" if r.ech_aceptado else ("✗" if r.ech_aceptado is False else "?")
            print(
                f"  {r.hostname:<32} ECH={ech_str}  noECH={sin_str}"
                f"  delta={r.delta_medio_ms} ms  ECH_conf={conf}"
                f"  cipher={r.cipher_con_ech or '?'}"
            )
        else:
            motivo = r.error_ech or r.dns_error or "desconocido"
            print(f"  {r.hostname:<32} ECH FALLIDO: {motivo}")


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

def _preflight() -> Optional[str]:
    _, bssl_path, _ = resolver_cliente_tls("bssl")
    print("Diagnóstico de herramientas TLS:")
    print(f"  bssl:    {bssl_path or 'NO ENCONTRADO ← conexiones fallarán'}")
    print(f"  Python:  {sys.executable}")
    print()
    return bssl_path


async def ejecutar(args: argparse.Namespace) -> int:
    configurar_logging(Path(args.log_file), args.log_level)

    bssl_path = _preflight()
    if not bssl_path:
        print("ERROR: bssl no encontrado.")
        print(f"  Ruta buscada: {Path(__file__).resolve().parents[2] / 'tools' / 'boringssl' / 'build' / 'bssl'}")
        return 1

    hostnames = cargar_dominios_csv(Path(args.input_csv), max_dominios=args.max_hostnames)
    if not hostnames:
        print("No se encontraron hostnames válidos en el CSV de entrada.")
        return 1

    logger.info("Cargados %d hostnames desde %s (repeticiones=%d)", len(hostnames), args.input_csv, args.repeticiones)

    resolver = dns.asyncresolver.Resolver()
    semaphore = asyncio.Semaphore(args.concurrency)

    tasks = [
        procesar_hostname(
            hostname=h,
            resolver=resolver,
            semaphore=semaphore,
            dns_timeout=args.dns_timeout,
            tls_timeout=args.tls_timeout,
            repeticiones=args.repeticiones,
        )
        for h in hostnames
    ]

    resultados: List[ResultadoLatenciaECH] = []
    with tqdm(total=len(tasks), desc="Latencia ECH", unit="host") as pbar:
        for coro in asyncio.as_completed(tasks):
            r = await coro
            resultados.append(r)
            estado = "ECH ✓" if r.ech_aceptado else ("ECH OK" if r.conexion_ech_exitosa else "sin ECH")
            pbar.set_postfix(host=r.hostname[:26], estado=estado)
            pbar.update(1)

    exportar_csv(resultados, Path(args.output_csv))
    imprimir_resumen(resultados)
    print(f"\nCSV guardado en: {args.output_csv}")
    logger.info("Sonda finalizada. CSV: %s", args.output_csv)
    return 0


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Sonda de latencia ECH: con vs sin ECH")
    p.add_argument("--input-csv",      default=DEFAULT_INPUT_CSV,    help="CSV de hostnames de entrada")
    p.add_argument("--output-csv",     default=DEFAULT_OUTPUT_CSV,   help="CSV de resultados de salida")
    p.add_argument("--log-file",       default=DEFAULT_LOG_FILE,     help="Ruta del archivo de log")
    p.add_argument("--log-level",      default="INFO",               help="DEBUG, INFO, WARNING, ERROR")
    p.add_argument("--dns-timeout",    type=float, default=DEFAULT_DNS_TIMEOUT)
    p.add_argument("--tls-timeout",    type=float, default=DEFAULT_TLS_TIMEOUT)
    p.add_argument("--concurrency",    type=int,   default=DEFAULT_CONCURRENCY)
    p.add_argument("--max-hostnames",  type=int,   default=DEFAULT_MAX_HOSTNAMES)
    p.add_argument("--repeticiones",   type=int,   default=DEFAULT_REPETICIONES,
                   help="Número de mediciones por hostname para calcular media/stddev (default: 3)")
    return p


def main() -> int:
    args = construir_parser().parse_args()
    return asyncio.run(ejecutar(args))


if __name__ == "__main__":
    raise SystemExit(main())
