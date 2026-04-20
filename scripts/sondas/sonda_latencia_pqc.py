#!/usr/bin/env python3
"""
Sonda de latencia PQC: compara el tiempo de handshake TLS para múltiples grupos
post-cuánticos frente al grupo clásico X25519, con y sin ECH cuando es posible.

Para cada hostname con config ECH y para cada grupo PQC:
  1. Mide latencia DNS de la consulta HTTPS RR.
  2. Si el grupo lo soporta bssl (-curves): N mediciones con ECH + PQC.
  3. N mediciones sin ECH + PQC (bssl o OpenSSL OQS según el grupo).
  4. N mediciones sin ECH + X25519 clásico (baseline con bssl).
  5. Agrega media ± stddev y calcula deltas entre escenarios.

Genera una fila CSV por (hostname × grupo_pqc).

Backends:
  - bssl: grupos X25519Kyber768Draft00 y X25519MLKEM768 → soporta ECH.
  - OpenSSL OQS (/opt/openssl/bin/openssl): resto de grupos → sin ECH.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, asdict, fields as dc_fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
from sondas.sonda_latencia_ech import (
    _run_cmd,
    _parsear_bssl,
    _extraer_error,
    _agregar,
)

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_CSV   = str(BASE_DIR / "data" / "hostnames_ech.csv")
DEFAULT_OUTPUT_CSV  = str(BASE_DIR / "resultados" / "resultados_latencia_pqc.csv")
DEFAULT_LOG_FILE    = str(BASE_DIR / "resultados" / "sonda_latencia_pqc.log")

DEFAULT_DNS_TIMEOUT   = 5.0
DEFAULT_TLS_TIMEOUT   = 10.0
DEFAULT_CONCURRENCY   = 5
DEFAULT_MAX_HOSTNAMES = 10_000
DEFAULT_REPETICIONES  = 3

# Traducción de nombre de grupo → nombre de curva para bssl -curves.
# Grupos NO presentes en este mapa se miden con OpenSSL OQS (sin ECH).
BSSL_CURVE_MAP: Dict[str, str] = {
    "X25519Kyber768Draft00": "X25519Kyber768Draft00",
    "x25519_kyber768":       "X25519Kyber768Draft00",  # mismo algoritmo, nombre OQS
    "X25519MLKEM768":        "X25519MLKEM768",
}

# Lista completa de grupos PQC a probar por defecto
DEFAULT_GRUPOS_PQC: List[str] = [
    "X25519Kyber768Draft00",   # bssl: híbrido draft (≡ x25519_kyber768)
    "X25519MLKEM768",          # bssl: estándar NIST híbrido
    "mlkem768",                # OQS: puro moderno (ML-KEM-768)
    "kyber768",                # OQS: puro previo (Kyber768)
    "SecP256r1MLKEM768",       # OQS: híbrido P-256 + ML-KEM-768
    "x25519_mlkem512",         # OQS: híbrido nivel 1 moderno
    "x25519_kyber512",         # OQS: híbrido nivel 1 previo
    "x25519_bikel1",           # OQS: híbrido BIKE nivel 1
    "x25519_hqc128",           # OQS: híbrido HQC nivel 1
]

DEFAULT_OQS_BIN = "/opt/openssl/bin/openssl"


@dataclass
class ResultadoLatenciaPQC:
    hostname: str
    timestamp: str
    grupo_pqc: str
    cliente_pqc: str            # "bssl" o "openssl_oqs"
    ech_config_disponible: bool
    ech_soportado_por_grupo: bool  # True solo si cliente_pqc == "bssl"
    # ECH + PQC (solo disponible cuando cliente_pqc == "bssl")
    conexion_ech_pqc_exitosa: bool
    latencia_ech_pqc_media_ms: Optional[float]
    latencia_ech_pqc_stddev_ms: Optional[float]
    ech_aceptado_pqc: Optional[bool]
    cipher_ech_pqc: Optional[str]
    error_ech_pqc: Optional[str]
    # Sin ECH + PQC
    conexion_sin_ech_pqc_exitosa: bool
    latencia_sin_ech_pqc_media_ms: Optional[float]
    latencia_sin_ech_pqc_stddev_ms: Optional[float]
    cipher_sin_ech_pqc: Optional[str]
    error_sin_ech_pqc: Optional[str]
    # Deltas
    delta_ech_pqc_ms: Optional[float]       # noECH_pqc − ECH_pqc  (solo si bssl)
    n_mediciones: int
    latencia_dns_ms: Optional[float]
    outer_sni: Optional[str]
    dns_error: Optional[str]


# ---------------------------------------------------------------------------
# Mediciones TLS
# ---------------------------------------------------------------------------

async def _una_medicion_bssl(
    domain: str,
    port: int,
    bssl_path: str,
    timeout: float,
    curvas: Optional[str] = None,
    ech_tmp_path: Optional[str] = None,
) -> Tuple[bool, Optional[float], Optional[str], Optional[bool], Optional[str]]:
    """Una medición con bssl. Devuelve (ok, latencia_ms, error, ech_aceptado, cipher)."""
    cmd = [
        bssl_path, "client",
        "-connect", f"{domain}:{port}",
        "-server-name", domain,
        "-debug",
    ]
    if ech_tmp_path:
        cmd += ["-ech-config-list", ech_tmp_path]
    if curvas:
        cmd += ["-curves", curvas]

    t0 = time.perf_counter()
    rc, stdout, stderr = await _run_cmd(cmd, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    combined = f"{stdout}\n{stderr}"
    ok = detectar_handshake_completo(combined, rc)
    if not ok:
        return False, None, _extraer_error(stdout, stderr, rc), None, None

    cipher, ech_aceptado = _parsear_bssl(stderr)
    return True, round(elapsed_ms, 2), None, ech_aceptado, cipher


async def _una_medicion_oqs(
    domain: str,
    port: int,
    oqs_bin: str,
    grupo: str,
    timeout: float,
) -> Tuple[bool, Optional[float], Optional[str], Optional[str]]:
    """Una medición con OpenSSL OQS. Devuelve (ok, latencia_ms, error, cipher)."""
    cmd = [
        oqs_bin, "s_client",
        "-connect", f"{domain}:{port}",
        "-servername", domain,
        "-tls1_3",
        "-groups", grupo,
        "-provider", "oqsprovider",
        "-provider", "default",
    ]
    try:
        t0 = time.perf_counter()
        rc, stdout, stderr = await _run_cmd(cmd, timeout=timeout)
        elapsed_ms = (time.perf_counter() - t0) * 1000
    except FileNotFoundError:
        return False, None, f"OQS_BIN_NOT_FOUND:{oqs_bin}", None

    combined = f"{stdout}\n{stderr}"

    # OQS openssl s_client: éxito si hay cipher negociado y return code 0 o 1
    # (s_client suele devolver 1 al cerrar el stdin; lo tratamos igual que 0)
    import re
    cipher_match = re.search(r"^\s*Cipher\s*:\s*(.+)$", stdout, re.MULTILINE)
    cipher = cipher_match.group(1).strip() if cipher_match else None
    handshake_ok = cipher and "(NONE)" not in cipher and rc in (0, 1)

    if not handshake_ok:
        return False, None, _extraer_error(stdout, stderr, rc), None

    return True, round(elapsed_ms, 2), None, cipher


async def _medir_bssl(
    domain: str,
    port: int,
    bssl_path: str,
    timeout: float,
    repeticiones: int,
    curvas: Optional[str],
    ech_value: Optional[str] = None,
) -> Tuple[bool, List[float], Optional[str], Optional[bool], Optional[str]]:
    """
    N mediciones con bssl. Si ech_value se proporciona, activa ECH.
    Devuelve (alguna_ok, latencias, error_ultimo, ech_aceptado, cipher).
    """
    tmp_path: Optional[str] = None
    if ech_value:
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
            ok, lat, err, ea, ci = await _una_medicion_bssl(
                domain, port, bssl_path, timeout,
                curvas=curvas, ech_tmp_path=tmp_path,
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
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)

    return bool(latencias), latencias, ultimo_error, ech_aceptado, cipher


async def _medir_oqs(
    domain: str,
    port: int,
    oqs_bin: str,
    grupo: str,
    timeout: float,
    repeticiones: int,
) -> Tuple[bool, List[float], Optional[str], Optional[str]]:
    """N mediciones con OpenSSL OQS. Devuelve (alguna_ok, latencias, error_ultimo, cipher)."""
    latencias: List[float] = []
    ultimo_error: Optional[str] = None
    cipher: Optional[str] = None

    for _ in range(repeticiones):
        ok, lat, err, ci = await _una_medicion_oqs(domain, port, oqs_bin, grupo, timeout)
        if ok and lat is not None:
            latencias.append(lat)
            if cipher is None:
                cipher = ci
        else:
            ultimo_error = err

    return bool(latencias), latencias, ultimo_error, cipher


# ---------------------------------------------------------------------------
# Pipeline por hostname × grupo
# ---------------------------------------------------------------------------

async def procesar_hostname_grupo(
    hostname: str,
    grupo_pqc: str,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
    dns_timeout: float,
    tls_timeout: float,
    repeticiones: int,
    bssl_path: str,
    oqs_bin: str,
    # Resultado DNS/ECH precalculado para no repetir por cada grupo
    https_present: bool,
    ech_value: Optional[str],
    parsed_configs: Optional[list],
    dns_error: Optional[str],
    latencia_dns_ms: float,
) -> ResultadoLatenciaPQC:
    ts = datetime.now(timezone.utc).isoformat()

    outer_sni: Optional[str] = None
    if parsed_configs:
        outer_sni = parsed_configs[0].get("public_name")

    bssl_curve = BSSL_CURVE_MAP.get(grupo_pqc)
    cliente_pqc = "bssl" if bssl_curve else "openssl_oqs"
    ech_soportado = bssl_curve is not None

    # Determinar si ECH está disponible para este hostname
    ech_disponible = bool(https_present and ech_value and parsed_configs)
    if not ech_disponible:
        motivo_sin_ech = "Sin HTTPS RR" if not https_present else "Sin parámetro ECH en HTTPS RR"
    else:
        motivo_sin_ech = None

    domain, port = _split_host_port(hostname)

    async with semaphore:
        # --- Medición sin ECH + PQC (siempre, independientemente de si hay ECH) ---
        if bssl_curve:
            ok_sin_ech_pqc, lats_sin_ech_pqc, err_sin_ech_pqc, _, ci_sin_ech_pqc = \
                await _medir_bssl(domain, port, bssl_path, tls_timeout, repeticiones,
                                  curvas=bssl_curve, ech_value=None)
        else:
            ok_sin_ech_pqc, lats_sin_ech_pqc, err_sin_ech_pqc, ci_sin_ech_pqc = \
                await _medir_oqs(domain, port, oqs_bin, grupo_pqc, tls_timeout, repeticiones)

        # --- Medición con ECH + PQC (solo si bssl soporta el grupo Y hay config ECH) ---
        ok_ech_pqc: bool = False
        lats_ech_pqc: List[float] = []
        err_ech_pqc: Optional[str] = motivo_sin_ech  # None si hay ECH, motivo si no
        ea_pqc: Optional[bool] = None
        ci_ech_pqc: Optional[str] = None

        if bssl_curve and ech_disponible:
            ok_ech_pqc, lats_ech_pqc, err_ech_pqc, ea_pqc, ci_ech_pqc = \
                await _medir_bssl(domain, port, bssl_path, tls_timeout, repeticiones,
                                  curvas=bssl_curve, ech_value=ech_value)
        elif bssl_curve and not ech_disponible:
            pass  # err_ech_pqc ya tiene el motivo

    media_ech_pqc,     stddev_ech_pqc     = _agregar(lats_ech_pqc)
    media_sin_ech_pqc, stddev_sin_ech_pqc = _agregar(lats_sin_ech_pqc)

    delta_ech_pqc: Optional[float] = None
    if media_ech_pqc is not None and media_sin_ech_pqc is not None:
        delta_ech_pqc = round(media_sin_ech_pqc - media_ech_pqc, 2)

    n = max(len(lats_ech_pqc), len(lats_sin_ech_pqc))

    return ResultadoLatenciaPQC(
        hostname=hostname, timestamp=ts,
        grupo_pqc=grupo_pqc, cliente_pqc=cliente_pqc,
        ech_config_disponible=ech_disponible, ech_soportado_por_grupo=ech_soportado,
        conexion_ech_pqc_exitosa=ok_ech_pqc,
        latencia_ech_pqc_media_ms=media_ech_pqc, latencia_ech_pqc_stddev_ms=stddev_ech_pqc,
        ech_aceptado_pqc=ea_pqc, cipher_ech_pqc=ci_ech_pqc, error_ech_pqc=err_ech_pqc,
        conexion_sin_ech_pqc_exitosa=ok_sin_ech_pqc,
        latencia_sin_ech_pqc_media_ms=media_sin_ech_pqc, latencia_sin_ech_pqc_stddev_ms=stddev_sin_ech_pqc,
        cipher_sin_ech_pqc=ci_sin_ech_pqc, error_sin_ech_pqc=err_sin_ech_pqc,
        delta_ech_pqc_ms=delta_ech_pqc,
        n_mediciones=n, latencia_dns_ms=latencia_dns_ms,
        outer_sni=outer_sni, dns_error=dns_error,
    )


async def procesar_hostname(
    hostname: str,
    grupos_pqc: List[str],
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
    dns_timeout: float,
    tls_timeout: float,
    repeticiones: int,
    bssl_path: str,
    oqs_bin: str,
) -> List[ResultadoLatenciaPQC]:
    """Procesa un hostname para todos los grupos PQC. Devuelve una lista de resultados."""
    domain, _ = _split_host_port(hostname)

    # 1. DNS bajo el semáforo: evita saturar el resolver con consultas
    # simultáneas de todos los hosts (problema observado sin semáforo).
    async with semaphore:
        t_dns = time.perf_counter()
        https_present, ech_value, parsed_configs, dns_error = await descubrir_https_rr(
            resolver=resolver, domain=domain, dns_timeout=dns_timeout,
        )
        latencia_dns_ms = round((time.perf_counter() - t_dns) * 1000, 2)

    # 2. Una fila por grupo PQC
    resultados = []
    for grupo in grupos_pqc:
        r = await procesar_hostname_grupo(
            hostname=hostname, grupo_pqc=grupo,
            resolver=resolver, semaphore=semaphore,
            dns_timeout=dns_timeout, tls_timeout=tls_timeout,
            repeticiones=repeticiones,
            bssl_path=bssl_path, oqs_bin=oqs_bin,
            https_present=https_present, ech_value=ech_value,
            parsed_configs=parsed_configs, dns_error=dns_error,
            latencia_dns_ms=latencia_dns_ms,
        )
        resultados.append(r)

    return resultados


# ---------------------------------------------------------------------------
# Exportación y resumen
# ---------------------------------------------------------------------------

def exportar_csv(resultados: List[ResultadoLatenciaPQC], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    field_names = [f.name for f in dc_fields(ResultadoLatenciaPQC)]
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=field_names)
        writer.writeheader()
        for r in resultados:
            writer.writerow(asdict(r))


def imprimir_resumen(resultados: List[ResultadoLatenciaPQC], grupos: List[str]) -> None:
    total = len(resultados)
    print(f"\n--- Resultados latencia PQC ({total} filas, {total // max(len(grupos), 1)} hosts) ---")

    for grupo in grupos:
        filas_g = [r for r in resultados if r.grupo_pqc == grupo]
        if not filas_g:
            continue

        ech_ok   = sum(1 for r in filas_g if r.conexion_ech_pqc_exitosa)
        pqc_ok   = sum(1 for r in filas_g if r.conexion_sin_ech_pqc_exitosa)
        d_ech    = [r.delta_ech_pqc_ms for r in filas_g if r.delta_ech_pqc_ms is not None]

        cliente = filas_g[0].cliente_pqc if filas_g else "?"
        print(f"\n  [{grupo}] ({cliente})")
        print(f"    Hosts con noECH+PQC exitoso:  {pqc_ok}/{len(filas_g)}")
        if any(r.ech_soportado_por_grupo for r in filas_g):
            print(f"    Hosts con ECH+PQC exitoso:    {ech_ok}/{len(filas_g)}")
            if d_ech:
                avg = round(sum(d_ech) / len(d_ech), 2)
                print(f"    δ(noECH−ECH) medio:           {avg} ms  (n={len(d_ech)}, min={min(d_ech)}, max={max(d_ech)})")
        else:
            print(f"    ECH: no soportado por este grupo (OQS-only)")


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

def _preflight(oqs_bin: str) -> Optional[str]:
    _, bssl_path, _ = resolver_cliente_tls("bssl")
    oqs_ok = Path(oqs_bin).is_file()
    print("Diagnóstico de herramientas TLS:")
    print(f"  bssl:         {bssl_path or 'NO ENCONTRADO ← grupos bssl fallarán'}")
    print(f"  OpenSSL OQS:  {oqs_bin if oqs_ok else oqs_bin + ' ← NO ENCONTRADO, grupos OQS fallarán'}")
    print(f"  Python:       {sys.executable}")
    print()
    return bssl_path


async def ejecutar(args: argparse.Namespace) -> int:
    configurar_logging(Path(args.log_file), args.log_level)

    grupos_pqc: List[str] = args.grupos_pqc if args.grupos_pqc else DEFAULT_GRUPOS_PQC

    bssl_path = _preflight(args.oqs_bin)
    if not bssl_path:
        print("ERROR: bssl no encontrado.")
        print(f"  Ruta buscada: {Path(__file__).resolve().parents[2] / 'tools' / 'boringssl' / 'build' / 'bssl'}")
        return 1

    hostnames = cargar_dominios_csv(Path(args.input_csv), max_dominios=args.max_hostnames)
    if not hostnames:
        print("No se encontraron hostnames válidos en el CSV de entrada.")
        return 1

    oqs_disponible = Path(args.oqs_bin).is_file()
    grupos_bssl = [g for g in grupos_pqc if g in BSSL_CURVE_MAP]
    grupos_oqs  = [g for g in grupos_pqc if g not in BSSL_CURVE_MAP]

    if grupos_oqs and not oqs_disponible:
        print(f"AVISO: OpenSSL OQS no encontrado en '{args.oqs_bin}'.")
        print(f"  Se omitirán los {len(grupos_oqs)} grupos OQS: {grupos_oqs}")
        print(f"  Solo se medirán los grupos bssl: {grupos_bssl}")
        print()
        grupos_pqc = grupos_bssl

    if not grupos_pqc:
        print("ERROR: no hay grupos a probar (ni bssl ni OQS disponibles).")
        return 1

    logger.info(
        "Cargados %d hostnames, %d grupos (%d bssl, %d OQS), repeticiones=%d",
        len(hostnames), len(grupos_pqc), len(grupos_bssl), len(grupos_oqs), args.repeticiones,
    )
    logger.info("Grupos bssl (con ECH): %s", grupos_bssl)
    if oqs_disponible:
        logger.info("Grupos OQS (sin ECH): %s", grupos_oqs)
    else:
        logger.warning("OpenSSL OQS no disponible, grupos OQS omitidos: %s", grupos_oqs)

    resolver = dns.asyncresolver.Resolver()
    semaphore = asyncio.Semaphore(args.concurrency)

    tasks = [
        procesar_hostname(
            hostname=h,
            grupos_pqc=grupos_pqc,
            resolver=resolver,
            semaphore=semaphore,
            dns_timeout=args.dns_timeout,
            tls_timeout=args.tls_timeout,
            repeticiones=args.repeticiones,
            bssl_path=bssl_path,
            oqs_bin=args.oqs_bin,
        )
        for h in hostnames
    ]

    todos: List[ResultadoLatenciaPQC] = []
    with tqdm(total=len(tasks), desc="Latencia PQC", unit="host") as pbar:
        for coro in asyncio.as_completed(tasks):
            filas = await coro
            todos.extend(filas)
            if filas:
                r0 = filas[0]
                exitos = sum(1 for r in filas if r.conexion_sin_ech_pqc_exitosa)
                pbar.set_postfix(host=r0.hostname[:22], pqc_ok=f"{exitos}/{len(filas)}")
            pbar.update(1)

    exportar_csv(todos, Path(args.output_csv))
    imprimir_resumen(todos, grupos_pqc)
    print(f"\nCSV guardado en: {args.output_csv}  ({len(todos)} filas)")
    logger.info("Sonda finalizada. CSV: %s  (%d filas)", args.output_csv, len(todos))
    return 0


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Sonda de latencia PQC: múltiples grupos vs clásico, con/sin ECH"
    )
    p.add_argument("--input-csv",     default=DEFAULT_INPUT_CSV,  help="CSV de hostnames de entrada")
    p.add_argument("--output-csv",    default=DEFAULT_OUTPUT_CSV, help="CSV de resultados de salida")
    p.add_argument("--log-file",      default=DEFAULT_LOG_FILE,   help="Ruta del archivo de log")
    p.add_argument("--log-level",     default="INFO",             help="DEBUG, INFO, WARNING, ERROR")
    p.add_argument("--dns-timeout",   type=float, default=DEFAULT_DNS_TIMEOUT)
    p.add_argument("--tls-timeout",   type=float, default=DEFAULT_TLS_TIMEOUT)
    p.add_argument("--concurrency",   type=int,   default=DEFAULT_CONCURRENCY)
    p.add_argument("--max-hostnames", type=int,   default=DEFAULT_MAX_HOSTNAMES)
    p.add_argument("--repeticiones",  type=int,   default=DEFAULT_REPETICIONES,
                   help="Mediciones por combinación para calcular media/stddev (default: 3)")
    p.add_argument("--oqs-bin",       default=DEFAULT_OQS_BIN,
                   help=f"Ruta al binario OpenSSL con soporte OQS (default: {DEFAULT_OQS_BIN})")
    p.add_argument("--grupos-pqc",    nargs="+", default=None, metavar="GRUPO",
                   help="Grupos PQC a probar (default: lista completa predefinida)")
    return p


def main() -> int:
    args = construir_parser().parse_args()
    return asyncio.run(ejecutar(args))


if __name__ == "__main__":
    raise SystemExit(main())
