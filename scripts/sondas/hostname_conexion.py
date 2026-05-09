#!/usr/bin/env python3
"""
hostname_conexion.py
--------------------
Herramienta de diagnóstico para probar la conexión TLS con un hostname concreto
y un grupo PQC específico. Útil para depurar fallos en la sonda principal sin
tener que lanzar el pipeline completo.

Uso rápido:
    python3 scripts/sondas/hostname_conexion.py --hostname cloudflare.com
    python3 scripts/sondas/hostname_conexion.py --hostname pq.cloudflareresearch.com --grupo X25519MLKEM768
    python3 scripts/sondas/hostname_conexion.py --hostname example.com --grupo mlkem768 --verbose
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from sondas.sonda_pqc_final import sonda_pqc

GRUPOS_DISPONIBLES = [
    "X25519",
    "X25519MLKEM768",
    "x25519_kyber768",
    "mlkem768",
    "kyber768",
    "p256_kyber768",
    "SecP256r1MLKEM768",
    "x25519_mlkem512",
    "x25519_kyber512",
    "frodo640aes",
    "bikel1",
    "x25519_bikel1",
    "x25519_hqc128",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Diagnóstico de conexión TLS PQC para un hostname concreto"
    )
    parser.add_argument("--hostname", required=True, help="Hostname a probar (ej. cloudflare.com)")
    parser.add_argument(
        "--grupo", default="X25519MLKEM768",
        choices=GRUPOS_DISPONIBLES,
        help="Grupo PQC a negociar (default: X25519MLKEM768)",
    )
    parser.add_argument(
        "--todos", action="store_true",
        help="Probar todos los grupos disponibles secuencialmente",
    )
    parser.add_argument("--verbose", action="store_true", help="Mostrar todos los campos del resultado")
    args = parser.parse_args()

    grupos = GRUPOS_DISPONIBLES if args.todos else [args.grupo]

    print(f"\nDiagnóstico TLS PQC → {args.hostname}")
    print("=" * 60)

    for grupo in grupos:
        resultado = sonda_pqc(args.hostname, grupo)
        estado = resultado.get("connection_result", "?")
        error = resultado.get("error_category") or resultado.get("tls_alert") or ""
        hs_ms = resultado.get("openssl_subprocess_time_ms")
        cipher = resultado.get("cipher_suite", "?")
        ip = resultado.get("ip", "?")

        tiempo_str = f"{hs_ms:.1f} ms" if hs_ms is not None else "—"
        error_str = f"  [{error}]" if error else ""
        print(f"  {grupo:<26} {estado:<12} {tiempo_str:>9}  cipher={cipher}  ip={ip}{error_str}")

        if args.verbose:
            for k, v in sorted(resultado.items()):
                if v is not None and v != "" and k not in ("grupo",):
                    print(f"      {k}: {v}")
            print()

    print()


if __name__ == "__main__":
    main()
