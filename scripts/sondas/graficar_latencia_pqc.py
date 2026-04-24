#!/usr/bin/env python3
"""
Genera una gráfica comparativa de latencia TLS PQC vs Clásico (X25519).
"""

import argparse
import logging
import sys
from pathlib import Path

import pandas as pd

_SONDAS_DIR = Path(__file__).resolve().parent
import sys as _sys
if str(_SONDAS_DIR) not in _sys.path:
    _sys.path.insert(0, str(_SONDAS_DIR))

from graficar_latencia_ech import plot_latencia_boxplot

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-csv",  default="resultados/resultados_latencia_pqc.csv")
    parser.add_argument("--output-dir", default="imagenes")
    parser.add_argument("--log-level",  default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    csv_path = Path(args.input_csv)
    if not csv_path.exists():
        logger.error("CSV no encontrado: %s", csv_path)
        sys.exit(1)

    df = pd.read_csv(csv_path)
    df = df[
        df["latencia_ech_pqc_media_ms"].notna()
        & df["latencia_sin_ech_pqc_media_ms"].notna()
        & df["conexion_ech_pqc_exitosa"].eq(True)
        & df["conexion_sin_ech_pqc_exitosa"].eq(True)
    ].copy()
    logger.info("Filas válidas: %d", len(df))

    plot_latencia_boxplot(
        df=df,
        col_a="latencia_ech_pqc_media_ms",
        col_b="latencia_sin_ech_pqc_media_ms",
        label_a="PQC con ECH",
        label_b="PQC sin ECH",
        colores={"PQC con ECH": "#2ca02c", "PQC sin ECH": "#9467bd"},
        titulo="Latencia TLS PQC: Con ECH vs Sin ECH",
        out_path=Path(args.output_dir) / "latencia_pqc_ech_vs_sin_ech.png",
    )


if __name__ == "__main__":
    main()
