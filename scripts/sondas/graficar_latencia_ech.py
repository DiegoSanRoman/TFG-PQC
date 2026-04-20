#!/usr/bin/env python3
"""
Genera una gráfica comparativa de latencia TLS con ECH vs sin ECH.
"""

import argparse
import logging
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

logger = logging.getLogger(__name__)

sns.set_style("whitegrid")
plt.rcParams["font.size"] = 11


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-csv",  default="resultados/resultados_latencia_ech.csv")
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
        df["latencia_con_ech_media_ms"].notna()
        & df["latencia_sin_ech_media_ms"].notna()
        & df["conexion_ech_exitosa"].eq(True)
        & df["conexion_sin_ech_exitosa"].eq(True)
    ].copy()
    logger.info("Hosts válidos: %d", len(df))

    data = pd.DataFrame({
        "Latencia (ms)": pd.concat(
            [df["latencia_con_ech_media_ms"], df["latencia_sin_ech_media_ms"]],
            ignore_index=True,
        ),
        "Modo": ["Con ECH"] * len(df) + ["Sin ECH"] * len(df),
    })

    mediana_ech = df["latencia_con_ech_media_ms"].median()
    mediana_sin = df["latencia_sin_ech_media_ms"].median()

    # Límite del eje Y: percentil 99 de ambas series para no aplastar por outliers
    p99 = max(
        df["latencia_con_ech_media_ms"].quantile(0.99),
        df["latencia_sin_ech_media_ms"].quantile(0.99),
    )
    y_max = p99 * 1.15

    fig, ax = plt.subplots(figsize=(8, 6))
    sns.boxplot(
        data=data, x="Modo", y="Latencia (ms)", hue="Modo",
        palette={"Con ECH": "#2ca02c", "Sin ECH": "#1f77b4"},
        legend=False, width=0.45,
        flierprops={"marker": ".", "alpha": 0.3, "markersize": 4},
        ax=ax,
    )
    ax.set_ylim(0, y_max)
    n_outliers = (data["Latencia (ms)"] > y_max).sum()
    ax.set_title(
        "Latencia TLS: Con ECH vs Sin ECH"
        + (f"\n(se omiten {n_outliers} outliers > {p99:.0f} ms)" if n_outliers else "")
    )
    ax.set_ylabel("Latencia media por host (ms)")
    ax.set_xlabel("")
    offset = y_max * 0.03
    ax.text(0, mediana_ech + offset, f"Mediana: {mediana_ech:.1f} ms",
            ha="center", va="bottom", fontsize=10, color="#2ca02c", fontweight="bold")
    ax.text(1, mediana_sin + offset, f"Mediana: {mediana_sin:.1f} ms",
            ha="center", va="bottom", fontsize=10, color="#1f77b4", fontweight="bold")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "latencia_ech_vs_sin_ech.png"
    fig.savefig(out_path, bbox_inches="tight", dpi=150)
    plt.close(fig)
    logger.info("Gráfica guardada: %s", out_path)


if __name__ == "__main__":
    main()
