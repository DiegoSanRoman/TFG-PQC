#!/usr/bin/env python3
"""
Genera una gráfica comparativa de latencia TLS con ECH vs sin ECH.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

logger = logging.getLogger(__name__)

sns.set_style("whitegrid")
plt.rcParams["font.size"] = 11


def plot_latencia_boxplot(
    df: pd.DataFrame,
    col_a: str,
    col_b: str,
    label_a: str,
    label_b: str,
    colores: Dict[str, str],
    titulo: str,
    out_path: Path,
) -> None:
    """
    Genera y guarda un boxplot comparativo de dos series de latencia.

    Los parámetros permiten reutilizar la misma lógica para comparaciones
    ECH vs noECH y PQC vs clásico sin duplicar código.
    """
    mediana_a = df[col_a].median()
    mediana_b = df[col_b].median()

    p99 = max(df[col_a].quantile(0.99), df[col_b].quantile(0.99))
    y_max = p99 * 1.15

    data = pd.DataFrame({
        "Latencia (ms)": pd.concat([df[col_a], df[col_b]], ignore_index=True),
        "Modo": [label_a] * len(df) + [label_b] * len(df),
    })

    fig, ax = plt.subplots(figsize=(8, 6))
    sns.boxplot(
        data=data, x="Modo", y="Latencia (ms)", hue="Modo",
        palette=colores, legend=False, width=0.45,
        flierprops={"marker": ".", "alpha": 0.3, "markersize": 4},
        ax=ax,
    )
    ax.set_ylim(0, y_max)
    n_outliers = (data["Latencia (ms)"] > y_max).sum()
    ax.set_title(
        titulo + (f"\n(se omiten {n_outliers} outliers > {p99:.0f} ms)" if n_outliers else "")
    )
    ax.set_ylabel("Latencia media por host (ms)")
    ax.set_xlabel("")
    offset = y_max * 0.03
    ax.text(0, mediana_a + offset, f"Mediana: {mediana_a:.1f} ms",
            ha="center", va="bottom", fontsize=10,
            color=colores[label_a], fontweight="bold")
    ax.text(1, mediana_b + offset, f"Mediana: {mediana_b:.1f} ms",
            ha="center", va="bottom", fontsize=10,
            color=colores[label_b], fontweight="bold")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight", dpi=150)
    plt.close(fig)
    logger.info("Gráfica guardada: %s", out_path)


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

    plot_latencia_boxplot(
        df=df,
        col_a="latencia_con_ech_media_ms",
        col_b="latencia_sin_ech_media_ms",
        label_a="Con ECH",
        label_b="Sin ECH",
        colores={"Con ECH": "#2ca02c", "Sin ECH": "#1f77b4"},
        titulo="Latencia TLS: Con ECH vs Sin ECH",
        out_path=Path(args.output_dir) / "latencia_ech_vs_sin_ech.png",
    )


if __name__ == "__main__":
    main()
