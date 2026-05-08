#!/usr/bin/env python3
"""
Clasificación de grupo criptográfico TLS mediante side-channel de timing y bytes.

Pregunta de investigación: ¿puede un observador de red inferir qué grupo
criptográfico negoció una conexión TLS *sin* leer el campo cipher_suite?

Tres experimentos en cascada, con features crecientemente ricas:
  Exp 1 - Solo timing:        handshake_time_ms
  Exp 2 - Timing + bytes TLS: + bytes_sent, bytes_received,
                                 handshake_overhead
  Exp 3 - Timing + bytes tot: + handshake_total_bytes_sent,
                                 handshake_total_bytes_received,
                                 handshake_total_overhead

Target: grupo negociado (X25519 clásico + 3 grupos PQC con conexiones aceptadas).

Metodología de evaluación (sin leakage):
  1. GroupShuffleSplit(80/20) por hostname → train set y test set completamente
     separados: ningún hostname aparece en ambos conjuntos.
  2. GroupKFold(5) sobre el train set → métricas de accuracy/F1 (CV en train).
  3. Modelo final entrenado en el train set completo.
  4. Matriz de confusión evaluada en el test set (hostnames no vistos en entrenamiento).

Modelos: RandomForest y GradientBoosting.

Salidas en `imagenes/`:
  clasificacion_distribucion_features.png    — distribución de features por grupo
  clasificacion_experimentos_comparativa.png — accuracy/F1 de los 3 experimentos
  clasificacion_confusion_mejor.png          — matriz de confusión sobre test set
  clasificacion_importancia_features.png     — feature importance del mejor modelo
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, cross_validate
from sklearn.preprocessing import LabelEncoder

_SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

sns.set_style("whitegrid")
plt.rcParams["font.size"] = 11

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_JSON = str(BASE_DIR / "resultados" / "resultados_sonda_pqc.json")
DEFAULT_OUTPUT_DIR = str(BASE_DIR / "imagenes")

# Grupos con conexiones ACEPTADO suficientes para clasificar
GRUPOS_VIABLES = {"X25519", "X25519MLKEM768", "x25519_kyber768", "SecP256r1MLKEM768"}

# Etiquetas más legibles para las gráficas
LABEL_MAP = {
    "X25519":            "X25519\n(clásico)",
    "X25519MLKEM768":    "X25519MLKEM768\n(híbrido NIST)",
    "x25519_kyber768":   "x25519_kyber768\n(híbrido OQS)",
    "SecP256r1MLKEM768": "SecP256r1MLKEM768\n(híbrido P-256)",
}

# Colores por grupo
PALETTE = {
    "X25519\n(clásico)":            "#1f77b4",
    "X25519MLKEM768\n(híbrido NIST)": "#d62728",
    "x25519_kyber768\n(híbrido OQS)": "#ff7f0e",
    "SecP256r1MLKEM768\n(híbrido P-256)": "#2ca02c",
}

# Definición de los 3 experimentos
# Nota: dns_time_ms queda excluido deliberadamente — mide la latencia del resolver
# DNS en el momento de la prueba, no una propiedad del grupo criptográfico, y
# podría introducir correlaciones espurias en el clasificador.
EXPERIMENTOS = {
    "Exp 1\nSolo timing": [
        "handshake_time_ms",
    ],
    "Exp 2\nTiming + bytes TLS": [
        "handshake_time_ms",
        "bytes_sent", "bytes_received", "handshake_overhead",
    ],
    "Exp 3\nTiming + bytes totales": [
        "handshake_time_ms",
        "bytes_sent", "bytes_received", "handshake_overhead",
        "handshake_total_bytes_sent", "handshake_total_bytes_received",
        "handshake_total_overhead",
    ],
}


# ---------------------------------------------------------------------------
# Carga y preparación de datos
# ---------------------------------------------------------------------------

def cargar_datos(json_path: Path) -> pd.DataFrame:
    with json_path.open(encoding="utf-8") as f:
        raw = json.load(f)

    registros = raw["datos"] if isinstance(raw, dict) else raw

    filas = []
    for entrada in registros:
        hostname = entrada["hostname"]
        for prueba in entrada["pruebas"]:
            if prueba["connection_result"] != "ACEPTADO":
                continue
            if prueba["grupo"] not in GRUPOS_VIABLES:
                continue
            filas.append({
                "hostname":                    hostname,
                "grupo":                       prueba["grupo"],
                "dns_time_ms":                 prueba.get("dns_time_ms"),
                "tcp_time_ms":                 prueba.get("tcp_time_ms"),
                "handshake_time_ms":           prueba.get("handshake_time_ms"),
                "bytes_sent":                  prueba.get("bytes_sent"),
                "bytes_received":              prueba.get("bytes_received"),
                "handshake_overhead":          prueba.get("handshake_overhead"),
                "handshake_total_bytes_sent":  prueba.get("handshake_total_bytes_sent"),
                "handshake_total_bytes_received": prueba.get("handshake_total_bytes_received"),
                "handshake_total_overhead":    prueba.get("handshake_total_overhead"),
            })

    df = pd.DataFrame(filas)
    df["grupo_label"] = df["grupo"].map(LABEL_MAP)
    logger.info(
        "Dataset: %d registros, %d grupos, %d hostnames únicos",
        len(df), df["grupo"].nunique(), df["hostname"].nunique(),
    )
    for g, n in df["grupo"].value_counts().items():
        logger.info("  %-28s  %d registros", g, n)
    return df


# ---------------------------------------------------------------------------
# Split train / test por hostname
# ---------------------------------------------------------------------------

def split_train_test(
    df: pd.DataFrame,
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Divide el dataset en train y test agrupando por hostname (GroupShuffleSplit).
    Ningún hostname aparece en ambos conjuntos.
    """
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(gss.split(df, groups=df["hostname"].values))
    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_test  = df.iloc[test_idx].reset_index(drop=True)
    logger.info(
        "Train: %d registros (%d hostnames únicos)",
        len(df_train), df_train["hostname"].nunique(),
    )
    logger.info(
        "Test:  %d registros (%d hostnames únicos)",
        len(df_test), df_test["hostname"].nunique(),
    )
    logger.info("Distribución train:")
    for g, n in df_train["grupo"].value_counts().items():
        logger.info("  %-28s  %d", g, n)
    logger.info("Distribución test:")
    for g, n in df_test["grupo"].value_counts().items():
        logger.info("  %-28s  %d", g, n)
    return df_train, df_test


# ---------------------------------------------------------------------------
# Evaluación con cross-validación por hostname (GroupKFold sobre train)
# ---------------------------------------------------------------------------

def evaluar_experimento(
    df_train: pd.DataFrame,
    features: list[str],
    le: LabelEncoder,
    n_splits: int = 5,
) -> dict:
    """
    Evalúa RandomForest y GradientBoosting con GroupKFold(hostname) sobre df_train.
    El LabelEncoder se recibe ya ajustado sobre todas las clases del dataset completo.
    Devuelve métricas de CV y el modelo ganador entrenado en el train set completo.
    """
    X      = df_train[features].values
    y_enc  = le.transform(df_train["grupo"].values)
    groups = df_train["hostname"].values

    gkf = GroupKFold(n_splits=n_splits)

    modelos = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=200, learning_rate=0.1, max_depth=4, random_state=42
        ),
    }

    resultados = {}
    for nombre, modelo in modelos.items():
        cv = cross_validate(
            modelo, X, y_enc,
            groups=groups,
            cv=gkf,
            scoring=["accuracy", "f1_macro", "f1_weighted"],
            n_jobs=-1,
            return_estimator=False,
        )
        resultados[nombre] = {
            "accuracy":    cv["test_accuracy"].mean(),
            "f1_macro":    cv["test_f1_macro"].mean(),
            "f1_weighted": cv["test_f1_weighted"].mean(),
            "acc_std":     cv["test_accuracy"].std(),
        }
        logger.info(
            "  %s — accuracy=%.3f±%.3f  f1_macro=%.3f  f1_weighted=%.3f",
            nombre,
            resultados[nombre]["accuracy"], resultados[nombre]["acc_std"],
            resultados[nombre]["f1_macro"], resultados[nombre]["f1_weighted"],
        )

    # Modelo ganador entrenado en el train set completo
    mejor_nombre = max(resultados, key=lambda k: resultados[k]["f1_macro"])
    mejor_modelo = modelos[mejor_nombre]
    mejor_modelo.fit(X, y_enc)
    resultados["_mejor_nombre"] = mejor_nombre
    resultados["_mejor_modelo"] = mejor_modelo
    resultados["_features"]     = features
    return resultados


# ---------------------------------------------------------------------------
# Gráficas
# ---------------------------------------------------------------------------

def graficar_distribucion_features(df: pd.DataFrame, out_dir: Path) -> None:
    """Boxplots de los features clave por grupo (sin cipher suite)."""
    features_plot = [
        ("handshake_time_ms",           "Handshake TLS (ms)"),
        ("dns_time_ms",                 "DNS (ms)"),
        ("bytes_sent",                  "Bytes enviados (trace)"),
        ("bytes_received",              "Bytes recibidos (trace)"),
        ("handshake_total_bytes_sent",  "Bytes enviados (total)"),
        ("handshake_total_bytes_received", "Bytes recibidos (total)"),
    ]

    fig, axes = plt.subplots(2, 3, figsize=(15, 9))
    axes = axes.flatten()

    for ax, (col, titulo) in zip(axes, features_plot):
        orden = [LABEL_MAP[g] for g in sorted(GRUPOS_VIABLES) if LABEL_MAP[g] in df["grupo_label"].unique()]
        grupos_presentes = [g for g in orden if g in df["grupo_label"].unique()]
        data_por_grupo = [df[df["grupo_label"] == g][col].dropna().values for g in grupos_presentes]
        bp = ax.boxplot(data_por_grupo, patch_artist=True,
                        flierprops={"marker": ".", "markersize": 2, "alpha": 0.3})
        for patch, g in zip(bp["boxes"], grupos_presentes):
            patch.set_facecolor(PALETTE.get(g, "#999999"))
        ax.set_xticks(range(1, len(grupos_presentes) + 1))
        ax.set_xticklabels(grupos_presentes)
        ax.set_title(titulo)
        ax.set_xlabel("")
        ax.set_ylabel("")
        ax.tick_params(axis="x", labelsize=8)

    fig.suptitle(
        "Distribución de features observables por grupo criptográfico\n"
        "(sin acceso al campo cipher_suite)",
        fontsize=13, y=1.01,
    )
    fig.tight_layout()
    out = out_dir / "clasificacion_distribucion_features.png"
    fig.savefig(out, bbox_inches="tight", dpi=150)
    plt.close(fig)
    logger.info("Guardada: %s", out)


def graficar_comparativa_experimentos(
    resultados_por_exp: dict[str, dict],
    out_dir: Path,
) -> None:
    """Gráfica de barras comparando accuracy y F1 de los 3 experimentos."""
    exp_names = list(resultados_por_exp.keys())
    model_names = ["RandomForest", "GradientBoosting"]
    metricas = ["accuracy", "f1_macro", "f1_weighted"]
    metrica_labels = ["Accuracy", "F1 Macro", "F1 Weighted"]

    fig, axes = plt.subplots(1, 3, figsize=(15, 5), sharey=True)
    x = np.arange(len(exp_names))
    width = 0.35

    for ax, metrica, ml in zip(axes, metricas, metrica_labels):
        for i, modelo in enumerate(model_names):
            vals = [resultados_por_exp[exp][modelo][metrica] for exp in exp_names]
            errs = [resultados_por_exp[exp][modelo]["acc_std"] if metrica == "accuracy" else 0
                    for exp in exp_names]
            bars = ax.bar(
                x + i * width - width / 2, vals,
                width, label=modelo,
                color=["#1f77b4", "#d62728"][i],
                alpha=0.8,
                yerr=errs if metrica == "accuracy" else None,
                capsize=3,
            )
            for bar, val in zip(bars, vals):
                ax.text(
                    bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.005,
                    f"{val:.3f}", ha="center", va="bottom", fontsize=8,
                )

        ax.set_xticks(x)
        ax.set_xticklabels(exp_names, fontsize=9)
        ax.set_ylim(0, 1.12)
        ax.set_title(ml)
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
        if ax is axes[0]:
            ax.legend(fontsize=9)

    fig.suptitle(
        "Capacidad de clasificación del grupo PQC por tipo de feature\n"
        "(validación GroupKFold-5 por hostname — sin acceso a cipher_suite)",
        fontsize=12, y=1.02,
    )
    fig.tight_layout()
    out = out_dir / "clasificacion_experimentos_comparativa.png"
    fig.savefig(out, bbox_inches="tight", dpi=150)
    plt.close(fig)
    logger.info("Guardada: %s", out)


def graficar_confusion_matrix(
    modelo,
    le: LabelEncoder,
    X_test: np.ndarray,
    y_test_enc: np.ndarray,
    titulo: str,
    n_test: int,
    out_dir: Path,
) -> None:
    """Matriz de confusión normalizada evaluada sobre el test set (hostnames no vistos)."""
    y_pred = modelo.predict(X_test)
    cm = confusion_matrix(y_test_enc, y_pred, normalize="true")
    labels_short = [LABEL_MAP.get(c, c) for c in le.classes_]

    acc  = accuracy_score(y_test_enc, y_pred)
    f1m  = f1_score(y_test_enc, y_pred, average="macro")

    # Reporte por clase: precision, recall, F1 e support por cada grupo.
    # El "support" muestra el desbalance real del test set, lo que permite
    # interpretar correctamente un accuracy global alto con clases minoritarias mal clasificadas.
    report_str = classification_report(
        y_test_enc, y_pred,
        target_names=le.classes_,
        digits=3,
    )
    logger.info("Classification report (test set):\n%s", report_str)

    report_path = out_dir / "clasificacion_informe_por_clase.txt"
    report_path.write_text(
        f"Modelo: {titulo}\nTest set: {n_test} registros\n\n{report_str}",
        encoding="utf-8",
    )
    logger.info("Guardado: %s", report_path)

    # También como CSV para facilitar análisis posterior
    report_dict = classification_report(
        y_test_enc, y_pred,
        target_names=le.classes_,
        output_dict=True,
    )
    pd.DataFrame(report_dict).T.to_csv(out_dir / "clasificacion_informe_por_clase.csv")
    logger.info("Guardado: %s", out_dir / "clasificacion_informe_por_clase.csv")

    fig, ax = plt.subplots(figsize=(8, 7))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels_short)
    disp.plot(ax=ax, colorbar=True, cmap="Blues", values_format=".2f")
    ax.set_title(
        f"Matriz de confusión — {titulo}\n"
        f"Test set: {n_test} registros (hostnames no vistos en entrenamiento)\n"
        f"Accuracy={acc:.3f}  F1-macro={f1m:.3f}",
        fontsize=10,
    )
    ax.tick_params(axis="x", labelsize=8, rotation=15)
    ax.tick_params(axis="y", labelsize=8)
    fig.tight_layout()
    out = out_dir / "clasificacion_confusion_mejor.png"
    fig.savefig(out, bbox_inches="tight", dpi=150)
    plt.close(fig)
    logger.info("Guardada: %s", out)
    logger.info("Métricas en test set — accuracy=%.3f  f1_macro=%.3f", acc, f1m)


def graficar_importancia_features(
    modelo,
    features: list[str],
    nombre_modelo: str,
    out_dir: Path,
) -> None:
    """Feature importance del mejor modelo (solo RandomForest y GradientBoosting)."""
    if not hasattr(modelo, "feature_importances_"):
        logger.warning("El modelo %s no tiene feature_importances_", nombre_modelo)
        return

    importancias = modelo.feature_importances_
    idx = np.argsort(importancias)[::-1]
    feats_sorted = [features[i] for i in idx]
    vals_sorted  = importancias[idx]

    fig, ax = plt.subplots(figsize=(9, 5))
    colors = ["#d62728" if "bytes" in f or "overhead" in f else "#1f77b4" for f in feats_sorted]
    ax.barh(range(len(feats_sorted))[::-1], vals_sorted, color=colors, alpha=0.85)
    ax.set_yticks(range(len(feats_sorted)))
    ax.set_yticklabels(feats_sorted[::-1], fontsize=10)
    ax.set_xlabel("Importancia relativa")
    ax.set_title(
        f"Importancia de features — {nombre_modelo} (Exp 3, todos los features)\n"
        "Rojo = bytes, Azul = timing"
    )

    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(color="#d62728", alpha=0.85, label="Bytes (tamaño de paquete)"),
        Patch(color="#1f77b4", alpha=0.85, label="Timing (latencia)"),
    ], fontsize=9)

    fig.tight_layout()
    out = out_dir / "clasificacion_importancia_features.png"
    fig.savefig(out, bbox_inches="tight", dpi=150)
    plt.close(fig)
    logger.info("Guardada: %s", out)


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Clasifica grupo criptográfico TLS desde features de timing/bytes"
    )
    parser.add_argument("--input-json",  default=DEFAULT_INPUT_JSON)
    parser.add_argument("--output-dir",  default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--n-splits",    type=int, default=5,
                        help="Folds para GroupKFold (default: 5)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Carga y split train/test por hostname ---
    df = cargar_datos(Path(args.input_json))
    graficar_distribucion_features(df, out_dir)

    df_train, df_test = split_train_test(df, test_size=0.2, random_state=42)

    # LabelEncoder ajustado sobre todas las clases del dataset completo
    le = LabelEncoder().fit(df["grupo"].values)

    # --- 3 experimentos: CV sobre train, modelo final entrenado en train ---
    resultados_por_exp: dict[str, dict] = {}
    mejor_global_f1 = -1.0
    mejor_exp_nombre = ""
    mejor_modelo_global = None
    mejor_features_global: list[str] = []
    mejor_modelo_nombre_global = ""

    for nombre_exp, features in EXPERIMENTOS.items():
        logger.info("--- %s ---", nombre_exp.replace("\n", " "))
        df_train_exp = df_train.dropna(subset=features)
        res = evaluar_experimento(df_train_exp, features, le=le, n_splits=args.n_splits)
        resultados_por_exp[nombre_exp] = {
            "RandomForest":     res["RandomForest"],
            "GradientBoosting": res["GradientBoosting"],
        }

        mejor_f1_exp = max(
            res["RandomForest"]["f1_macro"],
            res["GradientBoosting"]["f1_macro"],
        )
        if mejor_f1_exp > mejor_global_f1:
            mejor_global_f1 = mejor_f1_exp
            mejor_exp_nombre = nombre_exp
            mejor_modelo_global      = res["_mejor_modelo"]
            mejor_features_global    = features
            mejor_modelo_nombre_global = res["_mejor_nombre"]

    # --- Gráficas de resultados ---
    graficar_comparativa_experimentos(resultados_por_exp, out_dir)

    # Matriz de confusión evaluada en el TEST SET (hostnames no vistos)
    df_test_best = df_test.dropna(subset=mejor_features_global)
    X_test    = df_test_best[mejor_features_global].values
    y_test_enc = le.transform(df_test_best["grupo"].values)
    graficar_confusion_matrix(
        mejor_modelo_global, le,
        X_test, y_test_enc,
        titulo=f"{mejor_modelo_nombre_global} — {mejor_exp_nombre.replace(chr(10), ' ')}",
        n_test=len(df_test),
        out_dir=out_dir,
    )

    # Feature importance del modelo entrenado en train
    graficar_importancia_features(
        mejor_modelo_global, mejor_features_global,
        mejor_modelo_nombre_global,
        out_dir,
    )

    # --- Resumen en consola ---
    print("\n" + "=" * 70)
    print("RESUMEN — Clasificación de grupo PQC por side-channel")
    print(f"Train: {len(df_train)} registros ({df_train['hostname'].nunique()} hostnames)")
    print(f"Test:  {len(df_test)} registros ({df_test['hostname'].nunique()} hostnames)")
    print("Métricas de CV calculadas sobre el train set (GroupKFold-5)")
    print("=" * 70)
    print(f"{'Experimento':<32} {'Modelo':<20} {'Acc':>6} {'F1 mac':>7} {'F1 wgt':>7}")
    print("-" * 70)
    for exp_name, res_exp in resultados_por_exp.items():
        short = exp_name.replace("\n", " ")
        for modelo_name, metricas in res_exp.items():
            if modelo_name.startswith("_"):
                continue
            print(
                f"{short:<32} {modelo_name:<20} "
                f"{metricas['accuracy']:>6.3f} {metricas['f1_macro']:>7.3f} {metricas['f1_weighted']:>7.3f}"
            )
    print("=" * 70)
    print(f"\nMejor configuración (CV): {mejor_exp_nombre.replace(chr(10), ' ')}  (f1_macro={mejor_global_f1:.3f})")
    print(f"Imágenes guardadas en: {out_dir}/")


if __name__ == "__main__":
    main()
