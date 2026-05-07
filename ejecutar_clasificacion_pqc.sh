#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_DIR}"

# En WSL con proyecto en /mnt/ usar venv nativo para que los paquetes binarios funcionen
if [[ "$(uname -r)" == *microsoft* ]] && [[ "$PROJECT_DIR" == /mnt/* ]]; then
    VENV_DIR="$HOME/.venv-tfg-pqc"
else
    VENV_DIR="${PROJECT_DIR}/venv"
fi

if [[ ! -d "$VENV_DIR" ]]; then
    echo "--- Creando entorno virtual en ${VENV_DIR}..."
    python3 -m venv "$VENV_DIR"
fi

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    source "${VENV_DIR}/bin/activate"
fi

"$VENV_DIR/bin/pip" install -q scikit-learn 2>/dev/null || \
    "$VENV_DIR/bin/pip" install scikit-learn
PYTHON_BIN="python3"

INPUT_JSON="resultados/resultados_sonda_pqc.json"
OUTPUT_DIR="imagenes"
N_SPLITS="5"

show_help() {
    cat <<EOF
Uso: ./ejecutar_clasificacion_pqc.sh [opciones]

Clasifica el grupo criptográfico TLS (clásico vs PQC) usando solo features
observables sin acceso al campo cipher_suite (timing y tamaños de paquete).

Ejecuta 3 experimentos en cascada:
  Exp 1 — Solo timing (dns, tcp, handshake)
  Exp 2 — Timing + bytes del handshake TLS
  Exp 3 — Timing + todos los bytes (total de sesión)

Validación: GroupKFold-N agrupando por hostname para evitar leakage.
Modelos: RandomForest y GradientBoosting.

Opciones:
  --input-json RUTA   JSON de la sonda PQC (default: resultados/resultados_sonda_pqc.json)
  --output-dir RUTA   Directorio de imágenes de salida (default: imagenes)
  --n-splits N        Folds para GroupKFold (default: 5)
  -h, --help          Muestra esta ayuda

Salidas en imagenes/:
  clasificacion_distribucion_features.png    — distribución de features por grupo
  clasificacion_experimentos_comparativa.png — accuracy/F1 de los 3 experimentos
  clasificacion_confusion_mejor.png          — matriz de confusión del mejor modelo
  clasificacion_importancia_features.png     — feature importance del mejor modelo
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input-json)  INPUT_JSON="$2"; shift 2 ;;
        --output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
        --n-splits)    N_SPLITS="$2";   shift 2 ;;
        -h|--help)     show_help; exit 0 ;;
        *)
            echo "ERROR - Argumento desconocido: $1"
            show_help
            exit 1
            ;;
    esac
done

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    echo "ERROR - No se encontró python3 en PATH"
    exit 1
fi

if [[ ! -f "${INPUT_JSON}" ]]; then
    echo "ERROR - JSON de entrada no encontrado: ${INPUT_JSON}"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

echo "====================================================================="
echo "    Clasificación de grupo PQC por side-channel (timing + bytes)"
echo "====================================================================="
echo "- JSON entrada:   ${INPUT_JSON}"
echo "- Imágenes:       ${OUTPUT_DIR}"
echo "- GroupKFold:     ${N_SPLITS} folds"
echo

"${PYTHON_BIN}" scripts/ml/clasificar_grupo_pqc.py \
    --input-json  "${INPUT_JSON}" \
    --output-dir  "${OUTPUT_DIR}" \
    --n-splits    "${N_SPLITS}"

echo
echo "OK - Imágenes guardadas en: ${OUTPUT_DIR}/"
