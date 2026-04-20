#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_DIR}"

# Activar venv si existe y no está ya activado
if [[ -z "${VIRTUAL_ENV:-}" && -f "${PROJECT_DIR}/venv/bin/activate" ]]; then
    source "${PROJECT_DIR}/venv/bin/activate"
fi
PYTHON_BIN="python3"

INPUT_CSV="data/hostnames_ech.csv"
OUTPUT_CSV="resultados/resultados_latencia_ech.csv"
LOG_FILE="resultados/sonda_latencia_ech.log"
LOG_LEVEL="INFO"
DNS_TIMEOUT="5"
TLS_TIMEOUT="10"
CONCURRENCY="10"
MAX_HOSTNAMES="10000"
REPETICIONES="30"

show_help() {
    cat <<EOF
Uso: ./ejecutar_sonda_latencia_ech.sh [opciones]

Opciones:
  --input-csv RUTA        CSV de hostnames de entrada (default: data/hostnames_ech.csv)
  --output-csv RUTA       CSV de resultados de salida (default: resultados/resultados_latencia_ech.csv)
  --log-file RUTA         Archivo de log (default: resultados/sonda_latencia_ech.log)
  --log-level NIVEL       DEBUG|INFO|WARNING|ERROR (default: INFO)
  --dns-timeout SEG       Timeout DNS en segundos (default: 5)
  --tls-timeout SEG       Timeout TLS en segundos (default: 10)
  --concurrency N         Concurrencia asyncio (default: 10)
  --max-hostnames N       Máximo de hostnames a procesar (default: 10000)
  --repeticiones N        Mediciones por hostname para media/stddev (default: 3)
  -h, --help              Muestra esta ayuda
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input-csv)      INPUT_CSV="$2";      shift 2 ;;
        --output-csv)     OUTPUT_CSV="$2";     shift 2 ;;
        --log-file)       LOG_FILE="$2";       shift 2 ;;
        --log-level)      LOG_LEVEL="$2";      shift 2 ;;
        --dns-timeout)    DNS_TIMEOUT="$2";    shift 2 ;;
        --tls-timeout)    TLS_TIMEOUT="$2";    shift 2 ;;
        --concurrency)    CONCURRENCY="$2";    shift 2 ;;
        --max-hostnames)  MAX_HOSTNAMES="$2";  shift 2 ;;
        --repeticiones)   REPETICIONES="$2";   shift 2 ;;
        -h|--help)        show_help; exit 0 ;;
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

if [[ ! -f "${INPUT_CSV}" ]]; then
    echo "ERROR - CSV de entrada no encontrado: ${INPUT_CSV}"
    exit 1
fi

mkdir -p resultados

echo "====================================================================="
echo "           Sonda de Latencia ECH (con vs sin ECH)"
echo "====================================================================="
echo "- CSV entrada:      ${INPUT_CSV}"
echo "- CSV salida:       ${OUTPUT_CSV}"
echo "- Log:              ${LOG_FILE}"
echo "- DNS timeout (s):  ${DNS_TIMEOUT}"
echo "- TLS timeout (s):  ${TLS_TIMEOUT}"
echo "- Concurrencia:     ${CONCURRENCY}"
echo "- Max hostnames:    ${MAX_HOSTNAMES}"
echo "- Repeticiones:     ${REPETICIONES}"
echo

"${PYTHON_BIN}" scripts/sondas/sonda_latencia_ech.py \
    --input-csv     "${INPUT_CSV}" \
    --output-csv    "${OUTPUT_CSV}" \
    --log-file      "${LOG_FILE}" \
    --log-level     "${LOG_LEVEL}" \
    --dns-timeout   "${DNS_TIMEOUT}" \
    --tls-timeout   "${TLS_TIMEOUT}" \
    --concurrency   "${CONCURRENCY}" \
    --max-hostnames "${MAX_HOSTNAMES}" \
    --repeticiones  "${REPETICIONES}"

echo
echo "OK - Sonda finalizada"
echo "- CSV: ${OUTPUT_CSV}"
echo "- Log: ${LOG_FILE}"
echo
echo "====================================================================="
echo "           Generando gráficas..."
echo "====================================================================="

"${PYTHON_BIN}" scripts/sondas/graficar_latencia_ech.py \
    --input-csv  "${OUTPUT_CSV}" \
    --output-dir "imagenes" \
    --log-level  "${LOG_LEVEL}"

echo
echo "OK - Gráfica guardada en: imagenes/latencia_ech_vs_sin_ech.png"
