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

"$VENV_DIR/bin/pip" install -q tqdm dnspython cryptography 2>/dev/null || \
    "$VENV_DIR/bin/pip" install tqdm dnspython cryptography
PYTHON_BIN="python3"

INPUT_CSV="data/hostnames_ech.csv"
OUTPUT_CSV="resultados/resultados_latencia_pqc.csv"
LOG_FILE="resultados/sonda_latencia_pqc.log"
LOG_LEVEL="INFO"
DNS_TIMEOUT="5"
TLS_TIMEOUT="10"
CONCURRENCY="5"
MAX_HOSTNAMES="80000"
REPETICIONES="30"
OQS_BIN="/opt/openssl/bin/openssl"
GRUPOS_PQC=""   # vacío = lista completa predefinida

show_help() {
    cat <<EOF
Uso: ./ejecutar_sonda_latencia_pqc.sh [opciones]

Mide la latencia del handshake TLS para múltiples grupos PQC frente al clásico X25519.
Para grupos soportados por bssl (X25519Kyber768Draft00, X25519MLKEM768) también compara
con y sin ECH. Para el resto de grupos usa OpenSSL OQS (sin ECH).

Genera una fila CSV por (hostname × grupo_pqc).

Opciones:
  --input-csv RUTA        CSV de hostnames de entrada (default: data/hostnames_ech.csv)
  --output-csv RUTA       CSV de resultados de salida (default: resultados/resultados_latencia_pqc.csv)
  --log-file RUTA         Archivo de log (default: resultados/sonda_latencia_pqc.log)
  --log-level NIVEL       DEBUG|INFO|WARNING|ERROR (default: INFO)
  --dns-timeout SEG       Timeout DNS en segundos (default: 5)
  --tls-timeout SEG       Timeout TLS en segundos (default: 10)
  --concurrency N         Concurrencia asyncio (default: 5)
  --max-hostnames N       Máximo de hostnames a procesar (default: 20000)
  --repeticiones N        Mediciones por combinación para media/stddev (default: 30)
  --oqs-bin RUTA          Binario OpenSSL OQS (default: /opt/openssl/bin/openssl)
  --grupos-pqc G1 G2 ...  Grupos PQC a probar (default: lista completa predefinida)
  -h, --help              Muestra esta ayuda

Grupos predefinidos:
  bssl (ECH disponible): X25519Kyber768Draft00, X25519MLKEM768
  OQS (sin ECH):         mlkem768, kyber768, SecP256r1MLKEM768,
                         x25519_mlkem512, x25519_kyber512, x25519_bikel1, x25519_hqc128
EOF
}

EXTRA_ARGS=()

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
        --oqs-bin)        OQS_BIN="$2";        shift 2 ;;
        --grupos-pqc)
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do
                GRUPOS_PQC="${GRUPOS_PQC} $1"
                shift
            done
            ;;
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
echo "        Sonda de Latencia PQC (múltiples grupos + comparativa ECH)"
echo "====================================================================="
echo "- CSV entrada:      ${INPUT_CSV}"
echo "- CSV salida:       ${OUTPUT_CSV}"
echo "- Log:              ${LOG_FILE}"
echo "- DNS timeout (s):  ${DNS_TIMEOUT}"
echo "- TLS timeout (s):  ${TLS_TIMEOUT}"
echo "- Concurrencia:     ${CONCURRENCY}"
echo "- Max hostnames:    ${MAX_HOSTNAMES}"
echo "- Repeticiones:     ${REPETICIONES}"
echo "- OpenSSL OQS:      ${OQS_BIN}"
if [[ -n "${GRUPOS_PQC}" ]]; then
    echo "- Grupos PQC:       ${GRUPOS_PQC}"
else
    echo "- Grupos PQC:       (lista predefinida completa)"
fi
echo

CMD=(
    "${PYTHON_BIN}" scripts/sondas/sonda_latencia_pqc.py
    --input-csv     "${INPUT_CSV}"
    --output-csv    "${OUTPUT_CSV}"
    --log-file      "${LOG_FILE}"
    --log-level     "${LOG_LEVEL}"
    --dns-timeout   "${DNS_TIMEOUT}"
    --tls-timeout   "${TLS_TIMEOUT}"
    --concurrency   "${CONCURRENCY}"
    --max-hostnames "${MAX_HOSTNAMES}"
    --repeticiones  "${REPETICIONES}"
    --oqs-bin       "${OQS_BIN}"
)

if [[ -n "${GRUPOS_PQC}" ]]; then
    # shellcheck disable=SC2206
    CMD+=(--grupos-pqc ${GRUPOS_PQC})
fi

"${CMD[@]}"

echo
echo "OK - Sonda finalizada"
echo "- CSV: ${OUTPUT_CSV}"
echo "- Log: ${LOG_FILE}"
echo
echo "====================================================================="
echo "           Generando gráfica..."
echo "====================================================================="

"${PYTHON_BIN}" scripts/sondas/graficar_latencia_pqc.py \
    --input-csv  "${OUTPUT_CSV}" \
    --output-dir "imagenes" \
    --log-level  "${LOG_LEVEL}"

echo
echo "OK - Gráfica guardada en: imagenes/latencia_pqc_ech_vs_sin_ech.png"
