#!/usr/bin/env bash

# Para los errores, variables no definidas y errores en pipes
set -euo pipefail

# Variables por defecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${PROJECT_DIR}/venv/bin/python3" ]]; then
    PYTHON_BIN="${PROJECT_DIR}/venv/bin/python3"
else
    PYTHON_BIN="python3"
fi

INPUT_CSV="data/majestic_million.csv"
MAX_DOMINIOS="1000"
MAX_CONCURRENCY="40"
TLS_CLIENT="auto"
DNS_TIMEOUT="8"
TLS_TIMEOUT="20"
BSSL_PATH="${PROJECT_DIR}/tools/boringssl/build/bssl"
OUTPUT_JSON="resultados/resultados_ech_prevalencia.json"
OUTPUT_CSV="resultados/resultados_ech_prevalencia.csv"

# Función para mostrar la ayuda
show_help() {
    cat <<EOF
Uso: ./ejecutar_sonda_ech.sh [opciones]

Opciones:
  --input-csv RUTA          CSV de entrada (default: data/majestic_million.csv)
  --max-dominios N          Máximo de dominios a procesar (default: 1000)
    --max-concurrency N       Concurrencia asyncio (default: 40)
  --tls-client MODO         auto|bssl|openssl (default: auto)
    --dns-timeout SEG         Timeout DNS en segundos (default: 8)
    --tls-timeout SEG         Timeout TLS en segundos (default: 20)
    --bssl-path RUTA          Ruta explícita a bssl (opcional)
  --output-json RUTA        Salida JSON
  --output-csv RUTA         Salida CSV
  -h, --help                Muestra esta ayuda
EOF
}

# Parseo de argumentos de línea de comandos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input-csv)
            INPUT_CSV="$2"
            shift 2
            ;;
        --max-dominios)
            MAX_DOMINIOS="$2"
            shift 2
            ;;
        --max-concurrency)
            MAX_CONCURRENCY="$2"
            shift 2
            ;;
        --tls-client)
            TLS_CLIENT="$2"
            shift 2
            ;;
        --dns-timeout)
            DNS_TIMEOUT="$2"
            shift 2
            ;;
        --tls-timeout)
            TLS_TIMEOUT="$2"
            shift 2
            ;;
        --bssl-path)
            BSSL_PATH="$2"
            shift 2
            ;;
        --output-json)
            OUTPUT_JSON="$2"
            shift 2
            ;;
        --output-csv)
            OUTPUT_CSV="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "ERROR - Argumento desconocido: $1"
            show_help
            exit 1
            ;;
    esac
done

# Verificar que el CSV de entrada existe
if [[ ! -x "${PYTHON_BIN}" ]]; then
    echo "ERROR - Python no ejecutable: ${PYTHON_BIN}"
    exit 1
fi

"${PYTHON_BIN}" -c "import dns" 2>/dev/null || {
    echo "--- Instalando dependencias Python..."
    "${PYTHON_BIN}" -m pip install -q dnspython cryptography
}

# Crear directorio de resultados si no existe
mkdir -p "${PROJECT_DIR}/resultados"

# Mostrar configuración
echo "====================================================================="
echo "           Sonda de Prevalencia ECH (TLS 1.3)"
echo "====================================================================="
echo "- CSV entrada:      ${INPUT_CSV}"
echo "- Max dominios:     ${MAX_DOMINIOS}"
echo "- Max concurrencia: ${MAX_CONCURRENCY}"
echo "- TLS client:       ${TLS_CLIENT}"
echo "- DNS timeout (s):  ${DNS_TIMEOUT}"
echo "- TLS timeout (s):  ${TLS_TIMEOUT}"
if [[ -n "${BSSL_PATH}" ]]; then
echo "- bssl path:        ${BSSL_PATH}"
fi
echo

# Ejecutar el script de la sonda
"${PYTHON_BIN}" "${PROJECT_DIR}/scripts/sondas/sonda_ech_prevalencia.py" \
    --input-csv "${INPUT_CSV}" \
    --max-dominios "${MAX_DOMINIOS}" \
    --max-concurrency "${MAX_CONCURRENCY}" \
    --dns-timeout "${DNS_TIMEOUT}" \
    --tls-timeout "${TLS_TIMEOUT}" \
    --tls-client "${TLS_CLIENT}" \
    ${BSSL_PATH:+--bssl-path "${BSSL_PATH}"} \
    --output-json "${OUTPUT_JSON}" \
    --output-csv "${OUTPUT_CSV}"

# Extraer hostnames con ECH exitoso y escribir data/hostnames_ech.csv
HOSTNAMES_ECH="${PROJECT_DIR}/data/hostnames_ech.csv"
echo
echo "====================================================================="
echo "           Extrayendo hostnames con ECH exitoso..."
echo "====================================================================="
"${PYTHON_BIN}" - <<PYEOF
import json, csv, sys
from pathlib import Path

json_path = Path("${OUTPUT_JSON}")
out_path  = Path("${HOSTNAMES_ECH}")

try:
    data = json.loads(json_path.read_text(encoding="utf-8"))
except Exception as e:
    print(f"ERROR - No se pudo leer {json_path}: {e}", file=sys.stderr)
    sys.exit(1)

results = data.get("results") or data.get("datos") or []
hostnames = [
    r["domain"]
    for r in results
    if r.get("ech_negotiation_status") == "EXITO_OUTER_CLIENT_HELLO"
    and r.get("handshake_completed") is True
    and r.get("domain")
]

out_path.parent.mkdir(parents=True, exist_ok=True)
with out_path.open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["hostname"])
    for h in hostnames:
        w.writerow([h])

print(f"OK - {len(hostnames)} hostnames con ECH exitoso escritos en {out_path}")
PYEOF

# Mostrar resultados
echo
echo "OK - Sonda ECH finalizada"
echo "- JSON:            ${OUTPUT_JSON}"
echo "- CSV:             ${OUTPUT_CSV}"
echo "- Hostnames ECH:   ${HOSTNAMES_ECH}"
