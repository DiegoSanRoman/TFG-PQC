#!/bin/bash
# test_pipeline.sh
# Script para probar el pipeline completo: sonda + análisis
# Uso: ./test_pipeline.sh --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N]

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Valores por defecto
INPUT_CSV="majestic_million.csv"
MAX_HOSTNAMES=100
REPETICIONES=3
MAX_WORKERS=20

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input-csv)
            INPUT_CSV="$2"
            shift 2
            ;;
        --max-hostnames)
            MAX_HOSTNAMES="$2"
            shift 2
            ;;
        --repeticiones)
            REPETICIONES="$2"
            shift 2
            ;;
        --max-workers)
            MAX_WORKERS="$2"
            shift 2
            ;;
        *)
            echo "❌ Argumento desconocido: $1"
            echo "Uso: ./test_pipeline.sh --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N]"
            exit 1
            ;;
    esac
done 

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║            Test Pipeline: Sonda + Análisis                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "Paso 1️⃣  - Ejecutar sonda PQC..."
echo "  Comando: ./ejecutar_sonda.sh --input-csv ${INPUT_CSV} --max-hostnames ${MAX_HOSTNAMES} --repeticiones ${REPETICIONES} --max-workers ${MAX_WORKERS}"
echo ""

cd "${PROJECT_DIR}"
./ejecutar_sonda.sh --input-csv "${INPUT_CSV}" --max-hostnames "${MAX_HOSTNAMES}" --repeticiones "${REPETICIONES}" --max-workers "${MAX_WORKERS}"

echo ""
echo "Paso 2️⃣  - Ejecutar análisis..."
echo ""

./ejecutar_analisis.sh

echo ""
echo "✅ Pipeline completado"
echo ""
