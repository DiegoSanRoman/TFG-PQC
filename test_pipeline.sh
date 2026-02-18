#!/bin/bash
# test_pipeline.sh
# Script para probar el pipeline completo: sonda + análisis
# Uso: ./test_pipeline.sh [max_hostnames]

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_HOSTNAMES="${1:-100}"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║            Test Pipeline: Sonda + Análisis                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "Paso 1️⃣  - Ejecutar sonda PQC..."
echo "  Comando: ./ejecutar_sonda.sh ${MAX_HOSTNAMES} 3 20"
echo ""

cd "${PROJECT_DIR}"
./ejecutar_sonda.sh "${MAX_HOSTNAMES}" 3 20

echo ""
echo "Paso 2️⃣  - Ejecutar análisis..."
echo ""

./ejecutar_analisis.sh

echo ""
echo "✅ Pipeline completado"
echo ""
