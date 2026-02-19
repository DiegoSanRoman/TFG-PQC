#!/bin/bash
# calibrar_sonda.sh
# Script para calibrar la sonda PQC contra un servidor de control local
# Uso: ./calibrar_sonda.sh [puerto] [repeticiones]

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuración
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PUERTO="${1:-4433}"
REPETICIONES="${2:-2}"
OUTPUT_DIR="${PROJECT_DIR}/resultados/calibracion"
TEMP_CSV="${OUTPUT_DIR}/localhost_test.csv"

# Limpiar CSV temporal siempre al salir, tanto en éxito como en error
trap "rm -f '$TEMP_CSV'" EXIT

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           Calibración de Sonda PQC - Servidor Local           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}📋 Configuración:${NC}"
echo "  Servidor: localhost:${PUERTO}"
echo "  Repeticiones: ${REPETICIONES}"
echo "  Directorio salida: ${OUTPUT_DIR}"
echo ""

# Verificar que el servidor está corriendo
echo -e "${YELLOW}🔍 Verificando servidor...${NC}"
if ! nc -z localhost "$PUERTO" 2>/dev/null; then
    echo -e "${RED}❌ Error: Servidor no accesible en localhost:${PUERTO}${NC}"
    echo ""
    echo "Inicia el servidor primero con:"
    echo "  ./servidor_control_pqc_docker.sh ${PUERTO}"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓ Servidor accesible${NC}"
echo ""

# Crear CSV temporal con localhost
mkdir -p "$OUTPUT_DIR"
echo "Rank,Domain" > "$TEMP_CSV"
echo "1,localhost:${PUERTO}" >> "$TEMP_CSV"

echo -e "${BLUE}🚀 Ejecutando calibración...${NC}"
echo -e "${YELLOW}   (Esto tomará ~2-3 minutos)${NC}"
echo ""

# Ejecutar sonda con Docker
cd "$PROJECT_DIR"
docker run -it --rm \
    --network host \
    -v "${PROJECT_DIR}/data:/app/data" \
    -v "${OUTPUT_DIR}:/app/resultados" \
    tfg-sonda \
    --input-csv /app/resultados/localhost_test.csv \
    --max-hostnames 1 \
    --repeticiones "${REPETICIONES}" \
    --max-workers 1 \
    --domain-column 1

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ Calibración completada exitosamente${NC}"

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    JSON_ORIG="${OUTPUT_DIR}/resultados_sonda_pqc.json"
    JSON_DEST="${OUTPUT_DIR}/calibracion_${TIMESTAMP}.json"

    if [ -f "$JSON_ORIG" ]; then
        mv "$JSON_ORIG" "$JSON_DEST"
        echo -e "${BLUE}📁 Resultados guardados:${NC}"
        echo "  JSON: ${JSON_DEST}"

        if [ -f "${OUTPUT_DIR}/resumen_por_grupo.csv" ]; then
            mv "${OUTPUT_DIR}/resumen_por_grupo.csv" "${OUTPUT_DIR}/calibracion_resumen_${TIMESTAMP}.csv"
            echo "  CSV:  ${OUTPUT_DIR}/calibracion_resumen_${TIMESTAMP}.csv"
        fi

        echo ""
        echo -e "${YELLOW}📊 Generando análisis de calibración...${NC}"
        if [ -d "${PROJECT_DIR}/venv" ]; then
            source "${PROJECT_DIR}/venv/bin/activate"
            python "${PROJECT_DIR}/scripts/ml/analizar_resultados.py" \
                --input "$JSON_DEST" \
                --output "${OUTPUT_DIR}/imagenes_${TIMESTAMP}/"
            echo -e "${GREEN}✓ Análisis generado en: ${OUTPUT_DIR}/imagenes_${TIMESTAMP}/${NC}"
        else
            echo -e "${YELLOW}⚠️  venv no encontrado, omitiendo análisis Python${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  No se encontró el archivo de resultados esperado: ${JSON_ORIG}${NC}"
    fi

    echo ""
    echo -e "${BLUE}💡 Interpretación de Resultados:${NC}"
    echo "  • Latencia de red (~0ms): Confirma entorno controlado"
    echo "  • Overhead de handshake: Refleja el costo real del algoritmo PQC"
    echo "  • Variabilidad baja: Indica mediciones precisas de la sonda"
    echo ""
    echo -e "${GREEN}📝 Usa estos datos para la sección de 'Calibración' en tu TFG${NC}"
else
    echo -e "${RED}❌ Error durante la calibración (código: $EXIT_CODE)${NC}"
    exit $EXIT_CODE
fi