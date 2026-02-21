#!/bin/bash
# ejecutar_pruebas_calibracion.sh
# Script para ejecutar pruebas PQC contra el servidor de calibración local
# Usa el contenedor Docker con OpenSSL PQC para probar todos los grupos contra localhost

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Directorio base del proyecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Configuración
DOCKER_IMAGE="tfg-sonda"
DATASET_CSV="calibracion.csv"
MAX_HOSTNAMES="1"
REPETICIONES="${1:-5}"  # Por defecto 5 repeticiones para calibración
MAX_WORKERS="1"         # Solo 1 worker porque solo hay 1 hostname
CONTAINER_NAME="pqc-calibration-server"
HOST_PORT="4433"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          Ejecutar Pruebas de Calibración PQC                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar que el servidor está corriendo
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${RED}❌ Error: El servidor de calibración no está corriendo${NC}"
    echo "Ejecuta primero: ./scripts/calibracion/levantar_servidor.sh"
    exit 1
fi

echo -e "${CYAN}📋 Configuración:${NC}"
echo "  • Dataset: ${DATASET_CSV}"
echo "  • Servidor: localhost:${HOST_PORT}"
echo "  • Repeticiones por grupo: ${REPETICIONES}"
echo "  • Imagen Docker: ${DOCKER_IMAGE}"
echo ""

# Verificar que Docker esté disponible
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    exit 1
fi

# Verificar que el CSV existe
if [ ! -f "${PROJECT_DIR}/data/${DATASET_CSV}" ]; then
    echo -e "${RED}❌ Error: Archivo no encontrado: ${PROJECT_DIR}/data/${DATASET_CSV}${NC}"
    exit 1
fi

# Verificar que el Dockerfile existe
if [ ! -f "${PROJECT_DIR}/Dockerfile" ]; then
    echo -e "${RED}❌ Error: Dockerfile no encontrado en ${PROJECT_DIR}${NC}"
    exit 1
fi

# Crear directorio de resultados si no existe
mkdir -p "${PROJECT_DIR}/resultados"

# Verificar si la imagen existe, si no, construirla
if ! docker image inspect "${DOCKER_IMAGE}" &> /dev/null; then
    echo -e "${YELLOW}🔨 Construyendo imagen Docker: ${DOCKER_IMAGE}...${NC}"
    docker build -t "${DOCKER_IMAGE}" "${PROJECT_DIR}"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Imagen construida exitosamente${NC}"
    else
        echo -e "${RED}❌ Error al construir la imagen Docker${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ Imagen Docker encontrada${NC}"
fi

echo ""
echo -e "${GREEN}🔬 Iniciando pruebas de calibración...${NC}"
echo -e "${YELLOW}   (Esto puede tardar varios minutos dependiendo del número de repeticiones)${NC}"
echo ""

# Ejecutar el contenedor Docker con la sonda
# Necesitamos usar --network="host" para que el contenedor pueda acceder a localhost:4433
docker run --rm \
    --network="host" \
    -v "${PROJECT_DIR}/data:/app/data:ro" \
    -v "${PROJECT_DIR}/resultados:/app/resultados" \
    "${DOCKER_IMAGE}" \
    --input-csv "data/${DATASET_CSV}" \
    --max-hostnames "${MAX_HOSTNAMES}" \
    --repeticiones "${REPETICIONES}" \
    --max-workers "${MAX_WORKERS}" \
    --log-level "INFO"

# Verificar si se generaron resultados
if [ -f "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" ]; then
    echo ""
    echo -e "${GREEN}✅ Pruebas de calibración completadas${NC}"
    echo -e "${CYAN}📁 Resultados guardados en: ${PROJECT_DIR}/resultados/${NC}"
    echo ""
    
    # Mostrar resumen rápido si jq está disponible
    if command -v jq &> /dev/null; then
        echo -e "${CYAN}📊 Resumen de resultados:${NC}"
        jq -r '.resumen | "  • Total pruebas: \(.total_pruebas)\n  • Pruebas exitosas: \(.pruebas_exitosas)\n  • Tasa de éxito: \(.tasa_exito_pruebas_percent)%\n  • Tiempo total: \(.tiempo_total_segundos)s"' \
            "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
    fi
else
    echo -e "${RED}❌ Error: No se generaron resultados${NC}"
    exit 1
fi
