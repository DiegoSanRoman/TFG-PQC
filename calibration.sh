#!/bin/bash
# calibration.sh
# Script maestro para ejecutar la calibración completa: servidor + sonda
# Uso: ./calibration.sh [--port PORT] [--repeticiones N] [--max-workers N] [--no-cleanup]

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="tfg-pqc-server"

# Valores por defecto
SERVER_PORT="8443"
REPETICIONES="3"
MAX_WORKERS="5"
CLEANUP=true

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            SERVER_PORT="$2"
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
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        *)
            echo -e "${RED}❌ Argumento desconocido: $1${NC}"
            echo "Uso: $0 [--port PORT] [--repeticiones N] [--max-workers N] [--no-cleanup]"
            exit 1
            ;;
    esac
done

# Headers
print_header() {
    echo -e "${MAGENTA}"
    echo "════════════════════════════════════════════════════════════════"
    echo "  🔐 CALIBRACIÓN COMPLETA - SERVIDOR PQC + SONDA"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

# Cleanup en caso de error o al finalizar
cleanup() {
    echo ""
    echo -e "${YELLOW}🧹 Limpiando recursos...${NC}"
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${YELLOW}  Deteniendo servidor Docker (${CONTAINER_NAME})...${NC}"
        docker stop "${CONTAINER_NAME}" 2>/dev/null || true
        docker rm "${CONTAINER_NAME}" 2>/dev/null || true
        echo -e "${GREEN}  ✓ Servidor detenido${NC}"
    fi
    echo ""
}

# Trap para limpiar al salir
trap cleanup EXIT

print_header

echo -e "${YELLOW}📋 Configuración de Calibración:${NC}"
echo "  • Puerto del servidor: ${SERVER_PORT}"
echo "  • Repeticiones por grupo: ${REPETICIONES}"
echo "  • Max workers: ${MAX_WORKERS}"
echo "  • Limpiar recursos al finalizar: ${CLEANUP}"
echo ""

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    exit 1
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${MAGENTA}PASO 1️⃣  - Iniciando Servidor PQC${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

bash "${PROJECT_DIR}/docker_server_run.sh" --port "${SERVER_PORT}"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Error al iniciar el servidor${NC}"
    exit 1
fi

# Esperar a que el servidor esté listo
echo ""
echo -e "${YELLOW}⏳ Esperando a que el servidor esté listo...${NC}"
sleep 3

# Intentar conectar al servidor una vez para verificar que está activo
SERVER_READY=false
for attempt in {1..10}; do
    if nc -z localhost "${SERVER_PORT}" 2>/dev/null || \
       timeout 2 bash -c "echo | openssl s_client -connect localhost:${SERVER_PORT}" &>/dev/null; then
        SERVER_READY=true
        echo -e "${GREEN}✓ Servidor respondiendo en puerto ${SERVER_PORT}${NC}"
        break
    fi
    echo -e "${YELLOW}  Intento ${attempt}/10 - esperando servidor...${NC}"
    sleep 1
done

if [ "$SERVER_READY" = false ]; then
    echo -e "${YELLOW}⚠️  No se pudo verificar el servidor, pero continuando...${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${MAGENTA}PASO 2️⃣  - Ejecutando Sonda de Calibración${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

bash "${PROJECT_DIR}/docker_probe_run.sh" \
  --hostname "localhost" \
  --port "${SERVER_PORT}" \
  --repeticiones "${REPETICIONES}" \
  --max-workers "${MAX_WORKERS}"

PROBE_EXIT=$?

if [ $PROBE_EXIT -ne 0 ]; then
    echo -e "${RED}❌ Error al ejecutar la sonda${NC}"
    exit $PROBE_EXIT
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ CALIBRACIÓN COMPLETADA EXITOSAMENTE${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}📊 Resultados disponibles en:${NC}"
echo "  • JSON: ${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
echo "  • CSV:  ${PROJECT_DIR}/resultados/resumen_por_grupo.csv"
echo "  • LOG:  ${PROJECT_DIR}/resultados/sonda_pqc.log"
echo ""

echo -e "${YELLOW}💡 Próximos pasos:${NC}"
echo "  1. Revisar los resultados en: ${PROJECT_DIR}/resultados/"
echo "  2. Ejecutar análisis: ./ejecutar_analisis.sh"
echo "  3. O ejecutar otra calibración con diferentes parámetros"
echo ""

if [ "$CLEANUP" = true ]; then
    echo -e "${YELLOW}⏳ Los recursos Docker se limpiarán automáticamente${NC}"
else
    echo -e "${YELLOW}⚠️  NOTA: Los recursos Docker NO se han limpiado (--no-cleanup usado)${NC}"
    echo "         Detén manualmente con: docker stop ${CONTAINER_NAME}"
fi

echo ""
