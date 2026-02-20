#!/bin/bash
# docker_probe_run.sh
# Ejecuta la sonda PQC contra el servidor de calibración en Docker
# Usa: ./docker_probe_run.sh [--hostname HOST] [--port PORT] [--repeticiones N] [--max-workers N]

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_IMAGE="tfg-sonda"

# Valores por defecto
HOSTNAME="localhost"
PORT="8443"
REPETICIONES="3"
MAX_WORKERS="5"

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
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
            echo -e "${RED}❌ Argumento desconocido: $1${NC}"
            echo "Uso: $0 [--hostname HOST] [--port PORT] [--repeticiones N] [--max-workers N]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║       Sonda PQC para Calibración contra Servidor              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}📋 Configuración:${NC}"
echo "  • Hostname: ${HOSTNAME}:${PORT}"
echo "  • Repeticiones: ${REPETICIONES}"
echo "  • Max workers: ${MAX_WORKERS}"
echo "  • Imagen Docker: ${DOCKER_IMAGE}"
echo ""

# Obtener la IP del contenedor del servidor
SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tfg-pqc-server 2>/dev/null)

if [ -z "$SERVER_IP" ]; then
    echo -e "${RED}❌ Error: No se pudo obtener la IP del servidor Docker${NC}"
    echo -e "${YELLOW}  Verifica que el servidor está corriendo: docker ps | grep tfg-pqc-server${NC}"
    exit 1
fi

echo -e "${YELLOW}📍 IP del servidor detectada: ${SERVER_IP}${NC}"

# Si se passa hostname=localhost, reemplazar con la IP del contenedor
if [ "$HOSTNAME" = "localhost" ] || [ "$HOSTNAME" = "127.0.0.1" ]; then
    HOSTNAME="$SERVER_IP"
    echo -e "${YELLOW}   (usando IP del contenedor en lugar de localhost)${NC}"
fi

echo ""

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    exit 1
fi

# Verificar/construir imagen
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

# Crear CSV de calibración con la IP del servidor (formato compatible con sonda)
mkdir -p "${PROJECT_DIR}/data"
CALIBRATION_CSV="${PROJECT_DIR}/data/calibration.csv"

# Usar encabezado "domain" para compatibilidad con la sonda
echo "domain" > "${CALIBRATION_CSV}"
echo "${HOSTNAME}:${PORT}" >> "${CALIBRATION_CSV}"

echo -e "${GREEN}✓ CSV de calibración creado con ${HOSTNAME}:${PORT}${NC}"

# Crear directorio de resultados
mkdir -p "${PROJECT_DIR}/resultados"

echo ""
echo -e "${BLUE}🚀 Iniciando sonda de calibración en Docker...${NC}"
echo -e "${YELLOW}Probando diferentes grupos PQC contra ${HOSTNAME}:${PORT}${NC}"
echo ""

# Ejecutar la sonda usando la red default bridge de Docker
docker run -it --rm \
  -v "${PROJECT_DIR}/data:/app/data" \
  -v "${PROJECT_DIR}/resultados:/app/resultados" \
  "${DOCKER_IMAGE}" \
  --input-csv /app/data/calibration.csv \
  --max-hostnames 1 \
  --repeticiones "${REPETICIONES}" \
  --max-workers "${MAX_WORKERS}"

EXIT_CODE=$?

echo ""

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ ¡Sonda de calibración completada exitosamente!${NC}"
    echo -e "${BLUE}📁 Resultados guardados en:${NC}"
    echo "  • JSON: ${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
    echo "  • CSV:  ${PROJECT_DIR}/resultados/resumen_por_grupo.csv"
    echo "  • LOG:  ${PROJECT_DIR}/resultados/sonda_pqc.log"
    echo ""
else
    echo -e "${RED}❌ Error durante la ejecución (código: $EXIT_CODE)${NC}"
    exit $EXIT_CODE
fi
