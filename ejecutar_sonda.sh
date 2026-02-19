#!/bin/bash
# ejecutar_sonda.sh
# Script auxiliar para ejecutar la sonda PQC dentro de Docker
# Uso: ./ejecutar_sonda.sh --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N]

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directorio base del proyecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Valores por defecto
MAX_HOSTNAMES="100"
REPETICIONES="3"
MAX_WORKERS="20"
DOCKER_IMAGE="tfg-sonda"
DATASET_CSV="majestic_million.csv"

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --input-csv)
            DATASET_CSV="$2"
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
            echo -e "${RED}❌ Argumento desconocido: $1${NC}"
            echo "Uso: $0 --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           Ejecutar Sonda PQC con Docker                       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Mostrar configuración
echo -e "${YELLOW}📋 Configuración:${NC}"
echo "  • Dataset: ${DATASET_CSV}"
echo "  • Max hostnames: ${MAX_HOSTNAMES}"
echo "  • Repeticiones: ${REPETICIONES}"
echo "  • Hilos paralelelos: ${MAX_WORKERS}"
echo "  • Imagen Docker: ${DOCKER_IMAGE}"
echo ""

# Verificar que Docker esté disponible
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    echo "Asegúrate de tener Docker instalado y en el PATH"
    exit 1
fi

# Verificar que el CSV existe
if [ ! -f "${PROJECT_DIR}/data/${DATASET_CSV}" ]; then
    echo -e "${RED}❌ Error: Archivo no encontrado: ${PROJECT_DIR}/data/${DATASET_CSV}${NC}"
    echo "Archivos disponibles en data/:"
    ls -1 "${PROJECT_DIR}/data/" 2>/dev/null || echo "  (directorio vacío)"
    exit 1
fi

# Verificar que el Dockerfile existe
if [ ! -f "${PROJECT_DIR}/Dockerfile" ]; then
    echo -e "${RED}❌ Error: Dockerfile no encontrado en ${PROJECT_DIR}${NC}"
    exit 1
fi

# Crear directorio de resultados si no existe
mkdir -p "${PROJECT_DIR}/resultados"

# Verificar si la imagen existe, si no, la construimos
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
echo -e "${BLUE}🚀 Iniciando sonda PQC en Docker...${NC}"
echo -e "${YELLOW}Espera a que termine (puede tomar varios minutos)${NC}"
echo ""

# Ejecutar la sonda en Docker
docker run -it --rm \
  -v "${PROJECT_DIR}/data:/app/data" \
  -v "${PROJECT_DIR}/resultados:/app/resultados" \
  "${DOCKER_IMAGE}" \
  --input-csv /app/data/${DATASET_CSV} \
  --max-hostnames "${MAX_HOSTNAMES}" \
  --repeticiones "${REPETICIONES}" \
  --max-workers "${MAX_WORKERS}"

EXIT_CODE=$?

echo ""

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ ¡Sonda completada exitosamente!${NC}"
    echo -e "${BLUE}📁 Resultados guardados en:${NC}"
    echo "  • JSON: ${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
    echo "  • CSV:  ${PROJECT_DIR}/resultados/resumen_por_grupo.csv"
    echo "  • LOG:  ${PROJECT_DIR}/resultados/sonda_pqc.log"
    echo ""
    echo -e "${YELLOW}💡 Próximo paso: ejecutar análisis${NC}"
    echo "  $ ./ejecutar_analisis.sh"
else
    echo -e "${RED}❌ Error durante la ejecución (código: $EXIT_CODE)${NC}"
    exit $EXIT_CODE
fi
