#!/bin/bash
# levantar_servidor_legacy.sh
# Script para levantar un servidor HTTPS con soporte PQC LEGACY
# Utiliza una versión antigua de openquantumsafe/nginx con nomenclatura kyber*

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuración
CONTAINER_NAME="pqc-legacy-server"
IMAGE_NAME="openquantumsafe/nginx:0.10.1"  # Versión legacy con soporte kyber*
HOST_PORT="4433"
CONTAINER_PORT="4433"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_CONF="${SCRIPT_DIR}/nginx-pqc-legacy.conf"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      Levantar Servidor HTTPS con Soporte PQC LEGACY          ║"
echo "║         (Algoritmos kyber*, p256_kyber*, frodo*, etc.)       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar que Docker esté disponible
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    echo "Asegúrate de tener Docker instalado y en el PATH"
    exit 1
fi

# Verificar si ya existe un contenedor con el mismo nombre
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}⚠️  Contenedor ${CONTAINER_NAME} ya existe${NC}"
    echo -e "${YELLOW}   Deteniéndolo y eliminándolo...${NC}"
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
fi

# Verificar si el puerto está en uso
if lsof -Pi :${HOST_PORT} -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${RED}❌ Error: Puerto ${HOST_PORT} ya está en uso${NC}"
    echo "Detén el proceso que está usando el puerto o cambia HOST_PORT en el script"
    exit 1
fi

echo -e "${CYAN}📦 Configuración:${NC}"
echo "  • Imagen Docker: ${IMAGE_NAME}"
echo "  • Nombre contenedor: ${CONTAINER_NAME}"
echo "  • Puerto: localhost:${HOST_PORT} → container:${CONTAINER_PORT}"
echo "  • Tipo: LEGACY (kyber768, x25519_kyber768, p256_kyber768, frodo*, bikel1, hqc128)"
echo "  • Config: Usando defaults de OpenSSL (sin configuración personalizada)"
echo ""

# Descargar imagen si no existe
if ! docker image inspect "${IMAGE_NAME}" &> /dev/null; then
    echo -e "${YELLOW}📥 Descargando imagen ${IMAGE_NAME}...${NC}"
    docker pull "${IMAGE_NAME}"
fi

# Levantar el servidor (SIN montar configuración personalizada, usa defaults de OpenSSL)
echo -e "${GREEN}🚀 Levantando servidor HTTPS con soporte PQC LEGACY...${NC}"

docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:${CONTAINER_PORT}" \
    "${IMAGE_NAME}"

# Verificar que el contenedor está corriendo
sleep 2

if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${GREEN}✅ Servidor LEGACY levantado exitosamente${NC}"
    echo ""
    echo -e "${CYAN}📊 Información del servidor:${NC}"
    echo "  • URL: https://localhost:${HOST_PORT}"
    echo "  • Estado: $(docker inspect -f '{{.State.Status}}' ${CONTAINER_NAME})"
    echo "  • Container ID: $(docker ps -q -f name=${CONTAINER_NAME})"
    echo "  • Algoritmos: kyber768, x25519_kyber768, p256_kyber768, frodo640aes, bikel1, hqc128, etc."
    echo ""
    echo -e "${YELLOW}💡 El servidor está configurado para algoritmos LEGACY${NC}"
    echo ""
else
    echo -e "${RED}❌ Error: El contenedor no pudo iniciarse${NC}"
    echo "Logs del contenedor:"
    docker logs "${CONTAINER_NAME}" 2>&1 || true
    exit 1
fi
