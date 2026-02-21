#!/bin/bash
# detener_servidor_legacy.sh
# Script para detener el servidor de calibración PQC LEGACY

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
CONTAINER_NAME="pqc-legacy-server"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        Detener Servidor de Calibración PQC LEGACY            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar si el contenedor existe
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}🛑 Deteniendo servidor LEGACY...${NC}"
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    echo -e "${GREEN}✅ Servidor LEGACY detenido y eliminado${NC}"
else
    echo -e "${YELLOW}ℹ️  El servidor LEGACY no está corriendo${NC}"
fi

echo ""
