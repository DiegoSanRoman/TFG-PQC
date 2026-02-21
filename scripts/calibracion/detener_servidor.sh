#!/bin/bash
# detener_servidor.sh
# Script para detener el servidor de calibración PQC

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
CONTAINER_NAME="pqc-calibration-server"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           Detener Servidor de Calibración PQC                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar si el contenedor existe
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}🛑 Deteniendo servidor...${NC}"
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    echo -e "${GREEN}✅ Servidor detenido y eliminado${NC}"
else
    echo -e "${YELLOW}ℹ️  El servidor no está corriendo${NC}"
fi

echo ""
