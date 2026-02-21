#!/bin/bash
# detener_servidor_moderno.sh
# Script para detener el servidor de calibración PQC MODERNO

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
CONTAINER_NAME="pqc-modern-server"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║       Detener Servidor de Calibración PQC MODERNO            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar si el contenedor existe
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}🛑 Deteniendo servidor MODERNO...${NC}"
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    echo -e "${GREEN}✅ Servidor MODERNO detenido y eliminado${NC}"
else
    echo -e "${YELLOW}ℹ️  El servidor MODERNO no está corriendo${NC}"
fi

echo ""
