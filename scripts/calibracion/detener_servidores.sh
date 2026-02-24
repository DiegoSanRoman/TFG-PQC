#!/bin/bash
# detener_servidores.sh
# Script para detener AMBOS servidores PQC (legacy + moderno)

# Para asegurar que el script falle si algún comando falla y no haya resultados inconsistentes
set -e

# Colores para output
# \033 es el caracter ESC (escape).
# [ inicia la secuencia de control ANSI.
# 0;31m, 0;32m, etc. son codigos de color.
# La m indica "cambio de estilo".
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuración
LEGACY_CONTAINER="pqc-legacy-server"
MODERN_CONTAINER="pqc-modern-server"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Detener Servidores de Calibración PQC (Dual)         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar que Docker esté disponible (command -v busca docker en el PATH)
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    exit 1
fi

# ============================================================
# DETENER SERVIDOR LEGACY
# ============================================================
echo -e "${CYAN}🛑 Deteniendo servidor LEGACY...${NC}"

# docker ps lista contenedores en ejecución, --format muestra solo nombres, grep -q busca el nombre exacto
if docker ps --format '{{.Names}}' | grep -q "^${LEGACY_CONTAINER}$"; then
    docker stop "${LEGACY_CONTAINER}" > /dev/null 2>&1 # Detiene el contenedor stop detiene el contenedor pero no lo elimina, por eso se hace un rm después
    docker rm "${LEGACY_CONTAINER}" > /dev/null 2>&1 # Elimina el contenedor -rm elimina el contenedor, -f fuerza la eliminación incluso si está corriendo
    echo -e "${GREEN}✅ Servidor LEGACY detenido y eliminado${NC}"
else
    echo -e "${YELLOW}ℹ️  El servidor LEGACY no está corriendo${NC}"
fi

# ============================================================
# DETENER SERVIDOR MODERNO
# ============================================================
echo ""
echo -e "${CYAN}🛑 Deteniendo servidor MODERNO...${NC}"

# docker ps lista contenedores en ejecución, --format muestra solo nombres, grep -q busca el nombre exacto
if docker ps --format '{{.Names}}' | grep -q "^${MODERN_CONTAINER}$"; then
    docker stop "${MODERN_CONTAINER}" > /dev/null 2>&1 # Detiene el contenedor stop detiene el contenedor pero no lo elimina, por eso se hace un rm después
    docker rm "${MODERN_CONTAINER}" > /dev/null 2>&1 # Elimina el contenedor -rm elimina el contenedor, -f fuerza la eliminación incluso si está corriendo
    echo -e "${GREEN}✅ Servidor MODERNO detenido y eliminado${NC}"
else
    echo -e "${YELLOW}ℹ️  El servidor MODERNO no está corriendo${NC}"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          ✅ SERVIDORES DETENIDOS CORRECTAMENTE ✅              ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
