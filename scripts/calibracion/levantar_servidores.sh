#!/bin/bash
# levantar_servidores.sh
# Script para levantar AMBOS servidores PQC (legacy + moderno) simultáneamente

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Levantar Servidores HTTPS con Soporte PQC (Dual)         ║"
echo "║            LEGACY (4433) + MODERNO (4434)                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar que Docker esté disponible
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    exit 1
fi

# ============================================================
# SERVIDOR LEGACY (kyber*, frodo*, bikel1, hqc128)
# ============================================================
LEGACY_CONTAINER="pqc-legacy-server"
LEGACY_IMAGE="openquantumsafe/nginx:0.10.1"
LEGACY_PORT="4433"

echo -e "${CYAN}🚀 Levantando servidor LEGACY...${NC}"
echo -e "  • Imagen: ${LEGACY_IMAGE}"
echo -e "  • Puerto: localhost:${LEGACY_PORT}"
echo -e "  • Algoritmos: kyber*, x25519_kyber*, p256_kyber*, frodo*, bikel1, hqc128"
echo ""

# Detener contenedor anterior si existe
if docker ps -a --format '{{.Names}}' | grep -q "^${LEGACY_CONTAINER}$"; then
    docker rm -f "${LEGACY_CONTAINER}" > /dev/null 2>&1
fi

# Verificar si el puerto está ocupado
if lsof -Pi :${LEGACY_PORT} -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${RED}❌ Error: Puerto ${LEGACY_PORT} ya está en uso${NC}"
    exit 1
fi

# Levantar servidor LEGACY
docker run -d \
    --name "${LEGACY_CONTAINER}" \
    -p "${LEGACY_PORT}:4433" \
    "${LEGACY_IMAGE}" > /dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Servidor LEGACY levantado (${LEGACY_CONTAINER})${NC}"
else
    echo -e "${RED}❌ Error al levantar servidor LEGACY${NC}"
    exit 1
fi

# ============================================================
# SERVIDOR MODERNO (mlkem*, x25519_mlkem*, secp256r1_mlkem*)
# ============================================================
MODERN_CONTAINER="pqc-modern-server"
MODERN_IMAGE="openquantumsafe/nginx:latest"
MODERN_PORT="4434"

echo ""
echo -e "${CYAN}🚀 Levantando servidor MODERNO...${NC}"
echo -e "  • Imagen: ${MODERN_IMAGE}"
echo -e "  • Puerto: localhost:${MODERN_PORT}"
echo -e "  • Algoritmos: mlkem*, x25519_mlkem*, secp256r1_mlkem*"
echo ""

# Detener contenedor anterior si existe
if docker ps -a --format '{{.Names}}' | grep -q "^${MODERN_CONTAINER}$"; then
    docker rm -f "${MODERN_CONTAINER}" > /dev/null 2>&1
fi

# Verificar si el puerto está ocupado
if lsof -Pi :${MODERN_PORT} -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${RED}❌ Error: Puerto ${MODERN_PORT} ya está en uso${NC}"
    # Limpiar servidor legacy
    docker rm -f "${LEGACY_CONTAINER}" > /dev/null 2>&1
    exit 1
fi

# Levantar servidor MODERNO
docker run -d \
    --name "${MODERN_CONTAINER}" \
    -p "${MODERN_PORT}:4433" \
    "${MODERN_IMAGE}" > /dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Servidor MODERNO levantado (${MODERN_CONTAINER})${NC}"
else
    echo -e "${RED}❌ Error al levantar servidor MODERNO${NC}"
    # Limpiar servidor legacy
    docker rm -f "${LEGACY_CONTAINER}" > /dev/null 2>&1
    exit 1
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            ✅ AMBOS SERVIDORES LEVANTADOS ✅                   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}📊 Servidores en ejecución:${NC}"
echo -e "  • LEGACY:  https://localhost:${LEGACY_PORT} (${LEGACY_CONTAINER})"
echo -e "  • MODERNO: https://localhost:${MODERN_PORT} (${MODERN_CONTAINER})"
echo ""
echo -e "${YELLOW}💡 Para detenerlos: ./scripts/calibracion/detener_servidores.sh${NC}"
