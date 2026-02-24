#!/bin/bash
# levantar_servidores.sh
# Script para levantar AMBOS servidores PQC (legacy + moderno) simultáneamente

# Para asegurar que el script falle si algún comando falla y no haya resultados inconsistentes
set -e

echo "====================================================================="
echo "     Levantar Servidores HTTPS con Soporte PQC (Dual)"
echo "            LEGACY (4433) + MODERNO (4434)"
echo "====================================================================="

# Verificar que Docker esté disponible (command -v busca docker en el PATH)
if ! command -v docker &> /dev/null; then
    echo "ERROR - Docker no encontrado"
    exit 1
fi

# ============================================================
# SERVIDOR LEGACY (kyber*, frodo*, bikel1, hqc128) (nginx con Open Quantum Safe - legacy significa que antiguo)
# ============================================================
LEGACY_CONTAINER="pqc-legacy-server"
LEGACY_IMAGE="openquantumsafe/nginx:0.10.1" # Esta versión es la última que incluye soporte para los algoritmos "legacy" (kyber*, frodo*, bikel1, hqc128). Las versiones posteriores solo incluyen los modernos (mlkem*).
LEGACY_PORT="4433"

echo "--- Levantando servidor LEGACY..."
echo "  - Imagen: ${LEGACY_IMAGE}"
echo "  - Puerto: localhost:${LEGACY_PORT}"
echo "  - Algoritmos: kyber*, x25519_kyber*, p256_kyber*, frodo*, bikel1, hqc128"
echo ""

# Detener contenedor anterior si existe 
# docker ps -a lista todos los contenedores, --format muestra solo nombres, grep -q busca el nombre exacto
if docker ps -a --format '{{.Names}}' | grep -q "^${LEGACY_CONTAINER}$"; then
    docker rm -f "${LEGACY_CONTAINER}" > /dev/null 2>&1 # -f fuerza la eliminación incluso si está corriendo
fi

# Verificar si el puerto está ocupado
# lsof -Pi busca procesos en el puerto, -sTCP:LISTEN filtra por conexiones escuchando, -t muestra solo PIDs
if lsof -Pi :${LEGACY_PORT} -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "ERROR - Puerto ${LEGACY_PORT} ya está en uso"
    exit 1
fi

# Levantar servidor LEGACY
# -d: modo detached (background), --name: nombre del contenedor
# -p puerto_host:puerto_contenedor mapea puertos entre host y contenedor
docker run -d \
    --name "${LEGACY_CONTAINER}" \
    -p "${LEGACY_PORT}:4433" \
    "${LEGACY_IMAGE}" > /dev/null

if [ $? -eq 0 ]; then # $? contiene el código de salida del docker run (0 = éxito)
    echo "OK - Servidor LEGACY levantado (${LEGACY_CONTAINER})"
else
    echo "ERROR - Error al levantar servidor LEGACY"
    exit 1
fi

# ============================================================
# SERVIDOR MODERNO (mlkem*, x25519_mlkem*, secp256r1_mlkem*)
# ============================================================
MODERN_CONTAINER="pqc-modern-server"
MODERN_IMAGE="openquantumsafe/nginx:latest"
MODERN_PORT="4434"

echo ""
echo "--- Levantando servidor MODERNO..."
echo "  - Imagen: ${MODERN_IMAGE}"
echo "  - Puerto: localhost:${MODERN_PORT}"
echo "  - Algoritmos: mlkem*, x25519_mlkem*, secp256r1_mlkem*"
echo ""

# Detener contenedor anterior si existe
# docker ps -a lista todos los contenedores, --format muestra solo nombres, grep -q busca el nombre exacto
if docker ps -a --format '{{.Names}}' | grep -q "^${MODERN_CONTAINER}$"; then
    docker rm -f "${MODERN_CONTAINER}" > /dev/null 2>&1 # -f fuerza la eliminación incluso si está corriendo
fi

# Verificar si el puerto está ocupado
# lsof -Pi busca procesos en el puerto, -sTCP:LISTEN filtra por conexiones escuchando, -t muestra solo PIDs
if lsof -Pi :${MODERN_PORT} -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "ERROR - Puerto ${MODERN_PORT} ya está en uso"
    # Limpiar servidor legacy
    docker rm -f "${LEGACY_CONTAINER}" > /dev/null 2>&1
    exit 1
fi

# Levantar servidor MODERNO
# -d: modo detached (background), --name: nombre del contenedor
# -p puerto_host:puerto_contenedor mapea puertos entre host y contenedor
docker run -d \
    --name "${MODERN_CONTAINER}" \
    -p "${MODERN_PORT}:4433" \
    "${MODERN_IMAGE}" > /dev/null

if [ $? -eq 0 ]; then # $? contiene el código de salida del docker run (0 = éxito)
    echo "OK - Servidor MODERNO levantado (${MODERN_CONTAINER})"
else
    echo "ERROR - Error al levantar servidor MODERNO"
    # Limpiar servidor legacy -rm elimina el contenedor, -f fuerza la eliminación incluso si está corriendo
    docker rm -f "${LEGACY_CONTAINER}" > /dev/null 2>&1
    exit 1
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "====================================================================="
echo "            OK - AMBOS SERVIDORES LEVANTADOS"
echo "====================================================================="
echo ""
echo "--- Servidores en ejecucion:"
echo "  - LEGACY:  https://localhost:${LEGACY_PORT} (${LEGACY_CONTAINER})"
echo "  - MODERNO: https://localhost:${MODERN_PORT} (${MODERN_CONTAINER})"
echo ""
echo "--- Para detenerlos: ./scripts/calibracion/detener_servidores.sh"
