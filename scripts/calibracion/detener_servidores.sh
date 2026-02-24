#!/bin/bash
# detener_servidores.sh
# Script para detener AMBOS servidores PQC (legacy + moderno)

# Para asegurar que el script falle si algún comando falla y no haya resultados inconsistentes
set -e


# Configuración
LEGACY_CONTAINER="pqc-legacy-server"
MODERN_CONTAINER="pqc-modern-server"

echo "====================================================================="
echo "         Detener Servidores de Calibracion PQC (Dual)"
echo "====================================================================="

# Verificar que Docker esté disponible (command -v busca docker en el PATH)
if ! command -v docker &> /dev/null; then
    echo "ERROR - Docker no encontrado"
    exit 1
fi

# ============================================================
# DETENER SERVIDOR LEGACY
# ============================================================
echo "--- Deteniendo servidor LEGACY..."

# docker ps lista contenedores en ejecución, --format muestra solo nombres, grep -q busca el nombre exacto
if docker ps --format '{{.Names}}' | grep -q "^${LEGACY_CONTAINER}$"; then
    docker stop "${LEGACY_CONTAINER}" > /dev/null 2>&1
    docker rm "${LEGACY_CONTAINER}" > /dev/null 2>&1
    echo "OK - Servidor LEGACY detenido y eliminado"
else
    echo "INFO - El servidor LEGACY no esta corriendo"
fi

# ============================================================
# DETENER SERVIDOR MODERNO
# ============================================================
echo ""
echo "--- Deteniendo servidor MODERNO..."

# docker ps lista contenedores en ejecución, --format muestra solo nombres, grep -q busca el nombre exacto
if docker ps --format '{{.Names}}' | grep -q "^${MODERN_CONTAINER}$"; then
    docker stop "${MODERN_CONTAINER}" > /dev/null 2>&1
    docker rm "${MODERN_CONTAINER}" > /dev/null 2>&1
    echo "OK - Servidor MODERNO detenido y eliminado"
else
    echo "INFO - El servidor MODERNO no esta corriendo"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "====================================================================="
echo "   OK - SERVIDORES DETENIDOS CORRECTAMENTE"
echo "====================================================================="
