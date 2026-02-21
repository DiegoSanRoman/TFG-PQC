#!/bin/bash
# calibrar_servidor_pqc_dual.sh
# Script orquestador para calibración DUAL de servidores PQC
# Levanta AMBOS servidores (legacy + moderno) → Ejecuta pruebas → Detiene servidores
# Uso: ./calibrar_servidor_pqc_dual.sh [repeticiones]

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Directorio base del proyecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuración
REPETICIONES="${1:-5}"  # Por defecto 5 repeticiones
SCRIPTS_DIR="${PROJECT_DIR}/scripts/calibracion"

echo ""
echo -e "${MAGENTA}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║        🔬 CALIBRACIÓN DUAL: SERVIDORES PQC 🔬                  ║"
echo "║                                                                ║"
echo "║  Prueba algoritmos LEGACY (kyber*) y MODERNOS (mlkem*)        ║"
echo "║  contra dos servidores HTTPS locales con soporte PQC          ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}⚙️  Configuración de calibración DUAL:${NC}"
echo "  • Repeticiones por grupo: ${REPETICIONES}"
echo "  • Servidor LEGACY: localhost:4433 (nginx 0.10.1 con kyber*, frodo*, bikel1, hqc128)"
echo "  • Servidor MODERNO: localhost:4434 (nginx latest con mlkem*)"
echo "  • Total de algoritmos probados: 14"
echo ""

# Función de limpieza en caso de error o interrupción
cleanup() {
    echo ""
    echo -e "${YELLOW}🧹 Limpiando recursos...${NC}"
    "${SCRIPTS_DIR}/detener_servidores.sh"
    exit 1
}

# Capturar señales de interrupción
trap cleanup SIGINT SIGTERM EXIT

# Verificar que los scripts existen y son ejecutables
REQUIRED_SCRIPTS=(
    "levantar_servidores.sh"
    "detener_servidores.sh"
)

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [ ! -f "${SCRIPTS_DIR}/${script}" ]; then
        echo -e "${RED}❌ Error: Script no encontrado: ${SCRIPTS_DIR}/${script}${NC}"
        exit 1
    fi
    chmod +x "${SCRIPTS_DIR}/${script}"
done

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Fase 1/4: Levantar Servidores PQC (Legacy + Moderno)${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Paso 1: Levantar ambos servidores
if ! "${SCRIPTS_DIR}/levantar_servidores.sh"; then
    echo -e "${RED}❌ Error al levantar los servidores${NC}"
    trap - EXIT
    exit 1
fi

# Esperar a que ambos servidores estén completamente listos
echo -e "${YELLOW}⏳ Esperando 5 segundos para que los servidores estén listos...${NC}"
sleep 5

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Fase 2/4: Ejecutar Pruebas contra Servidor LEGACY${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Paso 3: Ejecutar pruebas contra el servidor LEGACY
INICIO_TIEMPO=$(date +%s)

# Ejecutar pruebas contra LEGACY usando su CSV
DOCKER_IMAGE="tfg-sonda"
DATASET_CSV="calibracion_legacy.csv"
MAX_HOSTNAMES="1"
MAX_WORKERS="1"
CONTAINER_NAME="pqc-legacy-server"

echo -e "${CYAN}🧪 Probando algoritmos LEGACY (kyber*, x25519_kyber*, p256_kyber*, frodo*, bikel1, hqc128)${NC}"

if ! docker run --rm \
    --network="host" \
    -v "${PROJECT_DIR}/data:/app/data:ro" \
    -v "${PROJECT_DIR}/resultados:/app/resultados" \
    "${DOCKER_IMAGE}" \
    --input-csv "data/${DATASET_CSV}" \
    --max-hostnames "${MAX_HOSTNAMES}" \
    --repeticiones "${REPETICIONES}" \
    --max-workers "${MAX_WORKERS}" \
    --log-level "INFO"; then
    echo -e "${RED}❌ Error al ejecutar pruebas LEGACY${NC}"
    trap - EXIT
    "${SCRIPTS_DIR}/detener_servidores.sh"
    exit 1
fi

# Copiar resultados del legacy
if [ -f "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" ]; then
    cp "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" \
       "${PROJECT_DIR}/resultados/resultados_calibracion_legacy.json"
    cp "${PROJECT_DIR}/resultados/resumen_por_grupo.csv" \
       "${PROJECT_DIR}/resultados/resumen_calibracion_legacy.csv" 2>/dev/null || true
fi

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Fase 3/4: Ejecutar Pruebas contra Servidor MODERNO${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Paso 4: Ejecutar pruebas contra el servidor MODERNO
DATASET_CSV="calibracion_moderno.csv"

echo -e "${CYAN}🧪 Probando algoritmos MODERNOS (mlkem768, x25519_mlkem768, x25519_mlkem512, secp256r1_mlkem768)${NC}"

if ! docker run --rm \
    --network="host" \
    -v "${PROJECT_DIR}/data:/app/data:ro" \
    -v "${PROJECT_DIR}/resultados:/app/resultados" \
    "${DOCKER_IMAGE}" \
    --input-csv "data/${DATASET_CSV}" \
    --max-hostnames "${MAX_HOSTNAMES}" \
    --repeticiones "${REPETICIONES}" \
    --max-workers "${MAX_WORKERS}" \
    --log-level "INFO"; then
    echo -e "${RED}❌ Error al ejecutar pruebas MODERNO${NC}"
    trap - EXIT
    "${SCRIPTS_DIR}/detener_servidores.sh"
    exit 1
fi

# Copiar resultados del moderno
if [ -f "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" ]; then
    cp "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" \
       "${PROJECT_DIR}/resultados/resultados_calibracion_moderno.json"
    cp "${PROJECT_DIR}/resultados/resumen_por_grupo.csv" \
       "${PROJECT_DIR}/resultados/resumen_calibracion_moderno.csv" 2>/dev/null || true
fi

FIN_TIEMPO=$(date +%s)
DURACION=$((FIN_TIEMPO - INICIO_TIEMPO))

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Fase 4/4: Detener Servidores${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Desactivar trap para limpieza manual controlada
trap - EXIT

# Paso 4: Detener ambos servidores
"${SCRIPTS_DIR}/detener_servidores.sh"

echo ""
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║           ✅ CALIBRACIÓN DUAL COMPLETADA ✅                    ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}📊 Resumen de ejecución:${NC}"
echo "  • Tiempo total: ${DURACION} segundos"
echo "  • Repeticiones por grupo: ${REPETICIONES}"
echo "  • Resultados LEGACY: ${PROJECT_DIR}/resultados/resultados_calibracion_legacy.json"
echo "  • Resultados MODERNO: ${PROJECT_DIR}/resultados/resultados_calibracion_moderno.json"
echo "  • Resumen CSV LEGACY: ${PROJECT_DIR}/resultados/resumen_calibracion_legacy.csv"
echo "  • Resumen CSV MODERNO: ${PROJECT_DIR}/resultados/resumen_calibracion_moderno.csv"
echo ""

# Mostrar estadísticas combinadas si jq está disponible
if command -v jq &> /dev/null; then
    echo -e "${CYAN}📈 Estadísticas de calibración LEGACY:${NC}"
    if [ -f "${PROJECT_DIR}/resultados/resultados_calibracion_legacy.json" ]; then
        jq -r '.resumen | "  • Total de pruebas: \(.total_pruebas)\n  • Pruebas exitosas: \(.pruebas_exitosas)\n  • Tasa de éxito: \(.tasa_exito_pruebas_percent)%"' \
            "${PROJECT_DIR}/resultados/resultados_calibracion_legacy.json"
    fi
    echo ""
    echo -e "${CYAN}📈 Estadísticas de calibración MODERNO:${NC}"
    if [ -f "${PROJECT_DIR}/resultados/resultados_calibracion_moderno.json" ]; then
        jq -r '.resumen | "  • Total de pruebas: \(.total_pruebas)\n  • Pruebas exitosas: \(.pruebas_exitosas)\n  • Tasa de éxito: \(.tasa_exito_pruebas_percent)%"' \
            "${PROJECT_DIR}/resultados/resultados_calibracion_moderno.json"
    fi
fi

echo ""
echo -e "${GREEN}🎯 Ahora tienes cobertura completa de algoritmos PQC (LEGACY + MODERNO)${NC}"
echo ""
