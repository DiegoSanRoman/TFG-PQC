#!/bin/bash
# calibrar_servidor_pqc.sh
# Script orquestador para calibración completa de servidor PQC local
# Levanta servidor → Ejecuta pruebas → Detiene servidor
# Uso: ./calibrar_servidor_pqc.sh [repeticiones]

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
echo "║        🔬 CALIBRACIÓN SERVIDOR PQC LOCAL 🔬                    ║"
echo "║                                                                ║"
echo "║  Prueba todos los grupos de criptografía post-cuántica        ║"
echo "║  contra un servidor HTTPS local con soporte PQC               ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}⚙️  Configuración de calibración:${NC}"
echo "  • Repeticiones por grupo: ${REPETICIONES}"
echo "  • Servidor: localhost:4433 (nginx con OQS)"
echo "  • Grupos a probar: 14 algoritmos PQC"
echo ""

# Función de limpieza en caso de error o interrupción
cleanup() {
    echo ""
    echo -e "${YELLOW}🧹 Limpiando recursos...${NC}"
    "${SCRIPTS_DIR}/detener_servidor.sh"
    exit 1
}

# Capturar señales de interrupción
trap cleanup SIGINT SIGTERM EXIT

# Verificar que los scripts existen y son ejecutables
if [ ! -f "${SCRIPTS_DIR}/levantar_servidor.sh" ]; then
    echo -e "${RED}❌ Error: Script no encontrado: ${SCRIPTS_DIR}/levantar_servidor.sh${NC}"
    exit 1
fi

if [ ! -f "${SCRIPTS_DIR}/ejecutar_pruebas_calibracion.sh" ]; then
    echo -e "${RED}❌ Error: Script no encontrado: ${SCRIPTS_DIR}/ejecutar_pruebas_calibracion.sh${NC}"
    exit 1
fi

if [ ! -f "${SCRIPTS_DIR}/detener_servidor.sh" ]; then
    echo -e "${RED}❌ Error: Script no encontrado: ${SCRIPTS_DIR}/detener_servidor.sh${NC}"
    exit 1
fi

# Dar permisos de ejecución a los scripts
chmod +x "${SCRIPTS_DIR}/levantar_servidor.sh"
chmod +x "${SCRIPTS_DIR}/ejecutar_pruebas_calibracion.sh"
chmod +x "${SCRIPTS_DIR}/detener_servidor.sh"

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Fase 1/3: Levantar Servidor PQC${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Paso 1: Levantar el servidor
if ! "${SCRIPTS_DIR}/levantar_servidor.sh"; then
    echo -e "${RED}❌ Error al levantar el servidor${NC}"
    trap - EXIT  # Desactivar trap para evitar doble ejecución
    exit 1
fi

# Esperar a que el servidor esté completamente listo
echo -e "${YELLOW}⏳ Esperando 5 segundos para que el servidor esté listo...${NC}"
sleep 5

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Fase 2/3: Ejecutar Pruebas de Calibración${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Paso 2: Ejecutar las pruebas
INICIO_TIEMPO=$(date +%s)

if ! "${SCRIPTS_DIR}/ejecutar_pruebas_calibracion.sh" "${REPETICIONES}"; then
    echo ""
    echo -e "${RED}❌ Error durante las pruebas de calibración${NC}"
    trap - EXIT  # Desactivar trap para que ejecute limpieza manual
    "${SCRIPTS_DIR}/detener_servidor.sh"
    exit 1
fi

FIN_TIEMPO=$(date +%s)
DURACION=$((FIN_TIEMPO - INICIO_TIEMPO))

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Fase 3/3: Detener Servidor${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Desactivar trap para limpieza manual controlada
trap - EXIT

# Paso 3: Detener el servidor
"${SCRIPTS_DIR}/detener_servidor.sh"

echo ""
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║              ✅ CALIBRACIÓN COMPLETADA ✅                      ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}📊 Resumen de ejecución:${NC}"
echo "  • Tiempo total: ${DURACION} segundos"
echo "  • Repeticiones por grupo: ${REPETICIONES}"
echo "  • Resultados: ${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
echo "  • Resumen CSV: ${PROJECT_DIR}/resultados/resumen_por_grupo.csv"
echo ""

# Mostrar estadísticas detalladas si jq está disponible
if command -v jq &> /dev/null && [ -f "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" ]; then
    echo -e "${CYAN}📈 Estadísticas de calibración:${NC}"
    jq -r '.resumen | "  • Total de pruebas: \(.total_pruebas)\n  • Pruebas exitosas: \(.pruebas_exitosas)\n  • Tasa de éxito: \(.tasa_exito_pruebas_percent)%\n  • Grupos probados: \(.grupos_probados | length)"' \
        "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
    echo ""
    echo -e "${YELLOW}💡 Grupos probados:${NC}"
    jq -r '.resumen.grupos_probados | .[] | "     - \(.)"' \
        "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
fi

echo ""
echo -e "${GREEN}🎯 Usa estos resultados para entender qué algoritmos PQC soporta tu servidor${NC}"
echo ""
