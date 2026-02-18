#!/bin/bash
# ejecutar_analisis.sh
# Script auxiliar para ejecutar el análisis de sondas PQC
# Uso: ./ejecutar_analisis.sh [archivo_json] [directorio_salida]

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directorio base del proyecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"
SCRIPT_PATH="${PROJECT_DIR}/scripts/ml/analizar_resultados.py"

# Valores por defecto
INPUT_JSON="${1:-${PROJECT_DIR}/resultados/resultados_sonda_pqc.json}"
OUTPUT_DIR="${2:-${PROJECT_DIR}/imagenes}"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Análisis y Visualización de Resultados de Sondas PQC      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar que Python 3 esté disponible
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Error: python3 no encontrado${NC}"
    exit 1
fi

# Crear entorno virtual si no existe
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}📦 Creando entorno virtual...${NC}"
    python3 -m venv "$VENV_DIR"
fi

# Activar entorno virtual
echo -e "${YELLOW}🔌 Activando entorno virtual...${NC}"
source "${VENV_DIR}/bin/activate"

# Instalar dependencias si no están presentes
echo -e "${YELLOW}📥 Verificando dependencias...${NC}"
pip install -q pandas numpy matplotlib seaborn 2>/dev/null || {
    echo -e "${YELLOW}   Instalando paquetes requeridos...${NC}"
    pip install pandas numpy matplotlib seaborn
}

# Verificar que el archivo JSON existe
if [ ! -f "$INPUT_JSON" ]; then
    echo -e "${RED}❌ Error: Archivo no encontrado: $INPUT_JSON${NC}"
    echo -e "${YELLOW}Uso: $0 [archivo_json] [directorio_salida]${NC}"
    exit 1
fi

# Crear directorio de salida
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}✓ Configuración completada${NC}"
echo -e "${BLUE}📊 Ejecutando análisis...${NC}"
echo ""

# Ejecutar el análisis
python "$SCRIPT_PATH" --input "$INPUT_JSON" --output "$OUTPUT_DIR"

# Mostrar resumen
echo ""
echo -e "${GREEN}✅ Análisis completado exitosamente${NC}"
echo -e "${BLUE}📁 Archivos generados en: $OUTPUT_DIR${NC}"
echo ""
echo "Gráficas generadas:"
ls -1 "$OUTPUT_DIR"/*.png 2>/dev/null | xargs -n1 basename || echo "No se encontraron gráficas"
