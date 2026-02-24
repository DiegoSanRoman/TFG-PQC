#!/bin/bash
# ejecutar_analisis.sh
# Script auxiliar para ejecutar el análisis de sondas PQC
# Uso: ./ejecutar_analisis.sh [archivo_json] [directorio_salida]

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
NC='\033[0m' # No Color

# Directorio base del proyecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Ruta al entorno virtual
VENV_DIR="${PROJECT_DIR}/venv"
# Ruta al script de análisis
SCRIPT_PATH="${PROJECT_DIR}/scripts/ml/analizar_resultados.py"

# Valores por defecto para argumentos (permiten ejecutar sin argumentos para análisis rápido de resultados por defecto)
INPUT_JSON="${1:-${PROJECT_DIR}/resultados/resultados_sonda_pqc.json}"
OUTPUT_DIR="${2:-${PROJECT_DIR}/imagenes}"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Análisis y Visualización de Resultados de Sondas PQC      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar que Python 3 esté disponible (command -v busca python3 en el PATH)
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Error: python3 no encontrado${NC}"
    exit 1
fi

# Crear entorno virtual si no existe (-d comprueba si existe el directorio)
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}📦 Creando entorno virtual...${NC}"   # -e sirve para el formato 
    python3 -m venv "$VENV_DIR" # -m venv crea un entorno virtual aislado
fi

# Activar entorno virtual
echo -e "${YELLOW}🔌 Activando entorno virtual...${NC}"
source "${VENV_DIR}/bin/activate"

# Instalar dependencias si no están presentes
echo -e "${YELLOW}📥 Verificando dependencias...${NC}"
pip install -q pandas numpy matplotlib seaborn 2>/dev/null || {     # -q silencia la salida de pip, y 2>/dev/null redirige errores a null para evitar ruido
    echo -e "${YELLOW}   Instalando paquetes requeridos...${NC}"
    pip install pandas numpy matplotlib seaborn
}

# Verificar que el archivo JSON existe (-f comprueba archivo regular)
if [ ! -f "$INPUT_JSON" ]; then
    echo -e "${RED}❌ Error: Archivo no encontrado: $INPUT_JSON${NC}"
    echo -e "${YELLOW}Uso: $0 [archivo_json] [directorio_salida]${NC}"
    exit 1
fi

# Crear directorio de salida si no existe (-p permite crear directorios padres si no existen)
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}✓ Configuración completada${NC}"
echo -e "${BLUE}📊 Ejecutando análisis...${NC}"
echo ""

# Ejecutar el análisis con el script de Python, pasando los argumentos necesarios
python "$SCRIPT_PATH" --input "$INPUT_JSON" --output "$OUTPUT_DIR"

# Mostrar resumen
echo ""
echo -e "${GREEN}✅ Análisis completado exitosamente${NC}"
echo -e "${BLUE}📁 Archivos generados en: $OUTPUT_DIR${NC}"
echo ""
echo "Gráficas generadas:"
ls -1 "$OUTPUT_DIR"/*.png 2>/dev/null | xargs -n1 basename || echo "No se encontraron gráficas"
