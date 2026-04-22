#!/bin/bash
# ejecutar_analisis.sh
# Script auxiliar para ejecutar el análisis de sondas PQC
# Uso: ./ejecutar_analisis.sh [archivo_json] [directorio_salida]

# Para asegurar que el script falle si algún comando falla y no haya resultados inconsistentes
set -e

# Directorio base del proyecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Ruta al entorno virtual
VENV_DIR="${PROJECT_DIR}/venv"
# Ruta al script de análisis
SCRIPT_PATH="${PROJECT_DIR}/scripts/ml/analizar_resultados.py"

# Valores por defecto para argumentos (permiten ejecutar sin argumentos para análisis rápido de resultados por defecto)
INPUT_JSON="${1:-${PROJECT_DIR}/resultados/resultados_sonda_pqc.json}"
OUTPUT_DIR="${2:-${PROJECT_DIR}/imagenes}"

echo ""
echo "====================================================================="
echo "     Análisis y Visualización de Resultados de Sondas PQC"
echo "====================================================================="
echo ""

# Verificar que Python 3 esté disponible (command -v busca python3 en el PATH)
if ! command -v python3 &> /dev/null; then
    echo "ERROR - python3 no encontrado"
    exit 1
fi

PYTHON_CMD="python"

# En contenedor usamos paquetes ya preinstalados en la imagen para evitar fallos TLS con pip.
if [ -f "/.dockerenv" ]; then
    echo "--- Entorno Docker detectado: usando Python del sistema con dependencias de la imagen..."
    PYTHON_CMD="python3"
    python3 -c "import pandas, numpy, matplotlib, seaborn" 2>/dev/null || {
        echo "ERROR - Faltan dependencias Python en la imagen Docker"
        exit 1
    }
else
    # Crear entorno virtual si no existe (-d comprueba si existe el directorio)
    if [ ! -d "$VENV_DIR" ]; then
        echo "--- Creando entorno virtual..."   # -e sirve para el formato
        python3 -m venv "$VENV_DIR" # -m venv crea un entorno virtual aislado
    fi

    # Activar entorno virtual
    echo "--- Activando entorno virtual..."
    source "${VENV_DIR}/bin/activate"

    # Instalar dependencias si no están presentes
    echo "--- Verificando dependencias..."
    pip install -q pandas numpy matplotlib seaborn dnspython cryptography
fi

# Verificar que el archivo JSON existe (-f comprueba archivo regular)
if [ ! -f "$INPUT_JSON" ]; then
    echo "ERROR - Archivo no encontrado: $INPUT_JSON"
    echo "Uso: $0 [archivo_json] [directorio_salida]"
    exit 1
fi

# Crear directorio de salida si no existe (-p permite crear directorios padres si no existen)
mkdir -p "$OUTPUT_DIR"

echo "OK - Configuracion completada"
echo "--- Ejecutando análisis..."
echo ""

# Ejecutar el análisis con el script de Python, pasando los argumentos necesarios
"$PYTHON_CMD" "$SCRIPT_PATH" --input "$INPUT_JSON" --output "$OUTPUT_DIR"

# Mostrar resumen
echo ""
echo "OK - Análisis completado exitosamente"
echo "--- Archivos generados en: $OUTPUT_DIR"
echo ""
echo "Gráficas generadas:"
ls -1 "$OUTPUT_DIR"/*.png 2>/dev/null | xargs -n1 basename || echo "No se encontraron gráficas"
