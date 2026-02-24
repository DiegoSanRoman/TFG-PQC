#!/bin/bash
# ejecutar_sonda.sh
# Script auxiliar para ejecutar la sonda PQC dentro de Docker
# Uso: ./ejecutar_sonda.sh --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N]

# Para asegurar que el script falle si algún comando falla y no haya resultados inconsistentes
set -e

# Directorio base del proyecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Valores por defecto
MAX_HOSTNAMES="100"
REPETICIONES="3"
MAX_WORKERS="20"
DOCKER_IMAGE="tfg-sonda"
DATASET_CSV="majestic_million.csv"

# Parsear argumentos
# Mientras sigue habiendo argumentos, procesarlos
while [[ $# -gt 0 ]]; do
    case $1 in
        --input-csv)
            DATASET_CSV="$2"
            shift 2
            ;;
        --max-hostnames)
            MAX_HOSTNAMES="$2"
            shift 2
            ;;
        --repeticiones)
            REPETICIONES="$2"
            shift 2
            ;;
        --max-workers)
            MAX_WORKERS="$2"
            shift 2
            ;;
        *)
        echo "- Argumento desconocido: $1"
            echo "Uso: $0 --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N]"
            exit 1
            ;;
    esac
done

echo ""
echo "====================================================================="
echo "           Ejecutar Sonda PQC con Docker"
echo "====================================================================="
echo ""

# Mostrar configuración
echo "--- Configuracion:"
echo "  • Dataset: ${DATASET_CSV}"
echo "  • Max hostnames: ${MAX_HOSTNAMES}"
echo "  • Repeticiones: ${REPETICIONES}"
echo "  • Hilos paralelelos: ${MAX_WORKERS}"
echo "  • Imagen Docker: ${DOCKER_IMAGE}"
echo ""

# Verificar que Docker esté disponible (command -v busca docker en el PATH; si no esta, aborta)
if ! command -v docker &> /dev/null; then
    echo "ERROR - Docker no encontrado"
    echo "Asegúrate de tener Docker instalado y en el PATH"
    exit 1
fi

# Verificar que el CSV existe (-f comprueba archivo regular)
if [ ! -f "${PROJECT_DIR}/data/${DATASET_CSV}" ]; then
    echo "ERROR - Archivo no encontrado: ${PROJECT_DIR}/data/${DATASET_CSV}"
    echo "Archivos disponibles en data/:"
    ls -1 "${PROJECT_DIR}/data/" 2>/dev/null || echo "  (directorio vacío)"
    exit 1
fi

# Verificar que el Dockerfile existe (-f comprueba archivo regular)
if [ ! -f "${PROJECT_DIR}/Dockerfile" ]; then
    echo "ERROR - Dockerfile no encontrado en ${PROJECT_DIR}"
    exit 1
fi

# Crear directorio de resultados si no existe
mkdir -p "${PROJECT_DIR}/resultados"

# Verificar si la imagen existe, si no, la construimos
if ! docker image inspect "${DOCKER_IMAGE}" &> /dev/null; then
    echo "--- Construyendo imagen Docker: ${DOCKER_IMAGE}..."
    docker build -t "${DOCKER_IMAGE}" "${PROJECT_DIR}"
    if [ $? -eq 0 ]; then # $? es el codigo de salida del comando anterior (0 = exito)
        echo "OK - Imagen construida exitosamente"
    else
        echo "ERROR - Error al construir la imagen Docker"
        exit 1
    fi
else
    echo "OK - Imagen Docker encontrada"
fi

echo ""
echo "--- Iniciando sonda PQC en Docker..."
echo "Espera a que termine (puede tomar varios minutos)"
echo ""

# Ejecutar la sonda en Docker
# -it: modo interactivo con pseudo-TTY para que se muestren los logs en tiempo real
# --rm: elimina el contenedor al terminar (para no acumular contenedores parados)
# -v host: contenedor monta carpetas del host dentro del contenedor
# "${DOCKER_IMAGE}" es la imagen que se ejecuta
# Los argumentos siguientes se pasan al programa dentro del contenedor
docker run -it --rm \
    -v "${PROJECT_DIR}/data:/app/data" \
    -v "${PROJECT_DIR}/resultados:/app/resultados" \
    "${DOCKER_IMAGE}" \
    --input-csv /app/data/${DATASET_CSV} \
    --max-hostnames "${MAX_HOSTNAMES}" \
    --repeticiones "${REPETICIONES}" \
    --max-workers "${MAX_WORKERS}"

EXIT_CODE=$?    # Guardamos el código de salida del contenedor para verificar si fue exitoso o no

echo ""

# Si fue exitoso, los resultados ya estarán en ${PROJECT_DIR}/resultados/ gracias al volumen montado. 
# Si hubo error, se muestra el código de error.
if [ $EXIT_CODE -eq 0 ]; then
    echo "OK - Sonda completada exitosamente"
    echo "--- Resultados guardados en:"
    echo "  • JSON: ${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
    echo "  • CSV:  ${PROJECT_DIR}/resultados/resumen_por_grupo.csv"
    echo "  • LOG:  ${PROJECT_DIR}/resultados/sonda_pqc.log"
    echo ""
    echo "--- Proximo paso: ejecutar análisis"
    echo "  $ ./ejecutar_analisis.sh"
else
    echo "ERROR - Error durante la ejecucion (codigo: $EXIT_CODE)"
    exit $EXIT_CODE
fi
