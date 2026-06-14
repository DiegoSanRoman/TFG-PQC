#!/bin/bash
# ejecutar_sonda.sh
# Script auxiliar para ejecutar la sonda PQC dentro de Docker
# Uso: ./ejecutar_sonda.sh --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N]

# Para asegurar que el script falle si algún comando falla y no haya resultados inconsistentes
set -euo pipefail

# Directorio base del proyecto
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Valores por defecto
MAX_HOSTNAMES="150000"
REPETICIONES="1"
MAX_WORKERS="20"
DOCKER_IMAGE="tfg-sonda"
DATASET_CSV="majestic_million.csv"
DATASET_BASENAME=""
FORCE_REBUILD="0"
IMAGE_HASH_FILE=""

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
        --rebuild)
            FORCE_REBUILD="1"
            shift
            ;;
        *)
        echo "- Argumento desconocido: $1"
            echo "Uso: $0 --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N] [--rebuild]"
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
echo "  • Rebuild forzado: ${FORCE_REBUILD}"
echo ""

# Verificar que el CSV existe (-f comprueba archivo regular)
if [[ "${DATASET_CSV}" = */* ]]; then
    DATASET_BASENAME="$(basename "${DATASET_CSV}")"
else
    DATASET_BASENAME="${DATASET_CSV}"
fi

if [ ! -f "${PROJECT_DIR}/data/${DATASET_BASENAME}" ]; then
    echo "ERROR - Archivo no encontrado: ${PROJECT_DIR}/data/${DATASET_BASENAME}"
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
IMAGE_HASH_FILE="${PROJECT_DIR}/resultados/.docker_image_hash_${DOCKER_IMAGE}.txt"

# Si Docker no está disponible pero estamos dentro del contenedor,
# ejecutar la sonda directamente (evita Docker-in-Docker).
if ! command -v docker &> /dev/null; then
    if [ -f "/.dockerenv" ]; then
        echo "--- Docker CLI no disponible en contenedor; ejecutando sonda localmente..."
        python3 "${PROJECT_DIR}/scripts/sondas/sonda_pqc_final.py" \
            --input-csv "${PROJECT_DIR}/data/${DATASET_BASENAME}" \
            --max-hostnames "${MAX_HOSTNAMES}" \
            --repeticiones "${REPETICIONES}" \
            --max-workers "${MAX_WORKERS}"

        EXIT_CODE=$?
        echo ""
        if [ $EXIT_CODE -eq 0 ]; then
            echo "OK - Sonda completada exitosamente"
            echo "--- Resultados guardados en:"
            echo "  • JSON: ${PROJECT_DIR}/resultados/resultados_sonda_pqc.json"
            echo "  • CSV:  ${PROJECT_DIR}/resultados/resumen_por_grupo.csv"
            echo "  • LOG:  ${PROJECT_DIR}/resultados/sonda_pqc.log"
            echo ""
            echo "--- Proximo paso: ejecutar análisis"
            echo "  $ ./ejecutar_analisis.sh"
            exit 0
        else
            echo "ERROR - Error durante la ejecucion local (codigo: $EXIT_CODE)"
            exit $EXIT_CODE
        fi
    else
        echo "ERROR - Docker no encontrado"
        echo "Asegúrate de tener Docker instalado y en el PATH"
        exit 1
    fi
fi

# Verificar si hay que reconstruir imagen (inexistente, forzado o código cambiado)
CURRENT_HASH="$(cat "${PROJECT_DIR}/Dockerfile" "${PROJECT_DIR}/scripts/sondas/sonda_pqc_final.py" | sha256sum | awk '{print $1}')"
LAST_HASH=""
if [ -f "${IMAGE_HASH_FILE}" ]; then
    LAST_HASH="$(cat "${IMAGE_HASH_FILE}" 2>/dev/null || true)"
fi

REBUILD_NEEDED="0"
if ! docker image inspect "${DOCKER_IMAGE}" &> /dev/null; then
    echo "--- Imagen Docker no encontrada, se construirá"
    REBUILD_NEEDED="1"
elif [ "${FORCE_REBUILD}" = "1" ]; then
    echo "--- Rebuild forzado por --rebuild"
    REBUILD_NEEDED="1"
elif [ "${CURRENT_HASH}" != "${LAST_HASH}" ]; then
    echo "--- Detectados cambios en Dockerfile/sonda, se reconstruirá la imagen"
    REBUILD_NEEDED="1"
else
    echo "OK - Imagen Docker al día"
fi

if [ "${REBUILD_NEEDED}" = "1" ]; then
    echo "--- Construyendo imagen Docker: ${DOCKER_IMAGE}..."
    docker build -t "${DOCKER_IMAGE}" "${PROJECT_DIR}"
    if [ $? -eq 0 ]; then # $? es el codigo de salida del comando anterior (0 = exito)
        echo "${CURRENT_HASH}" > "${IMAGE_HASH_FILE}"
        echo "OK - Imagen construida exitosamente"
    else
        echo "ERROR - Error al construir la imagen Docker"
        exit 1
    fi
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
# Forzamos ENTRYPOINT a python3 para evitar recursión con test_pipeline.sh
docker run -it --rm \
    -v "${PROJECT_DIR}/data:/app/data" \
    -v "${PROJECT_DIR}/resultados:/app/resultados" \
    --entrypoint python3 \
    "${DOCKER_IMAGE}" \
    /app/scripts/sondas/sonda_pqc_final.py \
    --input-csv "/app/data/${DATASET_BASENAME}" \
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
