#!/bin/bash
# calibrar_servidor_pqc_dual.sh
# Script orquestador para calibración DUAL de servidores PQC
# Levanta AMBOS servidores (legacy + moderno) → Ejecuta pruebas → Detiene servidores
# Uso: ./calibrar_servidor_pqc_dual.sh [repeticiones]

set -e

echo ""
echo "====================================================================="
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuración
REPETICIONES="${1:-5}"  # Por defecto 5 repeticiones
SCRIPTS_DIR="${PROJECT_DIR}/scripts/calibracion"

echo ""
echo "====================================================================="
echo ""
echo "        CALIBRACIÓN DUAL: SERVIDORES PQC"
echo ""
echo "  Prueba algoritmos LEGACY (kyber*) y MODERNOS (mlkem*)"
echo "  contra dos servidores HTTPS locales con soporte PQC"
echo ""
echo "====================================================================="

echo "--- Configuración de calibración DUAL:"
echo "  • Repeticiones por grupo: ${REPETICIONES}"
echo "  • Servidor LEGACY: localhost:4433 (nginx 0.10.1 con kyber*, frodo*, bikel1, hqc128)"
echo "  • Servidor MODERNO: localhost:4434 (nginx latest con mlkem*)"
echo "  • Total de algoritmos probados: 14"
echo ""

# Función de limpieza en caso de error o interrupción
cleanup() {
    echo ""
    echo "--- Limpiando recursos..."
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
    if [ ! -f "${SCRIPTS_DIR}/${script}" ]; then    # -f comprueba si el archivo existe y es un archivo regular
        echo "ERROR - Script no encontrado: ${SCRIPTS_DIR}/${script}"
        exit 1
    fi
    # Hacer ejecutable el script
    chmod +x "${SCRIPTS_DIR}/${script}"
done

echo ""
echo "========================================================================"
echo "  Fase 1/4: Levantar Servidores PQC (Legacy + Moderno)"
echo "========================================================================"
echo ""

# Paso 1: Levantar ambos servidores
if ! "${SCRIPTS_DIR}/levantar_servidores.sh"; then
    echo "ERROR - Error al levantar los servidores"
    trap - EXIT
    exit 1
fi

# Esperar a que ambos servidores estén completamente listos
echo "--- Esperando 5 segundos para que los servidores esten listos..."
sleep 5

echo ""
echo "========================================================================"
echo "  Fase 2/4: Ejecutar Pruebas contra Servidor LEGACY"
echo "========================================================================"
echo ""

# Paso 3: Ejecutar pruebas contra el servidor LEGACY
INICIO_TIEMPO=$(date +%s)

# Ejecutar pruebas contra LEGACY usando su CSV
DOCKER_IMAGE="tfg-sonda"
DATASET_CSV="calibracion_legacy.csv"
MAX_HOSTNAMES="1"
MAX_WORKERS="1"
CONTAINER_NAME="pqc-legacy-server"

echo "--- Probando algoritmos LEGACY (kyber*, x25519_kyber*, p256_kyber*, frodo*, bikel1, hqc128)"

# Ejecutar contenedor Docker con la sonda PQC contra el servidor LEGACY
# --rm: elimina el contenedor al terminar, --network="host": usa la red del host para conectarse a localhost:4433
# -v monta carpetas (data:ro es read-only, resultados es read-write)
# Si el comando falla, mostramos error, detenemos los servidores y abortamos
if ! docker run --rm \
    --network="host" \
    -v "${PROJECT_DIR}/data:/app/data:ro" \
    -v "${PROJECT_DIR}/resultados:/app/resultados" \
    "${DOCKER_IMAGE}" \
    --input-csv "data/${DATASET_CSV}" \
    --max-hostnames "${MAX_HOSTNAMES}" \
    --repeticiones "${REPETICIONES}" \
    --max-workers "${MAX_WORKERS}"; then
    echo "ERROR - Error al ejecutar pruebas LEGACY"
    trap - EXIT # Desactiva el trap para evitar limpieza no controlada
    "${SCRIPTS_DIR}/detener_servidores.sh"
    exit 1
fi

# Copiar resultados del legacy a archivo específico
# Renombramos resultados_sonda_pqc.json a resultados_calibracion_legacy.json para guardar histórico
if [ -f "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" ]; then
    # cp copia archivos, si el destino es un directorio, mantiene el nombre original, 
    # si es un archivo, lo renombra. 2>/dev/null redirige errores a null para evitar mensajes si el resumen_por_grupo.csv no existe
    cp "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" \
       "${PROJECT_DIR}/resultados/resultados_calibracion_legacy.json"
    cp "${PROJECT_DIR}/resultados/resumen_por_grupo.csv" \
       "${PROJECT_DIR}/resultados/resumen_calibracion_legacy.csv" 2>/dev/null || true # || true ignora errores
fi

echo ""
echo "========================================================================"
echo "  Fase 3/4: Ejecutar Pruebas contra Servidor MODERNO"
echo "========================================================================"
echo ""

# Paso 4: Ejecutar pruebas contra el servidor MODERNO
DATASET_CSV="calibracion_moderno.csv"

echo "--- Probando algoritmos MODERNOS (mlkem768, x25519_mlkem768, x25519_mlkem512, secp256r1_mlkem768)"

# Ejecutar contenedor Docker con la sonda PQC contra el servidor MODERNO
# --rm: elimina el contenedor al terminar, --network="host": usa la red del host para conectarse a localhost:4434
# -v monta carpetas (data:ro es read-only, resultados es read-write)
# Si el comando falla, mostramos error, detenemos los servidores y abortamos
if ! docker run --rm \
    --network="host" \
    -v "${PROJECT_DIR}/data:/app/data:ro" \
    -v "${PROJECT_DIR}/resultados:/app/resultados" \
    "${DOCKER_IMAGE}" \
    --input-csv "data/${DATASET_CSV}" \
    --max-hostnames "${MAX_HOSTNAMES}" \
    --repeticiones "${REPETICIONES}" \
    --max-workers "${MAX_WORKERS}"; then
    echo "ERROR - Error al ejecutar pruebas MODERNO"
    trap - EXIT # Desactiva el trap para evitar limpieza no controlada
    "${SCRIPTS_DIR}/detener_servidores.sh"
    exit 1
fi

# Copiar resultados del moderno a archivo específico
# Renombramos resultados_sonda_pqc.json a resultados_calibracion_moderno.json para guardar histórico
if [ -f "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" ]; then
    cp "${PROJECT_DIR}/resultados/resultados_sonda_pqc.json" \
       "${PROJECT_DIR}/resultados/resultados_calibracion_moderno.json"
    cp "${PROJECT_DIR}/resultados/resumen_por_grupo.csv" \
       "${PROJECT_DIR}/resultados/resumen_calibracion_moderno.csv" 2>/dev/null || true # || true ignora errores
fi

FIN_TIEMPO=$(date +%s)
DURACION=$((FIN_TIEMPO - INICIO_TIEMPO))

echo ""
echo "========================================================================"
echo "  Fase 4/4: Detener Servidores"
echo "========================================================================"
echo ""

# Antes de detener los servidores, desactivamos el trap para evitar que se ejecute la función de limpieza nuevamente
trap - EXIT

# Paso 4: Detener ambos servidores
"${SCRIPTS_DIR}/detener_servidores.sh"

echo ""
echo "====================================================================="
echo ""
echo "           OK - CALIBRACION DUAL COMPLETADA"
echo ""
echo "====================================================================="

echo "--- Resumen de ejecucion:"
echo "  • Tiempo total: ${DURACION} segundos"
echo "  • Repeticiones por grupo: ${REPETICIONES}"
echo "  • Resultados LEGACY: ${PROJECT_DIR}/resultados/resultados_calibracion_legacy.json"
echo "  • Resultados MODERNO: ${PROJECT_DIR}/resultados/resultados_calibracion_moderno.json"
echo "  • Resumen CSV LEGACY: ${PROJECT_DIR}/resultados/resumen_calibracion_legacy.csv"
echo "  • Resumen CSV MODERNO: ${PROJECT_DIR}/resultados/resumen_calibracion_moderno.csv"
echo ""

# Mostrar estadísticas combinadas si jq está disponible
# jq es una herramienta para procesar JSON desde línea de comandos (command -v busca jq en el PATH)
# -r: output raw (sin comillas), '.resumen': accede al objeto resumen del JSON
if command -v jq &> /dev/null; then
    echo "--- Estadisticas de calibracion LEGACY:"
    # -f comprueba si el archivo existe antes de procesarlo con jq
    if [ -f "${PROJECT_DIR}/resultados/resultados_calibracion_legacy.json" ]; then
        # jq extrae total_pruebas, pruebas_exitosas y tasa_exito_pruebas_percent del JSON
        # \n genera nuevas líneas dentro de la salida de jq
        jq -r '.resumen | "  • Total de pruebas: \(.total_pruebas)\n  • Pruebas exitosas: \(.pruebas_exitosas)\n  • Tasa de éxito: \(.tasa_exito_pruebas_percent)%"' \
            "${PROJECT_DIR}/resultados/resultados_calibracion_legacy.json"
    fi
    echo ""
    echo "--- Estadisticas de calibracion MODERNO:"
    # -f comprueba si el archivo existe antes de procesarlo con jq
    if [ -f "${PROJECT_DIR}/resultados/resultados_calibracion_moderno.json" ]; then
        # jq extrae total_pruebas, pruebas_exitosas y tasa_exito_pruebas_percent del JSON
        # \n genera nuevas líneas dentro de la salida de jq
        jq -r '.resumen | "  • Total de pruebas: \(.total_pruebas)\n  • Pruebas exitosas: \(.pruebas_exitosas)\n  • Tasa de éxito: \(.tasa_exito_pruebas_percent)%"' \
            "${PROJECT_DIR}/resultados/resultados_calibracion_moderno.json"
    fi
fi

echo ""
echo "Ahora tienes cobertura completa de algoritmos PQC (LEGACY + MODERNO)"
echo ""
