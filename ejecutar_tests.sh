#!/bin/bash
# ejecutar_tests.sh
# Ejecuta los tests unitarios del proyecto TFG-PQC.
# Uso: ./ejecutar_tests.sh [--verbose] [--filter PATRON] [--failfast]

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PROJECT_DIR}/venv/bin/python3"
TESTS_DIR="${PROJECT_DIR}/scripts/tests"

# Valores por defecto
VERBOSE=""
FILTER=""
FAILFAST=""

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose|-v)
            VERBOSE="-v"
            shift
            ;;
        --filter|-k)
            FILTER="-k $2"
            shift 2
            ;;
        --failfast|-x)
            FAILFAST="-x"
            shift
            ;;
        --help|-h)
            echo "Uso: ./ejecutar_tests.sh [--verbose] [--filter PATRON] [--failfast]"
            echo ""
            echo "  --verbose,  -v          Muestra cada test individualmente"
            echo "  --filter,   -k PATRON   Ejecuta solo los tests que coincidan con PATRON"
            echo "  --failfast, -x          Para al primer fallo"
            echo ""
            echo "Ejemplos:"
            echo "  ./ejecutar_tests.sh --verbose"
            echo "  ./ejecutar_tests.sh --filter parse_trace"
            echo "  ./ejecutar_tests.sh --filter TestLeerHostnamesCsv --verbose"
            echo "  ./ejecutar_tests.sh --failfast"
            exit 0
            ;;
        *)
            echo "ERROR - Argumento desconocido: $1"
            echo "Usa --help para ver las opciones disponibles."
            exit 1
            ;;
    esac
done

echo ""
echo "====================================================================="
echo "                  Tests Unitarios TFG-PQC"
echo "====================================================================="
echo ""

# Comprobar que el entorno virtual existe
if [[ ! -f "${PYTHON}" ]]; then
    echo "ERROR - No se encontró el entorno virtual en ${PROJECT_DIR}/venv/"
    echo "Ejecuta primero: python3 -m venv venv && pip install -r requirements.txt"
    exit 1
fi

# Comprobar que pytest está instalado
if ! "${PYTHON}" -m pytest --version &>/dev/null; then
    echo "ERROR - pytest no está instalado en el entorno virtual."
    echo "Ejecuta: pip install pytest"
    exit 1
fi

# Ejecutar tests
CMD="${PYTHON} -m pytest ${TESTS_DIR} ${VERBOSE} ${FILTER} ${FAILFAST}"
echo "Comando: ${CMD}"
echo ""

${PYTHON} -m pytest "${TESTS_DIR}" ${VERBOSE} ${FILTER} ${FAILFAST}

echo ""
echo "OK - Tests completados"
echo ""
