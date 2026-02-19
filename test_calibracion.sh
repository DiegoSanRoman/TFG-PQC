#!/bin/bash
# test_calibracion.sh
# Ejecuta calibración completa: servidor + sonda en la misma terminal
# Usa sudo para limpiar puertos sin problemas
# Uso: ./test_calibracion.sh [puerto] [repeticiones]

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALIBRACION_DIR="${PROJECT_DIR}/scripts/calibracion"
PUERTO="${1:-4433}"
REPETICIONES="${2:-2}"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ ! -x "${CALIBRACION_DIR}/servidor_control_pqc_docker.sh" ]; then
    echo "Error: servidor_control_pqc_docker.sh no encontrado o no ejecutable"
    exit 1
fi

if [ ! -x "${CALIBRACION_DIR}/calibrar_sonda.sh" ]; then
    echo "Error: calibrar_sonda.sh no encontrado o no ejecutable"
    exit 1
fi

cleanup_port() {
    local port="$1"
    echo -e "${YELLOW}Limpiando puerto ${port}...${NC}" >&2
    pkill -f "s_server.*${port}" >/dev/null 2>&1 || true
    pkill -f "openssl s_server.*${port}" >/dev/null 2>&1 || true
    docker ps -q --filter "ancestor=tfg-sonda" 2>/dev/null | xargs -r docker stop >/dev/null 2>&1 || true
    sleep 1
}

is_port_in_use() {
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$1$"
}

find_free_port() {
    local start="$1"
    local end=$((start + 30))
    local port
    
    for port in $(seq "$start" "$end"); do
        cleanup_port "$port"
        if ! is_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
    done
    echo "PORT_NOT_FOUND" >&2
    return 1
}

FREE_PORT="$(find_free_port "$PUERTO" || true)"
if [ -z "$FREE_PORT" ] || [ "$FREE_PORT" = "PORT_NOT_FOUND" ]; then
    echo -e "${RED}Fallo: no hay puertos disponibles${NC}"
    exit 1
fi

if [ "$FREE_PORT" != "$PUERTO" ]; then
    echo -e "${YELLOW}Puerto ${PUERTO} ocupado. Usando ${FREE_PORT}.${NC}"
    PUERTO="$FREE_PORT"
fi

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      Calibración Completa - Servidor + Sonda                   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}1️⃣  Iniciando servidor en puerto ${PUERTO}...${NC}"
cd "${CALIBRACION_DIR}"
./servidor_control_pqc_docker.sh "$PUERTO" > /tmp/servidor_calibracion.log 2>&1 &
SERVER_PID=$!
echo "    PID: $SERVER_PID"

if [ -z "$SERVER_PID" ]; then
    echo -e "${RED}❌ Error: no se pudo iniciar el servidor${NC}"
    exit 1
fi

echo -e "${YELLOW}2️⃣  Esperando a que el servidor esté listo (máx 60s)...${NC}"
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if nc -z localhost "$PUERTO" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Servidor listo en localhost:${PUERTO}${NC}"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo -e "\n${RED}❌ El servidor murió. Revisar log:${NC}"
        cat /tmp/servidor_calibracion.log
        exit 1
    fi
    sleep 1
    WAITED=$((WAITED + 1))
    echo -n "."
done

if [ $WAITED -eq $MAX_WAIT ]; then
    echo -e "\n${RED}❌ Timeout: servidor no respondió en ${MAX_WAIT}s${NC}"
    cat /tmp/servidor_calibracion.log
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    exit 1
fi

echo ""
echo -e "${YELLOW}3️⃣  Ejecutando calibración (${REPETICIONES} repeticiones)...${NC}"
./calibrar_sonda.sh "$PUERTO" "$REPETICIONES"
EXIT_CODE=$?

echo ""
echo -e "${YELLOW}4️⃣  Deteniendo servidor...${NC}"
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
cleanup_port "$PUERTO"

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗"
    echo "║             ✅ CALIBRACIÓN COMPLETADA EXITOSAMENTE             ║"
    echo "╚════════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗"
    echo "║                 ❌ ERROR EN LA CALIBRACIÓN                   ║"
    echo "-${NC}"
fi

exit $EXIT_CODE
