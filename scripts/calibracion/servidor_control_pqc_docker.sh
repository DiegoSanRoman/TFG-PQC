#!/bin/bash
# servidor_control_pqc_docker.sh
# Servidor de control PQC usando Docker (no requiere instalación local de OpenSSL)
# Uso: ./servidor_control_pqc_docker.sh [puerto]

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PUERTO="${1:-4433}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERTS_DIR="${PROJECT_DIR}/scripts/calibracion/certs"
DOCKER_IMAGE="tfg-sonda"

is_port_in_use() {
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$1$"
}

cleanup_port() {
    local port="$1"
    pkill -f "s_server.*${port}" >/dev/null 2>&1 || true
    docker ps -q --filter "ancestor=${DOCKER_IMAGE}" --filter "expose=${port}" | xargs -r docker stop >/dev/null 2>&1 || true
}

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      Servidor de Control PQC - Docker (Calibración)            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    echo "Instala Docker: sudo apt install docker.io"
    exit 1
fi

# Verificar/construir imagen Docker
echo -e "${YELLOW}🔍 Verificando imagen Docker...${NC}"
if ! docker image inspect "$DOCKER_IMAGE" &> /dev/null; then
    echo -e "${YELLOW}🏗️  Construyendo imagen Docker (primera vez, ~5-10 min)...${NC}"
    cd "$PROJECT_DIR"
    docker build -t "$DOCKER_IMAGE" .
fi

echo -e "${GREEN}✓ Imagen Docker lista${NC}"

# Crear directorio de certificados si no existe
mkdir -p "$CERTS_DIR"

# Generar certificado si no existe o está expirado
CERT_FILE="${CERTS_DIR}/server-cert.pem"
KEY_FILE="${CERTS_DIR}/server-key.pem"

if [ -f "$CERT_FILE" ]; then
    # Verificar validez del certificado
    if openssl x509 -in "$CERT_FILE" -noout -checkend 86400 2>/dev/null; then
        echo -e "${GREEN}✓ Certificado existente válido${NC}"
    else
        echo -e "${YELLOW}⚠️  Certificado expirado, regenerando...${NC}"
        rm -f "$CERT_FILE" "$KEY_FILE"
    fi
fi

if [ ! -f "$CERT_FILE" ]; then
    echo -e "${YELLOW}🔐 Generando certificado self-signed...${NC}"
    
    # Generar usando el OpenSSL del contenedor Docker (Alpine usa /bin/sh)
    docker run --rm \
        --entrypoint /bin/sh \
        -v "${CERTS_DIR}:/certs" \
        "$DOCKER_IMAGE" \
        -c "/opt/openssl/bin/openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout /certs/server-key.pem \
            -out /certs/server-cert.pem \
            -days 365 \
            -subj '/CN=localhost/O=TFG-PQC-Calibration/C=ES'"
    
    echo -e "${GREEN}✓ Certificado generado${NC}"
fi

# Limpiar puerto en caso de ejecuciones previas
cleanup_port "$PUERTO"
sleep 1

if is_port_in_use "$PUERTO"; then
    echo -e "${RED}❌ Error: el puerto ${PUERTO} sigue en uso${NC}"
    echo "Prueba con otro puerto: ./servidor_control_pqc_docker.sh 4443"
    exit 1
fi

echo ""
echo -e "${BLUE}📋 Configuración:${NC}"
echo "  Puerto: ${PUERTO}"
echo "  Certificado: ${CERT_FILE}"
echo "  Algoritmos PQC: X25519, Kyber, MLKEM, Frodo, etc."
echo ""

echo -e "${GREEN}🚀 Iniciando servidor de control en Docker...${NC}"
echo -e "${YELLOW}Presiona CTRL+C para detener${NC}"
echo ""

# Ejecutar servidor s_server en Docker
# --network host permite que el servidor escuche en localhost
# -it mantiene el terminal interactivo
# --entrypoint sobrescribe el ENTRYPOINT del Dockerfile
# NOTA: Activamos explícitamente el provider OQS con -provider
# Los grupos disponibles se listan con nombres válidos en minúsculas
docker run --rm \
    --network host \
    --entrypoint /opt/openssl/bin/openssl \
    -v "${CERTS_DIR}:/certs:ro" \
    "$DOCKER_IMAGE" \
    s_server \
        -cert /certs/server-cert.pem \
        -key /certs/server-key.pem \
        -accept "$PUERTO" \
        -www \
        -provider oqsprovider \
        -provider default \
        -groups x25519:mlkem768:kyber768:x25519_kyber768:x25519_mlkem512:p256_kyber768:frodo640aes:bikel1:x25519_bikel1:x25519_hqc128 \
        -tls1_3
