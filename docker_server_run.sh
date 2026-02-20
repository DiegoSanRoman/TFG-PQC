#!/bin/bash
# docker_server_run.sh
# Arranca un servidor HTTPS con soporte PQC dentro de Docker para calibración
# Uso: ./docker_server_run.sh [--port PORT]

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_IMAGE="tfg-sonda"
SERVER_PORT="8443"
CONTAINER_NAME="tfg-pqc-server"

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            SERVER_PORT="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}❌ Argumento desconocido: $1${NC}"
            echo "Uso: $0 [--port PORT]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Servidor PQC para Calibración - Docker                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}📋 Configuración:${NC}"
echo "  • Puerto: ${SERVER_PORT}"
echo "  • Imagen Docker: ${DOCKER_IMAGE}"
echo "  • Contenedor: ${CONTAINER_NAME}"
echo ""

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no encontrado${NC}"
    exit 1
fi

# Verificar/construir imagen si no existe
if ! docker image inspect "${DOCKER_IMAGE}" &> /dev/null; then
    echo -e "${YELLOW}🔨 Construyendo imagen Docker: ${DOCKER_IMAGE}...${NC}"
    docker build -t "${DOCKER_IMAGE}" "${PROJECT_DIR}"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Imagen construida exitosamente${NC}"
    else
        echo -e "${RED}❌ Error al construir la imagen Docker${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ Imagen Docker encontrada${NC}"
fi

# Detener contenedor anterior si existe
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}🛑 Deteniendo contenedor anterior...${NC}"
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
fi

echo ""
echo -e "${BLUE}🚀 Iniciando servidor PQC en Docker...${NC}"

# Comando simplificado: generar certificado e iniciar servidor directamente
docker run -d --rm \
  --name "${CONTAINER_NAME}" \
  --entrypoint sh \
  -p "${SERVER_PORT}:8443" \
  "${DOCKER_IMAGE}" \
  -c "
    echo 'Generando certificado autofirmado...';
    /opt/openssl/bin/openssl genrsa -out /tmp/server.key 2048 2>/dev/null;
    /opt/openssl/bin/openssl req -new -x509 -key /tmp/server.key -out /tmp/server.crt \
      -days 365 -subj '/CN=localhost' 2>/dev/null;
    echo 'Servidor iniciado en puerto 8443...';
    exec /opt/openssl/bin/openssl s_server \
      -cert /tmp/server.crt -key /tmp/server.key \
      -accept 8443 -tls1_3 -www 2>&1
  "

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Servidor iniciado exitosamente${NC}"
    echo ""
    echo -e "${YELLOW}📡 Detalles del servidor:${NC}"
    echo "  • Host: localhost"
    echo "  • Puerto: ${SERVER_PORT}"
    echo "  • URL: https://localhost:${SERVER_PORT}"
    echo "  • Protocolo: TLS 1.3 con soporte PQC"
    echo ""
    echo -e "${BLUE}💡 Para detener el servidor:${NC}"
    echo "  $ docker stop ${CONTAINER_NAME}"
    echo ""
    echo -e "${YELLOW}⏳ El servidor está ejecutándose en background. Usa el script de calibración para ejecutar pruebas.${NC}"
else
    echo -e "${RED}❌ Error al iniciar el servidor${NC}"
    exit 1
fi
