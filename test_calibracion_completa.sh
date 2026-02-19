#!/bin/bash
# test_calibracion_completa.sh
# Script para probar el flujo completo de calibración
# Levanta servidor, ejecuta calibración y genera análisis

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALIBRACION_DIR="${PROJECT_DIR}/scripts/calibracion"
PUERTO=4433

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      Test Completo de Calibración (Servidor + Sonda)          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}Este script realizará:${NC}"
echo "  1️⃣  Levantar servidor de control en background"
echo "  2️⃣  Esperar a que el servidor esté listo"
echo "  3️⃣  Ejecutar calibración de la sonda"
echo "  4️⃣  Detener el servidor"
echo "  5️⃣  Mostrar resumen de resultados"
echo ""

# Verificar que los scripts existen
if [ ! -f "${CALIBRACION_DIR}/servidor_control_pqc_docker.sh" ]; then
    echo -e "${RED}❌ Error: servidor_control_pqc_docker.sh no encontrado${NC}"
    exit 1
fi

if [ ! -f "${CALIBRACION_DIR}/calibrar_sonda.sh" ]; then
    echo -e "${RED}❌ Error: calibrar_sonda.sh no encontrado${NC}"
    exit 1
fi

# Limpiar procesos previos
echo -e "${YELLOW}🧹 Limpiando procesos previos...${NC}"
pkill -f "s_server.*4433" 2>/dev/null || true
# Detener contenedores Docker que puedan estar ejecutando el servidor
docker ps -q --filter "ancestor=tfg-sonda" --filter "expose=4433" | xargs -r docker stop 2>/dev/null || true
sleep 2

# Paso 1: Levantar servidor en background
echo -e "${BLUE}1️⃣  Levantando servidor de control (Docker)...${NC}"
cd "${CALIBRACION_DIR}"
./servidor_control_pqc_docker.sh $PUERTO > /tmp/servidor_control.log 2>&1 &
SERVIDOR_PID=$!

echo "  PID del servidor: $SERVIDOR_PID"
echo "  Log: /tmp/servidor_control.log"

# Paso 2: Esperar a que el servidor esté listo
echo -e "${YELLOW}2️⃣  Esperando a que el servidor esté listo...${NC}"
MAX_INTENTOS=20
INTENTO=0

while [ $INTENTO -lt $MAX_INTENTOS ]; do
    if nc -z localhost $PUERTO 2>/dev/null; then
        echo -e "${GREEN}✓ Servidor listo${NC}"
        break
    fi
    
    INTENTO=$((INTENTO + 1))
    echo -n "."
    sleep 1
    
    # Verificar que el proceso sigue vivo
    if ! kill -0 $SERVIDOR_PID 2>/dev/null; then
        echo -e "\n${RED}❌ Error: Servidor murió inesperadamente${NC}"
        echo "Log del servidor:"
        cat /tmp/servidor_control.log
        exit 1
    fi
done

if [ $INTENTO -eq $MAX_INTENTOS ]; then
    echo -e "\n${RED}❌ Timeout: Servidor no respondió en ${MAX_INTENTOS}s${NC}"
    echo "Log del servidor:"
    cat /tmp/servidor_control.log
    kill $SERVIDOR_PID 2>/dev/null || true
    exit 1
fi

echo ""

# Paso 3: Ejecutar calibración
echo -e "${BLUE}3️⃣  Ejecutando calibración...${NC}"
./calibrar_sonda.sh $PUERTO 2

CALIBRACION_EXIT=$?

# Paso 4: Detener servidor
echo ""
echo -e "${YELLOW}4️⃣  Deteniendo servidor...${NC}"
kill $SERVIDOR_PID 2>/dev/null || true
wait $SERVIDOR_PID 2>/dev/null || true
# Asegurar que contenedores Docker se detienen
docker ps -q --filter "ancestor=tfg-sonda" --filter "expose=$PUERTO" | xargs -r docker stop 2>/dev/null || true
sleep 1
echo -e "${GREEN}✓ Servidor detenido${NC}"

# Paso 5: Mostrar resumen
echo ""
echo -e "${BLUE}5️⃣  Resumen de Resultados${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $CALIBRACION_EXIT -eq 0 ]; then
    echo -e "${GREEN}✅ Calibración completada exitosamente${NC}"
    echo ""
    
    # Buscar el archivo más reciente de calibración
    ULTIMO_JSON=$(ls -t ${PROJECT_DIR}/resultados/calibracion/calibracion_*.json 2>/dev/null | head -1)
    
    if [ -n "$ULTIMO_JSON" ]; then
        echo -e "${BLUE}📁 Archivos generados:${NC}"
        echo "  JSON: $(basename $ULTIMO_JSON)"
        
        ULTIMO_DIR=$(dirname $ULTIMO_JSON)
        TIMESTAMP=$(basename $ULTIMO_JSON | sed 's/calibracion_\(.*\)\.json/\1/')
        
        if [ -d "${ULTIMO_DIR}/imagenes_${TIMESTAMP}" ]; then
            echo "  Imágenes: imagenes_${TIMESTAMP}/"
            echo "    $(ls ${ULTIMO_DIR}/imagenes_${TIMESTAMP}/*.png 2>/dev/null | wc -l) gráficas generadas"
        fi
        
        echo ""
        echo -e "${BLUE}📊 Vista previa de resultados:${NC}"
        
        # Extraer resumen del JSON
        if command -v jq &> /dev/null; then
            echo ""
            jq -r '.resumen | "  Pruebas exitosas: \(.pruebas_exitosas)/\(.total_pruebas) (\(.tasa_exito_pruebas_percent)%)"' "$ULTIMO_JSON" 2>/dev/null || echo "  (Instala 'jq' para ver resumen detallado)"
            echo ""
        fi
        
        # Mostrar reporte si existe
        REPORTE="${ULTIMO_DIR}/imagenes_${TIMESTAMP}/reporte_analisis.txt"
        if [ -f "$REPORTE" ]; then
            echo -e "${BLUE}📝 Extracto del reporte:${NC}"
            head -30 "$REPORTE" | tail -20
        fi
    fi
    
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ TEST COMPLETO EXITOSO${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Próximos pasos:"
    echo "  1. Revisa las gráficas en: resultados/calibracion/imagenes_${TIMESTAMP}/"
    echo "  2. Incluye los resultados en tu TFG (sección 'Calibración')"
    echo "  3. Procede a escanear servidores reales: ./ejecutar_sonda.sh"
    
else
    echo -e "${RED}❌ Error durante la calibración (código: $CALIBRACION_EXIT)${NC}"
    exit $CALIBRACION_EXIT
fi
