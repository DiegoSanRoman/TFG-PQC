# Sonda de Detección de Criptografía Post-Cuántica (PQC) 🚀

> Una herramienta experimental para monitorizar y analizar la adopción de algoritmos criptográficos post-cuánticos en servidores web reales.

**Trabajo de Fin de Grado - Universidad Carlos III de Madrid (UC3M)**

---

## ⚡ Quick Start

### 1️⃣ Validar Instalación (2 minutos)
```bash
# Calibración completa: levanta servidor + ejecuta sonda
./calibration.sh
```
✅ **Esperar:** Latencias ~0-10 ms, éxito >95%

### 2️⃣ Escanear Servidores Reales
```bash
# Test rápido (10 hostnames) - ~5 minutos
./ejecutar_sonda.sh --input-csv prueba.csv --max-hostnames 10 --repeticiones 1 --max-workers 5

# Producción (100 hostnames) - ~30 minutos
./ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 100 --repeticiones 3 --max-workers 20
```

### 3️⃣ Generar Gráficas (30 segundos)
```bash
./ejecutar_analisis.sh
```
📊 **Resultados:** 7 gráficas profesionales en `imagenes/`

---

## 📋 Tabla de Contenidos

- [Quick Start](#-quick-start)
- [Descripción General](#-descripción-general)
- [Scripts Automatizados](#-scripts-automatizados)
- [Requisitos Previos](#-requisitos-previos)
- [Instalación](#-instalación)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Uso Básico](#-uso-básico)
  - [Calibración](#1-calibración-validar-sonda)
  - [Escaneo Internet](#2-escaneo-internet-datos-reales)
  - [Análisis y Gráficas](#3-análisis-y-gráficas)
  - [Pipeline Completo](#4-pipeline-completo)
- [Interpretación de Resultados](#-interpretación-de-resultados)
- [Configuración Avanzada](#-configuración-avanzada)
- [Troubleshooting](#-troubleshooting)
- [Para el TFG](#-para-el-tfg)

---

## 📖 Descripción General

Este proyecto implementa **sondas de conectividad HTTPS** diseñadas para evaluar la adopción de criptografía post-cuántica:

- **Sonda PQC** (`sonda_pqc_final.py`): Evalúa la capacidad de servidores para negociar algoritmos criptográficos post-cuánticos
- **Sistema de Calibración**: Servidor local de control para validar la metodología
- **Análisis Automático**: Generación de 7 gráficas profesionales y reportes estadísticos

### 🎯 Objetivo Principal

Evaluar la capacidad de los servidores actuales para negociar intercambios de claves **híbridos** (clásicos + cuánticos) y detectar fragmentación o problemas de interoperabilidad en la transición hacia los estándares del NIST.

### ✨ Características

- ✅ Escaneo concurrente de múltiples hostnames
- ✅ Soporte para algoritmos post-cuánticos (Kyber, FrodoKEM, etc.)
- ✅ Análisis de certificados X.509
- ✅ Métricas de timing detalladas (DNS, TCP, TLS handshake)
- ✅ Exportación de resultados en JSON y CSV
- ✅ Entorno containerizado con Docker
- ✅ Sistema de calibración con servidor de control
- ✅ 7 gráficas profesionales + reporte estadístico automático

---

## 🎬 Scripts Automatizados

### Scripts de Calibración

| Script | Propósito | Duración |
|--------|-----------|----------|
| [calibration.sh](calibration.sh) | 🧪 **Orquestador principal** - Levanta servidor + ejecuta sonda | ~3-5 min |
| [docker_server_run.sh](docker_server_run.sh) | 🚀 Levanta servidor HTTPS con soporte PQC en Docker | ~5s |
| [docker_probe_run.sh](docker_probe_run.sh) | 📡 Ejecuta sonda contra servidor de calibración | ~2-5 min |

### Scripts de Análisis

| Script | Propósito | Duración |
|--------|-----------|----------|
| [ejecutar_sonda.sh](ejecutar_sonda.sh) | 🌐 Escaneo Internet con Docker | Variable |
| [ejecutar_analisis.sh](ejecutar_analisis.sh) | 📊 Generar 7 gráficas profesionales | ~30s |
| [test_pipeline.sh](test_pipeline.sh) | 🔄 Pipeline completo (sonda + análisis) | Variable |

---

## 📦 Requisitos Previos

### Sistema Operativo
- Linux, macOS o Windows (con WSL2)

### Software Requerido
- **Docker** (versión 20.10 o superior) - [Descargar](https://www.docker.com/products/docker-desktop)
- **Python 3.7+** (para análisis)

### Verificar Instalación
```bash
docker --version
docker ps  # Verifica que puedes ejecutar comandos docker
```

---

## 🚀 Instalación

### Paso 1: Clonar o Descargar el Repositorio

```bash
git clone <repositorio_url>
cd TFG_Diego
```

### Paso 2: Verificar Estructura

```bash
ls -l
# Debe mostrar: ejecutar_sonda.sh, ejecutar_analisis.sh, test_calibracion_completa.sh, etc.
```

### Paso 3: Dar Permisos de Ejecución (si es necesario)

```bash
chmod +x *.sh
chmod +x scripts/**/*.sh
```

La imagen Docker se construye automáticamente al ejecutar los scripts.

---

## 📂 Estructura del Proyecto

```
TFG_Diego/
├── README.md                                  # Este archivo
├── Dockerfile                                 # Configuración Docker con OpenSSL-PQC
├── requirements.txt                           # Dependencias Python
│
├── calibration.sh                             # ⭐ Orquestador: levanta servidor + ejecuta sonda
├── docker_server_run.sh                       # 🚀 Levanta servidor PQC en Docker
├── docker_probe_run.sh                        # 📡 Ejecuta sonda contra servidor de calibración
├── ejecutar_sonda.sh                          # 🌐 Escaneo Internet
├── ejecutar_analisis.sh                       # 📊 Generar gráficas
├── test_pipeline.sh                           # 🔄 Pipeline completo
│
├── data/
│   ├── majestic_million.csv                   # Dataset principal (1M dominios)
│   ├── tranco.csv                             # Dataset alternativo
│   └── prueba.csv                             # Dataset de prueba
│
├── scripts/
│   ├── sondas/
│   │   └── sonda_pqc_final.py                 # Motor principal de escaneo
│   ├── ml/
│   │   └── analizar_resultados.py             # Generador de gráficas
│   └── individuales/
│       └── hostname_conexion.py               # Análisis individual
│
├── resultados/
│   ├── resultados_sonda_pqc.json              # Resultados Internet
│   ├── resumen_por_grupo.csv                  # Resumen estadístico
│   ├── calibration.csv                        # CSV de calibración (generado)
│   └── sonda_pqc.log                          # Log de ejecución
│
└── imagenes/                                  # Gráficas finales (para TFG)
    ├── 1_latencia_por_grupo.png
    ├── 2_overhead_bytes.png
    ├── 3_latencia_vs_bytes.png
    ├── 4_boxplot_distribucion.png
    ├── 5_heatmap_correlacion.png
    ├── 6_tendencia_lineal.png
    ├── 7_tasa_exito_conexiones.png
    └── reporte_analisis.txt
```

---

## 💻 Uso Básico

### 1. Calibración (Validar Sonda)

La calibración valida que tu sonda funciona correctamente contra un servidor local de control.

#### Modo Automático (Recomendado) ⭐

```bash
./calibration.sh
```

**Parámetros opcionales:**
```bash
# Usar puerto diferente
./calibration.sh --port 9443

# Personalizar repeticiones y workers
./calibration.sh --repeticiones 5 --max-workers 10

# Mantener el servidor corriendo (no limpiar)
./calibration.sh --no-cleanup
```

**Lo que hace:**
1. ✅ Levanta servidor HTTPS con soporte PQC en Docker
2. ✅ Espera a que esté listo (validación de puerto)
3. ✅ Ejecuta sonda contra `localhost:puerto` (14 algoritmos × 3 repeticiones)
4. ✅ Genera JSON y CSV con resultados
5. ✅ Detiene servidor automáticamente (a menos que uses `--no-cleanup`)

**Archivos generados:**
```
resultados/
├── resultados_sonda_pqc.json       # Resultados detallados
├── resumen_por_grupo.csv            # Resumen estadístico
├── calibration.csv                  # CSV utilizado (localhost:puerto)
└── sonda_pqc.log                    # Log detallado
```

**Salida esperada:**
```
✅ CALIBRACIÓN COMPLETADA EXITOSAMENTE
📊 Resultados disponibles en:
  • JSON: /path/to/resultados/resultados_sonda_pqc.json
  • CSV:  /path/to/resultados/resumen_por_grupo.csv
```

**Criterios de éxito:**
- ✅ Latencias totales: 0-10 ms (compara calibración vs Internet)
- ✅ Tasa de éxito: >95% (todos los algoritmos aceptados)
- ✅ Baja dispersión: σ < 5 ms (bajo ruido)
- ✅ Overhead consistente (diferencias estables entre grupos)

#### Modo Manual (Debug/Desarrollo)

Si necesitas control granular, ejecuta los scripts por separado:

**Terminal 1 - Levanta servidor:**
```bash
./docker_server_run.sh --port 8443
```

**Terminal 2 - Ejecuta sonda:**
```bash
./docker_probe_run.sh --hostname localhost --port 8443 --repeticiones 3 --max-workers 5
```

---

### 2. Escaneo Internet (Datos Reales)

Una vez validada la calibración, escanea servidores reales:

```bash
# Sintaxis
./ejecutar_sonda.sh --input-csv ARCHIVO.csv [--max-hostnames N] [--repeticiones N] [--max-workers N]

# Ejemplos
./ejecutar_sonda.sh --input-csv prueba.csv --max-hostnames 10 --repeticiones 1 --max-workers 5      # Test rápido (~5 min)
./ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 100 --repeticiones 3 --max-workers 20    # Producción (~30 min)
./ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 500 --repeticiones 3 --max-workers 20    # Full scan (~2 horas)
```

**Parámetros:**
- `--input-csv ARCHIVO.csv`: Archivo CSV con dominios (default: `majestic_million.csv`)
- `--max-hostnames N`: Número de dominios a escanear (default: 100)
- `--repeticiones N`: Repeticiones por grupo PQC (default: 3)
- `--max-workers N`: Hilos paralelos (default: 20)

**Algoritmos probados (14 total):**
```
1. Automático         - Negociación por defecto
2. X25519             - Clásico curva elíptica (baseline)
3. X25519MLKEM768     - Híbrido X25519 + Kyber768 (NIST)
4. x25519_kyber768    - Híbrido X25519 + Kyber768 (viejo)
5. mlkem768           - Puro Kyber768 (NIST)
6. kyber768           - Puro Kyber768 (antiguo)
7. p256_kyber768      - Híbrido P-256 + Kyber768
8. SecP256r1MLKEM768  - Híbrido P-256 + Kyber768 (NIST)
9. x25519_mlkem512    - Híbrido X25519 + Kyber512 (Nivel 1)
10. x25519_kyber512   - Híbrido X25519 + Kyber512 (Nivel 1)
11. frodo640aes       - Puro FrodoKEM (retículos)
12. bikel1            - Code-based puro
13. x25519_bikel1     - Híbrido X25519 + BIKE
14. x25519_hqc128     - Híbrido X25519 + HQC
```

**Archivos generados:**
```
resultados/
├── resultados_sonda_pqc.json     # JSON completo (una entrada por algoritmo/hostname)
├── resumen_por_grupo.csv          # Resumen estadístico (agregado por algoritmo)
└── sonda_pqc.log                  # Log detallado de ejecución
```

---

### 3. Análisis y Gráficas

Genera gráficas profesionales a partir de los resultados JSON:

```bash
# Uso básico (usa defaults)
./ejecutar_analisis.sh

# Personalizado
./ejecutar_analisis.sh resultados/resultados_sonda_pqc.json imagenes/

# Múltiples análisis
./ejecutar_analisis.sh resultados/sonda_test.json imagenes/test/
```

**Gráficas generadas (7):**

| # | Archivo | Descripción |
|---|---------|-------------|
| 1 | `1_latencia_por_grupo.png` | 📈 4-panel: DNS, TCP, TLS, Total por grupo |
| 2 | `2_overhead_bytes.png` | 📦 4-panel: Bytes enviados, recibidos, overhead |
| 3 | `3_latencia_vs_bytes.png` | 🎯 Scatter: Trade-off latencia vs tamaño |
| 4 | `4_boxplot_distribucion.png` | 📊 Box plots: Distribuciones y outliers |
| 5 | `5_heatmap_correlacion.png` | 🔥 Matriz: Correlación entre métricas |
| 6 | `6_tendencia_lineal.png` | 📈 Líneas: Tendencias por grupo |
| 7 | `7_tasa_exito_conexiones.png` | ✅ Stacked bar: Tasa de éxito por grupo |

**Además se genera:**
- `reporte_analisis.txt`: Reporte estadístico completo

---

### 4. Pipeline Completo

Ejecuta sonda + análisis en secuencia:

```bash
./test_pipeline.sh [hostnames]

# Ejemplo
./test_pipeline.sh 10  # Test rápido
./test_pipeline.sh 100 # Producción
```

---

## 📊 Interpretación de Resultados

### Calibración vs Internet

| Métrica | 🧪 Calibración (localhost) | 🌐 Internet | 📝 Interpretación |
|---------|---------------------------|--------------|-------------------|
| **Latencia DNS** | ~0 ms | 10-50 ms | Red de resolución |
| **Latencia TCP** | ~0-1 ms | 20-100 ms | Propagación de señal |
| **Latencia TLS** | 1-5 ms | 50-200 ms | Handshake + red |
| **Latencia Total** | **1-10 ms** | **80-350 ms** | Suma de todas |
| **Overhead Kyber** | 1200-1300 bytes | 1200-1300 bytes | ✅ Consistente |
| **Tasa de éxito** | **>95%** | **60-80%** | Timeouts/firewalls |

### Validación Metodológica

La calibración **valida** que tu sonda funciona si:

1. ✅ **Latencias bajas** (~0-10 ms total)
2. ✅ **Alta tasa de éxito** (>95%)
3. ✅ **Overhead consistente** (diferencias estables)
4. ✅ **Baja dispersión** (σ < 5 ms)

### Fórmulas de Análisis

```
Latencia_Red ≈ Latencia_Internet - Latencia_Calibración

Overhead_Algoritmo = Bytes_Algoritmo - Bytes_Baseline

Ejemplo:
  Kyber_Internet = 180 ms
  Kyber_Calibración = 3 ms
  Latencia_Red ≈ 177 ms
  → Solo 3 ms son del procesamiento criptográfico
```

### Interpretación de Gráficas

#### Gráfica 1: Latencia por Grupo
- ✅ Barras cortas = algoritmo más rápido
- ⚠️ Barras largas = overhead de handshake TLS
- 📊 Las barras de error muestran variabilidad

#### Gráfica 3: Latencia vs Bytes
- 🟢 Esquina inferior-izquierda = IDEAL (rápido + pequeño)
- 🔴 Esquina superior-derecha = EVITAR (lento + grande)
- 🟡 Trade-off visible entre latencia y tamaño

#### Gráfica 5: Heatmap
- 🔴 Rojo = correlación alta positiva
- 🔵 Azul = correlación alta negativa
- ⚪ Blanco = sin correlación

---

# Sistema de Clasificación de Errores - Sonda PQC

## Estructura de Resultados

Cada resultado de prueba ahora contiene dos campos principales:

### 1. `error_category` (Categoría de Error)
Campo normalizado que clasifica el tipo de error ocurrido. Valores posibles:

- **`null`**: No hubo error (conexión exitosa)
- **`ERROR_DNS`**: Fallo en la resolución DNS del hostname
- **`ERROR_TCP_REFUSED`**: Puerto 443 cerrado o conexión rechazada a nivel TCP
- **`ERROR_TCP_TIMEOUT`**: Timeout durante la conexión TCP inicial
- **`ERROR_TCP_OTHER`**: Otros errores de red/TCP (unreachable, etc.)
- **`ERROR_TLS_TIMEOUT`**: Timeout durante el handshake TLS
- **`ERROR_TLS_ALERT`**: El servidor envió un TLS Alert rechazando el handshake
- **`ERROR_UNKNOWN`**: Error inesperado o desconocido

### 2. `connection_result` (Resultado de Conexión)
Indica si el handshake TLS fue exitoso o rechazado. Valores posibles:

- **`ACEPTADO`**: El servidor aceptó la conexión y completó el handshake TLS exitosamente
- **`RECHAZADO`**: El servidor rechazó explícitamente el handshake (incompatibilidad de grupos, protocolo, etc.)
- **`null`**: No aplicable (hubo un error antes del handshake TLS)

### 3. `res` (Detalles)
Campo de texto libre con información adicional sobre el resultado o error.

## Matriz de Clasificación

| error_category      | connection_result | Significado                                                    |
|---------------------|-------------------|----------------------------------------------------------------|
| `null`              | `ACEPTADO`        | ✅ Conexión exitosa                                            |
| `ERROR_TLS_ALERT`   | `RECHAZADO`       | ⚠️ Servidor rechazó el handshake (ej: grupo no soportado)     |
| `ERROR_DNS`         | `null`            | ❌ No se pudo resolver el hostname                             |
| `ERROR_TCP_REFUSED` | `null`            | ❌ Puerto 443 cerrado o firewall                               |
| `ERROR_TCP_TIMEOUT` | `null`            | ❌ Timeout en conexión TCP                                     |
| `ERROR_TCP_OTHER`   | `null`            | ❌ Otro error de red (unreachable, etc.)                       |
| `ERROR_TLS_TIMEOUT` | `null`            | ❌ Timeout durante handshake TLS                               |
| `ERROR_UNKNOWN`     | `null`            | ❌ Error inesperado                                            |

## Ejemplos de Resultados

### ✅ Conexión Exitosa
```json
{
    "error_category": null,
    "connection_result": "ACEPTADO",
    "res": "Server Temp Key: X25519 MLKEM768, 256 bits",
    "grupo": "X25519MLKEM768",
    ...
}
```

### ⚠️ Servidor Rechazó el Grupo PQC
```json
{
    "error_category": "ERROR_TLS_ALERT",
    "connection_result": "RECHAZADO",
    "res": "TLS alert: handshake failure",
    "grupo": "mlkem768",
    ...
}
```

### ❌ Error de Infraestructura (DNS)
```json
{
    "error_category": "ERROR_DNS",
    "connection_result": null,
    "res": "DNS no resolvió",
    "grupo": "X25519MLKEM768",
    ...
}
```

### ❌ Timeout
```json
{
    "error_category": "ERROR_TLS_TIMEOUT",
    "connection_result": null,
    "res": "Timeout durante handshake TLS",
    "grupo": "frodo640aes",
    ...
}
```

## Análisis de Resultados

### Filtrar solo conexiones exitosas:
```python
exitosas = [p for p in pruebas if p["connection_result"] == "ACEPTADO"]
```

### Filtrar por tipo de error:
```python
errores_dns = [p for p in pruebas if p["error_category"] == "ERROR_DNS"]
rechazos_tls = [p for p in pruebas if p["connection_result"] == "RECHAZADO"]
```

### Estadísticas por categoría:
```python
from collections import Counter

# Contar errores por categoría
error_stats = Counter(p["error_category"] for p in pruebas)

# Contar resultados de conexión
connection_stats = Counter(p["connection_result"] for p in pruebas)
```

## Beneficios

1. **Normalización**: Los errores están clasificados de forma consistente
2. **Análisis**: Facilita la agregación y análisis estadístico
3. **Separación**: Distingue claramente entre errores de infraestructura y rechazo activo del servidor
4. **Compatibilidad**: El campo `res` mantiene información detallada para debugging

---

## ⚙️ Configuración Avanzada

### Usar Dataset Personalizado

```bash
# Copiar tu CSV a data/
cp mis_dominios.csv data/

# Modificar ejecutar_sonda.sh para usar tu CSV
# (actualmente usa majestic_million.csv por defecto)
```

**Formato esperado del CSV:**
```
rank,domain
1,google.com
2,facebook.com
3,wikipedia.org
```

### Aumentar Límites de Procesos

Para escaneos grandes (>1000 dominios):

```bash
# En el host (fuera del contenedor)
ulimit -n 4096  # Aumentar file descriptors
```

### Configurar Puerto del Servidor

```bash
# Calibración en puerto diferente
./scripts/calibracion/servidor_control_pqc_docker.sh 4444
./scripts/calibracion/calibrar_sonda.sh 4444 5
```

### Aumentar Velocidad de Escaneo

```bash
# Más workers = más rápido (pero más recursos)
./ejecutar_sonda.sh 100 3 30  # 30 workers en lugar de 20
```

---

## 🔧 Troubleshooting

### Error: "Docker no encontrado"

```bash
# Ubuntu/Debian
sudo apt-get install docker.io

# macOS
brew install docker

# Verificar
docker --version
```

### Error: "Puerto 4433 ocupado"

```bash
# Detener procesos antiguos
docker stop $(docker ps -q)
pkill -f "s_server.*4433"

# O usar puerto diferente
./test_calibracion_completa.sh
```

### Error: "ModuleNotFoundError: seaborn"

```bash
# Instalar dependencias
pip install -r requirements.txt

# O manualmente
pip install pandas numpy matplotlib seaborn
```

### La sonda es muy lenta

```bash
# Aumentar workers
./ejecutar_sonda.sh 100 1 30

# Reducir repeticiones
./ejecutar_sonda.sh 100 1 20
```

### Servidor no accesible

```bash
# Verificar que el servidor está corriendo
docker ps

# Ver logs del servidor
docker logs $(docker ps -q)

# Reiniciar completamente
docker stop $(docker ps -q)
./test_calibracion_completa.sh
```

### Gráficas no se generan

```bash
# Verificar que el JSON existe
ls -lh resultados/resultados_sonda_pqc.json

# Verificar dependencias
pip list | grep -E 'pandas|matplotlib|seaborn'

# Ejecutar análisis manualmente
python3 scripts/ml/analizar_resultados.py \
  --input resultados/resultados_sonda_pqc.json \
  --output imagenes/
```

---

## 🎓 Para el TFG

### Estructura Sugerida de Capítulos

**Capítulo 4: Metodología**
- 4.1 Diseño de la sonda PQC
- 4.2 Entorno de ejecución (Docker + OpenSSL)
- 4.3 Sistema de calibración
- 4.4 Métricas recolectadas

**Capítulo 5: Validación**
- 5.1 Calibración con servidor de control
  - Tabla de resultados calibración
  - Figura 5.1: `resultados/calibracion/imagenes_*/1_latencia_por_grupo.png`
  - Figura 5.2: `resultados/calibracion/imagenes_*/2_overhead_bytes.png`
  - Figura 5.3: `resultados/calibracion/imagenes_*/7_tasa_exito_conexiones.png`
- 5.2 Análisis de consistencia
  - Comparativa calibración vs Internet (tabla)
  - Desglose de latencias: red vs. algoritmo

**Capítulo 6: Resultados**
- 6.1 Escaneo de 100+ servidores reales
  - Figura 6.1: `imagenes/1_latencia_por_grupo.png`
  - Figura 6.2: `imagenes/3_latencia_vs_bytes.png`
  - Figura 6.3: `imagenes/5_heatmap_correlacion.png`
  - Tabla: Resumen estadístico (de `reporte_analisis.txt`)
- 6.2 Discusión de resultados

**Anexo A: Scripts**
- Metodología de calibración
- Código relevante (extractos)

### Workflow Completo para TFG

```bash
# 1. Validar instalación
./test_calibracion_completa.sh

# 2. Guardar resultados calibración
cp -r resultados/calibracion/imagenes_* docs/imagenes/calibracion/

# 3. Test rápido Internet
./ejecutar_sonda.sh 10 1 5
./ejecutar_analisis.sh

# 4. Escaneo producción
./ejecutar_sonda.sh 200 3 20

# 5. Análisis final
./ejecutar_analisis.sh

# 6. Copiar gráficas a memoria
cp imagenes/*.png docs/imagenes/resultados/
cp imagenes/reporte_analisis.txt docs/
```

### Checklist Pre-Entrega

- [ ] Calibración ejecutada y documentada
- [ ] Gráficas calibración incluidas en Figura 5.x
- [ ] Escaneo Internet completado (≥100 hostnames)
- [ ] Gráficas finales en Figura 6.x
- [ ] Comparativa calibración vs Internet (tabla)
- [ ] Reporte estadístico revisado
- [ ] Scripts documentados en anexo
- [ ] Dataset utilizado especificado

---

## 📈 Tiempo Estimado por Tarea

| Hostnames | Repeticiones | Tiempo Sonda | Tamaño JSON |
|-----------|--------------|--------------|-------------|
| 10 | 1 | ~1-5 min | ~100 KB |
| 50 | 2 | ~10 min | ~500 KB |
| 100 | 3 | ~30 min | ~1 MB |
| 200 | 3 | ~60 min | ~2 MB |
| 500 | 3 | ~2-3 horas | ~5 MB |

**Análisis:** Siempre ~30 segundos (independiente del tamaño)

---

## 🏆 Características del Sistema

| Componente | Líneas de Código | Archivos |
|------------|------------------|----------|
| Scripts calibración | ~400 | 3 |
| Análisis de datos | ~550 | 1 |
| Automatización | ~500 | 4 |
| Documentación | ~1500 | 1 (este archivo) |
| **TOTAL** | **~2950** | **9** |

---

## 📞 Soporte y Recursos

### Logs y Debug

```bash
# Logs de calibración
cat /tmp/servidor_control.log

# Logs de sonda
cat resultados/sonda_pqc.log

# Logs de Docker
docker logs $(docker ps -q)
```

### Verificar Estado

```bash
# Docker funcionando
docker ps

# Puerto disponible
netstat -tuln | grep 4433

# Dependencias instaladas
pip list | grep -E 'pandas|numpy|matplotlib|seaborn'
```

### Comandos Útiles

```bash
# Limpiar todos los contenedores
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)

# Ver espacio en disco
df -h
du -sh resultados/ imagenes/

# Ver memoria
free -h
```

---

## 📊 Resultados Esperados

### Calibración (localhost:4433)
```
Latencias: 0-10 ms
Éxito: >95%
Overhead: 100-1300 bytes (según algoritmo)
Desviación: σ < 5 ms
```

### Internet (servidores reales)
```
Latencias: 80-350 ms
Éxito: 60-80%
Overhead: 100-1300 bytes (igual que calibración ✅)
Desviación: σ ~ 20-50 ms
```

---

## 📝 Notas Finales

- **Reproducibilidad**: Todos los scripts son deterministas y reproducibles
- **Portabilidad**: Docker garantiza mismo entorno en cualquier máquina
- **Escalabilidad**: Soporta desde 10 hasta 10,000+ hostnames
- **Documentación**: Sistema completamente auto-documentado

---

**Creado:** 2024-2026  
**Universidad:** Carlos III de Madrid (UC3M)  
**Proyecto**: TFG - Análisis de Criptografía Post-Cuántica en Internet  
**Última actualización:** Febrero 2026

---

## 🎯 Resumen de Comandos

```bash
# Validar todo
./test_calibracion_completa.sh

# Escanear Internet
./ejecutar_sonda.sh 100 3 20

# Generar gráficas
./ejecutar_analisis.sh

# Ver resultados
ls -lh imagenes/
cat imagenes/reporte_analisis.txt
```

**¡Sistema listo para uso! 🚀**
