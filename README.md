# Sonda de Detección de Criptografía Post-Cuántica (PQC) 🚀

> Una herramienta experimental para monitorizar y analizar la adopción de algoritmos criptográficos post-cuánticos en servidores web reales.

**Trabajo de Fin de Grado - Universidad Carlos III de Madrid (UC3M)**

---

## 📋 Tabla de Contenidos

- [Descripción General](#-descripción-general)
- [Requisitos Previos](#-requisitos-previos)
- [Instalación](#-instalación)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Uso](#-uso)
- [Configuración Avanzada](#-configuración-avanzada)
- [Resultados y Análisis](#-resultados-y-análisis)
- [Detalles Técnicos](#-detalles-técnicos)
- [Troubleshooting](#-troubleshooting)

---

## 📖 Descripción General

Este proyecto implementa dos **sondas de conectividad HTTPS** diseñadas para:

1. **Sonda Base** (`sonda_base.py`): Analiza suites de cifrado clásicas y datos del certificado de servidores HTTPS
2. **Sonda PQC** (`sonda_pqc_final.py`): Evalúa la capacidad de los servidores para negociar algoritmos criptográficos post-cuánticos

### 🎯 Objetivo Principal

Evaluar la capacidad de los servidores actuales para negociar intercambios de claves **híbridos** (clásicos + cuánticos) y detectar fragmentación o problemas de interoperabilidad en la transición hacia los estándares del NIST.

### ✨ Características

- ✅ Escaneo concurrente de múltiples hostnames
- ✅ Soporte para algoritmos post-cuánticos (Kyber, FrodoKEM, SIKE, etc.)
- ✅ Análisis de certificados X.509
- ✅ Métricas de timing detalladas (DNS, TCP, TLS handshake)
- ✅ Exportación de resultados en JSON
- ✅ Entorno containerizado con Docker
- ✅ Conversión automática de JSON a CSV para análisis ML

---

## 📦 Requisitos Previos

Antes de comenzar, asegúrate de tener instalado:

### Sistema Operativo
- Linux, macOS o Windows (con WSL2)

### Software Requerido
- **Docker** (versión 20.10 o superior)
  - [Descargar Docker Desktop](https://www.docker.com/products/docker-desktop)
  - O instalar Docker Engine: `sudo apt-get install docker.io` (Ubuntu/Debian)

### Verificar Instalación
```bash
docker --version
docker ps  # Verifica que puedes ejecutar comandos docker
```

---

## 🚀 Instalación

### Paso 1: Clonar o Descargar el Repositorio

```bash
# Si tienes git
git clone <repositorio_url>
cd TFG_Diego

# O descarga directamente y descomprime
unzip TFG_Diego.zip
cd TFG_Diego
```

### Paso 2: Construir la Imagen Docker

La imagen incluye OpenSSL con soporte para algoritmos post-cuánticos (Open Quantum Safe):

```bash
docker build -t tfg-pqc .
```

**Tiempo estimado**: 2-5 minutos

Puedes verificar que se construyó correctamente:
```bash
docker images | grep tfg-pqc
```

### Paso 3: Lanzar el Contenedor

```bash
docker run -it -v $(pwd):/home/tfg tfg-pqc
```

Dentro del contenedor, te encontrarás en `/home/tfg` con acceso a todos tus archivos.

---

## 📂 Estructura del Proyecto

```
TFG_Diego/
├── README.md                                  # Documentación completa
├── Dockerfile                                 # Configuración del contenedor Docker
├── data/
│   └── tranco.csv                            # Lista de dominios (Tranco ranking)
├── scripts/
│   ├── sondas/
│   │   ├── sonda_base.py                     # Sonda de línea base (análisis clásico)
│   │   └── sonda_pqc_final.py                # Sonda post-cuántica (algoritmos PQC)
│   ├── individuales/
│   │   └── hostname_conexion.py              # Análisis individual de un hostname específico
│   ├── auxiliares/
│   │   └── json_to_csv.py                    # Convertidor JSON → CSV para ML
│   └── ml/
│       ├── estudio_sonda_base.py             # Análisis ML de datos sonda base
│       └── estudio_sonda_pqc.py              # Análisis ML de datos sonda PQC
├── resultados/                                # Resultados de escaneos (JSON)
│   ├── resultados_sonda_base.json            # Resultados de escaneos base
│   ├── resultados_sonda_pqc.json             # Resultados de escaneos PQC
│   └── *.json                                # Resultados individuales por hostname
├── ml_data/                                  # Datos procesados para ML (CSV)
│   └── *.csv
└── venv/                                     # Entorno virtual (si lo usas localmente)
```

### Descripción de Archivos Clave

| Archivo | Descripción |
|---------|------------|
| `sondas/sonda_base.py` | Extrae información TLS clásica (versión, cipher, certificados) |
| `sondas/sonda_pqc_final.py` | Prueba algoritmos híbridos/puros PQC contra servidores |
| `individuales/hostname_conexion.py` | Conecta a un host específico y extrae toda la información posible |
| `auxiliares/json_to_csv.py` | Transforma resultados JSON a CSV para análisis |
| `ml/estudio_sonda_base.py` | Modelo ML para predecir seguridad alta en conexiones TLS |
| `ml/estudio_sonda_pqc.py` | Modelo ML para clasificar grupos PQC de conexiones TLS |
| `tranco.csv` | Datos de entrada: 1 millón de dominios ordenados por popularidad |
| `Dockerfile` | Automatiza la instalación de OpenSSL-OQS en Alpine Linux |

---

## 💻 Uso

### Dentro del Contenedor Docker

Una vez lanzado el contenedor (`docker run -it ...`):

#### 1. Sonda Base - Análisis Clásico

Realiza un escaneo básico de TLS en los primeros 500 dominios:

```bash
python3 scripts/sondas/sonda_base.py --max-hostnames 500
```

**Opciones disponibles:**
```bash
python3 scripts/sondas/sonda_base.py --help

# Ejemplos personalizados:
python3 scripts/sondas/sonda_base.py --max-hostnames 1000 --max-workers 50
python3 scripts/sondas/sonda_base.py --max-hostnames 200 --max-workers 30 --log-level DEBUG
```

**Parámetros:**
- `--max-hostnames`: Número máximo de dominios a escanear (default: 100)
- `--max-workers`: Hilos concurrentes (default: 20)
- `--log-level`: DEBUG, INFO, WARNING, ERROR (default: INFO)
- `--log-file`: Ruta del archivo de log

**Salida:**
```
resultados/resultados_sonda_base.json
```

---

#### 2. Sonda PQC - Análisis Post-Cuántico

Prueba algoritmos post-cuánticos contra servidores:

```bash
python3 scripts/sondas/sonda_pqc_final.py --max-hostnames 100
```

**Opciones disponibles:**
```bash
python3 scripts/sondas/sonda_pqc_final.py --help

# Ejemplos personalizados:
python3 scripts/sondas/sonda_pqc_final.py --max-hostnames 200 --max-workers 30
python3 scripts/sondas/sonda_pqc_final.py --max-hostnames 50 --max-openssl-procs 8
```

**Parámetros:**
- `--max-hostnames`: Número máximo de dominios a escanear (default: 100)
- `--max-workers`: Hilos para escaneo (default: 20)
- `--max-openssl-procs`: Límite de procesos OpenSSL concurrentes (default: auto)
- `--log-level`: DEBUG, INFO, WARNING, ERROR (default: INFO)

**Algoritmos Probados:**
- `Automático`: Negociación por defecto de OpenSSL
- `prime256v1`: ECDSA clásico (referencia)
- `x25519_mlkem768`: Híbrido X25519 + Kyber768
- `p256_kyber768`: Híbrido P-256 + Kyber768
- `kyber768`: Puro Kyber768 (NIST)
- `frodo640aes`: Puro FrodoKEM
- `sikep434`: Puro SIKE

**Salida:**
```
resultados/resultados_sonda_pqc.json
```

---

#### 3. Análisis Individual de un Hostname

Para analizar un hostname específico en detalle **FUERA DEL CONTENEDOR DOCKER**:

```bash
# En tu terminal local (NO dentro del contenedor)
python3 scripts/individuales/hostname_conexion.py --hostname www.ejemplo.com
```

**Características:**
- Análisis completo de TLS/SSL del hostname
- Extracción detallada del certificado X.509
- Medición de tiempos (DNS, TCP, handshake)
- Prueba de todas las versiones TLS soportadas (1.0, 1.1, 1.2, 1.3)
- Exportación de resultados a JSON individual

**Opciones disponibles:**
```bash
python3 scripts/individuales/hostname_conexion.py --help

# Ejemplos:
python3 scripts/individuales/hostname_conexion.py --hostname cosec.inf.uc3m.es
python3 scripts/individuales/hostname_conexion.py --hostname www.google.com
```

**Salida:**
```
resultados/[hostname].json  # Ejemplo: www.ejemplo.com.json
```

**⚠️ IMPORTANTE:** Este script se ejecuta **FUERA del contenedor Docker**, ya que necesita acceso directo al entorno Python del sistema host. Asegúrate de tener instaladas las dependencias necesarias:

```bash
# Si usas entorno virtual (recomendado)
source venv/bin/activate

# Instalar dependencias si es necesario
pip install cryptography dnspython
```

---

#### 4. Convertidor JSON a CSV

Transforma los resultados JSON para análisis con ML:

```bash
# Uso básico (el nombre se genera automáticamente)
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_pqc.json

# Con nombre personalizado
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_pqc.json -o mis_datos.csv
```

**Entrada:** Archivos JSON de `resultados/`  
**Salida:** Archivos CSV en `ml_data/`

**Formato del nombre de salida:**
- Entrada: `resultados_sonda_pqc.json` (200 hostnames)
- Salida: `resultados_sonda_pqc_200_hostnames.csv`

---

#### 5. Análisis de Machine Learning

Una vez que tienes los datos en formato CSV, puedes ejecutar los scripts de análisis ML **FUERA DEL CONTENEDOR**:

##### Análisis de Sonda Base

```bash
# En tu terminal local (NO dentro del contenedor)
python3 scripts/ml/estudio_sonda_base.py
```

**Objetivo:** Predecir si una conexión TLS tiene "Seguridad Alta" basándose en:
- Versión TLS (preferiblemente 1.3)
- HSTS activo
- Perfect Forward Secrecy
- Tamaño de claves
- Algoritmos de certificado

**Genera:**
- Modelo de clasificación (Random Forest)
- Matriz de confusión
- Importancia de características
- Reporte de métricas (accuracy, precision, recall, F1-score)

##### Análisis de Sonda PQC

```bash
# En tu terminal local (NO dentro del contenedor)
python3 scripts/ml/estudio_sonda_pqc.py
```

**Objetivo:** Clasificar el grupo PQC de una conexión TLS basándose en:
- Tiempos de handshake
- Tamaño de respuesta
- Cipher suite negociado
- Versión TLS
- Características del certificado

**Genera:**
- Modelo de clasificación multiclase
- Matriz de confusión por grupo PQC
- Importancia de características
- Reporte detallado por clase

**⚠️ Requisitos para scripts ML:**
```bash
# Activar entorno virtual
source venv/bin/activate

# Instalar dependencias ML
pip install pandas numpy matplotlib seaborn scikit-learn
```

---

### Flujo Típico de Trabajo

```bash
# 1. Dentro del contenedor - Ejecutar escaneos
docker run -it -v $(pwd):/home/tfg tfg-pqc

# 2. Ejecutar escaneo base (rápido)
python3 scripts/sondas/sonda_base.py --max-hostnames 100

# 3. Ejecutar escaneo PQC (más lento, pero más completo)
python3 scripts/sondas/sonda_pqc_final.py --max-hostnames 100

# 4. Convertir resultados a CSV (dentro del contenedor)
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_base.json
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_pqc.json

# 5. Salir del contenedor
exit

# 6. FUERA DEL CONTENEDOR - Análisis individual de un host
python3 scripts/individuales/hostname_conexion.py --hostname www.uc3m.es

# 7. FUERA DEL CONTENEDOR - Ejecutar análisis ML
source venv/bin/activate
python3 scripts/ml/estudio_sonda_base.py
python3 scripts/ml/estudio_sonda_pqc.py

# 8. Los resultados estarán disponibles en:
ls resultados/     # JSON de escaneos
ls ml_data/        # CSV para análisis
```

---

## ⚙️ Configuración Avanzada

### Aumentar Límites de Procesos

Para escaneos muy grandes (>1000 dominios), aumenta los límites del sistema:

```bash
# En el host (fuera del contenedor)
ulimit -n 4096  # Aumentar límite de file descriptors
```

### Usar Archivo CSV Personalizado

```bash
# Copiar tu propio CSV a la carpeta data/
cp mis_dominios.csv data/mis_dominios.csv

# Usarlo en la sonda (dentro del contenedor)
python3 scripts/sondas/sonda_base.py --input-csv data/mis_dominios.csv --max-hostnames 200
```

**Formato esperado del CSV:**
```
rank,domain
1,google.com
2,facebook.com
3,wikipedia.org
...
```

### Variables de Entorno

```bash
# Especificar ruta del binario OpenSSL personalizado
export OPENSSL_BIN=/opt/openssl/bin/openssl
python3 scripts/sondas/sonda_pqc_final.py
```

### Configuración del Entorno Virtual (para scripts fuera del contenedor)

```bash
# Crear entorno virtual (primera vez)
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate  # En Linux/macOS
# O en Windows:
# venv\Scripts\activate

# Instalar dependencias
pip install cryptography dnspython pandas numpy matplotlib seaborn scikit-learn tqdm

# Verificar instalación
pip list
```

---

## 📊 Resultados y Análisis

### Estructura de Resultados JSON

#### Sonda Base (`resultados_sonda_base.json`)
```json
{
  "resumen": {
    "timestamp_finalizacion": "2026-02-03T18:36:51.102226+00:00",
    "total_hostnames": 200,
    "escaneos_exitosos": 141,
    "escaneos_fallidos": 59,
    "tasa_exito_percent": 70.5
  },
  "datos": [
    {
      "hostname": "google.com",
      "timestamp": "2026-02-03T18:32:51.282598+00:00",
      "estado": "exito",
      "tls_version": "TLSv1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "alpn": "h2",
      "cert_issuer": "CN=...",
      ...
    }
  ]
}
```

#### Sonda PQC (`resultados_sonda_pqc.json`)
```json
{
  "resumen": {
    "total_hostnames": 100,
    "hosts_con_al_menos_un_exito": 50,
    "total_pruebas": 700,
    "pruebas_exitosas": 100,
    "tasa_exito_pruebas_percent": 14.29,
    "grupos_probados": ["Automático", "prime256v1", "x25519_mlkem768", ...]
  },
  "datos": [
    {
      "hostname": "example.com",
      "timestamp": "2026-02-03T18:32:51.282598+00:00",
      "pruebas": [
        {
          "status": "ACEPTADO",
          "grupo": "x25519_mlkem768",
          "tls_version": "TLSv1.3",
          "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256",
          "ip": "93.184.216.34",
          "dns_time_ms": 12.5,
          "tcp_time_ms": 25.3,
          "handshake_time_ms": 145.8,
          ...
        }
      ]
    }
  ]
}
```

#### Análisis Individual (`resultados/[hostname].json`)

Para análisis de un hostname específico ejecutado con `hostname_conexion.py`:

```json
{
  "hostname": "www.uc3m.es",
  "timestamp": "2026-02-11T10:30:45.123456+00:00",
  "estado": "exito",
  "ip": "163.117.128.1",
  "latencia_dns_ms": 15.23,
  "datos_conexion": {
    "tiempo_conexion_segundos": 0.458,
    "puerto": 443
  },
  "datos_protocolo": {
    "version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "bits_clave": 256,
    "versiones_soportadas": {
      "TLS1.0": false,
      "TLS1.1": false,
      "TLS1.2": true,
      "TLS1.3": true
    },
    "perfect_forward_secrecy": true,
    "alpn": "h2"
  },
  "datos_certificado": {
    "subject": "CN=www.uc3m.es",
    "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1",
    "valid_from": "2025-01-15T00:00:00",
    "valid_to": "2026-02-15T23:59:59",
    "dias_valido": 35,
    "clave_publica_algoritmo": "RSA",
    "clave_publica_tamaño_bits": 2048,
    "san": ["www.uc3m.es", "uc3m.es"],
    "fingerprint_sha256": "a1:b2:c3:..."
  },
  "datos_seguridad_avanzada": {
    "hsts_presente": true,
    "hsts_max_age_segundos": 31536000,
    "ocsp_stapling": true
  }
}
```

### Interpretación de Estados

| Estado | Significado |
|--------|-----------|
| **ACEPTADO** ✅ | El servidor soporta el grupo de cifrado. Conexión segura. |
| **RECHAZADO** ❌ | Incompatibilidad de protocolo o versión (draft mismatch). |
| **ERROR** ⚠️ | Fallo de DNS, TCP, timeout u otro error de infraestructura. |

### Métricas Clave

- `dns_time_ms`: Tiempo de resolución DNS
- `tcp_time_ms`: Tiempo de establecimiento de conexión TCP
- `handshake_time_ms`: Tiempo del handshake TLS
- `cert_issuer`: Emisor del certificado X.509
- `cert_not_after`: Fecha de expiración del certificado
- `versiones_soportadas`: Qué versiones TLS acepta el servidor (solo en análisis individual)
- `perfect_forward_secrecy`: Si la conexión tiene PFS
- `hsts_presente`: Si el servidor tiene HSTS activo

### Análisis de Machine Learning

#### Resultados del Modelo de Sonda Base

El script `estudio_sonda_base.py` genera:

1. **Variable objetivo**: "Seguridad Alta" (TLS 1.3 + HSTS activo)
2. **Features principales**:
   - Versión TLS
   - Tamaño de claves
   - Perfect Forward Secrecy
   - Algoritmo de clave pública
   - OCSP Stapling
   - Días de validez del certificado

3. **Métricas del modelo**:
   - Accuracy
   - Precision
   - Recall
   - F1-Score

4. **Visualizaciones**:
   - Importancia de características
   - Matriz de confusión
   - Distribución de predicciones

#### Resultados del Modelo de Sonda PQC

El script `estudio_sonda_pqc.py` genera:

1. **Variable objetivo**: Grupo PQC utilizado
2. **Features principales**:
   - Tiempos de handshake
   - Tamaño de respuesta TLS
   - Versión TLS
   - Cipher suite
   - Familia IP (IPv4/IPv6)

3. **Clasificación multiclase** por grupo:
   - Automático
   - prime256v1
   - x25519_mlkem768
   - p256_kyber768
   - kyber768
   - frodo640aes
   - sikep434

4. **Visualizaciones**:
   - Matriz de confusión por clase
   - Importancia de características
   - Métricas por grupo PQC

---

## 🔧 Detalles Técnicos

### Arquitectura

```
┌─────────────────────────────────────────┐
│     Docker Container (Alpine Linux)     │
├─────────────────────────────────────────┤
│  Python 3 + OpenSSL (OQS Provider)     │
│  ├── sondas/sonda_base.py              │
│  ├── sondas/sonda_pqc_final.py         │
│  └── auxiliares/json_to_csv.py         │
├─────────────────────────────────────────┤
│  Librerías de OpenSSL                  │
│  ├── liboqs (quantum-safe algorithms)  │
│  └── classic crypto (AES, SHA, etc.)   │
├─────────────────────────────────────────┤
│  Volumen montado: /home/tfg            │
│  (sincronización con host)             │
└─────────────────────────────────────────┘
            ↕
┌─────────────────────────────────────────┐
│        Host System (Linux/macOS)        │
├─────────────────────────────────────────┤
│  Entorno Python local (venv)           │
│  ├── individuales/hostname_conexion.py │
│  ├── ml/estudio_sonda_base.py          │
│  └── ml/estudio_sonda_pqc.py           │
├─────────────────────────────────────────┤
│  Carpetas compartidas:                 │
│  ├── resultados/ (JSON)                │
│  ├── ml_data/ (CSV)                    │
│  └── data/ (input)                     │
└─────────────────────────────────────────┘
```

### Separación de Entornos

El proyecto está diseñado con dos entornos de ejecución:

#### Dentro del Contenedor Docker
- **Sondas de escaneo masivo** (`sonda_base.py`, `sonda_pqc_final.py`)
- **Conversión de datos** (`json_to_csv.py`)
- OpenSSL con soporte PQC
- Entorno aislado y reproducible

#### Fuera del Contenedor (Host)
- **Análisis individual** (`hostname_conexion.py`)
- **Machine Learning** (`estudio_sonda_base.py`, `estudio_sonda_pqc.py`)
- Acceso directo al sistema de archivos
- Mayor flexibilidad para debugging y visualización

### Dependencias

**En el Dockerfile:**
- OpenSSL 3.0 con OQS Provider
- Python 3.11
- Librerías base: cryptography, dnspython, tqdm, pandas, numpy, matplotlib, seaborn, scikit-learn

**En el Host (venv):**
- cryptography: Manejo de certificados X.509
- dnspython: Resolución DNS con métricas
- pandas: Análisis de datos
- numpy: Operaciones numéricas
- matplotlib + seaborn: Visualización
- scikit-learn: Machine Learning
- tqdm: Barras de progreso

### Concurrencia

- **ThreadPoolExecutor**: Para paralelizar escaneos por hostname
- **BoundedSemaphore**: Para limitar procesos OpenSSL concurrentes (evita saturación)
- **Timeout**: 8 segundos por handshake TLS
- **Max Workers**: Configurable (default: 20 threads)

### Manejo de Errores

La herramienta diferencia entre:
- **Fallos de infraestructura**: DNS no resuelve, puerto cerrado
- **Fallos de PQC**: El servidor rechaza el grupo de cifrado
- **Fallos de timeout**: Conexión muy lenta o servidor no responde
- **Fallos de certificado**: Certificado inválido, caducado o autofirmado (se permite la conexión de todas formas)

### Flujo de Datos

```
┌──────────────┐
│  tranco.csv  │
└──────┬───────┘
       │
       ▼
┌──────────────────────┐
│  Sondas (Docker)     │
│  ├─ sonda_base.py    │
│  └─ sonda_pqc.py     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  resultados/*.json   │
└──────┬───────────────┘
       │
       ├─────────────────────────────┬───────────────────┐
       │                             │                   │
       ▼                             ▼                   ▼
┌──────────────┐            ┌──────────────┐   ┌────────────────┐
│ json_to_csv  │            │  hostname_   │   │  Análisis      │
│ (Docker)     │            │  conexion.py │   │  manual JSON   │
└──────┬───────┘            │  (Host)      │   └────────────────┘
       │                    └──────┬───────┘
       ▼                           │
┌──────────────┐                  ▼
│ ml_data/*.csv│           ┌──────────────┐
└──────┬───────┘           │ resultados/  │
       │                   │ [host].json  │
       ▼                   └──────────────┘
┌──────────────────────┐
│  Modelos ML (Host)   │
│  ├─ estudio_base.py  │
│  └─ estudio_pqc.py   │
└──────────────────────┘
```

---

## 🐛 Troubleshooting

### Docker no está instalado
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install docker.io

# macOS
brew install docker docker-desktop

# Verificar
docker --version
```

### Permiso denegado en docker.sock
```bash
sudo usermod -aG docker $USER
newgrp docker
docker ps  # Debería funcionar sin sudo
```

### La imagen Docker no se construye
```bash
# Limpiar imágenes previas
docker rmi tfg-pqc

# Reconstruir sin caché
docker build --no-cache -t tfg-pqc .
```

### El contenedor se cuelga en escaneos grandes
```bash
# Reducir número de workers
python3 scripts/sondas/sonda_pqc_final.py --max-workers 10 --max-openssl-procs 4

# Aumentar timeout del sistema
ulimit -n 8192
```

### No se generan archivos en ml_data/
Verifica que:
1. El archivo JSON existe en `resultados/`
2. El formato JSON es válido
3. Tienes permisos de escritura en `ml_data/`

```bash
# Dentro del contenedor
ls -la resultados/
ls -la ml_data/

# Verificar formato JSON
cat resultados/resultados_sonda_base.json | python3 -m json.tool
```

### Pandas no está instalado en el contenedor
```bash
# Reconstruir la imagen
docker build --no-cache -t tfg-pqc .
```

### Error al ejecutar hostname_conexion.py

```bash
# Asegúrate de estar FUERA del contenedor
exit  # Si estás dentro del contenedor

# Activar entorno virtual
source venv/bin/activate

# Verificar dependencias
pip install cryptography dnspython

# Ejecutar el script
python3 scripts/individuales/hostname_conexion.py --hostname www.uc3m.es
```

### Error "ModuleNotFoundError" en scripts ML

```bash
# Asegúrate de estar FUERA del contenedor y con venv activo
source venv/bin/activate

# Instalar todas las dependencias ML
pip install pandas numpy matplotlib seaborn scikit-learn

# Verificar instalación
python3 -c "import pandas, sklearn, matplotlib; print('OK')"
```

### Los scripts de sonda no encuentran los archivos

**Problema:** Error `FileNotFoundError: [Errno 2] No such file or directory: '../data/tranco.csv'`

**Solución:**
```bash
# Dentro del contenedor, verifica que estás en /home/tfg
pwd  # Debe mostrar: /home/tfg

# Verifica la estructura
ls -la data/
ls -la scripts/sondas/

# Si no ves los archivos, verifica el montaje del volumen
# Sal del contenedor y vuelve a entrar con:
docker run -it -v $(pwd):/home/tfg tfg-pqc
```

### Las sondas no detectan OpenSSL con soporte PQC

```bash
# Dentro del contenedor, verifica OpenSSL
which openssl
openssl version

# Debe mostrar algo como: OpenSSL 3.0.x con OQS provider

# Verificar grupos PQC disponibles
openssl list -kem-algorithms

# Debe listar: kyber, frodo, sike, etc.
```

### Error "Connection refused" al escanear

**Problema:** Muchos hosts muestran "ERROR" con "Connection refused"

**Causas comunes:**
1. El servidor no tiene puerto 443 abierto
2. Firewall o rate limiting
3. El dominio no existe o cambió

**Solución:**
```bash
# Verificar manualmente con curl
curl -I https://ejemplo.com

# O con openssl
openssl s_client -connect ejemplo.com:443

# Reducir concurrencia para evitar rate limiting
python3 scripts/sondas/sonda_base.py --max-workers 5 --max-hostnames 50
```

### Los archivos CSV están vacíos

**Problema:** `ml_data/*.csv` tiene 0 bytes o solo headers

**Solución:**
```bash
# Verificar que hay datos exitosos en el JSON
cat resultados/resultados_sonda_base.json | grep "estado" | grep "exito" | wc -l

# Si no hay datos exitosos, ejecuta la sonda con más hostnames
python3 scripts/sondas/sonda_base.py --max-hostnames 500

# Luego convierte nuevamente
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_base.json
```

---

## 📈 Casos de Uso

### 1. Escaneo Inicial de una Región
```bash
# Dentro del contenedor
python3 scripts/sondas/sonda_base.py --max-hostnames 1000
python3 scripts/sondas/sonda_pqc_final.py --max-hostnames 1000
```

### 2. Monitoreo Continuo
```bash
# Script de cron (fuera del contenedor)
0 2 * * * docker run -v $(pwd):/home/tfg tfg-pqc \
  python3 scripts/sondas/sonda_pqc_final.py --max-hostnames 500
```

### 3. Análisis de Compatibilidad PQC
```bash
# Dentro del contenedor
python3 scripts/sondas/sonda_pqc_final.py --max-hostnames 100
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_pqc.json

# Fuera del contenedor - Análisis ML
exit
source venv/bin/activate
python3 scripts/ml/estudio_sonda_pqc.py
```

### 4. Debugging de un Host Específico
```bash
# Fuera del contenedor
python3 scripts/individuales/hostname_conexion.py --hostname problema.ejemplo.com

# Ver resultados detallados
cat resultados/problema.ejemplo.com.json | python3 -m json.tool
```

### 5. Comparación de Seguridad TLS
```bash
# Dentro del contenedor - Escanear múltiples dominios
python3 scripts/sondas/sonda_base.py --max-hostnames 500
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_base.json

# Fuera del contenedor - Análisis ML para clasificar seguridad
source venv/bin/activate
python3 scripts/ml/estudio_sonda_base.py

# El modelo identificará qué características predicen "Seguridad Alta"
```

### 6. Pipeline Completo de Investigación
```bash
# FASE 1: Escaneo Masivo (Docker)
docker run -it -v $(pwd):/home/tfg tfg-pqc
python3 scripts/sondas/sonda_base.py --max-hostnames 1000
python3 scripts/sondas/sonda_pqc_final.py --max-hostnames 1000
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_base.json
python3 scripts/auxiliares/json_to_csv.py resultados_sonda_pqc.json
exit

# FASE 2: Análisis Individual de Outliers (Host)
python3 scripts/individuales/hostname_conexion.py --hostname outlier1.com
python3 scripts/individuales/hostname_conexion.py --hostname outlier2.com

# FASE 3: Machine Learning (Host)
source venv/bin/activate
python3 scripts/ml/estudio_sonda_base.py
python3 scripts/ml/estudio_sonda_pqc.py

# FASE 4: Visualización y Reporting (Jupyter/Pandas)
jupyter notebook  # Cargar CSVs de ml_data/
```

---

## 👤 Autor

**Diego San Román Posada**  
Trabajo de Fin de Grado - Universidad Carlos III de Madrid (UC3M)  
Febrero 2026

---

## 📝 Notas

- Este proyecto es experimental y está diseñado con fines educativos/investigativos
- Los resultados pueden variar según la infraestructura de red y versiones de OpenSSL
- Algunos servidores pueden rechazar escaneos agresivos; usa `--max-workers` bajo si es necesario
- Los datos de entrada (tranco.csv) deben actualizarse periódicamente

---

**Última actualización:** Febrero 2026
