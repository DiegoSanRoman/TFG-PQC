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
├── README.md                          # Documentación completa
├── Dockerfile                         # Configuración del contenedor Docker
├── data/
│   └── tranco.csv                    # Lista de dominios (Tranco ranking)
├── scripts/
│   ├── sonda_base.py                 # Sonda de línea base (análisis clásico)
│   ├── sonda_pqc_final.py            # Sonda post-cuántica (algoritmos PQC)
│   └── json_to_csv.py                # Convertidor JSON → CSV para ML
├── resultados/                        # Resultados de escaneos (JSON)
│   ├── resultados_sonda_base.json
│   └── resultados_sonda_pqc.json
├── ml_data/                          # Datos procesados para ML (CSV)
│   └── *.csv
└── venv/                             # Entorno virtual (si lo usas localmente)
```

### Descripción de Archivos Clave

| Archivo | Descripción |
|---------|------------|
| `sonda_base.py` | Extrae información TLS clásica (versión, cipher, certificados) |
| `sonda_pqc_final.py` | Prueba algoritmos híbridos/puros PQC contra servidores |
| `json_to_csv.py` | Transforma resultados JSON a CSV para análisis |
| `tranco.csv` | Datos de entrada: 1 millón de dominios ordenados por popularidad |
| `Dockerfile` | Automatiza la instalación de OpenSSL-OQS en Alpine Linux |

---

## 💻 Uso

### Dentro del Contenedor Docker

Una vez lanzado el contenedor (`docker run -it ...`):

#### 1. Sonda Base - Análisis Clásico

Realiza un escaneo básico de TLS en los primeros 500 dominios:

```bash
python3 scripts/sonda_base.py --max-hostnames 500
```

**Opciones disponibles:**
```bash
python3 scripts/sonda_base.py --help

# Ejemplos personalizados:
python3 scripts/sonda_base.py --max-hostnames 1000 --max-workers 50
python3 scripts/sonda_base.py --max-hostnames 200 --max-workers 30 --log-level DEBUG
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
python3 scripts/sonda_pqc_final.py --max-hostnames 100
```

**Opciones disponibles:**
```bash
python3 scripts/sonda_pqc_final.py --help

# Ejemplos personalizados:
python3 scripts/sonda_pqc_final.py --max-hostnames 200 --max-workers 30
python3 scripts/sonda_pqc_final.py --max-hostnames 50 --max-openssl-procs 8
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

#### 3. Convertidor JSON a CSV

Transforma los resultados JSON para análisis con ML:

```bash
# Uso básico (el nombre se genera automáticamente)
python3 scripts/json_to_csv.py resultados_sonda_pqc.json

# Con nombre personalizado
python3 scripts/json_to_csv.py resultados_sonda_pqc.json -o mis_datos.csv
```

**Entrada:** Archivos JSON de `resultados/`  
**Salida:** Archivos CSV en `ml_data/`

**Formato del nombre de salida:**
- Entrada: `resultados_sonda_pqc.json` (200 hostnames)
- Salida: `resultados_sonda_pqc_200_hostnames.csv`

---

### Flujo Típico de Trabajo

```bash
# 1. Dentro del contenedor
docker run -it -v $(pwd):/home/tfg tfg-pqc

# 2. Ejecutar escaneo base (rápido)
python3 scripts/sonda_base.py --max-hostnames 100

# 3. Ejecutar escaneo PQC (más lento, pero más completo)
python3 scripts/sonda_pqc_final.py --max-hostnames 100

# 4. Convertir resultados a CSV
python3 scripts/json_to_csv.py resultados_sonda_base.json
python3 scripts/json_to_csv.py resultados_sonda_pqc.json

# 5. Salir del contenedor
exit

# 6. Los resultados estarán en resultados/ y ml_data/
ls resultados/
ls ml_data/
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

# Usarlo en la sonda
python3 scripts/sonda_base.py --input-csv ../data/mis_dominios.csv --max-hostnames 200
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
python3 scripts/sonda_pqc_final.py
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

---

## 🔧 Detalles Técnicos

### Arquitectura

```
┌─────────────────────────────────────────┐
│     Docker Container (Alpine Linux)     │
├─────────────────────────────────────────┤
│  Python 3 + OpenSSL (OQS Provider)     │
│  ├── sonda_base.py                      │
│  ├── sonda_pqc_final.py                │
│  └── json_to_csv.py                    │
├─────────────────────────────────────────┤
│  Librerías de OpenSSL                  │
│  ├── liboqs (quantum-safe algorithms)  │
│  └── classic crypto (AES, SHA, etc.)   │
├─────────────────────────────────────────┤
│  Volumen montado: /home/tfg            │
│  (sincronización con host)             │
└─────────────────────────────────────────┘
```

### Dependencias

**En el Dockerfile:**
- OpenSSL 3.0 con OQS Provider
- Python 3.11
- Librerías: cryptography, dnspython, tqdm, pandas

**En el Host:**
- Docker Engine

### Concurrencia

- **ThreadPoolExecutor**: Para paralelizar escaneos por hostname
- **BoundedSemaphore**: Para limitar procesos OpenSSL concurrentes
- **Timeout**: 8 segundos por handshake TLS

### Manejo de Errores

La herramienta diferencia entre:
- **Fallos de infraestructura**: DNS no resuelve, puerto cerrado
- **Fallos de PQC**: El servidor rechaza el grupo de cifrado
- **Fallos de timeout**: Conexión muy lenta o servidor no responde

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
python3 scripts/sonda_pqc_final.py --max-workers 10 --max-openssl-procs 4

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
```

### Pandas no está instalado en el contenedor
```bash
# Reconstruir la imagen
docker build --no-cache -t tfg-pqc .
```

---

## 📈 Casos de Uso

### 1. Escaneo Inicial de una Región
```bash
python3 scripts/sonda_base.py --max-hostnames 1000
python3 scripts/sonda_pqc_final.py --max-hostnames 1000
```

### 2. Monitoreo Continuo
```bash
# Script de cron (fuera del contenedor)
0 2 * * * docker run -v $(pwd):/home/tfg tfg-pqc \
  python3 scripts/sonda_pqc_final.py --max-hostnames 500
```

### 3. Análisis de Compatibilidad PQC
```bash
python3 scripts/sonda_pqc_final.py --max-hostnames 100
python3 scripts/json_to_csv.py resultados_sonda_pqc.json
# Usar CSV en Pandas/Jupyter para análisis
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
