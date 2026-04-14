# Sonda de Detección de Criptografía Post-Cuántica (PQC)

Herramienta de investigación para medir la adopción de algoritmos post-cuánticos en servidores HTTPS reales. Implementa una pipeline completa de calibración controlada, escaneo concurrente, análisis estadístico y generación de artefactos para investigación.

---

## Índice

- [Objetivo](#objetivo)
- [Requisitos](#requisitos)
- [Quick Start](#quick-start)
- [Uso detallado](#uso-detallado)
- [Arquitectura](#arquitectura)
- [Estructura del repositorio](#estructura-del-repositorio)
- [Grupos criptográficos probados](#grupos-criptográficos-probados)
- [Métricas recolectadas](#métricas-recolectadas)
- [Artefactos de salida](#artefactos-de-salida)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)

---

## Objetivo

Evaluar la capacidad de servidores HTTPS reales para negociar grupos criptográficos post-cuánticos (híbridos y puros), separando de forma rigurosa:

- Fallos de infraestructura (DNS, TCP, timeout)
- Rechazo criptográfico real (TLS alert, incompatibilidad de grupo)

Esto permite responder preguntas como:

- ¿Qué porcentaje de servidores acepta cada grupo PQC?
- ¿Cuál es el coste en latencia de cada grupo respecto a X25519?
- ¿Cuál es el overhead de bytes del handshake TLS por grupo?

---

## Requisitos

- **Docker** 20.10+ (la imagen `openquantumsafe/openssl3` incluye OpenSSL con el proveedor OQS)
- **Python** 3.7+
- **Linux** / macOS / WSL2

Dependencias Python (solo para análisis y tests, no para la sonda que corre en Docker):

```text
pandas>=1.3.0
numpy>=1.20.0
matplotlib>=3.3.0
seaborn>=0.11.0
dnspython>=2.4.0
tqdm>=4.60.0
pytest>=7.0.0
```

```bash
pip install -r requirements.txt
```

Verificar entorno:

```bash
docker --version && docker ps
python3 --version
```

---

## Quick Start

**1. Calibrar con servidores locales** (recomendado antes de escanear Internet):

```bash
./calibrar_servidor_pqc.sh 5
```

**2. Escanear dominios reales:**

```bash
# Test rápido (7 dominios de prueba)
./ejecutar_sonda.sh --input-csv prueba.csv --max-hostnames 10 --repeticiones 1 --max-workers 5

# Escaneo representativo
./ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 100 --repeticiones 3 --max-workers 20
```

**3. Analizar resultados y generar gráficas:**

```bash
./ejecutar_analisis.sh
```

**4. Pipeline completo (sonda + análisis en un paso):**

```bash
./test_pipeline.sh --input-csv prueba.csv --max-hostnames 10 --repeticiones 1 --max-workers 5
```

---

## Uso detallado

### `calibrar_servidor_pqc.sh [repeticiones]`

Valida el correcto funcionamiento de la sonda en un entorno controlado antes de realizar escaneos en Internet.

- Levanta dos contenedores Docker locales con OpenSSL-OQS (versión legacy en puerto 4433, moderna en 4434)
- Ejecuta la sonda contra `localhost` con todos los grupos criptográficos
- Genera resultados de calibración en `resultados/resultados_calibracion_*.json`

```bash
./calibrar_servidor_pqc.sh       # 1 repetición (defecto)
./calibrar_servidor_pqc.sh 5     # 5 repeticiones por grupo
```

### `ejecutar_sonda.sh [opciones]`

Comando principal de escaneo. Construye la imagen Docker si es necesario (detección automática por hash del Dockerfile) y ejecuta la sonda en el contenedor.

| Opción | Descripción | Defecto |
| --- | --- | --- |
| `--input-csv ARCHIVO` | CSV de entrada (Majestic Million o Tranco) | requerido |
| `--max-hostnames N` | Número máximo de dominios a probar | 100 |
| `--repeticiones N` | Repeticiones por (hostname, grupo) | 1 |
| `--max-workers N` | Hilos concurrentes | 20 |
| `--rebuild` | Forzar reconstrucción de la imagen Docker | — |

```bash
./ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 500 --repeticiones 3 --max-workers 30
```

### `ejecutar_analisis.sh`

Carga `resultados/resultados_sonda_pqc.json`, aplica filtrado y estadísticas robustas, y genera las figuras de publicación en `imagenes/`.

### `ejecutar_sonda_ech.sh`

Ejecuta la sonda especializada para medir la prevalencia de **ECH (Encrypted Client Hello)** en los dominios del CSV de entrada.

### `ejecutar_tests.sh`

Ejecuta la suite completa de tests unitarios con pytest.

---

## Arquitectura

```text
Bash orchestration (*.sh)
    │
    ├── Construye imagen Docker (openquantumsafe/openssl3 + Python + OQS)
    ├── Monta volúmenes: data/ → /app/data, resultados/ → /app/resultados
    │
    └── Contenedor Docker
            │
            └── sonda_pqc_final.py
                    │
                    ├── Lee CSV (detección automática de formato Majestic/Tranco)
                    ├── ThreadPoolExecutor (N workers concurrentes)
                    │
                    └── Por cada (hostname, grupo):
                            ├── Pre-check DNS + TCP (separa infra de crypto)
                            ├── openssl s_client -trace -provider oqsprovider -groups GRUPO
                            ├── Parsea salida: versión TLS, cipher, bytes, latencia
                            ├── Clasifica: ACEPTADO | RECHAZADO | ERROR_*
                            └── Reintento si timeout (máx. 2 intentos)
                    │
                    ├── Promedia N repeticiones por (hostname, grupo)
                    └── Exporta: resultados_sonda_pqc.json + resumen_por_grupo.csv

analizar_resultados.py
    ├── Filtra: solo conexiones ACEPTADO
    ├── Elimina outliers (IQR)
    ├── Construye "cohorte justa" (hosts que aceptan X25519 + ≥1 grupo PQC)
    ├── Estadísticas robustas: mediana, IQR por grupo
    ├── Deltas: latencia_grupo − latencia_X25519 (por hostname, para eliminar ruido de red)
    └── Genera: latencia_limpia.png, bytes_limpia.png, delta_*.csv
```

---

## Estructura del repositorio

```text
TFG-PQC/
├── calibrar_servidor_pqc.sh       # Calibración con servidores locales
├── ejecutar_sonda.sh              # Escaneo principal
├── ejecutar_analisis.sh           # Análisis y visualización
├── ejecutar_sonda_ech.sh          # Sonda ECH
├── test_pipeline.sh               # Pipeline completo (sonda + análisis)
├── ejecutar_tests.sh              # Suite de tests
├── limpiar_docker.sh              # Limpieza de imágenes Docker
├── Dockerfile                     # Imagen basada en openquantumsafe/openssl3
├── requirements.txt
│
├── scripts/
│   ├── constants.py               # Constantes compartidas (categorías de error/resultado)
│   ├── exceptions.py              # Jerarquía de excepciones personalizada
│   ├── utils.py                   # Utilidades: DNS, certificados, logging, validación
│   ├── sondas/
│   │   ├── sonda_pqc_final.py     # Motor principal de escaneo PQC
│   │   ├── sonda_base.py          # Sonda TLS base (referencia/baseline)
│   │   └── sonda_ech_prevalencia.py  # Sonda ECH
│   ├── ml/
│   │   └── analizar_resultados.py # Análisis estadístico y visualización
│   ├── individuales/
│   │   └── hostname_conexion.py   # Diagnóstico profundo de un único host
│   ├── calibracion/
│   │   ├── levantar_servidores.sh
│   │   └── detener_servidores.sh
│   └── tests/
│       ├── test_sonda_pqc.py      # 37+ tests del motor de escaneo
│       ├── test_sonda_ech_prevalencia.py  # 30+ tests de la sonda ECH
│       └── test_utils.py          # 15+ tests de utilidades
│
├── data/
│   ├── prueba.csv                 # 7 dominios para pruebas rápidas
│   ├── majestic_million.csv       # 1M dominios (Majestic Million)
│   ├── tranco.csv                 # 1M dominios (Tranco)
│   ├── calibracion_legacy.csv     # localhost:4433
│   └── calibracion_moderno.csv    # localhost:4434
│
├── resultados/                    # Artefactos de salida (generados)
│   ├── resultados_sonda_pqc.json
│   ├── resumen_por_grupo.csv
│   └── sonda_pqc.log
│
└── imagenes/                      # Figuras generadas (generadas)
    ├── latencia_limpia.png
    ├── bytes_limpia.png
    └── delta_*.csv
```

---

## Grupos criptográficos probados

La sonda prueba 14 grupos TLS, incluyendo el clásico de referencia, híbridos y algoritmos PQC puros:

| Grupo | Tipo | Estándar |
| --- | --- | --- |
| `X25519` | Clásico (referencia) | RFC 8446 |
| `X25519MLKEM768` | Híbrido | IETF draft |
| `SecP256r1MLKEM768` | Híbrido | IETF draft |
| `x25519_kyber768` | Híbrido | OQS |
| `x25519_mlkem512` | Híbrido | OQS |
| `x25519_kyber512` | Híbrido | OQS |
| `p256_kyber768` | Híbrido | OQS |
| `x25519_bikel1` | Híbrido | OQS |
| `x25519_hqc128` | Híbrido | OQS |
| `mlkem768` | PQC puro | NIST ML-KEM |
| `kyber768` | PQC puro | OQS |
| `frodo640aes` | PQC puro | OQS |
| `bikel1` | PQC puro | OQS |
| `Automático` | Negociación del cliente | — |

---

## Métricas recolectadas

Cada resultado de sonda contiene ~54 campos. Los más relevantes:

**Estado de conexión:**

- `connection_result` — `ACEPTADO` | `RECHAZADO`
- `error_category` — `ERROR_DNS` | `ERROR_TCP_REFUSED` | `ERROR_TCP_TIMEOUT` | `ERROR_TLS_TIMEOUT` | `ERROR_TLS_ALERT` | `ERROR_UNKNOWN`

**Latencia (ms):**

- `dns_time_ms` — Resolución DNS
- `tcp_time_ms` — Establecimiento de conexión TCP
- `handshake_time_ms` — Handshake TLS completo
- `openssl_execution_time_ms` — Tiempo total de ejecución de OpenSSL

**Bytes del handshake** (extraídos del output `-trace`):

- `bytes_sent` / `bytes_received` — Bytes de registros TLS enviados/recibidos
- `handshake_overhead` — Suma de ambos
- `handshake_total_bytes_sent` / `handshake_total_bytes_received` — Del resumen de OpenSSL
- `measurement_method` — `traced` | `partial` | `unknown`

**TLS/Protocolo:**

- `tls_version` — `TLSv1.2` | `TLSv1.3`
- `cipher_suite` — Cifrado simétrico negociado
- `alpn` — Protocolo ALPN (ej. `h2`)
- `tls_alert` — Alerta TLS recibida del servidor

**Certificado:**

- `cert_issuer`, `cert_not_before`, `cert_not_after`
- `cert_san` — Subject Alternative Names
- `cert_fingerprint_sha256`

**El CSV `resumen_por_grupo.csv`** agrega por grupo: `total_pruebas`, `aceptados`, `rechazados`, `errores`, `porcentaje_aceptacion`, y estadísticas (media, mediana, desv. std., mín., máx.) de todas las métricas numéricas.

---

## Artefactos de salida

| Archivo | Descripción |
| --- | --- |
| `resultados/resultados_sonda_pqc.json` | Resultados completos de todos los probes |
| `resultados/resumen_por_grupo.csv` | Estadísticas agregadas por grupo criptográfico |
| `resultados/sonda_pqc.log` | Log de ejecución |
| `imagenes/latencia_limpia.png` | Comparativa de latencia por grupo (3 subplots) |
| `imagenes/bytes_limpia.png` | Overhead de bytes por grupo (4 subplots) |
| `imagenes/delta_openssl_execution_time_vs_x25519.csv` | Deltas de tiempo de ejecución vs X25519 |
| `imagenes/delta_openssl_tcp_tls_vs_x25519.csv` | Deltas de tiempo TCP+TLS vs X25519 |
| `imagenes/ranking_justo_handshake.csv` | Ranking de grupos por velocidad de handshake |

Los resultados de calibración se guardan como `resultados/resultados_calibracion_*.json` y `resultados/resumen_calibracion_*.csv`.

---

## Tests

```bash
# Ejecutar todos los tests
./ejecutar_tests.sh

# O directamente con pytest
pytest -v scripts/tests/
```

La suite cubre:

- **`test_utils.py`** — Validación de hostnames, configuración de logging, construcción del esquema de resultados
- **`test_sonda_pqc.py`** — Parseo de `-trace`, detección de cifrados débiles/PFS, estadísticas por grupo, exportación CSV, clases `TLSOutputParser` y `PQCProbe`
- **`test_sonda_ech_prevalencia.py`** — Lógica completa de la sonda ECH

---

## Troubleshooting

**La imagen Docker no se construye:**

```bash
docker pull openquantumsafe/openssl3:latest
./ejecutar_sonda.sh --rebuild --input-csv prueba.csv --max-hostnames 5
```

**Error de permisos en los scripts:**

```bash
chmod +x *.sh scripts/calibracion/*.sh
```

**Resultados vacíos o todos con error DNS:**

Verificar conectividad y que Docker puede resolver DNS desde el contenedor:

```bash
docker run --rm openquantumsafe/openssl3 nslookup google.com
```

**Demasiados timeouts:**

Reducir `--max-workers` o ajustar el timeout en `sonda_pqc_final.py` (variable `TIMEOUT_INTERNET_S`, defecto 8s).

**El análisis no genera gráficas** (`filtrar_por_muestras_minimas` descarta todos los grupos):

Se necesitan al menos 30 muestras aceptadas por grupo. Aumentar `--max-hostnames` o reducir el umbral mínimo en `analizar_resultados.py`.

**Diagnóstico de un host concreto:**

```bash
# Dentro del contenedor Docker o con openssl-oqs instalado localmente
python3 scripts/individuales/hostname_conexion.py
```
