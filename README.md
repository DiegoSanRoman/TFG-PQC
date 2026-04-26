# Sonda de Detección de Criptografía Post-Cuántica (PQC) y ECH

Herramienta de investigación para medir la adopción de algoritmos post-cuánticos y Encrypted Client Hello (ECH) en servidores HTTPS reales. Implementa pipelines completas de calibración controlada, escaneo concurrente, análisis estadístico y generación de artefactos para investigación.

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

---

## Objetivo

Dos líneas de investigación complementarias:

### 1. Criptografía Post-Cuántica (PQC)

Evaluar la capacidad de servidores HTTPS reales para negociar grupos criptográficos post-cuánticos (híbridos y puros), separando de forma rigurosa:

- Fallos de infraestructura (DNS, TCP, timeout)
- Rechazo criptográfico real (TLS alert, incompatibilidad de grupo)

Esto permite responder preguntas como:

- ¿Qué porcentaje de servidores acepta cada grupo PQC?
- ¿Cuál es el coste en latencia de cada grupo respecto a X25519?
- ¿Cuál es el overhead de bytes del handshake TLS por grupo?

### 2. Encrypted Client Hello (ECH)

Medir la prevalencia de ECH en Internet y cuantificar su overhead real en el handshake TLS, respondiendo preguntas como:

- ¿Qué porcentaje de dominios anuncia configuración ECH en DNS (HTTPS RR)?
- ¿Cuánto overhead de latencia añade ECH respecto a TLS estándar?
- ¿Qué proveedores CDN despliegan ECH activamente?

### 3. Latencia PQC por grupo (con y sin ECH)

Medir y comparar el tiempo de handshake TLS para múltiples grupos post-cuánticos frente al clásico X25519, combinando también el efecto de ECH cuando es posible:

- ¿Cuánto tiempo añade cada grupo PQC respecto a X25519?
- ¿Cómo interactúa PQC con ECH? ¿Se acumulan los overheads?
- ¿Qué diferencia hay entre grupos híbridos bssl (X25519Kyber768Draft00, X25519MLKEM768) y grupos OQS puros?

### 4. Clasificación de grupo PQC por side-channel (ML)

Estudiar si un observador de red puede inferir qué grupo criptográfico negoció una conexión TLS **sin acceso al campo `cipher_suite`**, usando únicamente features observables desde el exterior (timing y tamaños de paquete).

Tres experimentos en cascada con features crecientemente ricas:

- **Exp 1 — Solo timing**: ¿es la latencia del handshake suficiente para clasificar el grupo?
- **Exp 2 — Timing + bytes TLS**: añadir el tamaño de los mensajes del handshake (observables contando bytes en tráfico de red).
- **Exp 3 — Timing + bytes totales**: añadir el volumen total de la sesión TLS.

Modelos: RandomForest y GradientBoosting. Validación sin leakage: `GroupShuffleSplit(80/20)` por hostname para separar train y test, más `GroupKFold(5)` sobre el train para las métricas de CV.

---

## Requisitos

- **Docker** 20.10+ (la imagen `openquantumsafe/openssl3` incluye OpenSSL con el proveedor OQS)
- **Python** 3.7+
- **Linux** / macOS / WSL2
- **BoringSSL** (`bssl`) compilado localmente — requerido para la sonda de latencia ECH

Dependencias Python (solo para análisis y tests, no para la sonda que corre en Docker):

```text
pandas>=1.3.0
numpy>=1.20.0
matplotlib>=3.3.0
seaborn>=0.11.0
dnspython>=2.4.0
tqdm>=4.60.0
pytest>=7.0.0
scikit-learn>=1.0.0
scipy>=1.9.0
cryptography>=38.0.0
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

### Sonda PQC

**1. Escanear dominios reales:**

```bash
# Test rápido (7 dominios de prueba)
./ejecutar_sonda.sh --input-csv prueba.csv --max-hostnames 10 --repeticiones 1 --max-workers 5

# Escaneo representativo
./ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 100 --repeticiones 3 --max-workers 20
```

**2. Analizar resultados y generar gráficas:**

```bash
./ejecutar_analisis.sh
```

**3. Pipeline completo (sonda + análisis en un paso):**

```bash
./test_pipeline.sh --input-csv prueba.csv --max-hostnames 10 --repeticiones 1 --max-workers 5
```

### Sonda de latencia ECH

**1. Medir overhead de ECH con los dominios de referencia incluidos:**

```bash
./ejecutar_sonda_latencia_ech.sh
```

**2. Con más repeticiones para mayor precisión estadística:**

```bash
./ejecutar_sonda_latencia_ech.sh --repeticiones 10
```

**3. Con un CSV propio:**

```bash
./ejecutar_sonda_latencia_ech.sh --input-csv data/mis_dominios.csv --repeticiones 5
```

### Sonda de prevalencia ECH (a gran escala)

```bash
./ejecutar_sonda_ech.sh --input-csv data/majestic_million.csv --max-dominios 5000
```

### Sonda de latencia PQC (múltiples grupos)

**1. Ejecutar con los dominios de referencia incluidos (30 repeticiones por defecto):**

```bash
./ejecutar_sonda_latencia_pqc.sh
```

**2. Con más repeticiones para mayor precisión estadística:**

```bash
./ejecutar_sonda_latencia_pqc.sh --repeticiones 50
```

**3. Solo grupos bssl (sin necesidad de OpenSSL OQS):**

```bash
./ejecutar_sonda_latencia_pqc.sh --grupos-pqc X25519Kyber768Draft00 X25519MLKEM768
```

Al finalizar, genera automáticamente la gráfica comparativa en `imagenes/latencia_pqc_ech_vs_sin_ech.png`.

### Clasificación PQC por side-channel (ML)

**1. Ejecutar con el JSON de resultados de la sonda PQC:**

```bash
./ejecutar_clasificacion_pqc.sh
```

**2. Con más folds de validación cruzada:**

```bash
./ejecutar_clasificacion_pqc.sh --n-splits 10
```

**3. Con un JSON alternativo:**

```bash
./ejecutar_clasificacion_pqc.sh --input-json resultados/mi_sonda.json
```

Al finalizar, genera automáticamente las gráficas en `imagenes/clasificacion_*.png`.

---

## Uso detallado

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

Ejecuta la sonda de **prevalencia ECH** a gran escala: descubre registros HTTPS RR, decodifica ECHConfigList, mide longitud de ClientHello y detecta patrones de padding.

| Opción | Descripción | Defecto |
| --- | --- | --- |
| `--input-csv ARCHIVO` | CSV de dominios de entrada | `data/majestic_million.csv` |
| `--max-dominios N` | Máximo de dominios a procesar | 1000 |
| `--max-concurrency N` | Concurrencia asyncio | 40 |
| `--tls-client MODO` | `auto` \| `bssl` \| `openssl` | `auto` |
| `--dns-timeout SEG` | Timeout DNS | 8 |
| `--tls-timeout SEG` | Timeout TLS | 20 |

### `ejecutar_sonda_latencia_ech.sh`

Mide el **overhead real de latencia de ECH** comparando handshakes TLS con y sin ECH activo, usando el mismo cliente (bssl) en ambos casos para una comparación justa. Para cada hostname realiza N mediciones y calcula media y desviación típica. Al finalizar genera automáticamente la gráfica `imagenes/latencia_ech_vs_sin_ech.png`.

| Opción | Descripción | Defecto |
| --- | --- | --- |
| `--input-csv ARCHIVO` | CSV de hostnames con ECH | `data/hostnames_ech.csv` |
| `--output-csv ARCHIVO` | CSV de resultados | `resultados/resultados_latencia_ech.csv` |
| `--repeticiones N` | Mediciones por hostname (para media/stddev) | 30 |
| `--dns-timeout SEG` | Timeout DNS | 5 |
| `--tls-timeout SEG` | Timeout por handshake | 10 |
| `--concurrency N` | Hostnames en paralelo | 10 |
| `--max-hostnames N` | Máximo de hostnames a procesar | 10000 |
| `--log-level NIVEL` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` | `INFO` |

```bash
# Ejecución estándar (30 repeticiones)
./ejecutar_sonda_latencia_ech.sh

# Alta precisión (100 repeticiones)
./ejecutar_sonda_latencia_ech.sh --repeticiones 100

# Con CSV propio y más repeticiones
./ejecutar_sonda_latencia_ech.sh --input-csv data/mis_dominios.csv --repeticiones 10
```

### `ejecutar_sonda_latencia_pqc.sh`

Mide la **latencia del handshake TLS para múltiples grupos PQC** frente al clásico X25519. Para grupos soportados por bssl (`X25519Kyber768Draft00`, `X25519MLKEM768`) compara además con y sin ECH. Para el resto de grupos usa OpenSSL OQS (sin ECH). Genera una fila CSV por `(hostname × grupo_pqc)` y al finalizar produce automáticamente la gráfica `imagenes/latencia_pqc_ech_vs_sin_ech.png`.

| Opción | Descripción | Defecto |
| --- | --- | --- |
| `--input-csv ARCHIVO` | CSV de hostnames de entrada | `data/hostnames_ech.csv` |
| `--output-csv ARCHIVO` | CSV de resultados | `resultados/resultados_latencia_pqc.csv` |
| `--log-file ARCHIVO` | Archivo de log | `resultados/sonda_latencia_pqc.log` |
| `--log-level NIVEL` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` | `INFO` |
| `--dns-timeout SEG` | Timeout DNS | 5 |
| `--tls-timeout SEG` | Timeout por handshake | 10 |
| `--concurrency N` | Hostnames en paralelo | 5 |
| `--max-hostnames N` | Máximo de hostnames a procesar | 10000 |
| `--repeticiones N` | Mediciones por combinación (para media/stddev) | 30 |
| `--oqs-bin RUTA` | Binario OpenSSL OQS | `/opt/openssl/bin/openssl` |
| `--grupos-pqc G1 G2 ...` | Grupos PQC a probar | lista predefinida completa |

Grupos predefinidos:

| Backend | Grupos | ECH |
| --- | --- | --- |
| bssl | `X25519Kyber768Draft00`, `X25519MLKEM768` | Sí |
| OpenSSL OQS | `mlkem768`, `kyber768`, `SecP256r1MLKEM768`, `x25519_mlkem512`, `x25519_kyber512`, `x25519_bikel1`, `x25519_hqc128` | No |

```bash
# Ejecución con todos los grupos (bssl + OQS)
./ejecutar_sonda_latencia_pqc.sh

# Solo grupos bssl (sin necesidad de OpenSSL OQS)
./ejecutar_sonda_latencia_pqc.sh --grupos-pqc X25519Kyber768Draft00 X25519MLKEM768

# Mayor precisión estadística
./ejecutar_sonda_latencia_pqc.sh --repeticiones 50

# Con CSV propio y ruta OQS personalizada
./ejecutar_sonda_latencia_pqc.sh --input-csv data/mis_dominios.csv --oqs-bin /usr/local/bin/openssl
```

### `ejecutar_clasificacion_pqc.sh`

Ejecuta el análisis de **clasificación de grupo PQC por side-channel** sobre el JSON de resultados de la sonda principal. Entrena RandomForest y GradientBoosting en los 3 experimentos y genera 4 gráficas en `imagenes/`.

| Opción | Descripción | Defecto |
| --- | --- | --- |
| `--input-json RUTA` | JSON de la sonda PQC | `resultados/resultados_sonda_pqc.json` |
| `--output-dir RUTA` | Directorio de imágenes de salida | `imagenes` |
| `--n-splits N` | Folds para GroupKFold en CV | 5 |

```bash
# Ejecución estándar
./ejecutar_clasificacion_pqc.sh

# Mayor rigor estadístico (más folds)
./ejecutar_clasificacion_pqc.sh --n-splits 10
```

### `ejecutar_tests.sh`

Ejecuta la suite completa de tests unitarios con pytest.

---

## Arquitectura

### Pipeline PQC

```text
Bash orchestration (ejecutar_sonda.sh)
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

### Pipeline de latencia ECH

```text
ejecutar_sonda_latencia_ech.sh
    │
    ├── sonda_latencia_ech.py
    │       │
    │       ├── Carga hostnames desde CSV (cargar_dominios_csv)
    │       ├── asyncio + Semaphore (N hostnames en paralelo)
    │       │
    │       └── Por cada hostname:
    │               ├── Consulta DNS HTTPS RR  ← mide latencia_dns_ms
    │               │       └── Extrae ECHConfigList (kem_id, public_name/outer_sni)
    │               │
    │               ├── [Si hay config ECH] × N repeticiones:
    │               │       └── bssl client -ech-config-list <config.bin>
    │               │               ├── Mide latencia_con_ech (media ± stddev)
    │               │               ├── Confirma: "Encrypted ClientHello: yes/no"
    │               │               └── Captura cipher suite negociada
    │               │
    │               └── [Si ECH exitoso] × N repeticiones:
    │                       └── bssl client (sin ECH)
    │                               ├── Mide latencia_sin_ech (media ± stddev)
    │                               └── delta = latencia_sin_ech − latencia_con_ech
    │       │
    │       └── Exporta: resultados_latencia_ech.csv
    │
    └── graficar_latencia_ech.py → imagenes/latencia_ech_vs_sin_ech.png
```

### Pipeline de latencia PQC

```text
ejecutar_sonda_latencia_pqc.sh
    │
    ├── sonda_latencia_pqc.py
    │       │
    │       ├── Carga hostnames desde CSV (cargar_dominios_csv)
    │       ├── asyncio + Semaphore (N hostnames en paralelo)
    │       │
    │       └── Por cada hostname:
    │               ├── Consulta DNS HTTPS RR  ← mide latencia_dns_ms
    │               │       └── Extrae ECHConfigList (para grupos bssl con ECH)
    │               │
    │               └── Por cada grupo PQC:
    │                       ├── [Backend bssl: X25519Kyber768Draft00, X25519MLKEM768]
    │                       │       ├── × N repeticiones con ECH + grupo PQC (bssl -curves -ech-config-list)
    │                       │       │       └── Mide latencia_ech_pqc (media ± stddev)
    │                       │       └── × N repeticiones sin ECH + grupo PQC (bssl -curves)
    │                       │               └── Mide latencia_sin_ech_pqc (media ± stddev)
    │                       │               └── delta_ech_pqc = latencia_sin_ech_pqc − latencia_ech_pqc
    │                       │
    │                       └── [Backend OQS: resto de grupos]
    │                               └── × N repeticiones sin ECH (openssl s_client -groups GRUPO)
    │                                       └── Mide latencia_sin_ech_pqc (media ± stddev)
    │       │
    │       └── Exporta: resultados_latencia_pqc.csv  (una fila por hostname × grupo)
    │
    └── graficar_latencia_pqc.py → imagenes/latencia_pqc_ech_vs_sin_ech.png
```

### Pipeline de clasificación ML (side-channel)

```text
ejecutar_clasificacion_pqc.sh
    │
    └── clasificar_grupo_pqc.py
            │
            ├── cargar_datos(resultados_sonda_pqc.json)
            │       └── Filtra: solo ACEPTADO de grupos viables (X25519, X25519MLKEM768,
            │                   x25519_kyber768, SecP256r1MLKEM768)
            │
            ├── GroupShuffleSplit(80/20) por hostname
            │       └── Train: ~80% hostnames  |  Test: ~20% hostnames (sin solapamiento)
            │
            ├── Por cada experimento (Exp 1, 2, 3):
            │       ├── GroupKFold(5) sobre train  ← métricas de CV (accuracy, F1)
            │       └── Modelo final entrenado en train completo
            │
            ├── Mejor modelo evaluado en test set → matriz de confusión real
            │
            └── Exporta 4 gráficas en imagenes/clasificacion_*.png
```

---

## Estructura del repositorio

```text
TFG-PQC/
├── ejecutar_sonda.sh                 # Escaneo PQC principal
├── ejecutar_analisis.sh              # Análisis y visualización PQC
├── ejecutar_sonda_ech.sh             # Sonda de prevalencia ECH (a gran escala)
├── ejecutar_sonda_latencia_ech.sh    # Sonda de latencia ECH (overhead con/sin ECH)
├── ejecutar_sonda_latencia_pqc.sh    # Sonda de latencia PQC (múltiples grupos, con/sin ECH)
├── ejecutar_clasificacion_pqc.sh     # Clasificación ML de grupo PQC por side-channel
├── test_pipeline.sh                  # Pipeline completo (sonda + análisis)
├── ejecutar_tests.sh                 # Suite de tests
├── limpiar_docker.sh                 # Limpieza de imágenes Docker
├── Dockerfile                        # Imagen basada en openquantumsafe/openssl3
├── requirements.txt
│
├── scripts/
│   ├── constants.py                  # Constantes compartidas (categorías de error/resultado)
│   ├── exceptions.py                 # Jerarquía de excepciones personalizada
│   ├── utils.py                      # Utilidades: DNS, certificados, logging, validación
│   ├── sondas/
│   │   ├── sonda_pqc_final.py        # Motor principal de escaneo PQC
│   │   ├── sonda_ech_prevalencia.py  # Sonda de prevalencia ECH a gran escala
│   │   ├── sonda_latencia_ech.py     # Sonda de latencia ECH (overhead con/sin ECH)
│   │   ├── sonda_latencia_pqc.py     # Sonda de latencia PQC (múltiples grupos, con/sin ECH)
│   │   ├── graficar_latencia_ech.py  # Genera imagenes/latencia_ech_vs_sin_ech.png
│   │   ├── graficar_latencia_pqc.py  # Genera imagenes/latencia_pqc_ech_vs_sin_ech.png
│   │   ├── tls_utils.py              # Utilidades TLS compartidas (ECHConfig, bssl, decode)
│   │   └── hostname_conexion.py      # Diagnóstico manual de un hostname concreto
│   ├── ml/
│   │   ├── analizar_resultados.py    # Análisis estadístico y visualización PQC
│   │   └── clasificar_grupo_pqc.py   # Clasificación ML de grupo por side-channel
│   └── tests/
│       ├── test_sonda_pqc.py                 # 37+ tests del motor de escaneo
│       ├── test_sonda_ech_prevalencia.py     # 30+ tests de la sonda de prevalencia ECH
│       ├── test_sonda_latencia_ech.py        # 59 tests de la sonda de latencia ECH
│       ├── test_sonda_latencia_pqc.py        # 52 tests de la sonda de latencia PQC
│       ├── test_clasificar_grupo_pqc.py      # 30 tests del clasificador ML
│       └── test_utils.py                     # 15+ tests de utilidades
│
├── data/
│   ├── prueba.csv                    # 7 dominios para pruebas rápidas
│   ├── majestic_million.csv          # 1M dominios (Majestic Million)
│   ├── tranco.csv                    # 1M dominios (Tranco)
│   └── hostnames_ech.csv             # Dominios con ECH activo (referencia)
│
├── resultados/                       # Artefactos de salida (generados)
│   ├── resultados_sonda_pqc.json
│   ├── resumen_por_grupo.csv
│   ├── resultados_ech_prevalencia.csv
│   ├── resultados_ech_prevalencia.json
│   ├── resultados_latencia_ech.csv
│   ├── resultados_latencia_pqc.csv
│   ├── sonda_pqc.log
│   ├── sonda_latencia_ech.log
│   └── sonda_latencia_pqc.log
│
└── imagenes/                         # Figuras generadas (generadas)
    ├── latencia_limpia.png
    ├── bytes_limpia.png
    ├── latencia_ech_vs_sin_ech.png
    ├── latencia_pqc_ech_vs_sin_ech.png
    ├── significancia_latencia.png
    ├── significancia_latencia.csv
    ├── tasas_resultado_por_grupo.png
    ├── tasas_resultado_por_grupo.csv
    └── delta_*.csv
```

---

## Grupos criptográficos probados

La sonda prueba 13 grupos TLS, incluyendo el clásico de referencia, híbridos y algoritmos PQC puros:

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

### Artefactos PQC

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
| `imagenes/significancia_latencia.png` | Test de Wilcoxon: significancia estadística de deltas de latencia |
| `imagenes/significancia_latencia.csv` | Tabla de p-valores y estadísticos del test de Wilcoxon |
| `imagenes/tasas_resultado_por_grupo.png` | Tasas de ACEPTADO/RECHAZADO/error por grupo |
| `imagenes/tasas_resultado_por_grupo.csv` | Tabla de tasas de resultado por grupo |

### Artefactos de latencia ECH

| Archivo | Descripción |
| --- | --- |
| `resultados/resultados_latencia_ech.csv` | Un registro por hostname con todas las métricas |
| `resultados/sonda_latencia_ech.log` | Log de ejecución |
| `imagenes/latencia_ech_vs_sin_ech.png` | Gráfica comparativa ECH vs sin ECH (generada automáticamente) |

Campos del CSV de resultados:

| Campo | Descripción |
| --- | --- |
| `ech_config_disponible` | El dominio anuncia ECH en su HTTPS RR de DNS |
| `conexion_ech_exitosa` | bssl completó el handshake con ECH activo |
| `conexion_sin_ech_exitosa` | bssl completó el handshake sin ECH |
| `ech_aceptado` | El servidor confirmó ECH (`Encrypted ClientHello: yes`) |
| `cipher_con_ech` / `cipher_sin_ech` | Suite de cifrado negociada en cada condición |
| `latencia_dns_ms` | Tiempo de consulta DNS HTTPS RR |
| `n_mediciones` | Número de repeticiones realizadas |
| `latencia_con_ech_media_ms` / `_stddev_ms` | Latencia media ± desv. típica con ECH |
| `latencia_sin_ech_media_ms` / `_stddev_ms` | Latencia media ± desv. típica sin ECH |
| `delta_medio_ms` | `latencia_sin_ech − latencia_con_ech` (positivo = ECH más lento) |
| `outer_sni` | Outer SNI del ECHConfig (identifica el proveedor CDN) |

### Artefactos de latencia PQC

| Archivo | Descripción |
| --- | --- |
| `resultados/resultados_latencia_pqc.csv` | Una fila por `(hostname × grupo_pqc)` con todas las métricas |
| `resultados/sonda_latencia_pqc.log` | Log de ejecución |
| `imagenes/latencia_pqc_ech_vs_sin_ech.png` | Gráfica comparativa por grupo PQC (generada automáticamente) |
| `imagenes/latencia_pqc_vs_clasico.png` | Comparativa de latencia PQC vs X25519 clásico |

Campos del CSV de resultados (una fila por hostname × grupo):

| Campo | Descripción |
| --- | --- |
| `hostname` | Dominio medido |
| `grupo_pqc` | Nombre del grupo criptográfico probado |
| `cliente_pqc` | Backend usado: `bssl` (grupos híbridos estándar) u `openssl_oqs` (resto) |
| `ech_config_disponible` | El dominio anuncia ECH en DNS |
| `ech_soportado_por_grupo` | El grupo permite combinar PQC con ECH (solo `True` para grupos bssl) |
| `conexion_ech_pqc_exitosa` | Handshake ECH + PQC completado (solo grupos bssl) |
| `latencia_ech_pqc_media_ms` / `_stddev_ms` | Latencia media ± desv. típica con ECH + PQC |
| `ech_aceptado_pqc` | El servidor confirmó ECH al usar este grupo PQC |
| `cipher_ech_pqc` | Suite de cifrado negociada con ECH + PQC |
| `conexion_sin_ech_pqc_exitosa` | Handshake sin ECH + PQC completado |
| `latencia_sin_ech_pqc_media_ms` / `_stddev_ms` | Latencia media ± desv. típica sin ECH + PQC |
| `cipher_sin_ech_pqc` | Suite de cifrado negociada sin ECH + PQC |
| `delta_ech_pqc_ms` | `latencia_sin_ech_pqc − latencia_ech_pqc` (solo grupos bssl) |
| `n_mediciones` | Número de repeticiones realizadas |
| `latencia_dns_ms` | Tiempo de consulta DNS HTTPS RR |
| `outer_sni` | Outer SNI del ECHConfig (identifica el proveedor CDN) |

### Artefactos de clasificación ML

| Archivo | Descripción |
| --- | --- |
| `imagenes/clasificacion_distribucion_features.png` | Boxplots de timing y bytes por grupo criptográfico |
| `imagenes/clasificacion_experimentos_comparativa.png` | Accuracy y F1 de los 3 experimentos para ambos modelos |
| `imagenes/clasificacion_confusion_mejor.png` | Matriz de confusión del mejor modelo evaluada en el test set |
| `imagenes/clasificacion_importancia_features.png` | Importancia relativa de cada feature en el mejor modelo |

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
- **`test_sonda_ech_prevalencia.py`** — Lógica completa de la sonda de prevalencia ECH
- **`test_sonda_latencia_ech.py`** — 59 tests de la sonda de latencia ECH: parseo de salida bssl (`_parsear_bssl`), extracción de errores, cálculo de media/stddev (`_agregar`), dataclass `ResultadoLatenciaECH`, exportación CSV, parser de argumentos CLI, `_run_cmd` con subprocesos reales, y pipeline `procesar_hostname` con mocks de DNS y TLS
- **`test_sonda_latencia_pqc.py`** — 52 tests de la sonda de latencia PQC: mediciones bssl y OQS (`_una_medicion_bssl`, `_una_medicion_oqs`), lógica de selección de backend, dataclass `ResultadoLatenciaPQC`, exportación CSV, parser de argumentos CLI, y pipeline `procesar_hostname_grupo` con mocks de DNS y TLS
- **`test_clasificar_grupo_pqc.py`** — 30 tests del clasificador ML: constantes (`GRUPOS_VIABLES`, `EXPERIMENTOS`, `LABEL_MAP`), carga y filtrado del JSON (`cargar_datos`), split sin leakage por hostname (`split_train_test`), estructura y métricas de `evaluar_experimento`, y smoke tests de las 4 gráficas de salida

---

## Troubleshooting

**La imagen Docker no se construye:**

```bash
docker pull openquantumsafe/openssl3:latest
./ejecutar_sonda.sh --rebuild --input-csv prueba.csv --max-hostnames 5
```

**Error de permisos en los scripts:**

```bash
chmod +x *.sh
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
# Probar un hostname concreto con el grupo por defecto (X25519MLKEM768):
python3 scripts/sondas/hostname_conexion.py --hostname cloudflare.com

# Probar con un grupo específico:
python3 scripts/sondas/hostname_conexion.py --hostname pq.cloudflareresearch.com --grupo mlkem768

# Probar todos los grupos de una vez:
python3 scripts/sondas/hostname_conexion.py --hostname cloudflare.com --todos
```

**La sonda de latencia ECH da TIMEOUT en todas las conexiones:**

El motivo más frecuente es que bssl no se encuentre o que el script se ejecute sin el venv activado. El bloque de diagnóstico al inicio indica la ruta encontrada:

```text
Diagnóstico de herramientas TLS:
  bssl:    /ruta/a/bssl   ← si pone NO ENCONTRADO, compilar BoringSSL
  Python:  /ruta/venv/bin/python3
```

Para compilar bssl:

```bash
git clone https://boringssl.googlesource.com/boringssl tools/boringssl
cmake -B tools/boringssl/build tools/boringssl && make -C tools/boringssl/build bssl
```

El `.sh` activa el venv automáticamente si existe en `venv/`. Para el comando `python3 -m`, activar el venv manualmente antes:

```bash
source venv/bin/activate
python3 -m scripts.sondas.sonda_latencia_ech
```

**Todos los dominios aparecen como "Sin HTTPS RR" o "Sin parámetro ECH":**

La mayoría de dominios todavía no tienen ECH desplegado. Usar `data/hostnames_ech.csv` (incluido en el repositorio) que contiene dominios con ECH activo verificado, o ejecutar primero la sonda de prevalencia para identificar dominios con ECH.
