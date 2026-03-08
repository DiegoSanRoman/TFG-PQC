# Sonda de Detección de Criptografía Post-Cuántica (PQC)

Herramienta experimental para medir la adopción de algoritmos post-cuánticos en servidores HTTPS reales.

Este repositorio implementa una pipeline completa de:
- calibración controlada,
- escaneo concurrente,
- análisis estadístico,
- generación de artefactos (JSON/CSV/PNG) para investigación y TFG.

---

## 1. Objetivo técnico del proyecto

El objetivo principal es evaluar la capacidad de servidores HTTPS para negociar grupos criptográficos post-cuánticos (híbridos y puros), separando claramente:

1) problemas de infraestructura (DNS, TCP, timeout), y
2) rechazo criptográfico real (TLS alert / incompatibilidad de grupo).

Esto permite responder con rigor a preguntas como:
- ¿Qué porcentaje de servidores acepta cada grupo PQC?
- ¿Cuál es el coste en latencia por grupo?
- ¿Cuál es el overhead de bytes del handshake TLS?
- ¿Qué errores predominan y dónde ocurren?

---

## 2. Quick Start

### 2.1 Calibración local (recomendado primero)

```bash
./calibrar_servidor_pqc.sh
```

Opcional (repeticiones por grupo):

```bash
./calibrar_servidor_pqc.sh 5
```

### 2.2 Escaneo real (Internet)

Test rápido:

```bash
./ejecutar_sonda.sh --input-csv prueba.csv --max-hostnames 10 --repeticiones 1 --max-workers 5
```

Escaneo más representativo:

```bash
./ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 100 --repeticiones 3 --max-workers 20
```

### 2.3 Análisis y gráficas

```bash
./ejecutar_analisis.sh
```

### 2.4 Pipeline completo

```bash
./test_pipeline.sh --input-csv prueba.csv --max-hostnames 10 --repeticiones 1 --max-workers 5
```

---

## 3. Requisitos

- Docker 20.10+
- Python 3.7+
- Linux/macOS/WSL2

Verificación:

```bash
docker --version
docker ps
python3 --version
```

Permisos de ejecución si hace falta:

```bash
chmod +x *.sh
chmod +x scripts/calibracion/*.sh
```

---

## 4. Arquitectura funcional (alto nivel)

1) **Orquestación Bash**
- coordina levantado de servidores, ejecución de sonda y análisis.

2) **Motor de sonda (Python)**
- ejecuta OpenSSL-OQS, recoge métricas y clasifica errores.

3) **Motor de análisis (Python)**
- transforma JSON a DataFrame, filtra, agrega y grafica.

4) **Artefactos de salida**
- JSON detallado por host/grupo,
- CSV agregado por grupo,
- PNG de visualización.

---

## 5. Estructura del repositorio

```text
TFG-PQC/
├── .dockerignore
├── .gitignore
├── Dockerfile
├── README.md
├── calibrar_servidor_pqc.sh
├── ejecutar_analisis.sh
├── ejecutar_sonda.sh
├── requirements.txt
├── test_pipeline.sh
├── data/
│   ├── calibracion_legacy.csv
│   ├── calibracion_moderno.csv
│   ├── majestic_million.csv
│   ├── prueba.csv
│   └── tranco.csv
├── scripts/
│   ├── calibracion/
│   │   ├── detener_servidores.sh
│   │   └── levantar_servidores.sh
│   ├── individuales/
│   │   └── hostname_conexion.py
│   ├── ml/
│   │   └── analizar_resultados.py
│   └── sondas/
│       ├── sonda_base.py
│       └── sonda_pqc_final.py
├── resultados/
│   ├── resultados_calibracion_legacy.json
│   ├── resultados_calibracion_moderno.json
│   ├── resultados_sonda_pqc.json
│   ├── resumen_calibracion_legacy.csv
│   ├── resumen_calibracion_moderno.csv
│   ├── resumen_por_grupo.csv
│   └── sonda_pqc.log
└── imagenes/
    ├── bytes_limpia.png
    ├── latencia_limpia.png
    └── scatter_limpia.png
```

---

## 6. Documentación exhaustiva archivo por archivo

## 6.1 Archivos de configuración (raíz)

### `.dockerignore`
**Qué hace:** evita copiar archivos innecesarios al contexto de build Docker.

**Cómo lo hace:** excluye `venv`, `__pycache__`, `.git`, `.vscode`, `*.pyc`.

**Por qué:** reduce tamaño de build, acelera `docker build` y evita arrastrar estado local al contenedor.

---

### `.gitignore`
**Qué hace:** evita versionar archivos locales/no reproducibles.

**Cómo lo hace:** ignora `venv/`, `__pycache__/`, `.DS_Store`.

**Por qué:** mantener repositorio limpio, portable y sin artefactos de entorno local.

---

### `Dockerfile`
**Qué hace exactamente:** construye imagen de ejecución para la sonda con OpenSSL-OQS.

**Cómo lo hace (paso a paso):**
1. Usa base `openquantumsafe/openssl3:latest`.
2. Instala dependencias del sistema (python3, pip, compilación, certificados).
3. Configura variables de entorno de OpenSSL-PQC (`OPENSSL_BIN`, `OPENSSL_MODULES`, `LD_LIBRARY_PATH`, `PATH`).
4. Instala dependencias Python usadas por sonda y análisis.
5. Copia el proyecto a `/app`.
6. Crea carpetas de salida (`/app/resultados`, `/app/logs`).
7. Define `ENTRYPOINT` apuntando a `scripts/sondas/sonda_pqc_final.py`.

**Nivel de operación:** entorno de ejecución aislado y reproducible (infraestructura).

**Por qué:** garantiza consistencia criptográfica (OpenSSL con provider OQS), evitando depender del OpenSSL local del host.

---

### `requirements.txt`
**Qué hace:** define dependencias Python mínimas de análisis.

**Cómo:** versiones mínimas de `pandas`, `numpy`, `matplotlib`, `seaborn`.

**Por qué:** análisis reproducible y compatible entre entornos.

---

### `README.md`
**Qué hace:** documentación integral de uso, arquitectura y metodología.

**Cómo:** organiza quick start, detalle técnico, métricas y artefactos.

**Por qué:** soporte a ejecución operativa y a redacción del TFG.

---

## 6.2 Scripts Bash de orquestación (raíz)

### `calibrar_servidor_pqc.sh`
**Qué hace exactamente:** orquesta una calibración dual end-to-end.

**Cómo lo hace:**
1. Configura entorno y valida scripts auxiliares.
2. Levanta dos servidores locales con `scripts/calibracion/levantar_servidores.sh`.
3. Ejecuta la sonda en Docker contra `data/calibracion_legacy.csv` (localhost:4433).
4. Copia salidas a `resultados_calibracion_legacy.json` y `resumen_calibracion_legacy.csv`.
5. Ejecuta la sonda en Docker contra `data/calibracion_moderno.csv` (localhost:4434).
6. Copia salidas a `resultados_calibracion_moderno.json` y `resumen_calibracion_moderno.csv`.
7. Detiene servidores con `scripts/calibracion/detener_servidores.sh`.
8. Si existe `jq`, imprime resumen de éxito por consola.

**Nivel de operación:** proceso completo de validación metodológica controlada.

**Por qué:** antes de escanear Internet se valida que la sonda mide correctamente en un entorno controlado.

---

### `ejecutar_sonda.sh`
**Qué hace exactamente:** ejecuta escaneo PQC sobre dataset CSV usando Docker.

**Cómo lo hace:**
1. Parsea argumentos (`--input-csv`, `--max-hostnames`, `--repeticiones`, `--max-workers`).
2. Valida Docker, CSV de entrada y Dockerfile.
3. Crea directorio `resultados/`.
4. Construye imagen Docker `tfg-sonda` si no existe.
5. Ejecuta contenedor montando volúmenes:
   - `data/` -> `/app/data`
   - `resultados/` -> `/app/resultados`
6. Pasa argumentos a la sonda Python.
7. Reporta rutas de salida (JSON/CSV/LOG).

**Nivel de operación:** ejecución de campaña de escaneo sobre hosts reales.

**Por qué:** simplifica ejecución reproducible sin instalar OpenSSL-PQC en host local.

---

### `ejecutar_analisis.sh`
**Qué hace exactamente:** ejecuta el análisis estadístico y generación de imágenes.

**Cómo lo hace:**
1. Verifica `python3`.
2. Crea `venv/` si no existe.
3. Activa entorno virtual.
4. Instala dependencias de análisis si faltan.
5. Valida JSON de entrada.
6. Llama a `scripts/ml/analizar_resultados.py`.
7. Lista PNG generados.

**Nivel de operación:** post-procesado y visualización.

**Por qué:** desacopla escaneo (red) de análisis (estadística/figuras).

---

### `test_pipeline.sh`
**Qué hace exactamente:** pipeline completo automático en dos pasos.

**Cómo lo hace:**
1. Parsea los mismos argumentos de escaneo.
2. Ejecuta `./ejecutar_sonda.sh` con esos argumentos.
3. Al terminar, ejecuta `./ejecutar_analisis.sh`.

**Nivel de operación:** prueba funcional integral (end-to-end).

**Por qué:** permite validar en una sola orden que toda la cadena está operativa.

---

## 6.3 Scripts de calibración (`scripts/calibracion/`)

### `scripts/calibracion/levantar_servidores.sh`
**Qué hace exactamente:** levanta dos servidores HTTPS con soporte PQC en paralelo funcional.

**Cómo lo hace:**
1. Comprueba Docker.
2. Define LEGACY:
   - contenedor `pqc-legacy-server`
   - imagen `openquantumsafe/nginx:0.10.1`
   - puerto host `4433`
3. Define MODERNO:
   - contenedor `pqc-modern-server`
   - imagen `openquantumsafe/nginx:latest`
   - puerto host `4434`
4. Elimina contenedores previos si existen.
5. Verifica puertos libres con `lsof`.
6. Arranca ambos con `docker run -d`.

**Nivel de operación:** infraestructura de calibración local.

**Por qué:** separar algoritmos “legacy” y “modernos” para pruebas controladas de compatibilidad.

---

### `scripts/calibracion/detener_servidores.sh`
**Qué hace exactamente:** detiene y elimina ambos contenedores de calibración.

**Cómo lo hace:**
1. Verifica Docker.
2. Si `pqc-legacy-server` está activo, `stop + rm`.
3. Si `pqc-modern-server` está activo, `stop + rm`.
4. Imprime resumen final.

**Nivel de operación:** limpieza de entorno local.

**Por qué:** evitar recursos huérfanos, puertos ocupados y estados inconsistentes entre ejecuciones.

---

## 6.4 Scripts Python de sonda (`scripts/sondas/`)

### `scripts/sondas/sonda_pqc_final.py`
**Qué hace exactamente:** es el motor principal de escaneo PQC concurrente.

**Cómo lo hace (flujo técnico):**
1. Lee hostnames desde CSV con autodetección de formato (`leer_hostnames_csv`).
2. Define lista de 14 grupos criptográficos a probar.
3. Ejecuta escaneo concurrente por hostname (`ThreadPoolExecutor`).
4. Para cada `hostname + grupo`:
   - pre-check DNS/TCP,
   - ejecución `openssl s_client` con providers OQS + default,
   - parseo de TLS/certificado,
   - parseo de bytes desde `-trace` (`parse_trace_bytes`),
   - clasificación de resultado/error.
5. Repite N veces por grupo (`--repeticiones`) y promedia (`calcular_promedio_repeticiones`).
6. Agrega estadísticas por grupo (`generar_estadisticas_por_grupo`).
7. Exporta:
   - JSON completo (`resultados_sonda_pqc.json`),
   - CSV agregado (`resumen_por_grupo.csv`),
   - log (`sonda_pqc.log`).

**Nivel de operación:** capa de adquisición de datos criptográficos y de red.

**Por qué:** obtener evidencia cuantitativa reproducible de adopción PQC real.

**Puntos clave de implementación:**
- Semáforo `BoundedSemaphore` para limitar procesos OpenSSL simultáneos.
- Timeout distinto para localhost vs Internet.
- Clasificación explícita de errores para separar infraestructura vs criptografía.
- Extracción de certificado y metadatos de handshake.

---

### `scripts/sondas/sonda_base.py`
**Qué hace exactamente:** versión base/anterior de la sonda para escaneo TLS y certificado general (no enfocada en grupos PQC como la final).

**Cómo lo hace:**
- Implementa estructura de resultados con `dataclasses` (`ResultadoEscaneo`, `DatosExito`, etc.).
- Conecta por socket + SSL, analiza protocolo, certificado y seguridad avanzada.
- Recolecta latencia DNS, datos de clave pública, hashes, SAN y versiones TLS soportadas.
- Incluye concurrencia y exportación estructurada.

**Nivel de operación:** base metodológica/prototipo previo de adquisición TLS.

**Por qué existe:** aporta trazabilidad histórica del diseño y comparación frente a la versión final PQC.

---

## 6.5 Script Python de análisis (`scripts/ml/`)

### `scripts/ml/analizar_resultados.py`
**Qué hace exactamente:** procesa resultados JSON y genera visualizaciones comparativas.

**Cómo lo hace:**
1. Carga JSON (`cargar_y_procesar`).
2. Convierte pruebas a DataFrame de pandas.
3. Convierte columnas numéricas y filtra `ACEPTADO`.
4. Limpia outliers (`remover_outliers`, IQR por defecto).
5. Filtra grupos con mínimo de muestras (`filtrar_por_muestras_minimas`).
6. Genera 3 gráficos:
   - `latencia_limpia.png`
   - `bytes_limpia.png`
   - `scatter_limpia.png`

**Nivel de operación:** capa de post-procesado estadístico y comunicación visual.

**Por qué:** sin esta etapa los resultados son difíciles de comparar entre grupos y campañas.

---

## 6.6 Script Python individual (`scripts/individuales/`)

### `scripts/individuales/hostname_conexion.py`
**Qué hace exactamente:** analiza un único hostname con máxima profundidad de certificado/protocolo.

**Cómo lo hace:**
1. Resuelve DNS y mide latencia.
2. Establece conexión TCP+TLS.
3. Extrae versión TLS, cipher suite y tiempos.
4. Parsea certificado principal y cadena.
5. Prueba versiones TLS soportadas (TLS1.0 a TLS1.3).
6. Guarda JSON por host y log general.

**Nivel de operación:** diagnóstico puntual por host (no escaneo masivo).

**Por qué:** útil para análisis forense/manual de casos concretos detectados en la sonda masiva.

---

## 6.7 Archivos de datos (`data/`)

### `data/calibracion_legacy.csv`
**Qué hace:** input de calibración para servidor legacy (`localhost:4433`).

**Cómo:** contiene host/puerto de prueba controlada.

**Por qué:** medir algoritmos legacy en entorno determinista.

---

### `data/calibracion_moderno.csv`
**Qué hace:** input de calibración para servidor moderno (`localhost:4434`).

**Cómo:** contiene host/puerto de prueba controlada.

**Por qué:** medir algoritmos modernos en entorno determinista.

---

### `data/prueba.csv`
**Qué hace:** dataset pequeño de test rápido.

**Cómo:** pocos hostnames para validar pipeline en minutos.

**Por qué:** iteración rápida durante desarrollo.

---

### `data/majestic_million.csv`
**Qué hace:** dataset amplio para campañas de escaneo real.

**Cómo:** lista de dominios de alto tráfico.

**Por qué:** representatividad estadística del ecosistema web.

---

### `data/tranco.csv`
**Qué hace:** dataset alternativo para muestreo de dominios.

**Cómo:** formato compatible con autodetección de columna en la sonda.

**Por qué:** comparar resultados con otra fuente/ranking.

---

## 6.8 Artefactos de salida (`resultados/`)

### `resultados/resultados_sonda_pqc.json`
**Qué es:** salida principal de campaña de escaneo.

**Qué contiene:**
- resumen global de ejecución,
- lista de hostnames,
- pruebas por grupo con métricas y clasificación.

**Cómo se genera:** `sonda_pqc_final.py` al finalizar escaneo.

**Utilidad:** base completa para análisis y trazabilidad.

---

### `resultados/resumen_por_grupo.csv`
**Qué es:** agregado estadístico por grupo.

**Qué contiene:** éxito/rechazo/error y estadísticas de latencia/bytes.

**Cómo se genera:** función `exportar_estadisticas_csv`.

**Utilidad:** comparación rápida entre algoritmos.

---

### `resultados/sonda_pqc.log`
**Qué es:** log técnico de ejecución.

**Qué contiene:** inicio, configuración, avisos, errores y resumen final.

**Cómo se genera:** `logging.FileHandler` en sonda final.

**Utilidad:** depuración y auditoría de campaña.

---

### `resultados/resultados_calibracion_legacy.json`
**Qué es:** resultados de calibración contra servidor LEGACY.

**Cómo se genera:** `calibrar_servidor_pqc.sh` tras ejecutar sonda en `localhost:4433`.

**Utilidad:** validar aceptación esperada en grupos legacy.

---

### `resultados/resultados_calibracion_moderno.json`
**Qué es:** resultados de calibración contra servidor MODERNO.

**Cómo se genera:** `calibrar_servidor_pqc.sh` tras ejecutar sonda en `localhost:4434`.

**Utilidad:** validar aceptación esperada en grupos modernos.

---

### `resultados/resumen_calibracion_legacy.csv`
**Qué es:** resumen por grupo de calibración legacy.

**Cómo se genera:** copia de `resumen_por_grupo.csv` tras fase legacy.

**Utilidad:** evidencia cuantitativa para validación del entorno legacy.

---

### `resultados/resumen_calibracion_moderno.csv`
**Qué es:** resumen por grupo de calibración moderna.

**Cómo se genera:** copia de `resumen_por_grupo.csv` tras fase moderna.

**Utilidad:** evidencia cuantitativa para validación del entorno moderno.

---

## 6.9 Artefactos visuales (`imagenes/`)

### `imagenes/latencia_limpia.png`
**Qué representa:** análisis de latencia por grupo en 4 subgráficos:
1) DNS,
2) TCP,
3) Handshake TLS,
4) Tiempo total.

**Cómo se genera:** función `graficar_latencia` de `analizar_resultados.py` (medias + desviación estándar).

**Utilidad en el proyecto:** comparar coste temporal de cada grupo y descomponer dónde se consume el tiempo.

---

### `imagenes/bytes_limpia.png`
**Qué representa:** análisis de volumen de handshake por grupo:
1) bytes enviados,
2) bytes recibidos,
3) overhead total,
4) panel reservado.

**Cómo se genera:** función `graficar_bytes`, con control robusto para datos faltantes.

**Utilidad en el proyecto:** cuantificar coste de tráfico criptográfico y comparar eficiencia de grupos.

---

### `imagenes/scatter_limpia.png`
**Qué representa:** relación latencia vs overhead (cada punto es un grupo).

**Cómo se genera:** función `graficar_scatter`, usando medias por grupo y tamaño de punto proporcional a muestras.

**Utilidad en el proyecto:** visualizar trade-off rendimiento (ms) vs coste (bytes) entre grupos.

---

## 6.10 Directorios y artefactos automáticos

### `venv/`
**Qué es:** entorno virtual local de Python.

**Cómo se genera:** por `ejecutar_analisis.sh` si no existe (`python3 -m venv`).

**Utilidad:** aislar dependencias y evitar conflictos con Python global.

---

### `__pycache__/`
**Qué es:** bytecode cache generado por Python.

**Cómo se genera:** automáticamente al ejecutar scripts `.py`.

**Utilidad:** acelerar importación/ejecución, sin valor metodológico para el análisis.

---

### `.git/`
**Qué es:** metadatos de control de versiones.

**Cómo se genera:** al inicializar/clonar repositorio Git.

**Utilidad:** trazabilidad histórica de cambios, no participa en la pipeline de medición.

---

## 7. Métricas recolectadas (explicación completa)

Esta sección describe para **cada métrica**: cómo se obtiene, qué significa y por qué es útil.

## 7.1 Métricas de resultado

### `connection_result`
- **Cómo se obtiene:** inferido tras parsear salida OpenSSL y estado de handshake.
- **Qué significa:** estado lógico de negociación (`ACEPTADO`, `RECHAZADO` o `null`).
- **Utilidad:** métrica principal de adopción por grupo.

### `error_category`
- **Cómo se obtiene:** clasificación por rama de error en DNS/TCP/TLS/excepción.
- **Qué significa:** causa técnica del fallo (`ERROR_DNS`, `ERROR_TCP_TIMEOUT`, etc.).
- **Utilidad:** separar fallos de infraestructura de incompatibilidad criptográfica.

### `res`
- **Cómo se obtiene:** texto de salida contextual (línea negociada o mensaje de error).
- **Qué significa:** detalle humano del resultado.
- **Utilidad:** depuración y trazabilidad cualitativa.

---

## 7.2 Métricas de latencia

### `dns_time_ms`
- **Cómo se obtiene:** cronometrando `socket.getaddrinfo(...)`.
- **Qué significa:** tiempo de resolución DNS previo a conexión.
- **Utilidad:** identificar impacto de resolución de nombres en la latencia total.

### `tcp_time_ms`
- **Cómo se obtiene:** cronometrando `socket.connect(...)` al endpoint.
- **Qué significa:** tiempo de establecimiento TCP.
- **Utilidad:** aislar problemas de red/puerto antes de TLS.

### `handshake_time_ms`
- **Cómo se obtiene:** tiempo de ejecución de handshake durante `openssl s_client`.
- **Qué significa:** coste temporal de negociación TLS (incluyendo grupo criptográfico).
- **Utilidad:** comparar rendimiento criptográfico entre grupos.

### `tiempo_conexion_segundos`
- **Cómo se obtiene:** diferencia entre inicio y fin global de la operación.
- **Qué significa:** duración total de la prueba por grupo.
- **Utilidad:** KPI global de rendimiento percibido.

---

## 7.3 Métricas de volumen (bytes)

### `bytes_sent`
- **Cómo se obtiene:** parseando `-trace` de OpenSSL; suma de longitudes en registros enviados (+5 bytes de cabecera TLS por registro).
- **Qué significa:** tráfico saliente durante handshake.
- **Utilidad:** medir coste de subida asociado al grupo criptográfico.

### `bytes_received`
- **Cómo se obtiene:** parseando `-trace` de OpenSSL en registros recibidos (+5 cabecera TLS).
- **Qué significa:** tráfico entrante durante handshake.
- **Utilidad:** medir coste de descarga y peso de respuesta de servidor.

### `handshake_overhead`
- **Cómo se obtiene:** `bytes_sent + bytes_received`.
- **Qué significa:** tamaño total intercambiado en handshake.
- **Utilidad:** comparar huella total de red entre grupos.

### `measurement_method`
- **Cómo se obtiene:** estado del parser de trace (`traced`, `partial`, `unknown`).
- **Qué significa:** calidad/completitud de medición de bytes.
- **Utilidad:** filtrar/ponderar confianza en análisis de overhead.

---

## 7.4 Métricas TLS/protocolo

### `tls_version`
- **Cómo se obtiene:** regex sobre salida OpenSSL (`Protocol:`).
- **Qué significa:** versión TLS negociada.
- **Utilidad:** verificar compatibilidad moderna (especialmente TLS 1.3).

### `cipher_suite`
- **Cómo se obtiene:** regex sobre salida OpenSSL (`Cipher:` / `Cipher is`).
- **Qué significa:** suite criptográfica simétrica negociada.
- **Utilidad:** confirmar handshake válido y contexto de seguridad de sesión.

### `alpn`
- **Cómo se obtiene:** regex sobre líneas ALPN en salida OpenSSL.
- **Qué significa:** protocolo de aplicación negociado (p.ej. `h2`).
- **Utilidad:** contexto operativo de la sesión HTTPS.

### `tls_alert`
- **Cómo se obtiene:** búsqueda de líneas con “alert” en stdout/stderr.
- **Qué significa:** alerta TLS explícita del servidor.
- **Utilidad:** evidenciar rechazo criptográfico directo.

---

## 7.5 Métricas de endpoint/red

### `ip`
- **Cómo se obtiene:** primera dirección resultante de resolución DNS.
- **Qué significa:** IP objetivo de conexión.
- **Utilidad:** trazabilidad de endpoint medido.

### `ip_familia`
- **Cómo se obtiene:** familia de socket (`AF_INET`/`AF_INET6`).
- **Qué significa:** si conexión fue IPv4 o IPv6.
- **Utilidad:** análisis de diferencias de conectividad por familia IP.

### `sni_usado`
- **Cómo se obtiene:** valor enviado en `-servername` de OpenSSL.
- **Qué significa:** SNI efectivo usado en handshake.
- **Utilidad:** diagnósticos de virtual hosting TLS.

### `sni_difiere`
- **Cómo se obtiene:** bandera interna de diferencia hostname/SNI.
- **Qué significa:** indica desviación entre nombre objetivo y SNI.
- **Utilidad:** detectar posibles causas de rechazo por hostname.

### `retry`
- **Cómo se obtiene:** flag cuando hay reintento tras timeout inicial.
- **Qué significa:** si la prueba necesitó segunda ejecución.
- **Utilidad:** medir estabilidad/robustez de conectividad.

---

## 7.6 Métricas de certificado

### `cert_issuer`
- **Cómo se obtiene:** extracción con `openssl x509 -issuer` desde PEM parseado.
- **Qué significa:** entidad emisora del certificado.
- **Utilidad:** contexto de confianza y análisis de PKI.

### `cert_not_before`
- **Cómo se obtiene:** extracción con `openssl x509 -dates`.
- **Qué significa:** inicio de validez del certificado.
- **Utilidad:** detección de certs aún no válidos.

### `cert_not_after`
- **Cómo se obtiene:** extracción con `openssl x509 -dates`.
- **Qué significa:** fin de validez del certificado.
- **Utilidad:** detección de expiración/caducidad.

### `cert_san`
- **Cómo se obtiene:** `openssl x509 -ext subjectAltName`.
- **Qué significa:** dominios alternativos cubiertos por certificado.
- **Utilidad:** verificar cobertura de nombres y coherencia de endpoint.

### `cert_fingerprint_sha256`
- **Cómo se obtiene:** `openssl x509 -fingerprint -sha256`.
- **Qué significa:** huella única SHA-256 del certificado.
- **Utilidad:** identificación inequívoca para auditoría y comparación temporal.

---

## 7.7 Métricas agregadas por grupo (CSV)

### `total_pruebas`
- **Cómo se obtiene:** conteo de pruebas por grupo.
- **Qué significa:** volumen efectivo de observaciones.
- **Utilidad:** base estadística para comparar grupos.

### `aceptados`
- **Cómo se obtiene:** conteo de `connection_result == ACEPTADO`.
- **Qué significa:** éxitos de negociación.
- **Utilidad:** núcleo de adopción por grupo.

### `rechazados`
- **Cómo se obtiene:** conteo de `connection_result == RECHAZADO`.
- **Qué significa:** rechazos explícitos de handshake.
- **Utilidad:** cuantificar incompatibilidad criptográfica.

### `errores`
- **Cómo se obtiene:** `total - aceptados - rechazados`.
- **Qué significa:** fallos técnicos previos o no clasificables como rechazo explícito.
- **Utilidad:** medir “ruido” de infraestructura en campaña.

### `porcentaje_aceptacion`, `porcentaje_rechazo`, `porcentaje_error`
- **Cómo se obtiene:** normalización porcentual sobre `total_pruebas`.
- **Qué significa:** distribución de estados por grupo.
- **Utilidad:** comparabilidad directa entre grupos y campañas.

### Estadísticas numéricas (`media`, `mediana`, `desv_std`, `min`, `max`)
- **Cómo se obtiene:** agregación sobre listas numéricas de conexiones aceptadas.
- **Qué significa:** tendencia central + dispersión + extremos.
- **Utilidad:** evaluar estabilidad y rendimiento, no solo éxito binario.

---

## 8. Grupos criptográficos probados por la sonda final

1. Automático
2. X25519
3. X25519MLKEM768
4. x25519_kyber768
5. mlkem768
6. kyber768
7. p256_kyber768
8. SecP256r1MLKEM768
9. x25519_mlkem512
10. x25519_kyber512
11. frodo640aes
12. bikel1
13. x25519_bikel1
14. x25519_hqc128

---

## 9. Cómo se generan exactamente los resultados y figuras

## 9.1 Resultados JSON/CSV

Se generan en la fase de escaneo (`sonda_pqc_final.py`):

1. Por cada hostname y grupo:
   - se ejecuta prueba,
   - se recogen métricas,
   - se clasifica estado/error.

2. Tras repeticiones:
   - se promedian métricas por grupo-host.

3. Al finalizar campaña:
   - se agrega resumen global,
   - se agregan estadísticas por grupo,
   - se exporta JSON y CSV.

## 9.2 Gráficas PNG

Se generan en la fase de análisis (`analizar_resultados.py`):

1. Carga JSON.
2. Filtra solo conexiones `ACEPTADO` para análisis comparativo de rendimiento.
3. Limpia outliers (IQR en métricas de bytes).
4. Filtra grupos con mínimo de muestras.
5. Grafica 3 vistas complementarias:
   - latencia,
   - bytes,
   - trade-off latencia vs overhead.

---

## 10. Troubleshooting operativo

### Docker no disponible
```bash
docker --version
docker ps
```

### Puertos de calibración ocupados (4433/4434)
```bash
docker ps -a
```

### Sin resultados de sonda
- Revisar CSV de entrada y rutas montadas.
- Revisar `resultados/sonda_pqc.log`.

### Sin gráficas
- Verificar que existe `resultados/resultados_sonda_pqc.json`.
- Ejecutar `./ejecutar_analisis.sh` y revisar salida.

---

## 11. Flujo recomendado para TFG (reproducible)

1. Validación controlada:
```bash
./calibrar_servidor_pqc.sh 5
```

2. Campaña real:
```bash
./ejecutar_sonda.sh --input-csv majestic_million.csv --max-hostnames 100 --repeticiones 3 --max-workers 20
```

3. Post-procesado:
```bash
./ejecutar_analisis.sh
```

4. Artefactos para memoria:
- `resultados/*.json`
- `resultados/*.csv`
- `imagenes/*.png`

---

## 12. Resumen de valor del sistema

Este repositorio no solo “prueba conexión”, sino que ofrece una instrumentación completa para investigación:
- clasificación robusta de errores,
- métricas detalladas por fase de conexión,
- cuantificación de overhead por grupo,
- análisis reproducible y visual.

Con ello, la adopción PQC se puede evaluar con base empírica y no solo cualitativa.