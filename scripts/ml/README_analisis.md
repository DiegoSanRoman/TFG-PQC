# Análisis y Visualización de Resultados de Sondas PQC

## 📋 Descripción

`analizar_resultados.py` es un script profesional que transforma los datos JSON brutos generados por las sondas PQC en visualizaciones claras y un reporte detallado. Permite comparar de manera más comprensible el **impacto en latencia** y el **overhead de bytes** entre diferentes algoritmos criptográficos (híbridos y post-cuánticos puros).

## 🎯 Características Principales

✅ **7 Gráficas profesionales** con formato publication-ready  
✅ **Reporte automatizado** con estadísticas y conclusiones  
✅ **Análisis de latencia** en múltiples dimensiones (DNS, TCP, TLS, Total)  
✅ **Análisis de overhead de bytes** (enviados, recibidos, handshake)  
✅ **Comparativas visuales** entre algoritmos y servidores  
✅ **Heatmaps y box plots** para distribuciones estadísticas  
✅ **Tasas de éxito** por grupo criptográfico  

## 📦 Dependencias

```bash
pandas>=1.3.0
numpy>=1.20.0
matplotlib>=3.3.0
seaborn>=0.11.0
```

## 🚀 Instalación Rápida

### Opción 1: Con entorno virtual (Recomendado)

```bash
cd /home/diego-san-roman/TFG_Diego
python3 -m venv venv
source venv/bin/activate
pip install pandas numpy matplotlib seaborn
```

### Opción 2: Sin entorno virtual (Sistema)

```bash
pip3 install pandas numpy matplotlib seaborn
```

## 💻 Uso

### Sintaxis Básica

```bash
python scripts/ml/analizar_resultados.py --input <ruta_json> [--output <directorio_salida>]
```

### Ejemplos

**Ejemplo 1: Usar ubicaciones por defecto**
```bash
cd /home/diego-san-roman/TFG_Diego
source venv/bin/activate
python scripts/ml/analizar_resultados.py --input resultados/resultados_sonda_pqc.json
# Las gráficas se guardarán en: imagenes/
```

**Ejemplo 2: Especificar ubicación de salida personalizada**
```bash
python scripts/ml/analizar_resultados.py \
  --input resultados/resultados_sonda_pqc.json \
  --output /tmp/analisis_pqc/
```

**Ejemplo 3: Con archivo JSON diferente**
```bash
python scripts/ml/analizar_resultados.py \
  --input resultados/mi_analisis_personalizado.json \
  --output imagenes/nueva_sonda/
```

### Opciones disponibles

```
--input, -i      (requerido) Ruta al archivo JSON de resultados
--output, -o     (opcional)  Directorio de salida (default: imagenes/)
--no-show                    No mostrar gráficas, solo guardarlas
--help, -h                   Mostrar ayuda
```

## 📊 Salidas Generadas

El script genera 8 archivos en el directorio de salida:

### Gráficas de Latencia

| # | Archivo | Descripción |
|---|---------|-------------|
| 1 | `1_latencia_por_grupo.png` | 4 subgráficas: DNS, TCP, Handshake TLS y tiempo total |
| 4 | `4_distribucion_por_host.png` | Latencia y overhead promedio por hostname |
| 5 | `5_heatmap_latencia.png` | Matriz de calor: Hostnames vs Grupos criptográficos |
| 6 | `6_boxplot_distribucion.png` | Distribución estadística (box plots) de latencias |

### Gráficas de Overhead de Bytes

| # | Archivo | Descripción |
|---|---------|-------------|
| 2 | `2_overhead_bytes.png` | 4 subgráficas: bytes enviados, recibidos, overhead handshake, respuesta |
| 3 | `3_latencia_vs_bytes.png` | Scatter plot comparativo: latencia vs overhead |

### Tasa de Éxito

| # | Archivo | Descripción |
|---|---------|-------------|
| 7 | `7_tasa_exito.png` | Porcentaje de conexiones exitosas por grupo |

### Reporte de Texto

| Archivo | Descripción |
|---------|-------------|
| `reporte_analisis.txt` | Reporte completo con estadísticas, tablas y conclusiones |

## 📈 Estructura del Análisis

### 1️⃣ Estadísticas Generales
- Total de pruebas y tasa de éxito
- Distribución de grupos criptográficos
- Cobertura de hostnames

### 2️⃣ Análisis por Grupo Criptográfico
- Promedio, desviación estándar, mínimo y máximo para:
  - **Latencias**: DNS, TCP, Handshake TLS
  - **Bytes**: Enviados, recibidos, overhead del handshake

### 3️⃣ Comparativas Visuales
- Rendimiento relativo entre algoritmos
- Impacto de cada algoritmo en latencia y tamaño
- Variabilidad por servidor

### 4️⃣ Insights Automáticos
```
⚡ Algoritmo más rápido → X25519MLKEM768
🐢 Algoritmo más lento → X25519
📉 Menor overhead → x25519_kyber768
📈 Mayor overhead → X25519MLKEM768
```

## 🎨 Personalización de Gráficas

### Modificar esquema de colores

Edita el diccionario `COLORES_GRUPOS` en el script:

```python
COLORES_GRUPOS = {
    'X25519': '#FF0000',           # Rojo
    'X25519MLKEM768': '#00FF00',   # Verde
    'x25519_kyber768': '#0000FF',  # Azul
    # ... más grupos
}
```

### Cambiar tamaño de figuras

Modifica en el script:

```python
plt.rcParams['figure.figsize'] = (14, 8)  # Ancho x Alto en pulgadas
```

### Ajustar DPI de gráficas

En las funciones de visualización, cambia:

```python
plt.savefig(output_path / 'nombre.png', dpi=300)  # 300 = alta resolución
```

## 📋 Formato del JSON de Entrada

El script espera un archivo JSON con esta estructura:

```json
{
  "resumen": {
    "timestamp_finalizacion": "...",
    "total_hostnames": 10,
    "pruebas_exitosas": 16,
    "tasa_exito_pruebas_percent": 11.43,
    "grupos_probados": ["X25519", "X25519MLKEM768", ...]
  },
  "datos": [
    {
      "hostname": "example.com",
      "pruebas": [
        {
          "grupo": "X25519",
          "connection_result": "ACEPTADO",
          "dns_time_ms": 28.5,
          "tcp_time_ms": 42.3,
          "handshake_time_ms": 2679.8,
          "tiempo_conexion_segundos": 2.75,
          "bytes_sent": 486,
          "bytes_received": 4155,
          "handshake_overhead": 4641,
          "response_size_bytes": 4641
        }
      ]
    }
  ]
}
```

## 🔧 Troubleshooting

### Error: `ModuleNotFoundError: No module named 'seaborn'`

**Solución**: Asegúrate de tener el entorno virtual activado:

```bash
source venv/bin/activate  # En macOS/Linux
# o
venv\Scripts\activate     # En Windows
```

Luego instala las dependencias:

```bash
pip install seaborn pandas matplotlib numpy
```

### Error: `FileNotFoundError: [Errno 2] No such file or directory`

**Solución**: Verifica que la ruta del archivo JSON sea correcta:

```bash
ls resultados/resultados_sonda_pqc.json  # Confirmar que existe
```

### Las gráficas no se guardan

**Solución**: Verifica que el directorio de salida existe o déjalo que lo cree:

```bash
# El script lo crea automáticamente, pero puedes pre-crearlo:
mkdir -p imagenes/
```

## 📊 Interpretación de Gráficas

### Gráfica 1: Latencia por Grupo
- **Barras más cortas** = Algoritmos más rápidos
- **Líneas de error** = Variabilidad entre servidores
- **DNS Time** suele dominar especialmente en primeras conexiones

### Gráfica 2: Overhead de Bytes
- **Barras más cortas** = Menor consumo de ancho de banda
- **Handshake Overhead** es lo más crítico para latencia
- Considerar trade-off: latencia vs tamaño

### Gráfica 3: Latencia vs Bytes
- **Esquina inferior-izquierda** = Óptimo (rápido + pequeño)
- **Esquina superior-derecha** = Peor (lento + grande)
- Útil para identificar trade-offs

### Gráfica 5: Heatmap
- **Colores rojizos** = Mayor latencia
- Identifica servidores problemáticos y combinaciones malas

### Gráfica 6: Box Plots
- **Caja pequeña** = Comportamiento consistente
- **Outliers** = Casos anómalos
- **Mediana** (línea en la caja) vs media

## 🎓 Casos de Uso

### 📝 Para la Memoria TFG
```bash
# Generar análisis final con todas las gráficas
python scripts/ml/analizar_resultados.py \
  --input resultados/resultados_sonda_pqc.json \
  --output imagenes/tfg_final/
```

### 🧪 Para análisis iterativos
```bash
# Ejecutar después de cada sonda con datos nuevos
python scripts/ml/analizar_resultados.py \
  --input resultados/Nueva_sonda_$(date +%Y%m%d).json \
  --output imagenes/comparativa/
```

### 📊 Para presentaciones
```bash
# Usar --no-show para procesamiento batch
python scripts/ml/analizar_resultados.py \
  --input resultados/resultados_sonda_pqc.json \
  --output imagenes/ \
  --no-show
```

## 🔍 Ejemplo de Salida Esperada

```
📊 Inicializando análisis de resultados...
   Entrada: resultados/resultados_sonda_pqc.json
   Salida: imagenes

✓ Datos cargados exitosamente
  - Total de hostnames: 10
  - Total de pruebas: 140
  - Pruebas exitosas: 16

📈 Estadísticas generales:
   - Tasa de éxito: 11.43%
   - Grupos probados: 14
   - Hostnames exitosos: 8/10

📊 Generando gráficas...
✓ Guardado: imagenes/1_latencia_por_grupo.png
✓ Guardado: imagenes/2_overhead_bytes.png
✓ Guardado: imagenes/3_latencia_vs_bytes.png
✓ Guardado: imagenes/4_distribucion_por_host.png
✓ Guardado: imagenes/5_heatmap_latencia.png
✓ Guardado: imagenes/6_boxplot_distribucion.png
✓ Guardado: imagenes/7_tasa_exito.png

📝 Generando reporte de texto...
✓ Guardado: imagenes/reporte_analisis.txt

✅ ¡Análisis completado exitosamente!
   Se han generado 8 gráficas y 1 reporte en: imagenes
```

## 📚 Referencias

- [Matplotlib Documentation](https://matplotlib.org/)
- [Seaborn Documentation](https://seaborn.pydata.org/)
- [Pandas Data Analysis](https://pandas.pydata.org/)
- Post-Quantum Cryptography (NIST): https://csrc.nist.gov/projects/post-quantum-cryptography/

## 📝 Licencia

Parte del Trabajo de Fin de Grado (TFG) de Diego San Román
