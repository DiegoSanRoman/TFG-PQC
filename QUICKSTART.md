# QuickStart - Análisis de Sondas PQC

## ⚡ Inicio Rápido (3 pasos)

### 1️⃣ Opción A: Usar el wrapper (más fácil)

```bash
cd /home/diego-san-roman/TFG_Diego
./ejecutar_analisis.sh
```

### 2️⃣ Opción B: Ejecución manual

```bash
cd /home/diego-san-roman/TFG_Diego
source venv/bin/activate
python scripts/ml/analizar_resultados.py --input resultados/resultados_sonda_pqc.json --output imagenes/
```

### 3️⃣ Opción C: Con archivo JSON personalizado

```bash
python scripts/ml/analizar_resultados.py \
  --input resultados/mi_sonda_personalizada.json \
  --output imagenes/sonda_custom/
```

## 📊 Gráficas Generadas

| # | Archivo | Qué ves |
|---|---------|---------|
| 1️⃣ | **1_latencia_por_grupo.png** | 📈 Comparación de latencias (DNS, TCP, TLS, Total) |
| 2️⃣ | **2_overhead_bytes.png** | 📦 Bytes enviados/recibidos/overhead por grupo |
| 3️⃣ | **3_latencia_vs_bytes.png** | 🎯 Scatter: Trade-off entre latencia y overhead |
| 4️⃣ | **4_distribucion_por_host.png** | 🌐 Performance por hostname |
| 5️⃣ | **5_heatmap_latencia.png** | 🔥 Matriz: Hostnames × Grupos |
| 6️⃣ | **6_boxplot_distribucion.png** | 📊 Box plots: Distribución y outliers |
| 7️⃣ | **7_tasa_exito.png** | ✅ Porcentaje de conexiones exitosas |
| 📄 | **reporte_analisis.txt** | 📋 Reporte con all estadísticas |

## 🎯 Casos de Uso Típicos

### Para la Memoria TFG
```bash
./ejecutar_analisis.sh resultados/resultados_sonda_pqc.json imagenes/tfg_final/
```
→ Las 7 gráficas + reporte listos para incluir en la memoria

### Para análisis iterativos (múltiples sondas)
```bash
# Después de cada sonda:
./ejecutar_analisis.sh resultados/nueva_sonda_$(date +%Y%m%d).json imagenes/comparativa/
```

### Para presentaciones
```bash
# Sin abrir ventanas gráficas:
python scripts/ml/analizar_resultados.py \
  --input resultados/resultados_sonda_pqc.json \
  --output imagenes/ \
  --no-show
```

## 📋 Qué Incluye Este Paquete

✅ **analizar_resultados.py** (500+ líneas)
- Script principal con 7 funciones de visualización
- Clase AnalizadorResultados para procesar JSON
- Generación automática de reporte

✅ **ejecutar_analisis.sh**
- Wrapper que automatiza: venv, dependencias, ejecución
- Responde preguntas sobre configuración

✅ **README_analisis.md**
- Documentación completa (100+ líneas)
- Ejemplos, troubleshooting, personalización

✅ **ejemplo_uso_analisis.py**
- 6 ejemplos de uso programático
- Integración con otros scripts
- Filtros y análisis avanzados

✅ **requirements.txt**
- Especificación de dependencias para pip

## 🔧 Requisitos Mínimos

- Python 3.7+
- Linux/macOS/Windows
- ~50MB de espacio para el venv
- Archivo JSON de la sonda

## 🚨 Solución de Problemas

| Problema | Solución |
|----------|----------|
| `ModuleNotFoundError` | Ejecuta `./ejecutar_analisis.sh` |
| `FileNotFoundError` | Verifica la ruta del JSON |
| Gráficas borrosas | Aumenta DPI en el script: `dpi=600` |
| Lento | Reduce tamaño del JSON o usa --no-show |

## 📚 Documentación Completa

Para documentación detallada, ver: `scripts/ml/README_analisis.md`

## 💡 Tips Profesionales

1. **Para presentaciones**: Usa `--no-show` con salida a directorio `imagenes/presentacion/`

2. **Para memoria**: Guarda las gráficas en carpeta `docs/imagenes/` dentro de tu documento

3. **Para comparativas**: Ejecuta varias veces con diferentes JSONs y guarda en subdirectorios:
   ```
   imagenes/
   ├── sonda_0/     (primeras pruebas)
   ├── sonda_1/     (después de optimizar)
   └── sonda_final/ (versión final)
   ```

4. **Para reproducir**: Guarda el comando exacto usado en un script `.sh` para referencia

## 🎓 Interpretación Rápida de Gráficas

### Gráfica 1: Latencia
- ✅ Barras cortas = algoritmo más rápido
- ⚠️ Barras largas = overhead de handshake TLS
- 📊 Las líneas de error muestran variabilidad entre servidores

### Gráfica 3: Latencia vs Bytes
- 🟢 Esquina inferior-izquierda = IDEAL (rápido + pequeño)
- 🔴 Esquina superior-derecha = EVITAR (lento + grande)
- 🟡 Trade-off visible entre latencia y tamaño

### Gráfica 5: Heatmap
- 🔴 Rojo = latencia alta
- 🟡 Amarillo = latencia media
- 🟢 Verde = latencia baja
- Identifica combinaciones problemáticas

## 📞 Soporte

- Documentación: `README_analisis.md`
- Ejemplos: `ejemplo_uso_analisis.py`
- Source: `analizar_resultados.py`

---

**¡Ahora tienes gráficas profesionales para tu memoria! 🎉**

Ejecuta: `./ejecutar_analisis.sh` y ve las gráficas en `imagenes/`
