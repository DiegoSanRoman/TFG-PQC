# 🚀 Scripts de Ejecución - Pipeline Completo

## 📋 Descripción General

Este proyecto tiene **3 scripts principales** que automatiznan todo el flujo de trabajo:

| Script | Propósito | Tiempo |
|--------|-----------|--------|
| `ejecutar_sonda.sh` | Ejecutar la sonda PQC en Docker | ⏱️ Variable (depende de hostnames) |
| `ejecutar_analisis.sh` | Generar gráficas y análisis | ⏱️ ~30 segundos |
| `test_pipeline.sh` | Ejecutar sonda + análisis en secuencia | ⏱️ Variable |

---

## 🎯 Caso de Uso 1: Ejecutar Sonda (Recolectar Datos)

### Sintaxis Básica

```bash
./ejecutar_sonda.sh [max_hostnames] [repeticiones] [max_workers]
```

### Ejemplos

**Ejemplo 1: Con valores por defecto (100 hostnames, 3 repeticiones)**
```bash
./ejecutar_sonda.sh
```

**Ejemplo 2: Solo 10 hostnames, 1 repetición (prueba rápida)**
```bash
./ejecutar_sonda.sh 10 1 5
```

**Ejemplo 3: Máximo rendimiento (500 hostnames, 3 repeticiones)**
```bash
./ejecutar_sonda.sh 500 3 20
```

### Parámetros

| Parámetro | Default | Descripción |
|-----------|---------|-------------|
| `max_hostnames` | 100 | Número máximo de dominios a probar |
| `repeticiones` | 3 | Repeticiones por grupo PQC |
| `max_workers` | 20 | Hilos paralelos (aumentar = más rápido pero más recursos) |

### Lo que hace

✅ Verifica que Docker esté instalado  
✅ Construye la imagen Docker si no existe  
✅ Lee el dataset `majestic_million.csv`  
✅ Ejecuta la sonda contra cada hostname  
✅ Guarda resultados en JSON y CSV  

### Salida esperada

```
╔════════════════════════════════════════════════════════════════╗
║           Ejecutar Sonda PQC con Docker                       ║
╚════════════════════════════════════════════════════════════════╝

📋 Configuración:
  • Dataset: majestic_million.csv
  • Max hostnames: 100
  • Repeticiones: 3
  • Hilos paralelelos: 20
  • Imagen Docker: tfg-sonda

✓ Imagen Docker encontrada
🚀 Iniciando sonda PQC en Docker...

Escaneo PQC: 100%|██████████| 100/100 [02:34<00:00,  1.54s/host]

✅ ¡Sonda completada exitosamente!
📁 Resultados guardados en:
  • JSON: /home/.../resultados/resultados_sonda_pqc.json
  • CSV:  /home/.../resultados/resumen_por_grupo.csv
  • LOG:  /home/.../resultados/sonda_pqc.log

💡 Próximo paso: ejecutar análisis
  $ ./ejecutar_analisis.sh
```

### Archivos generados

```
resultados/
├── resultados_sonda_pqc.json     (JSON con todos los detalles)
├── resumen_por_grupo.csv          (Resumen estadístico)
└── sonda_pqc.log                  (Log detallado)
```

---

## 📊 Caso de Uso 2: Generar Análisis y Gráficas

### Sintaxis Básica

```bash
./ejecutar_analisis.sh [archivo_json] [directorio_salida]
```

### Ejemplos

**Ejemplo 1: Con valores por defecto**
```bash
./ejecutar_analisis.sh
```

**Ejemplo 2: Analizar archivo específico**
```bash
./ejecutar_analisis.sh resultados/resultados_sonda_pqc.json imagenes/
```

**Ejemplo 3: Organizados por fecha**
```bash
./ejecutar_analisis.sh resultados/resultados_sonda_pqc.json imagenes/$(date +%Y%m%d)/
```

### Lo que hace

✅ Carga el JSON de resultados  
✅ Genera 7 gráficas profesionales (PNG)  
✅ Crea reporte de texto con estadísticas  
✅ Calcula ratios y comparativas  

### Salida esperada

```
📊 Generando gráficas...
✓ Guardado: imagenes/1_latencia_por_grupo.png
✓ Guardado: imagenes/2_overhead_bytes.png
✓ Guardado: imagenes/3_latencia_vs_bytes.png
✓ Guardado: imagenes/4_distribucion_por_host.png
✓ Guardado: imagenes/5_heatmap_latencia.png
✓ Guardado: imagenes/6_boxplot_distribucion.png
✓ Guardado: imagenes/7_tasa_exito.png

✅ ¡Análisis completado exitosamente!
   Se han generado 8 gráficas y 1 reporte en: imagenes
```

### Archivos generados

```
imagenes/
├── 1_latencia_por_grupo.png
├── 2_overhead_bytes.png
├── 3_latencia_vs_bytes.png
├── 4_distribucion_por_host.png
├── 5_heatmap_latencia.png
├── 6_boxplot_distribucion.png
├── 7_tasa_exito.png
└── reporte_analisis.txt
```

---

## 🔄 Caso de Uso 3: Pipeline Completo (Sonda + Análisis)

### Sintaxis

```bash
./test_pipeline.sh [max_hostnames]
```

### Ejemplos

**Ejecutar pipeline con 10 hostnames (rapido para testing)**
```bash
./test_pipeline.sh 10
```

**Ejecutar pipeline completo (100 hostnames)**
```bash
./test_pipeline.sh
```

### Lo que hace

1️⃣ Ejecuta sonda (10 hostnames, 1 repetición, 5 workers) → Rápido para testing  
2️⃣ Espera a que termine  
3️⃣ Ejecuta análisis automáticamente  

---

## 📈 Flujo de Trabajo Completo (Paso a Paso)

### Para tu Memoria TFG

```bash
# 1. Ejecutar sonda con muchos hostnames
./ejecutar_sonda.sh 200 3 20

# Esperar a que termine (probablemente 30-60 minutos)

# 2. Generar análisis
./ejecutar_analisis.sh

# 3. Las gráficas están listas en imagenes/
# ¡Incluirlas en tu memoria!
```

### Para Testing/Desarrollo

```bash
# Forma rápida: solo 10 hostnames
./test_pipeline.sh 10

# Toma ~3-5 minutos, útil para verificar que funciona todo
```

### Para Comparativas (Múltiples Ejecuciones)

```bash
# Sonda 1
./ejecutar_sonda.sh 100 2 15
./ejecutar_analisis.sh resultados/resultados_sonda_pqc.json imagenes/sonda_1/

# Sonda 2 (después de cambios)
./ejecutar_sonda.sh 100 2 15
./ejecutar_analisis.sh resultados/resultados_sonda_pqc.json imagenes/sonda_2/

# Comparar sonda_1/ vs sonda_2/
```

---

## ⚙️ Configuración y Troubleshooting

### Error: "Docker no encontrado"

**Solución**: Instala Docker
```bash
# En Ubuntu/Debian
sudo apt-get install docker.io docker.io

# En macOS
brew install docker
```

### Error: "Archivo no encontrado: majestic_million.csv"

**Solución**: Verifica que el CSV exista
```bash
ls -lh data/
# Debe mostrar: majestic_million.csv
```

### La sonda es muy lenta

**Solución**: Aumenta los workers
```bash
./ejecutar_sonda.sh 100 1 30  # 30 workers en lugar de 20
```

### Quiero usar un dataset diferente

**Actualmente sofrecidos**:
```bash
ls data/
# majestic_million.csv
# prueba.csv
# tranco.csv
```

**Para usar Tranco (100 dominios)**:
```bash
# Necesitarías modificar el script, actualmente solo usa majestic_million
```

---

## 📚 Documentación Completa

Para más detalles:
- **Sonda**: Ver `scripts/sondas/sonda_pqc_final.py`
- **Análisis**: Ver `scripts/ml/README_analisis.md`
- **Ejemplos**: Ver `scripts/ml/ejemplo_uso_analisis.py`

---

## 🎓 Casos de Uso Reales

### Para la Memoria TFG
```bash
# 1. Ejecutar sonda
./ejecutar_sonda.sh 200 3 20

# 2. Analizar
./ejecutar_analisis.sh

# 3. Copiar gráficas a documentos/imagenes/
cp imagenes/*.png dokumentos/imagenes/
```

### Para Presentaciones
```bash
# Análisis rápido con pocos hostnames
./test_pipeline.sh 20

# O manualmente
./ejecutar_sonda.sh 20 1 10
./ejecutar_analisis.sh imagenes/presentacion/
```

### Para Investigación
```bash
# Ejecutar sin intervención automática
./ejecutar_sonda.sh 50 2 10 &
# (se ejecuta en background)

# Luego analizar cuando termine
./ejecutar_analisis.sh
```

---

## 📊 Recursos y Predicciones de Tiempo

| Hostnames | Repeticiones | Tiempo esperado | Tamaño JSON |
|-----------|--------------|-----------------|-------------|
| 10 | 1 | ~1 min | ~100 KB |
| 50 | 2 | ~10 min | ~500 KB |
| 100 | 3 | ~20 min | ~1 MB |
| 200 | 3 | ~40 min | ~2 MB |
| 500 | 3 | ~2 horas | ~5 MB |

---

## 🔗 Integración con Otros Scripts

### Ejecutar sonda y guardar con timestamp

```bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
./ejecutar_sonda.sh 100 3 20
mv resultados/resultados_sonda_pqc.json resultados/sonda_${TIMESTAMP}.json
./ejecutar_analisis.sh resultados/sonda_${TIMESTAMP}.json imagenes/analisis_${TIMESTAMP}/
```

### Ejecutar en background
```bash
nohup ./ejecutar_sonda.sh 500 3 20 > sonda.log 2>&1 &
# Puedes continuar trabajando, verifica con:
tail -f sonda.log
```

---

## ✅ Checklist para Ejecutar

- [ ] Docker está instalado y funcionando
- [ ] El CSV existe en `data/majestic_million.csv`
- [ ] El Dockerfile existe en la raíz
- [ ] Tienes espacio suficiente en disco (~500MB para 100 hostnames)
- [ ] Conexión a internet (para conectar a los servidores)

---

**¡Ahora estás listo para ejecutar tu pipeline completo! 🚀**

```bash
# ⚡ Forma más rápida:
./test_pipeline.sh 10

# 📊 Forma estándar:
./ejecutar_sonda.sh 100 3 20 && ./ejecutar_analisis.sh

# 🏆 Forma para la memoria:
./ejecutar_sonda.sh 200 3 20 && ./ejecutar_analisis.sh
```
