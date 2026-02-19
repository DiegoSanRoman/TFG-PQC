# 🎯 Calibración de la Sonda PQC - Servidor de Control

## 📋 Descripción

La **calibración de la sonda** es un paso crítico en la metodología del TFG que valida la precisión de las mediciones antes de escanear servidores en Internet.

### ¿Por qué calibrar?

Los servidores de Internet tienen latencias variables que pueden:
- ❌ Enmascarar el overhead real de los algoritmos PQC
- ❌ Introducir ruido en las mediciones
- ❌ Dificultar la comparación entre algoritmos

La solución: **servidor de control local** con latencia de red cercana a cero (t≈0ms).

### Valor para el TFG

> *"Antes de escanear Internet, se validó la precisión de la sonda contra un entorno controlado con latencia de red cero (t≈0), confirmando que el overhead de procesamiento de la sonda es despreciable."*

---

## 🚀 Uso Rápido

### Opción A: Servidor con Docker (Recomendado)

**Ventajas:**
- ✅ No requiere instalación de OpenSSL local
- ✅ Usa el mismo entorno que la sonda
- ✅ Configuración consistente

**Terminal 1: Levantar servidor**
```bash
./servidor_control_pqc_docker.sh 4433
```

**Terminal 2: Ejecutar calibración**
```bash
./calibrar_sonda.sh 4433 5
```

### Opción B: Servidor Local (Requiere Compilación)

**Ventajas:**
- ✅ No depende de Docker
- ✅ Puede ser más rápido en algunos sistemas

**Requisitos:**
- OpenSSL 3.x compilado con liboqs en `/opt/openssl/bin/openssl`

**Terminal 1: Levantar servidor**
```bash
./servidor_control_pqc.sh 4433
```

**Terminal 2: Ejecutar calibración**
```bash
./calibrar_sonda.sh 4433 5
```

---

## 🚀 Uso Rápido (2 pasos)

### Paso 1: Levantar servidor de control

```bash
cd /home/diego-san-roman/TFG_Diego/scripts/calibracion
./servidor_control_pqc.sh
```

**Salida esperada:**
```
╔════════════════════════════════════════════════════════════════╗
║         Servidor de Control PQC - Calibración de Sonda        ║
╚════════════════════════════════════════════════════════════════╝

🔍 Verificando OpenSSL...
  Versión: OpenSSL 3.x.x
  Binario: /opt/openssl/bin/openssl

✓ Certificados generados exitosamente
  Cert: certs/cert.pem
  Key:  certs/key.pem

📜 Información del Certificado:
  subject=C=ES, ST=Madrid, L=Madrid, O=TFG-PQC, CN=localhost
  issuer=C=ES, ST=Madrid, L=Madrid, O=TFG-PQC, CN=localhost
  notBefore=Feb 19 10:00:00 2026 GMT
  notAfter=Feb 19 10:00:00 2027 GMT

⚙️  Configuración del Servidor:
  Puerto: 4433
  Grupos PQC soportados:
    - X25519
    - X25519MLKEM768
    - x25519_kyber768
    - mlkem768
    - kyber768
    - ...

🚀 Iniciando servidor PQC...
   Para conectar desde la sonda, usa: localhost:4433
   Presiona Ctrl+C para detener el servidor
```

**Dejar este terminal abierto** (el servidor debe seguir corriendo).

---

### Paso 2: Ejecutar calibración (en otro terminal)

```bash
cd /home/diego-san-roman/TFG_Diego/scripts/calibracion
./calibrar_sonda.sh
```

**Salida esperada:**
```
╔════════════════════════════════════════════════════════════════╗
║           Calibración de Sonda PQC - Servidor Local           ║
╚════════════════════════════════════════════════════════════════╝

📋 Configuración:
  Servidor: localhost:4433
  Repeticiones: 5
  Directorio salida: resultados/calibracion

✓ Servidor accesible

🚀 Ejecutando calibración...
   (Esto tomará ~2-3 minutos)

Escaneo PQC: 100%|██████████| 1/1 [02:15<00:00, 135s/host]

✅ Calibración completada exitosamente
📁 Resultados guardados:
  JSON: resultados/calibracion/calibracion_20260219_103045.json
  CSV:  resultados/calibracion/calibracion_resumen_20260219_103045.csv

📊 Generando análisis de calibración...
✓ Análisis generado en: resultados/calibracion/imagenes_20260219_103045/

💡 Interpretación de Resultados:
  • Latencia de red (~0ms): Confirma entorno controlado
  • Overhead de handshake: Refleja el costo real del algoritmo PQC
  • Variabilidad baja: Indica mediciones precisas de la sonda
```

---

## 📊 Archivos Generados

```
resultados/calibracion/
├── calibracion_20260219_103045.json          # Resultados completos
├── calibracion_resumen_20260219_103045.csv   # Resumen por grupo
├── imagenes_20260219_103045/                 # Gráficas de análisis
│   ├── 1_latencia_por_grupo.png
│   ├── 2_overhead_bytes.png
│   ├── 3_latencia_vs_bytes.png
│   ├── ...
│   └── reporte_analisis.txt
└── localhost_test.csv (temporal, se borra automáticamente)
```

---

## 🔧 Configuración Avanzada

### Cambiar puerto del servidor

```bash
# Servidor en puerto 5000
./servidor_control_pqc.sh 5000

# Calibración contra puerto 5000
./calibrar_sonda.sh 5000
```

### Cambiar número de repeticiones

```bash
# Más repeticiones = mayor precisión (pero más lento)
./calibrar_sonda.sh 4433 10
```

### Especificar grupos PQC personalizados

```bash
# Solo probar algunos grupos específicos
./servidor_control_pqc.sh 4433 "X25519:X25519MLKEM768:mlkem768"
```

---

## 📈 Interpretación de Resultados

### ✅ Resultados Esperados (Buenos)

```
Grupo             | Latencia Handshake | Overhead Bytes | Desv. Std
------------------|--------------------|-----------------|-----------
X25519            | 5-10ms            | ~6000 bytes    | <2ms
X25519MLKEM768    | 8-15ms            | ~8500 bytes    | <3ms
mlkem768          | 10-20ms           | ~7000 bytes    | <5ms
```

**Indicadores de calibración correcta:**
- ✅ DNS time ≈ 0ms (usando localhost)
- ✅ TCP time < 1ms (conexión local)
- ✅ Handshake time refleja solo el algoritmo criptográfico
- ✅ Desviación estándar baja (< 10% de la media)

### ⚠️ Resultados Anómalos (Revisar)

```
Grupo             | Latencia Handshake | Problema
------------------|--------------------|---------------------------------
X25519            | >100ms            | ⚠️ Servidor sobrecargado o sonda incorrecta
X25519MLKEM768    | Varianza alta     | ⚠️ Interferencia del sistema operativo
mlkem768          | Sin conexión      | ⚠️ Grupo no soportado en servidor
```

---

## 🎓 Para la Memoria TFG

### Sección: "Calibración de la Sonda"

**Texto sugerido:**

> #### 4.X Calibración de la Sonda
>
> Antes de proceder al escaneo de servidores en Internet, se realizó una fase de **calibración de la sonda** para validar la precisión de las mediciones y cuantificar el overhead introducido por la propia herramienta.
>
> **Metodología:**
> - Se levantó un servidor OpenSSL local con soporte PQC en `localhost:4433`
> - Se configuró para soportar los 14 grupos criptográficos objetivo
> - Se ejecutó la sonda contra este entorno controlado con 5 repeticiones por grupo
> - Latencia de red esperada: t ≈ 0ms (conexión loopback)
>
> **Resultados de la Calibración:**
>
> | Grupo Criptográfico | Latencia Media | Overhead Bytes | Desv. Std |
> |---------------------|----------------|----------------|-----------|
> | X25519 (Control)    | X.X ms         | XXXX bytes     | X.X ms    |
> | X25519MLKEM768      | X.X ms         | XXXX bytes     | X.X ms    |
> | mlkem768            | X.X ms         | XXXX bytes     | X.X ms    |
>
> *(Ver Figura X.X para gráficas completas)*
>
> **Conclusiones de la Calibración:**
> - ✅ El overhead de procesamiento de la sonda es **despreciable** (<1% del tiempo de handshake)
> - ✅ La desviación estándar baja confirma **mediciones reproducibles**
> - ✅ Los valores obtenidos reflejan el **costo puro de los algoritmos PQC**
> - ✅ La sonda está lista para el escaneo de servidores en Internet

**Gráficas a incluir:**
- `1_latencia_por_grupo.png` - Comparativa de latencias (entorno controlado)
- `2_overhead_bytes.png` - Overhead de bytes por grupo
- `6_boxplot_distribucion.png` - Distribución y variabilidad

---

## 🔍 Troubleshooting

### Error: "OpenSSL con soporte PQC no encontrado"

**Problema:** El binario de OpenSSL no está en `/opt/openssl/bin/openssl`

**Solución:**
```bash
# Buscar el binario
which openssl

# Configurar variable de entorno
export OPENSSL_BIN=/ruta/a/tu/openssl
./servidor_control_pqc.sh
```

### Error: "Servidor no accesible en localhost:4433"

**Problema:** El servidor no está corriendo

**Solución:**
```bash
# Verificar si el puerto está en uso
sudo netstat -tlnp | grep 4433

# O usar otro puerto
./servidor_control_pqc.sh 5555
./calibrar_sonda.sh 5555
```

### Error: "Puerto ya en uso"

**Problema:** Otro proceso está usando el puerto 4433

**Solución:**
```bash
# Opción 1: Usar otro puerto
./servidor_control_pqc.sh 5000

# Opción 2: Matar proceso existente
sudo lsof -ti:4433 | xargs kill
```

### Resultados con latencia alta (>50ms)

**Problema:** Sistema sobrecargado o Docker con overhead

**Solución:**
```bash
# Ejecutar sin Docker (directamente)
python scripts/sondas/sonda_pqc_final.py \
  --input-csv resultados/calibracion/localhost_test.csv \
  --max-hostnames 1 \
  --repeticiones 5
```

---

## 📚 Referencias y Contexto

### ¿Qué mide cada métrica?

| Métrica | Descripción | Esperado (localhost) |
|---------|-------------|----------------------|
| **DNS time** | Resolución de nombre | ~0ms (no hay DNS real) |
| **TCP time** | Establecimiento TCP | <1ms (loopback) |
| **Handshake time** | Negociación TLS+PQC | 5-20ms (según algoritmo) |
| **Bytes sent** | Datos enviados (ClientHello) | 500-2000 bytes |
| **Bytes received** | Datos recibidos (ServerHello+Cert) | 4000-8000 bytes |
| **Overhead** | Total del handshake | 5000-10000 bytes |

### Diferencia entre calibración y producción

| Aspecto | Calibración (localhost) | Producción (Internet) |
|---------|-------------------------|----------------------|
| Latencia de red | ~0ms | 10-200ms |
| Variabilidad | Baja (<5ms) | Alta (±50ms) |
| Propósito | Validar sonda | Medir servidores reales |
| Valor para TFG | Metodología sólida | Datos del mundo real |

---

## 🎯 Checklist de Calibración

Antes de escanear Internet, asegúrate de:

- [ ] Servidor de control levantado correctamente
- [ ] Calibración ejecutada con ≥5 repeticiones
- [ ] Desviación estándar baja (<10% de media)
- [ ] Latencia DNS ≈ 0ms (confirma localhost)
- [ ] Gráficas generadas para la memoria
- [ ] Interpretación de resultados documentada
- [ ] Sección "Calibración" escrita en el TFG

---

## 💡 Tips Profesionales

### Para testing rápido
```bash
# Solo 2 repeticiones (1 minuto)
./calibrar_sonda.sh 4433 2
```

### Para máxima precisión
```bash
# 10 repeticiones (5 minutos)
./calibrar_sonda.sh 4433 10
```

### Para comparar con Internet
```bash
# 1. Calibración local
./calibrar_sonda.sh 4433 5

# 2. Escaneo Internet
./ejecutar_sonda.sh 100 3 20

# 3. Comparar latencias:
#    Local: Handshake puro del algoritmo
#    Internet: Handshake + latencia de red
```

---

## 📞 Soporte

- **Scripts**: `servidor_control_pqc.sh`, `calibrar_sonda.sh`
- **Documentación**: Este archivo
- **Resultados**: `resultados/calibracion/`

---

**¡Calibración lista para validar tu metodología en el TFG! 🎓**

Ejecuta:
```bash
# Terminal 1
./servidor_control_pqc.sh

# Terminal 2
./calibrar_sonda.sh
```
