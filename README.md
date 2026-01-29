# Sonda de Detección de Criptografía Post-Cuántica (PQC) 🚀

Este proyecto ha sido desarrollado como parte de un **Trabajo de Fin de Grado (TFG) en la UC3M**. Se trata de una herramienta experimental diseñada para monitorizar y analizar la adopción de algoritmos criptográficos post-cuánticos en servidores web reales.

## 📌 Objetivo
Evaluar la capacidad de los servidores actuales para negociar intercambios de claves híbridos (clásicos + cuánticos) y detectar fragmentación o problemas de interoperabilidad en la transición hacia los estándares del NIST.

## 📂 Estructura del Proyecto
* `sonda_base.py`: Realiza un análisis de línea base extrayendo suites de cifrado clásicas y datos del certificado.
* `sonda_detect_pqc.py`: Sonda avanzada que utiliza el motor de **Open Quantum Safe** para forzar handshakes PQC.
* `Dockerfile`: Automatiza la creación del entorno de laboratorio con las librerías criptográficas necesarias.
* `resultados/`: Carpeta donde se almacenan los informes técnicos en formato JSON.

## 🛠 Requisitos Previos
Es necesario tener instalado **Docker** en el sistema.

## 🚀 Instalación y Uso (Laboratorio Docker)

Para garantizar la reproducibilidad de los resultados sin alterar las librerías del sistema anfitrión, el proyecto utiliza un contenedor basado en **Open Quantum Safe (OQS)**.

### 1. Construir la imagen del laboratorio
Desde la carpeta raíz del proyecto, ejecuta:
```bash
docker build -t laboratorio_pqc .
```

### 2. Lanzar el contenedor

Montamos la carpeta actual como un volumen para que los resultados se sincronicen en tiempo real:
```
docker run -it -v "$(pwd)":/home/tfg laboratorio_pqc
```

### 3. Ejecutar las sondas (dentro del contenedor)

Una vez dentro de la terminal del contenedor, sitúate en la carpeta de trabajo:
```
cd /home/tfg

# Para un análisis estándar
python3 sonda_base.py

# Para la detección de algoritmos cuánticos (Google, Cloudflare, etc.)
python3 sonda_detect_pqc.py
```

### 📊 Interpretación de Resultados

La sonda PQC evalúa diferentes grupos de negociación. Estos son los estados posibles:
Resultado	Significado
ACEPTADO ✅	El servidor soporta el grupo híbrido (ej. p256_kyber768). Conexión segura ante ataques cuánticos.
RECHAZADO ❌	Incompatibilidad de protocolo o de versión del estándar (Draft Mismatch).

### 🧪 Detalles Técnicos

La herramienta utiliza el proveedor de OQS vinculado dinámicamente. Durante las pruebas, se ha confirmado la capacidad de negociar tráfico híbrido con éxito contra infraestructuras de producción de Google y Cloudflare.

#### Autor: Diego San Román - UC3M
