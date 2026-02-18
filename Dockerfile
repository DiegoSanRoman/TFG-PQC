# 1. Usamos la imagen base con criptografía cuántica
FROM openquantumsafe/openssl3

# Etiquetas
LABEL maintainer="Diego TFG"
LABEL description="Sonda PQC adaptada a estructura de proyecto"

# 2. Configurar variables de entorno para OpenSSL-OQS
ENV OPENSSL_BIN="/opt/openssl/bin/openssl"
ENV LD_LIBRARY_PATH="/opt/oqssa/lib:$LD_LIBRARY_PATH"
ENV PATH="/opt/oqssa/bin:$PATH"

# 3. Instalación de dependencias de sistema (Alpine Linux)
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    build-base \
    musl-dev \
    python3-dev \
    git \
    ca-certificates

# 4. Instalación de librerías Python
# Instalamos pandas y otras librerías científicas
RUN pip3 install --no-cache-dir --break-system-packages \
    tqdm \
    requests \
    pandas \
    numpy \
    matplotlib \
    seaborn

# 5. Preparar el entorno de trabajo
WORKDIR /app

# 6. Copiar TODO tu proyecto al contenedor
# Gracias al .dockerignore, ignorará 'venv' y copiará 'scripts', 'data', etc.
COPY . /app

# 7. Crear directorios necesarios (por seguridad)
RUN mkdir -p /app/resultados /app/logs

# 8. Comando de arranque
# OJO: Aquí indicamos la ruta exacta donde está tu script 
ENTRYPOINT ["python3", "scripts/sondas/sonda_pqc_final.py"]