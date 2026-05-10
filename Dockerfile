# 1. Imagen base con criptografía cuántica
FROM openquantumsafe/openssl3:latest

# Etiquetas para el contenedor
LABEL maintainer="Diego TFG"
LABEL description="Sonda PQC adaptada a estructura de proyecto"

# 2. Instalar dependencias de sistema usando el OpenSSL con soporte PQC
# Usamos env -u para temporalmente desactivar LD_LIBRARY_PATH durante apk
RUN env -u LD_LIBRARY_PATH apk update && \
    env -u LD_LIBRARY_PATH apk add --no-cache \
    bash \
    python3 \
    py3-pip \
    build-base \
    musl-dev \
    python3-dev \
    git \
    ca-certificates

# 3. Configurar variables de entorno para OpenSSL-OQS con soporte PQC
ENV OPENSSL_BIN="/opt/openssl/bin/openssl"
ENV OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"
ENV LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/oqssa/lib:$LD_LIBRARY_PATH"
ENV PATH="/opt/oqssa/bin:$PATH"

# 4. Instalación de librerías Python necesarias para el proyecto
# También desactivamos LD_LIBRARY_PATH para que pip use OpenSSL estándar
RUN env -u LD_LIBRARY_PATH pip3 install --no-cache-dir --break-system-packages \
    tqdm \
    pandas \
    numpy \
    matplotlib \
    seaborn \
    scipy \
    statsmodels \
    dnspython \
    cryptography \
    scikit-learn

# 5. Preparar el entorno de trabajo
WORKDIR /app

# 6. Copiar TODO el proyecto al contenedor
# Gracias al .dockerignore, ignorará 'venv' y copiará 'scripts', 'data', etc, ignorando
# la carpeta de resultados e imágenes.
COPY . /app

# 7. Crear directorios necesarios (por seguridad)
RUN mkdir -p /app/resultados /app/logs && \
    sed -i 's/\r$//' /app/test_pipeline.sh /app/ejecutar_sonda.sh /app/ejecutar_analisis.sh && \
    chmod +x /app/test_pipeline.sh /app/ejecutar_sonda.sh /app/ejecutar_analisis.sh

# 8. Comando de arranque --> Ejecutar pipeline completo
ENTRYPOINT ["bash", "/app/test_pipeline.sh"]