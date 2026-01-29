# Usamos la imagen base cuántica
FROM openquantumsafe/openssl3

# Instalamos Python y las dependencias necesarias
RUN apk update && apk add python3 py3-pip
RUN pip3 install cryptography --break-system-packages

# Creamos la carpeta de trabajo
WORKDIR /home/tfg

# Exponemos las librerías cuánticas para que el sistema las vea
ENV LD_LIBRARY_PATH="/opt/openssl/lib64:$LD_LIBRARY_PATH"

# Al arrancar, el contenedor nos dejará en la terminal
CMD ["/bin/sh"]