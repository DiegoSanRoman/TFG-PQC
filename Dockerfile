# Usamos la imagen base cuántica
FROM openquantumsafe/openssl3

# Instalamos Python, compiladores y dependencias necesarias
RUN apk update && apk add \
	python3 py3-pip \
	build-base musl-dev python3-dev \
	gfortran openblas-dev lapack-dev
RUN pip3 install --no-cache-dir cryptography dnspython tqdm pandas numpy matplotlib seaborn scikit-learn --break-system-packages

# Creamos la carpeta de trabajo
WORKDIR /home/tfg

# Exponemos las librerías cuánticas para que el sistema las vea
ENV LD_LIBRARY_PATH="/opt/openssl/lib64:$LD_LIBRARY_PATH"

# Al arrancar, el contenedor nos dejará en la terminal
CMD ["/bin/sh"]