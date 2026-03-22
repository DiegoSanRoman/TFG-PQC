#!/usr/bin/env bash
set -euo pipefail

WITH_VOLUMES=false
ASSUME_YES=false

for arg in "$@"; do
  case "$arg" in
    --with-volumes)
      WITH_VOLUMES=true
      ;;
    -y|--yes)
      ASSUME_YES=true
      ;;
    -h|--help)
      echo "Uso: ./limpiar_docker.sh [--with-volumes] [-y|--yes]"
      echo ""
      echo "Opciones:"
      echo "  --with-volumes   También elimina volúmenes no usados (más agresivo)."
      echo "  -y, --yes        No pedir confirmación."
      echo "  -h, --help       Mostrar esta ayuda."
      exit 0
      ;;
    *)
      echo "ERROR - Opción desconocida: $arg"
      echo "Usa --help para ver opciones."
      exit 1
      ;;
  esac
done

echo "====================================================================="
echo "                    Limpieza de espacio Docker"
echo "====================================================================="
echo ""

echo "--- Estado actual de Docker:" 
docker system df

echo ""
echo "Se ejecutará:"
echo "  1) docker container prune -f"
echo "  2) docker image prune -a -f"
echo "  3) docker builder prune -a -f"
if [[ "$WITH_VOLUMES" == "true" ]]; then
  echo "  4) docker volume prune -f"
fi

echo ""
if [[ "$ASSUME_YES" != "true" ]]; then
  read -r -p "¿Continuar con la limpieza? [y/N]: " reply
  if [[ ! "$reply" =~ ^[Yy]$ ]]; then
    echo "Cancelado por el usuario."
    exit 0
  fi
fi

echo ""
echo "--- Limpiando contenedores parados..."
docker container prune -f

echo ""
echo "--- Limpiando imágenes no usadas..."
docker image prune -a -f

echo ""
echo "--- Limpiando caché de build..."
docker builder prune -a -f

if [[ "$WITH_VOLUMES" == "true" ]]; then
  echo ""
  echo "--- Limpiando volúmenes no usados..."
  docker volume prune -f
fi

echo ""
echo "--- Estado final de Docker:"
docker system df

echo ""
echo "OK - Limpieza Docker completada"
