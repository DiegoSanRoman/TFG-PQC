"""
Script para convertir un archivo JSON de resultados a formato CSV, facilitando su uso en modelos de Machine Learning.
Este script toma un archivo JSON que contiene resultados y lo convierte en un archivo CSV, que puede ser utilizado para análisis posteriores.

El proceso se divide en las siguientes etapas:
1. Configuración de argumentos: Se configuran los argumentos de entrada y salida para el script, permitiendo al usuario especificar el archivo JSON de entrada y el nombre del archivo CSV de salida.
2. Conversión de datos: Se lee el archivo JSON y se convierte a un DataFrame de pandas, que luego se guarda como un archivo CSV en la carpeta "ml_data/".
3. Manejo de errores: Se capturan y manejan errores relacionados con la lectura del archivo JSON y la escritura del archivo CSV, asegurando que el script sea robusto y notifique al usuario sobre cualquier problema.

Ejemplo de uso:
python json_to_csv.py resultados/archivo.json -o ml_data/archivo.csv

Nota: Asegúrate de que el archivo JSON de entrada esté en la carpeta "resultados/" y que tengas permisos de escritura en la carpeta "ml_data/".
"""

# Importamos las librerías necesarias para la manipulación de datos, manejo de archivos y argumentos
import json
import pandas as pd
import argparse
import os
from pathlib import Path

def main():
    """
    Función principal que maneja la conversión de JSON a CSV.
    """
    
    # Configurar argparse
    parser = argparse.ArgumentParser(description='Convierte archivo JSON de resultados a CSV para ML')
    parser.add_argument('input_file', 
                        help='Nombre del archivo JSON de entrada (debe estar en la carpeta resultados/)')
    parser.add_argument('-o', '--output', 
                        help='Nombre del archivo CSV de salida (se guardará en ml_data/). Por defecto usa el nombre del input con extensión .csv')
    
    args = parser.parse_args()
    
    # Construir rutas
    base_dir = Path(__file__).parent.parent
    input_path = base_dir / 'resultados' / args.input_file
    
    # Verificar que el archivo de entrada existe
    if not input_path.exists():
        print(f"Error: El archivo {input_path} no existe")
        return
    
    # 1. Cargar el archivo JSON original
    print(f"Cargando {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Determinar nombre de salida
    if args.output:
        output_filename = args.output
    else:
        # Obtener el total_hostnames del resumen
        total_hostnames = data.get('resumen', {}).get('total_hostnames', 'unknown')
        # Usar el nombre del archivo de entrada con el total de hostnames
        base_name = Path(args.input_file).stem
        output_filename = f"{base_name}_{total_hostnames}_hostnames.csv"
    
    output_path = base_dir / 'ml_data' / output_filename
    
    # Crear la carpeta ml_data si no existe
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 2. Aplanar la lista de 'datos'
    # Comprobar si hay un campo 'pruebas' en algún registro (estructura PQC)
    if data['datos'] and isinstance(data['datos'][0].get('pruebas'), list):
        # Estructura con múltiples pruebas por hostname
        # Usar record_path para expandir el array de pruebas
        # y meta para mantener los campos del nivel superior (hostname, timestamp)
        df = pd.json_normalize(
            data['datos'],
            record_path='pruebas',
            meta=['hostname', 'timestamp'],
            sep='_'
        )
    else:
        # Estructura simple sin pruebas múltiples
        df = pd.json_normalize(data['datos'], sep='_')
    
    # 3. Guardar el resultado en un archivo CSV
    df.to_csv(output_path, index=False, encoding='utf-8')
    
    print(f"Archivo procesado correctamente: {output_path}")
    print(f"Se han generado {len(df)} filas y {len(df.columns)} columnas.")

if __name__ == '__main__':
    main()