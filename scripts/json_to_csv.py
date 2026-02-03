import json
import pandas as pd
import argparse
import os
from pathlib import Path

def main():
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
    # json_normalize recorre la lista y crea una columna por cada campo,
    # incluso si están dentro de diccionarios anidados.
    df = pd.json_normalize(data['datos'], sep='_')
    
    # 3. Guardar el resultado en un archivo CSV
    df.to_csv(output_path, index=False, encoding='utf-8')
    
    print(f"Archivo procesado correctamente: {output_path}")
    print(f"Se han generado {len(df)} filas y {len(df.columns)} columnas.")

if __name__ == '__main__':
    main()