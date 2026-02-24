#!/usr/bin/env python3
"""
Script analizar_resultados.py
Analizar resultados de las pruebas de conexión TLS a los servidores PQC.
Lee el JSON generado por hostname_conexion.py, procesa los datos, limpia outliers, y genera gráficas comparativas de latencia y overhead de bytes por grupo criptográfico. 
Las gráficas se guardan en la carpeta "imagenes" y se muestran estadísticas de cada grupo. Se aplica un filtro de muestras mínimas para asegurar comparaciones significativas. Se utiliza logging para mostrar el progreso y resultados del análisis.
"""

# Importar librerías
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurar estilo
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 8)
plt.rcParams['font.size'] = 10

COLORES_GRUPOS = {
    'Automático': '#1f77b4',
    'X25519': '#ff7f0e',
    'X25519MLKEM768': '#2ca02c',
    'x25519_kyber768': '#d62728',
    'mlkem768': '#9467bd',
    'kyber768': '#8c564b',
    'p256_kyber768': '#e377c2',
    'SecP256r1MLKEM768': '#7f7f7f',
    'x25519_mlkem512': '#bcbd22',
    'x25519_kyber512': '#17becf',
    'frodo640aes': '#aec7e8',
    'bikel1': '#ffbb78',
    'x25519_bikel1': '#98df8a',
    'x25519_hqc128': '#c5b0d5',
}

# Rutas de archivos
BASE_DIR = Path(__file__).parent.parent.parent
RESULTADOS_PATH = BASE_DIR / "resultados" / "resultados_sonda_pqc.json"
OUTPUT_DIR = BASE_DIR / "imagenes"

# Funciones de análisis
def cargar_y_procesar():
    """
    Carga datos y crea DataFrame filtrado y limpio.
    Input: JSON con resultados de pruebas de conexión TLS.
    Output: DataFrame completo y DataFrame solo con conexiones exitosas.
        - Carga el JSON y extrae los datos relevantes.
        - Crea un DataFrame con columnas para hostname, grupo, resultados de conexión, tiempos y bytes.
        - Convierte columnas numéricas a tipo numérico, manejando errores.
        - Filtra el DataFrame para obtener solo las conexiones exitosas (connection_result == "ACEPTADO").
        - Muestra estadísticas básicas de los datos cargados.
    """
    logger.info(f"Cargando datos desde {RESULTADOS_PATH}")
    
    # Cargar JSON
    with RESULTADOS_PATH.open('r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extraer datos y crear DataFrame
    registros = []
    for host_data in data['datos']:
        hostname = host_data['hostname']
        for prueba in host_data['pruebas']:
            registro = {
                'hostname': hostname,
                'grupo': prueba.get('grupo'),
                'connection_result': prueba.get('connection_result'),
                'dns_time_ms': prueba.get('dns_time_ms'),
                'tcp_time_ms': prueba.get('tcp_time_ms'),
                'handshake_time_ms': prueba.get('handshake_time_ms'),
                'tiempo_conexion_segundos': prueba.get('tiempo_conexion_segundos'),
                'bytes_sent': prueba.get('bytes_sent'),
                'bytes_received': prueba.get('bytes_received'),
                'handshake_overhead': prueba.get('handshake_overhead'),
                'response_size_bytes': prueba.get('response_size_bytes'),
            }
            registros.append(registro)
    
    # Crear DataFrame
    df = pd.DataFrame(registros)
    
    # Convertir a numérico
    for col in ['dns_time_ms', 'tcp_time_ms', 'handshake_time_ms', 'tiempo_conexion_segundos',
                'bytes_sent', 'bytes_received', 'handshake_overhead', 'response_size_bytes']:
        df[col] = pd.to_numeric(df[col], errors='coerce') # coerce convierte errores a NaN
    
    # Filtrar solo exitosas
    df_exitos = df[df['connection_result'] == 'ACEPTADO'].copy()
    
    logger.info(f"Total de pruebas: {len(df)}")
    logger.info(f"Pruebas exitosas: {len(df_exitos)}")
    
    return df, df_exitos

def remover_outliers(df, columnas, metodo='iqr', umbral_z=3):
    """
    Remueve outliers usando IQR o Z-score.
    IQR: Valores fuera de [Q1 - 1.5*IQR, Q3 + 1.5*IQR] se consideran outliers.
    Z-score: Valores con |Z| > umbral_z se consideran outliers.
    
    Args:
        df: DataFrame
        columnas: lista de columnas a procesar
        metodo: 'iqr' o 'zscore'
        umbral_z: umbral de Z-score (default 3)
    """
    # Crear copia del DataFrame para no modificar el original
    df_limpio = df.copy()
    outliers_removidos = 0
    
    # Procesar cada columna
    for col in columnas:
        if col not in df_limpio.columns:
            continue
        
        # Contar valores válidos antes
        antes = df_limpio[col].notna().sum()
        
        # Método IQR
        if metodo == 'iqr':
            Q1 = df_limpio[col].quantile(0.25)
            Q3 = df_limpio[col].quantile(0.75)
            IQR = Q3 - Q1
            lower_bound = Q1 - 1.5 * IQR
            upper_bound = Q3 + 1.5 * IQR
            df_limpio = df_limpio[(df_limpio[col].isna()) | (df_limpio[col] >= lower_bound) & (df_limpio[col] <= upper_bound)]
        
        # Método Z-score
        elif metodo == 'zscore':
            z_scores = np.abs((df_limpio[col] - df_limpio[col].mean()) / df_limpio[col].std())
            df_limpio = df_limpio[(z_scores <= umbral_z) | (df_limpio[col].isna())]
        
        # Contar valores válidos después y calcular removidos
        despues = df_limpio[col].notna().sum()
        removidos = antes - despues
        if removidos > 0:
            outliers_removidos += removidos
            logger.info(f"  {col}: removidos {removidos} outliers")
    
    logger.info(f"Total de outliers removidos: {outliers_removidos}")
    return df_limpio

def filtrar_por_muestras_minimas(df, min_muestras=20):
    """
    Filtra grupos con menos de min_muestras conexiones exitosas.
    Input: DataFrame con resultados de conexiones exitosas, número mínimo de muestras por grupo.
    Output: DataFrame filtrado solo con grupos que tienen al menos min_muestras conexiones exitos
        - Cuenta el número de muestras por grupo.
        - Identifica grupos que cumplen con el mínimo de muestras y los que no.
        - Muestra estadísticas de grupos válidos y excluidos.
        - Devuelve un DataFrame filtrado solo con los grupos válidos.
    """
    # Contar muestras por grupo
    grupos_counts = df['grupo'].value_counts()
    grupos_validos = grupos_counts[grupos_counts >= min_muestras].index.tolist()
    
    logger.info(f"\nFiltro de muestras mínimas (>={min_muestras}):")
    logger.info(f"  Grupos validos: {len(grupos_validos)}")
    # Mostrar conteo de muestras por grupo válido
    for grupo in grupos_validos:
        count = grupos_counts[grupo]
        logger.info(f"    - {grupo}: {count} muestras")
    
    # Mostrar grupos excluidos
    grupos_excluidos = grupos_counts[grupos_counts < min_muestras].index.tolist()
    if grupos_excluidos:
        logger.info(f"  Grupos excluidos: {len(grupos_excluidos)}")
        for grupo in grupos_excluidos:
            count = grupos_counts[grupo]
            logger.info(f"    - {grupo}: {count} muestras (insuficientes)")
    
    return df[df['grupo'].isin(grupos_validos)].copy()

def graficar_latencia(df, output_dir):
    """
    Gráfica de latencia por grupo.
    Crea una figura con 4 subplots para DNS, TCP, Handshake y Tiempo Total.
    Cada subplot muestra una barra horizontal con el tiempo promedio por grupo, con barras de error para
    la desviación estándar. Los grupos se ordenan de mayor a menor latencia promedio. Se aplican colores personalizados por grupo. Se guardan las gráficas en la carpeta de salida.
    Input: DataFrame con resultados de conexiones exitosas, carpeta de salida para las gráficas.
    Output: Gráficas guardadas en la carpeta de salida.
    """
    # Crear figura con 4 subplots
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Análisis de Latencia por Grupo Criptográfico (Datos Limpios)', 
                 fontsize=16, fontweight='bold')
    
    # DNS
    df_dns = df.groupby('grupo')['dns_time_ms'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[0, 0].barh(df_dns.index, df_dns['mean'], xerr=df_dns['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_dns.index], alpha=0.7, capsize=5)
    axes[0, 0].set_xlabel('Tiempo (ms)', fontweight='bold')
    axes[0, 0].set_title('Tiempo de Resolución DNS', fontweight='bold')
    axes[0, 0].grid(axis='x', alpha=0.3)
    
    # TCP
    df_tcp = df.groupby('grupo')['tcp_time_ms'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[0, 1].barh(df_tcp.index, df_tcp['mean'], xerr=df_tcp['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_tcp.index], alpha=0.7, capsize=5)
    axes[0, 1].set_xlabel('Tiempo (ms)', fontweight='bold')
    axes[0, 1].set_title('Tiempo de Establecimiento TCP', fontweight='bold')
    axes[0, 1].grid(axis='x', alpha=0.3)
    
    # Handshake
    df_hs = df.groupby('grupo')['handshake_time_ms'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1, 0].barh(df_hs.index, df_hs['mean'], xerr=df_hs['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_hs.index], alpha=0.7, capsize=5)
    axes[1, 0].set_xlabel('Tiempo (ms)', fontweight='bold')
    axes[1, 0].set_title('Tiempo de Handshake TLS', fontweight='bold')
    axes[1, 0].grid(axis='x', alpha=0.3)
    
    # Total
    df_total = df.groupby('grupo')['tiempo_conexion_segundos'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1, 1].barh(df_total.index, df_total['mean'], xerr=df_total['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_total.index], alpha=0.7, capsize=5)
    axes[1, 1].set_xlabel('Tiempo (segundos)', fontweight='bold')
    axes[1, 1].set_title('Tiempo Total de Conexión', fontweight='bold')
    axes[1, 1].grid(axis='x', alpha=0.3)
    
    # Ajustar layout y guardar figura
    plt.tight_layout()
    output_path = output_dir / 'latencia_limpia.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"✓ Guardado: {output_path}")
    plt.close()

def graficar_bytes(df, output_dir):
    """
    Gráfica de bytes por grupo.
    Crea una figura con 4 subplots para Bytes Enviados, Bytes Recibidos, Overhead del Handshake y Tamaño de Respuesta.
    Cada subplot muestra una barra horizontal con el valor promedio por grupo, con barras de error para
    la desviación estándar. Los grupos se ordenan de mayor a menor valor promedio. Se aplican colores personalizados por grupo. Se guardan las gráficas en la carpeta de salida.
    Input: DataFrame con resultados de conexiones exitosas, carpeta de salida para las gráficas
    Output: Gráficas guardadas en la carpeta de salida.
    """
    # Crear figura con 4 subplotsq
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Análisis de Overhead de Bytes por Grupo Criptográfico (Datos Limpios)', 
                 fontsize=16, fontweight='bold')
    
    # Bytes Sent
    df_sent = df.groupby('grupo')['bytes_sent'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[0, 0].barh(df_sent.index, df_sent['mean'], xerr=df_sent['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_sent.index], alpha=0.7, capsize=5)
    axes[0, 0].set_xlabel('Bytes', fontweight='bold')
    axes[0, 0].set_title('Bytes Enviados Promedio', fontweight='bold')
    axes[0, 0].grid(axis='x', alpha=0.3)
    
    # Bytes Received
    df_recv = df.groupby('grupo')['bytes_received'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[0, 1].barh(df_recv.index, df_recv['mean'], xerr=df_recv['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_recv.index], alpha=0.7, capsize=5)
    axes[0, 1].set_xlabel('Bytes', fontweight='bold')
    axes[0, 1].set_title('Bytes Recibidos Promedio', fontweight='bold')
    axes[0, 1].grid(axis='x', alpha=0.3)
    
    # Handshake Overhead
    df_ovh = df.groupby('grupo')['handshake_overhead'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1, 0].barh(df_ovh.index, df_ovh['mean'], xerr=df_ovh['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_ovh.index], alpha=0.7, capsize=5)
    axes[1, 0].set_xlabel('Bytes', fontweight='bold')
    axes[1, 0].set_title('Overhead del Handshake TLS', fontweight='bold')
    axes[1, 0].grid(axis='x', alpha=0.3)
    
    # Response Size
    df_resp = df.groupby('grupo')['response_size_bytes'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1, 1].barh(df_resp.index, df_resp['mean'], xerr=df_resp['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_resp.index], alpha=0.7, capsize=5)
    axes[1, 1].set_xlabel('Bytes', fontweight='bold')
    axes[1, 1].set_title('Tamaño de la Respuesta Promedio', fontweight='bold')
    axes[1, 1].grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    output_path = output_dir / 'bytes_limpia.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"✓ Guardado: {output_path}")
    plt.close()

def graficar_scatter(df, output_dir):
    """
    Gráfica scatter: latencia vs overhead.
    Crea una gráfica scatter donde cada punto representa un grupo criptográfico, con el tiempo de handshake promedio en el eje X y el overhead de bytes promedio en el eje Y. El tamaño de cada punto refleja la cantidad de muestras para ese grupo. Se aplican colores personalizados por grupo. Se guardan las gráficas en la carpeta de salida.
    Input: DataFrame con resultados de conexiones exitosas, carpeta de salida para las gráficas
    Output: Gráficas guardadas en la carpeta de salida.
    """
    fig, ax = plt.subplots(figsize=(12, 8))
    
    for grupo in df['grupo'].unique():
        df_grupo = df[df['grupo'] == grupo]
        mean_latencia = df_grupo['handshake_time_ms'].mean()
        mean_overhead = df_grupo['handshake_overhead'].mean()
        count = len(df_grupo)
        
        ax.scatter(mean_latencia, mean_overhead, s=count*5, alpha=0.6, 
                  color=COLORES_GRUPOS.get(grupo, '#999999'), label=f'{grupo} (n={count})')
    
    ax.set_xlabel('Tiempo de Handshake Promedio (ms)', fontweight='bold')
    ax.set_ylabel('Overhead del Handshake Promedio (bytes)', fontweight='bold')
    ax.set_title('Comparativa: Latencia vs Overhead de Bytes (Datos Limpios)', fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    
    # Ajustar layout y guardar figura
    plt.tight_layout()
    output_path = output_dir / 'scatter_limpia.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"✓ Guardado: {output_path}")
    plt.close()

def main():
    # Crear carpeta de salida si no existe
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Cargar datos
    df_total, df_exitos = cargar_y_procesar()
    
    # Limpiar outliers 
    logger.info("\n🧹 Limpiando outliers de bytes...")
    df_exitos = remover_outliers(df_exitos, 
                                 ['bytes_sent', 'bytes_received', 'handshake_overhead', 'response_size_bytes'],
                                 metodo='iqr')
    
    # Aplicar filtro de muestras mínimas
    logger.info("\n📊 Aplicando filtro de muestras mínimas...")
    df_filtrado = filtrar_por_muestras_minimas(df_exitos, min_muestras=20)
    
    logger.info(f"\nDatos finales para gráficas: {len(df_filtrado)} registros de {df_filtrado['grupo'].nunique()} grupos")
    
    # Generar gráficas
    logger.info("\n📈 Generando gráficas...")
    graficar_latencia(df_filtrado, OUTPUT_DIR)
    graficar_bytes(df_filtrado, OUTPUT_DIR)
    graficar_scatter(df_filtrado, OUTPUT_DIR)
    
    logger.info(f"\n✅ ¡Análisis completado! Gráficas guardadas en {OUTPUT_DIR}")

if __name__ == '__main__':
    main()
