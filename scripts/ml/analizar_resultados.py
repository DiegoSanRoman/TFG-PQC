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


def construir_dataset_justo(df, grupo_clasico='X25519'):
    """
    Construye el subconjunto justo:
    - Solo conexiones ACEPTADAS con handshake_time_ms válido.
    - Solo hostnames que aceptaron el grupo clásico y al menos un grupo no clásico.
    """
    if df.empty:
        return pd.DataFrame()

    base = df[['hostname', 'grupo', 'connection_result', 'handshake_time_ms']].copy()
    base = base[
        (base['connection_result'] == 'ACEPTADO') &
        (base['grupo'].notna()) &
        (base['handshake_time_ms'].notna())
    ]

    if base.empty:
        return pd.DataFrame()

    hosts_clasico = set(base[base['grupo'] == grupo_clasico]['hostname'].unique())
    hosts_no_clasico = set(base[base['grupo'] != grupo_clasico]['hostname'].unique())
    hosts_validos = hosts_clasico.intersection(hosts_no_clasico)

    if not hosts_validos:
        return pd.DataFrame()

    return base[base['hostname'].isin(hosts_validos)].copy()


def calcular_ranking_justo_handshake(df, grupo_clasico='X25519'):
    """
    Ranking justo de rapidez con tiempos absolutos (ms):
    - Usa solo hostnames comparables (aceptan clásico + >=1 no clásico).
    - Calcula media por (hostname, grupo).
    - Luego promedia por grupo para evitar sesgo de hostnames con más repeticiones.
    """
    df_justo = construir_dataset_justo(df, grupo_clasico=grupo_clasico)
    if df_justo.empty:
        return pd.DataFrame()

    host_group = df_justo.groupby(['hostname', 'grupo'], as_index=False)['handshake_time_ms'].mean()
    ranking = host_group.groupby('grupo').agg(
        handshake_medio_ms=('handshake_time_ms', 'mean'),
        handshake_std_ms=('handshake_time_ms', 'std'),
        hostnames=('hostname', 'nunique')
    ).reset_index()

    ranking['handshake_std_ms'] = ranking['handshake_std_ms'].fillna(0.0)
    ranking = ranking.sort_values('handshake_medio_ms', ascending=True)
    ranking['ranking_rapidez'] = np.arange(1, len(ranking) + 1)
    return ranking

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
            # Compatibilidad: usar handshake_overhead si existe, sino usar response_size_bytes
            overhead = prueba.get('handshake_overhead')
            if overhead is None:
                overhead = prueba.get('response_size_bytes')
            
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
                'handshake_overhead': overhead,
            }
            registros.append(registro)
    
    # Crear DataFrame
    df = pd.DataFrame(registros)
    
    # Convertir a numérico
    for col in ['dns_time_ms', 'tcp_time_ms', 'handshake_time_ms', 'tiempo_conexion_segundos',
                'bytes_sent', 'bytes_received', 'handshake_overhead']:
        df[col] = pd.to_numeric(df[col], errors='coerce') # coerce convierte errores a NaN

    # Métricas derivadas para análisis de conexión/TLS
    # Nota: tiempo_conexion_segundos se mide alrededor de la ejecución de OpenSSL,
    # por lo que ya excluye el pre-check DNS en la ruta normal.
    df['tiempo_total_ms'] = df['tiempo_conexion_segundos'] * 1000
    df['tiempo_conexion_sin_dns_ms'] = df['tiempo_total_ms']
    # Referencia opcional: aproximación end-to-end incluyendo DNS cuando exista.
    df['tiempo_total_con_dns_ms'] = df['tiempo_total_ms'] + df['dns_time_ms']
    
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


def remover_outliers_por_grupo(df, columnas, grupo_col='grupo', metodo='iqr', umbral_z=3, min_muestras_columna=4):
    """
    Remueve outliers por grupo para evitar sesgos entre grupos con escalas distintas.

    - Calcula umbrales por cada grupo y columna.
    - Si un grupo tiene muy pocas muestras válidas en una columna, no filtra esa columna.
    """
    df_limpio = df.copy()
    outliers_removidos = 0

    for grupo in df_limpio[grupo_col].dropna().unique():
        mask_grupo = df_limpio[grupo_col] == grupo

        for col in columnas:
            if col not in df_limpio.columns:
                continue

            valores = df_limpio.loc[mask_grupo, col].dropna()
            if len(valores) < min_muestras_columna:
                continue

            if metodo == 'iqr':
                q1 = valores.quantile(0.25)
                q3 = valores.quantile(0.75)
                iqr = q3 - q1
                lower_bound = q1 - 1.5 * iqr
                upper_bound = q3 + 1.5 * iqr
                mask_outlier = mask_grupo & df_limpio[col].notna() & ((df_limpio[col] < lower_bound) | (df_limpio[col] > upper_bound))
            elif metodo == 'zscore':
                std = valores.std()
                if std == 0 or np.isnan(std):
                    continue
                mean = valores.mean()
                z_scores = np.abs((df_limpio[col] - mean) / std)
                mask_outlier = mask_grupo & df_limpio[col].notna() & (z_scores > umbral_z)
            else:
                continue

            removidos = int(mask_outlier.sum())
            if removidos > 0:
                outliers_removidos += removidos
                logger.info(f"  {grupo} - {col}: removidos {removidos} outliers")
                df_limpio = df_limpio.loc[~mask_outlier].copy()

    logger.info(f"Total de outliers removidos (por grupo): {outliers_removidos}")
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

def graficar_latencia(df, output_dir, df_ranking=None):
    """
    Gráfica de latencia por grupo.
    Crea una figura con 4 subplots para DNS, TCP, Handshake y Tiempo Total.
    Cada subplot muestra una barra horizontal con el tiempo promedio por grupo, con barras de error para
    la desviación estándar. Los grupos se ordenan de mayor a menor latencia promedio. Se aplican colores personalizados por grupo. Se guardan las gráficas en la carpeta de salida.
    Input: DataFrame con resultados de conexiones exitosas, carpeta de salida para las gráficas.
    Output: Gráficas guardadas en la carpeta de salida.
    """
    # Crear figura con 3 subplots (sin TCP)
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle('Análisis de Latencia por Grupo Criptográfico', 
                 fontsize=16, fontweight='bold')
    
    # Handshake (ranking justo por hostname con tiempos absolutos)
    fuente_ranking = df_ranking if df_ranking is not None else df
    min_hostnames_concluyente = 30
    ranking_justo = calcular_ranking_justo_handshake(fuente_ranking, grupo_clasico='X25519')
    if not ranking_justo.empty:
        ranking_concluyente = ranking_justo[ranking_justo['hostnames'] >= min_hostnames_concluyente].copy()
        ranking_no_concluyente = ranking_justo[ranking_justo['hostnames'] < min_hostnames_concluyente].copy()

        if not ranking_concluyente.empty:
            ranking_concluyente = ranking_concluyente.sort_values('handshake_medio_ms', ascending=True)
            ranking_concluyente['ranking_rapidez'] = np.arange(1, len(ranking_concluyente) + 1)

            etiquetas = [f"{g} (hosts={n})" for g, n in zip(ranking_concluyente['grupo'], ranking_concluyente['hostnames'])]
        # Evitar que el error dibuje tiempos negativos (solo efecto visual; no hay tiempos < 0)
            err_left = np.minimum(ranking_concluyente['handshake_std_ms'].to_numpy(), ranking_concluyente['handshake_medio_ms'].to_numpy())
            err_right = ranking_concluyente['handshake_std_ms'].to_numpy()
            axes[0].barh(
                etiquetas,
                ranking_concluyente['handshake_medio_ms'],
                xerr=np.vstack([err_left, err_right]),
                color=[COLORES_GRUPOS.get(g, '#999999') for g in ranking_concluyente['grupo']],
                alpha=0.7,
                capsize=5
            )
            axes[0].set_xlabel('Tiempo (ms)', fontweight='bold')
            axes[0].set_title('Ranking justo Handshake TLS (concluyente: >=30 hosts)', fontweight='bold')
        else:
            axes[0].text(0.5, 0.5, 'Sin grupos concluyentes (>=30 hosts comparables)', ha='center', va='center', transform=axes[0].transAxes)
            axes[0].set_title('Ranking justo Handshake TLS', fontweight='bold')

        # Exportar ranking justo para auditoría (concluyente y no concluyente)
        ranking_concluyente_path = output_dir / 'ranking_justo_handshake.csv'
        ranking_concluyente.to_csv(ranking_concluyente_path, index=False)
        logger.info(f"✓ Guardado: {ranking_concluyente_path}")

        if not ranking_no_concluyente.empty:
            ranking_no_concluyente = ranking_no_concluyente.sort_values('hostnames', ascending=False).copy()
            ranking_no_concluyente['motivo'] = f'Muestra insuficiente (<{min_hostnames_concluyente} hostnames comparables)'
            ranking_no_concluyente_path = output_dir / 'ranking_justo_handshake_no_concluyente.csv'
            ranking_no_concluyente.to_csv(ranking_no_concluyente_path, index=False)
            logger.info(f"✓ Guardado: {ranking_no_concluyente_path}")
    else:
        df_hs = df.groupby('grupo')['handshake_time_ms'].agg(['mean', 'std']).sort_values('mean', ascending=False)
        axes[0].barh(df_hs.index, df_hs['mean'], xerr=df_hs['std'],
                        color=[COLORES_GRUPOS.get(g, '#999999') for g in df_hs.index], alpha=0.7, capsize=5)
        axes[0].set_xlabel('Tiempo (ms)', fontweight='bold')
        axes[0].set_title('Tiempo de Handshake TLS', fontweight='bold')
    axes[0].grid(axis='x', alpha=0.3)

    # Total sin DNS (métrica principal para conexión/TLS)
    df_sin_dns = df.groupby('grupo')['tiempo_conexion_sin_dns_ms'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1].barh(df_sin_dns.index, df_sin_dns['mean'], xerr=df_sin_dns['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_sin_dns.index], alpha=0.7, capsize=5)
    axes[1].set_xlabel('Tiempo (ms)', fontweight='bold')
    axes[1].set_title('Tiempo OpenSSL (sin precheck DNS)', fontweight='bold')
    axes[1].grid(axis='x', alpha=0.3)
    
    # Total (referencia)
    df_total = df.groupby('grupo')['tiempo_conexion_segundos'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[2].barh(df_total.index, df_total['mean'], xerr=df_total['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_total.index], alpha=0.7, capsize=5)
    axes[2].set_xlabel('Tiempo (segundos)', fontweight='bold')
    axes[2].set_title('Tiempo Total de Conexión (s)', fontweight='bold')
    axes[2].grid(axis='x', alpha=0.3)
    
    # Ajustar layout y guardar figura
    plt.tight_layout()
    output_path = output_dir / 'latencia_limpia.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"✓ Guardado: {output_path}")
    plt.close()



def graficar_bytes(df, output_dir):
    """
    Gráfica de bytes por grupo - Robusta ante datos faltantes.
    Crea una figura con 4 subplots mostrando promedios por grupo con barras de error.
    Input: DataFrame con resultados de conexiones exitosas, carpeta de salida para las gráficas
    Output: Gráficas guardadas en la carpeta de salida.
    """
    # Crear figura con 4 subplots
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Análisis de Overhead de Bytes por Grupo Criptográfico (Datos Limpios)', 
                 fontsize=16, fontweight='bold')
    
    # Bytes Sent
    if df['bytes_sent'].notna().any():
        df_sent = df[df['bytes_sent'].notna()].groupby('grupo')['bytes_sent'].agg(['mean', 'std']).sort_values('mean', ascending=False)
        if not df_sent.empty:
            axes[0, 0].barh(df_sent.index, df_sent['mean'], xerr=df_sent['std'],
                             color=[COLORES_GRUPOS.get(g, '#999999') for g in df_sent.index], alpha=0.7, capsize=5)
            axes[0, 0].set_xlabel('Bytes', fontweight='bold')
            axes[0, 0].set_title('Bytes Enviados Promedio', fontweight='bold')
            axes[0, 0].grid(axis='x', alpha=0.3)
        else:
            axes[0, 0].text(0.5, 0.5, 'Sin datos válidos', ha='center', va='center', transform=axes[0, 0].transAxes)
            axes[0, 0].set_title('Bytes Enviados Promedio', fontweight='bold')
    else:
        axes[0, 0].text(0.5, 0.5, 'Sin datos', ha='center', va='center', transform=axes[0, 0].transAxes)
        axes[0, 0].set_title('Bytes Enviados Promedio', fontweight='bold')
    
    # Bytes Received
    if df['bytes_received'].notna().any():
        df_recv = df[df['bytes_received'].notna()].groupby('grupo')['bytes_received'].agg(['mean', 'std']).sort_values('mean', ascending=False)
        if not df_recv.empty:
            axes[0, 1].barh(df_recv.index, df_recv['mean'], xerr=df_recv['std'],
                             color=[COLORES_GRUPOS.get(g, '#999999') for g in df_recv.index], alpha=0.7, capsize=5)
            axes[0, 1].set_xlabel('Bytes', fontweight='bold')
            axes[0, 1].set_title('Bytes Recibidos Promedio', fontweight='bold')
            axes[0, 1].grid(axis='x', alpha=0.3)
        else:
            axes[0, 1].text(0.5, 0.5, 'Sin datos válidos', ha='center', va='center', transform=axes[0, 1].transAxes)
            axes[0, 1].set_title('Bytes Recibidos Promedio', fontweight='bold')
    else:
        axes[0, 1].text(0.5, 0.5, 'Sin datos', ha='center', va='center', transform=axes[0, 1].transAxes)
        axes[0, 1].set_title('Bytes Recibidos Promedio', fontweight='bold')
    
    # Handshake Overhead
    if df['handshake_overhead'].notna().any():
        df_ovh = df[df['handshake_overhead'].notna()].groupby('grupo')['handshake_overhead'].agg(['mean', 'std']).sort_values('mean', ascending=False)
        if not df_ovh.empty:
            axes[1, 0].barh(df_ovh.index, df_ovh['mean'], xerr=df_ovh['std'],
                             color=[COLORES_GRUPOS.get(g, '#999999') for g in df_ovh.index], alpha=0.7, capsize=5)
            axes[1, 0].set_xlabel('Bytes', fontweight='bold')
            axes[1, 0].set_title('Overhead Total del Handshake', fontweight='bold')
            axes[1, 0].grid(axis='x', alpha=0.3)
        else:
            axes[1, 0].text(0.5, 0.5, 'Sin datos válidos', ha='center', va='center', transform=axes[1, 0].transAxes)
            axes[1, 0].set_title('Overhead Total del Handshake', fontweight='bold')
    else:
        axes[1, 0].text(0.5, 0.5, 'Sin datos', ha='center', va='center', transform=axes[1, 0].transAxes)
        axes[1, 0].set_title('Overhead Total del Handshake', fontweight='bold')
    
    # Placeholder para cuarta gráfica
    axes[1, 1].text(0.5, 0.5, 'Reservado para análisis adicional', ha='center', va='center', transform=axes[1, 1].transAxes, style='italic', color='gray')
    axes[1, 1].set_title('(Espacio reservado)', fontweight='bold')
    axes[1, 1].axis('off')
    
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
    
    # Verificar si hay datos válidos
    if df.empty or 'handshake_time_ms' not in df.columns or 'handshake_overhead' not in df.columns:
        ax.text(0.5, 0.5, 'Sin datos para scatter', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Comparativa: Latencia vs Overhead de Bytes (Datos Limpios)', fontweight='bold')
        plt.tight_layout()
        output_path = output_dir / 'scatter_limpia.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path}")
        plt.close()
        return
    
    # Filtrar solo datos válidos
    df_validos = df[(df['handshake_time_ms'].notna()) & (df['handshake_overhead'].notna())].copy()
    
    if df_validos.empty:
        ax.text(0.5, 0.5, 'Sin datos válidos para scatter', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Comparativa: Latencia vs Overhead de Bytes (Datos Limpios)', fontweight='bold')
        plt.tight_layout()
        output_path = output_dir / 'scatter_limpia.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path}")
        plt.close()
        return
    
    # Graficar por grupo
    puntos_graficados = 0
    for grupo in df_validos['grupo'].unique():
        df_grupo = df_validos[df_validos['grupo'] == grupo]
        mean_latencia = df_grupo['handshake_time_ms'].mean()
        mean_overhead = df_grupo['handshake_overhead'].mean()
        count = len(df_grupo)
        
        # Validar que sean números válidos
        if pd.notna(mean_latencia) and pd.notna(mean_overhead):
            ax.scatter(mean_latencia, mean_overhead, s=count*50, alpha=0.6, 
                      color=COLORES_GRUPOS.get(grupo, '#999999'), label=f'{grupo} (n={count})')
            puntos_graficados += 1
    
    if puntos_graficados == 0:
        ax.text(0.5, 0.5, 'No se pudieron graficar puntos', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Comparativa: Latencia vs Overhead de Bytes (Datos Limpios)', fontweight='bold')
    else:
        ax.set_xlabel('Tiempo de Handshake Promedio (ms)', fontweight='bold')
        ax.set_ylabel('Overhead del Handshake Promedio (bytes)', fontweight='bold')
        ax.set_title('Comparativa: Latencia vs Overhead de Bytes (Datos Limpios)', fontweight='bold', fontsize=12)
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
    df_exitos_ranking = df_exitos.copy()
    
    # Limpiar outliers de forma robusta por grupo (bytes + latencia sin DNS)
    logger.info("\n🧹 Limpiando outliers por grupo (latencia + bytes)...")
    columnas_outliers = [
        'tcp_time_ms',
        'handshake_time_ms',
        'tiempo_conexion_sin_dns_ms',
        'tiempo_conexion_segundos',
        'bytes_sent',
        'bytes_received',
        'handshake_overhead'
    ]
    df_exitos = remover_outliers_por_grupo(
        df_exitos,
        columnas_outliers,
        grupo_col='grupo',
        metodo='iqr',
        min_muestras_columna=4
    )
    
    # Aplicar filtro de muestras mínimas
    logger.info("\n📊 Aplicando filtro de muestras mínimas...")
    df_filtrado = filtrar_por_muestras_minimas(df_exitos, min_muestras=2)
    # df_filtrado = df_exitos.copy() # --- IGNORE ---
    
    logger.info(f"\nDatos finales para gráficas: {len(df_filtrado)} registros de {df_filtrado['grupo'].nunique()} grupos")
    
    # Generar gráficas
    logger.info("\n📈 Generando gráficas...")
    graficar_latencia(df_filtrado, OUTPUT_DIR, df_ranking=df_exitos_ranking)
    graficar_bytes(df_filtrado, OUTPUT_DIR)
    graficar_scatter(df_filtrado, OUTPUT_DIR)
    
    logger.info(f"\n✅ ¡Análisis completado! Gráficas guardadas en {OUTPUT_DIR}")

if __name__ == '__main__':
    main()
