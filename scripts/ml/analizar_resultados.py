#!/usr/bin/env python3
"""
Script analizar_resultados.py
Analizar resultados de las pruebas de conexión TLS a los servidores PQC.
Lee el JSON generado por sonda_pqc_final.py, procesa los datos, limpia outliers, y genera gráficas comparativas de latencia y overhead de bytes por grupo criptográfico.
Las gráficas se guardan en la carpeta "imagenes" y se muestran estadísticas de cada grupo. Se aplica un filtro de muestras mínimas para asegurar comparaciones significativas. Se utiliza logging para mostrar el progreso y resultados del análisis.

NOTA METODOLÓGICA:
- Latencia y Bytes: Se usa mediana + IQR (Interquartile Range) para consistencia.
  Esto es robusto ante outliers (valores extremos de red).
- Media y Desv.Est. serían más sensibles a outliers, especialmente en latencias de red.
"""

# Importar librerías
import argparse
import json
import logging
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# Importar constantes compartidas desde scripts/
_SCRIPTS_DIR = Path(__file__).parent.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from constants import (          # noqa: E402
    CONNECTION_ACCEPTED,
    CONNECTION_REJECTED,
    ERROR_TLS_TIMEOUT,
    ERROR_TLS_ALERT,
)
from utils import configurar_logging      # noqa: E402

logger = logging.getLogger(__name__)

# Configurar estilo
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 8)
plt.rcParams['font.size'] = 10

COLORES_GRUPOS = {
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
MIN_MUESTRAS_ANALISIS = 30
METRICA_CONNECT_TLS_MS = 'handshake_time_ms'


def construir_dataset_justo(df, grupo_clasico='X25519'):
    """
    Construye el subconjunto justo:
    - Solo conexiones ACEPTADAS con métrica TCP+TLS de OpenSSL válida.
    - Solo hostnames que aceptaron el grupo clásico y al menos un grupo no clásico.
    """
    if df.empty:
        return pd.DataFrame()

    base = df[['hostname', 'grupo', 'connection_result', METRICA_CONNECT_TLS_MS]].copy()
    base = base[
        (base['connection_result'] == CONNECTION_ACCEPTED) &
        (base['grupo'].notna()) &
        (base[METRICA_CONNECT_TLS_MS].notna())
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

    host_group = df_justo.groupby(['hostname', 'grupo'], as_index=False)[METRICA_CONNECT_TLS_MS].mean()
    ranking = host_group.groupby('grupo').agg(
        handshake_medio_ms=(METRICA_CONNECT_TLS_MS, 'mean'),
        handshake_std_ms=(METRICA_CONNECT_TLS_MS, 'std'),
        hostnames=('hostname', 'nunique')
    ).reset_index()

    ranking['handshake_std_ms'] = ranking['handshake_std_ms'].fillna(0.0)
    ranking = ranking.sort_values('handshake_medio_ms', ascending=True)
    ranking['ranking_rapidez'] = np.arange(1, len(ranking) + 1)
    return ranking


def _agregar_por_hostname_grupo(df, metrica_col):
    """
    Agrega una métrica por (hostname, grupo) para evitar sesgo por repeticiones desbalanceadas.
    """
    base = df[
        (df['connection_result'] == CONNECTION_ACCEPTED) &
        (df['hostname'].notna()) &
        (df['grupo'].notna()) &
        (df[metrica_col].notna())
    ][['hostname', 'grupo', metrica_col]].copy()

    if base.empty:
        return pd.DataFrame(columns=['hostname', 'grupo', metrica_col])

    return base.groupby(['hostname', 'grupo'], as_index=False)[metrica_col].mean()


def resumen_justo_metrica(df, metrica_col, grupo_clasico='X25519'):
    """
    Resumen robusto absoluto (no delta) por grupo usando hostnames comparables.

    - Toma hostnames que aceptan clásico + >=1 no clásico.
    - Agrega por hostname y grupo.
    - Resume por grupo con mediana e IQR para robustez.
    """
    if df.empty or metrica_col not in df.columns:
        return pd.DataFrame()

    host_group = _agregar_por_hostname_grupo(df, metrica_col)
    if host_group.empty:
        return pd.DataFrame()

    hosts_clasico = set(host_group[host_group['grupo'] == grupo_clasico]['hostname'].unique())
    hosts_no_clasico = set(host_group[host_group['grupo'] != grupo_clasico]['hostname'].unique())
    hosts_validos = hosts_clasico.intersection(hosts_no_clasico)
    if not hosts_validos:
        return pd.DataFrame()

    host_group = host_group[host_group['hostname'].isin(hosts_validos)].copy()
    resumen = host_group.groupby('grupo').agg(
        valor_mediana_ms=(metrica_col, 'median'),
        valor_q1_ms=(metrica_col, lambda s: s.quantile(0.25)),
        valor_q3_ms=(metrica_col, lambda s: s.quantile(0.75)),
        valor_media_ms=(metrica_col, 'mean'),
        valor_std_ms=(metrica_col, 'std'),
        hostnames=('hostname', 'nunique')
    ).reset_index()

    resumen['valor_std_ms'] = resumen['valor_std_ms'].fillna(0.0)
    resumen['iqr_ms'] = resumen['valor_q3_ms'] - resumen['valor_q1_ms']
    resumen = resumen.sort_values('valor_mediana_ms', ascending=True)
    return resumen


def resumen_delta_vs_clasico(df, metrica_col, grupo_clasico='X25519'):
    """
    Resumen robusto de deltas por hostname comparable:
    delta = metrica(grupo) - metrica(grupo_clasico)

    Esto elimina gran parte del ruido de red entre hostnames y hace la comparación más justa.
    """
    if df.empty or metrica_col not in df.columns:
        return pd.DataFrame()

    host_group = _agregar_por_hostname_grupo(df, metrica_col)
    if host_group.empty:
        return pd.DataFrame()

    pivot = host_group.pivot(index='hostname', columns='grupo', values=metrica_col)
    if grupo_clasico not in pivot.columns:
        return pd.DataFrame()

    deltas = pivot.subtract(pivot[grupo_clasico], axis=0)
    deltas_long = deltas.stack().reset_index(name='delta_ms')
    deltas_long = deltas_long[deltas_long['delta_ms'].notna()].copy()
    deltas_long = deltas_long.rename(columns={'grupo': 'grupo'})

    if deltas_long.empty:
        return pd.DataFrame()

    resumen = deltas_long.groupby('grupo').agg(
        delta_mediana_ms=('delta_ms', 'median'),
        delta_q1_ms=('delta_ms', lambda s: s.quantile(0.25)),
        delta_q3_ms=('delta_ms', lambda s: s.quantile(0.75)),
        delta_media_ms=('delta_ms', 'mean'),
        delta_std_ms=('delta_ms', 'std'),
        hostnames=('hostname', 'nunique')
    ).reset_index()

    resumen['delta_std_ms'] = resumen['delta_std_ms'].fillna(0.0)
    resumen['delta_iqr_ms'] = resumen['delta_q3_ms'] - resumen['delta_q1_ms']
    resumen = resumen.sort_values('delta_mediana_ms', ascending=True)
    return resumen


def resumen_delta_vs_clasico_restringido(
    df,
    metrica_col,
    grupo_clasico='X25519',
    grupos_permitidos=None,
    hosts_permitidos=None,
    min_hostnames=0
):
    """
    Variante de delta vs clásico con filtros opcionales por grupos y cohorte de hosts.
    Permite aplicar la misma lógica de cohorte común/muestras mínimas en múltiples subgráficas.
    """
    resumen = resumen_delta_vs_clasico(df, metrica_col, grupo_clasico=grupo_clasico)
    if resumen.empty:
        return resumen

    if grupos_permitidos is not None:
        resumen = resumen[resumen['grupo'].isin(grupos_permitidos)].copy()

    if hosts_permitidos is not None:
        host_group = _agregar_por_hostname_grupo(df, metrica_col)
        if host_group.empty:
            return pd.DataFrame()
        host_group = host_group[host_group['hostname'].isin(hosts_permitidos)].copy()
        if grupos_permitidos is not None:
            host_group = host_group[host_group['grupo'].isin(grupos_permitidos)].copy()

        pivot = host_group.pivot(index='hostname', columns='grupo', values=metrica_col)
        if grupo_clasico not in pivot.columns:
            return pd.DataFrame()

        deltas = pivot.subtract(pivot[grupo_clasico], axis=0)
        deltas_long = deltas.stack().reset_index(name='delta_ms')
        deltas_long = deltas_long[deltas_long['delta_ms'].notna()].copy()
        if deltas_long.empty:
            return pd.DataFrame()

        resumen = deltas_long.groupby('grupo').agg(
            delta_mediana_ms=('delta_ms', 'median'),
            delta_q1_ms=('delta_ms', lambda s: s.quantile(0.25)),
            delta_q3_ms=('delta_ms', lambda s: s.quantile(0.75)),
            delta_media_ms=('delta_ms', 'mean'),
            delta_std_ms=('delta_ms', 'std'),
            hostnames=('hostname', 'nunique')
        ).reset_index()
        resumen['delta_std_ms'] = resumen['delta_std_ms'].fillna(0.0)
        resumen['delta_iqr_ms'] = resumen['delta_q3_ms'] - resumen['delta_q1_ms']

    if min_hostnames > 0:
        resumen = resumen[resumen['hostnames'] >= min_hostnames].copy()

    return resumen.sort_values('delta_mediana_ms', ascending=True)


def seleccionar_grupos_y_cohorte_comun(host_group, grupos_candidatos, min_hostnames, grupo_clasico='X25519'):
    """
    Selecciona un subconjunto de grupos con cohorte común >= min_hostnames.
    Estrategia: eliminar iterativamente el grupo con menos hostnames hasta cumplir.
    Siempre intenta mantener el grupo clásico.
    """
    grupos = [g for g in grupos_candidatos if g in set(host_group['grupo'].unique())]
    if grupo_clasico not in grupos:
        return [], set()

    grupos_activos = grupos.copy()

    while len(grupos_activos) >= 2:
        hosts_por_grupo = {
            grupo: set(host_group[host_group['grupo'] == grupo]['hostname'].unique())
            for grupo in grupos_activos
        }

        if not hosts_por_grupo:
            return [], set()

        hosts_comunes = set.intersection(*hosts_por_grupo.values())
        if len(hosts_comunes) >= min_hostnames:
            return grupos_activos, hosts_comunes

        candidatos_eliminar = [g for g in grupos_activos if g != grupo_clasico]
        if not candidatos_eliminar:
            break

        grupo_a_eliminar = min(candidatos_eliminar, key=lambda g: len(hosts_por_grupo[g]))
        grupos_activos.remove(grupo_a_eliminar)

    return [], set()

# Funciones de análisis
def cargar_y_procesar(input_path: Path = RESULTADOS_PATH):
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
    logger.info(f"Cargando datos desde {input_path}")

    # Cargar JSON
    with input_path.open('r', encoding='utf-8') as f:
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
                'error_category': prueba.get('error_category'),
                'retry': prueba.get('retry', False),
                'dns_time_ms': prueba.get('dns_time_ms'),
                'tcp_time_ms': prueba.get('tcp_time_ms'),
                'handshake_time_ms': prueba.get('handshake_time_ms'),
                METRICA_CONNECT_TLS_MS: prueba.get(METRICA_CONNECT_TLS_MS, prueba.get('handshake_time_ms')),
                'tiempo_conexion_segundos': prueba.get('tiempo_conexion_segundos'),
                'bytes_sent': prueba.get('bytes_sent'),
                'bytes_received': prueba.get('bytes_received'),
                'handshake_overhead': overhead,
                'handshake_total_bytes_sent': prueba.get('handshake_total_bytes_sent'),
                'handshake_total_bytes_received': prueba.get('handshake_total_bytes_received'),
                'handshake_total_overhead': prueba.get('handshake_total_overhead'),
            }
            registros.append(registro)
    
    # Crear DataFrame
    df = pd.DataFrame(registros)
    
    # Convertir a numérico
    for col in ['dns_time_ms', 'tcp_time_ms', 'handshake_time_ms', METRICA_CONNECT_TLS_MS, 'tiempo_conexion_segundos',
            'bytes_sent', 'bytes_received', 'handshake_overhead',
            'handshake_total_bytes_sent', 'handshake_total_bytes_received', 'handshake_total_overhead']:
        df[col] = pd.to_numeric(df[col], errors='coerce') # coerce convierte errores a NaN

    # Compatibilidad: asegurar que ambas columnas estén sincronizadas
    df[METRICA_CONNECT_TLS_MS] = df[METRICA_CONNECT_TLS_MS].fillna(df['handshake_time_ms'])
    df['handshake_time_ms'] = df['handshake_time_ms'].fillna(df[METRICA_CONNECT_TLS_MS])

    # Métricas derivadas para análisis de conexión/TLS
    # Nota: tiempo_conexion_segundos se mide alrededor de la ejecución de OpenSSL,
    # por lo que ya excluye el pre-check DNS en la ruta normal.
    df['tiempo_total_ms'] = df['tiempo_conexion_segundos'] * 1000
    # Nombre explícito para evitar la interpretación errónea de "total - dns"
    df['openssl_execution_time_ms'] = df['tiempo_total_ms']
    # Alias legacy (compatibilidad temporal con artefactos/scripts antiguos)
    df['tiempo_conexion_sin_dns_ms'] = df['openssl_execution_time_ms']
    # Referencia opcional: aproximación end-to-end incluyendo DNS cuando exista.
    df['tiempo_total_con_dns_ms'] = df['tiempo_total_ms'] + df['dns_time_ms']
    
    # Filtrar solo exitosas
    df_exitos = df[df['connection_result'] == CONNECTION_ACCEPTED].copy()
    
    logger.info(f"Total de pruebas: {len(df)}")
    logger.info(f"Pruebas exitosas: {len(df_exitos)}")
    
    return df, df_exitos

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

    # Limpiar artefactos legacy para mantener nombres consistentes
    for legacy_name in ['delta_open_ssl_vs_x25519.csv', 'delta_handshake_vs_x25519.csv']:
        legacy_path = output_dir / legacy_name
        if legacy_path.exists():
            legacy_path.unlink()
    
    # Handshake (ranking justo por hostname con métrica robusta)
    fuente_ranking = df_ranking if df_ranking is not None else df
    min_hostnames_concluyente = 30
    grupos_concluyentes = []
    hosts_comunes_concluyentes = set()
    ranking_justo = resumen_justo_metrica(fuente_ranking, METRICA_CONNECT_TLS_MS, grupo_clasico='X25519')
    if not ranking_justo.empty:
        ranking_concluyente = ranking_justo[ranking_justo['hostnames'] >= min_hostnames_concluyente].copy()
        ranking_no_concluyente = ranking_justo[ranking_justo['hostnames'] < min_hostnames_concluyente].copy()

        if not ranking_concluyente.empty:
            hg = _agregar_por_hostname_grupo(fuente_ranking, METRICA_CONNECT_TLS_MS)
            grupos_concluyentes, hosts_comunes_concluyentes = seleccionar_grupos_y_cohorte_comun(
                hg,
                ranking_concluyente['grupo'].tolist(),
                min_hostnames=min_hostnames_concluyente,
                grupo_clasico='X25519'
            )

            if grupos_concluyentes and len(hosts_comunes_concluyentes) >= min_hostnames_concluyente:
                hg_comun = hg[
                    hg['hostname'].isin(hosts_comunes_concluyentes) &
                    hg['grupo'].isin(grupos_concluyentes)
                ].copy()
                ranking_concluyente = hg_comun.groupby('grupo').agg(
                    valor_mediana_ms=(METRICA_CONNECT_TLS_MS, 'median'),
                    valor_q1_ms=(METRICA_CONNECT_TLS_MS, lambda s: s.quantile(0.25)),
                    valor_q3_ms=(METRICA_CONNECT_TLS_MS, lambda s: s.quantile(0.75)),
                    valor_media_ms=(METRICA_CONNECT_TLS_MS, 'mean'),
                    valor_std_ms=(METRICA_CONNECT_TLS_MS, 'std'),
                    hostnames=('hostname', 'nunique')
                ).reset_index()
                ranking_concluyente['valor_std_ms'] = ranking_concluyente['valor_std_ms'].fillna(0.0)
                ranking_concluyente['iqr_ms'] = ranking_concluyente['valor_q3_ms'] - ranking_concluyente['valor_q1_ms']
                ranking_concluyente = ranking_concluyente.sort_values('valor_mediana_ms', ascending=True)
                ranking_concluyente['ranking_rapidez'] = np.arange(1, len(ranking_concluyente) + 1)

                etiquetas = [f"{g} (hosts={n})" for g, n in zip(ranking_concluyente['grupo'], ranking_concluyente['hostnames'])]
                err_left = ranking_concluyente['valor_mediana_ms'].to_numpy() - ranking_concluyente['valor_q1_ms'].to_numpy()
                err_right = ranking_concluyente['valor_q3_ms'].to_numpy() - ranking_concluyente['valor_mediana_ms'].to_numpy()
                axes[0].barh(
                    etiquetas,
                    ranking_concluyente['valor_mediana_ms'],
                    xerr=np.vstack([err_left, err_right]),
                    color=[COLORES_GRUPOS.get(g, '#999999') for g in ranking_concluyente['grupo']],
                    alpha=0.7,
                    capsize=5
                )
                axes[0].set_xlabel('Tiempo (ms)', fontweight='bold')
                axes[0].set_title('OpenSSL TCP+TLS justo (cohorte común, mediana/IQR)', fontweight='bold')
            else:
                axes[0].text(0.5, 0.5, f'Sin cohorte común >={min_hostnames_concluyente} hosts', ha='center', va='center', transform=axes[0].transAxes)
                axes[0].set_title('OpenSSL TCP+TLS justo', fontweight='bold')
        else:
            axes[0].text(0.5, 0.5, 'Sin grupos concluyentes (>=30 hosts comparables)', ha='center', va='center', transform=axes[0].transAxes)
            axes[0].set_title('OpenSSL TCP+TLS justo', fontweight='bold')

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
        df_hs = df.groupby('grupo')[METRICA_CONNECT_TLS_MS].agg(['median', 'mean', 'std']).sort_values('median', ascending=False)
        axes[0].barh(df_hs.index, df_hs['median'], xerr=df_hs['std'],
                        color=[COLORES_GRUPOS.get(g, '#999999') for g in df_hs.index], alpha=0.7, capsize=5)
        axes[0].set_xlabel('Tiempo (ms)', fontweight='bold')
        axes[0].set_title('Tiempo OpenSSL TCP+TLS (mediana)', fontweight='bold')
    axes[0].grid(axis='x', alpha=0.3)

    # Delta robusto por hostname vs X25519 para tiempo de ejecución de OpenSSL
    # Se aplica la misma lógica de grupos concluyentes + cohorte común que en Handshake TLS justo.
    usar_cohorte_comun = bool(grupos_concluyentes) and len(hosts_comunes_concluyentes) >= min_hostnames_concluyente
    delta_sin_dns = resumen_delta_vs_clasico_restringido(
        df,
        'openssl_execution_time_ms',
        grupo_clasico='X25519',
        grupos_permitidos=grupos_concluyentes if grupos_concluyentes else None,
        hosts_permitidos=hosts_comunes_concluyentes if usar_cohorte_comun else None,
        min_hostnames=min_hostnames_concluyente if grupos_concluyentes else 0
    )
    if not delta_sin_dns.empty:
        delta_sin_dns = delta_sin_dns.sort_values('delta_mediana_ms', ascending=True)
        etiquetas = [f"{g} (hosts={n})" for g, n in zip(delta_sin_dns['grupo'], delta_sin_dns['hostnames'])]
        err_left = delta_sin_dns['delta_mediana_ms'].to_numpy() - delta_sin_dns['delta_q1_ms'].to_numpy()
        err_right = delta_sin_dns['delta_q3_ms'].to_numpy() - delta_sin_dns['delta_mediana_ms'].to_numpy()
        axes[1].barh(
            etiquetas,
            delta_sin_dns['delta_mediana_ms'],
            xerr=np.vstack([err_left, err_right]),
            color=[COLORES_GRUPOS.get(g, '#999999') for g in delta_sin_dns['grupo']],
            alpha=0.7,
            capsize=5
        )
        axes[1].axvline(0, color='black', linewidth=1, alpha=0.6)
        axes[1].set_xlabel('Δ Tiempo (ms) vs X25519', fontweight='bold')
        axes[1].set_title('OpenSSL execution time (mediana/IQR por host, vs X25519)', fontweight='bold')

        delta_sin_dns_path = output_dir / 'delta_openssl_execution_time_vs_x25519.csv'
        delta_sin_dns.to_csv(delta_sin_dns_path, index=False)
        logger.info(f"✓ Guardado: {delta_sin_dns_path}")
    else:
        axes[1].text(0.5, 0.5, 'Sin datos comparables para delta vs X25519', ha='center', va='center', transform=axes[1].transAxes)
        axes[1].set_title('OpenSSL execution time (vs X25519)', fontweight='bold')
    axes[1].grid(axis='x', alpha=0.3)

    # Delta robusto por hostname vs X25519 para OpenSSL TCP+TLS
    # Se aplica la misma lógica de grupos concluyentes + cohorte común que en OpenSSL TCP+TLS justo.
    delta_connect_tls = resumen_delta_vs_clasico_restringido(
        df,
        METRICA_CONNECT_TLS_MS,
        grupo_clasico='X25519',
        grupos_permitidos=grupos_concluyentes if grupos_concluyentes else None,
        hosts_permitidos=hosts_comunes_concluyentes if usar_cohorte_comun else None,
        min_hostnames=min_hostnames_concluyente if grupos_concluyentes else 0
    )
    if not delta_connect_tls.empty:
        delta_connect_tls = delta_connect_tls.sort_values('delta_mediana_ms', ascending=True)
        etiquetas = [f"{g} (hosts={n})" for g, n in zip(delta_connect_tls['grupo'], delta_connect_tls['hostnames'])]
        err_left = delta_connect_tls['delta_mediana_ms'].to_numpy() - delta_connect_tls['delta_q1_ms'].to_numpy()
        err_right = delta_connect_tls['delta_q3_ms'].to_numpy() - delta_connect_tls['delta_mediana_ms'].to_numpy()
        axes[2].barh(
            etiquetas,
            delta_connect_tls['delta_mediana_ms'],
            xerr=np.vstack([err_left, err_right]),
            color=[COLORES_GRUPOS.get(g, '#999999') for g in delta_connect_tls['grupo']],
            alpha=0.7,
            capsize=5
        )
        axes[2].axvline(0, color='black', linewidth=1, alpha=0.6)
        axes[2].set_xlabel('Δ Tiempo (ms) vs X25519', fontweight='bold')
        axes[2].set_title('OpenSSL TCP+TLS (Δ mediana/IQR por host, vs X25519)', fontweight='bold')

        delta_connect_tls_path = output_dir / 'delta_openssl_tcp_tls_vs_x25519.csv'
        delta_connect_tls.to_csv(delta_connect_tls_path, index=False)
        logger.info(f"✓ Guardado: {delta_connect_tls_path}")
    else:
        axes[2].text(0.5, 0.5, 'Sin datos comparables para delta vs X25519', ha='center', va='center', transform=axes[2].transAxes)
        axes[2].set_title('OpenSSL TCP+TLS (vs X25519)', fontweight='bold')
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

    # Cohorte común (metodología equivalente a latencia robusta)
    min_hostnames_concluyente = 30
    grupos_concluyentes = []
    hosts_comunes_concluyentes = set()
    metrica_cohorte = None

    for candidata in ['handshake_overhead', 'bytes_sent', 'bytes_received', 'handshake_total_overhead']:
        if candidata in df.columns and df[candidata].notna().any():
            metrica_cohorte = candidata
            break

    if metrica_cohorte:
        ranking_base = resumen_justo_metrica(df, metrica_cohorte, grupo_clasico='X25519')
        if not ranking_base.empty:
            ranking_concluyente = ranking_base[ranking_base['hostnames'] >= min_hostnames_concluyente].copy()
            if not ranking_concluyente.empty:
                hg = _agregar_por_hostname_grupo(df, metrica_cohorte)
                grupos_concluyentes, hosts_comunes_concluyentes = seleccionar_grupos_y_cohorte_comun(
                    hg,
                    ranking_concluyente['grupo'].tolist(),
                    min_hostnames=min_hostnames_concluyente,
                    grupo_clasico='X25519'
                )

    usar_cohorte_comun = bool(grupos_concluyentes) and len(hosts_comunes_concluyentes) >= min_hostnames_concluyente
    if usar_cohorte_comun:
        logger.info(
            "Bytes: usando cohorte común robusta (%d hosts, %d grupos concluyentes)",
            len(hosts_comunes_concluyentes),
            len(grupos_concluyentes)
        )
    else:
        logger.info("Bytes: sin cohorte común suficiente, usando agregación por hostname/grupo")

    def resumir_bytes_metrica(metrica_col):
        if metrica_col not in df.columns:
            return pd.DataFrame()

        base = df[df[metrica_col].notna()].copy()
        if base.empty:
            return pd.DataFrame()

        if usar_cohorte_comun:
            base = base[
                base['hostname'].isin(hosts_comunes_concluyentes) &
                base['grupo'].isin(grupos_concluyentes)
            ].copy()

        host_group = _agregar_por_hostname_grupo(base, metrica_col)
        if host_group.empty:
            return pd.DataFrame()

        # Usar mediana e IQR para consistencia metodológica con latencia (robusto ante outliers)
        resumen = host_group.groupby('grupo').agg(
            mean=(metrica_col, 'median'),
            q1=(metrica_col, lambda s: s.quantile(0.25)),
            q3=(metrica_col, lambda s: s.quantile(0.75)),
            hostnames=('hostname', 'nunique')
        ).reset_index()
        resumen['iqr'] = resumen['q3'] - resumen['q1']
        resumen = resumen.drop(columns=['q1', 'q3'])
        return resumen.sort_values('mean', ascending=False)

    sufijo_titulo = ' (cohorte común)' if usar_cohorte_comun else ' (agregado por hostname)'
    
    # Bytes Sent
    df_sent = resumir_bytes_metrica('bytes_sent')
    if not df_sent.empty:
        axes[0, 0].barh(df_sent['grupo'], df_sent['mean'], xerr=df_sent['iqr'],
                             color=[COLORES_GRUPOS.get(g, '#999999') for g in df_sent['grupo']], alpha=0.7, capsize=5)
        axes[0, 0].set_xlabel('Bytes', fontweight='bold')
        axes[0, 0].set_title(f'Bytes Enviados (Trace TLS) Promedio{sufijo_titulo}', fontweight='bold')
        axes[0, 0].grid(axis='x', alpha=0.3)
    else:
        axes[0, 0].text(0.5, 0.5, 'Sin datos', ha='center', va='center', transform=axes[0, 0].transAxes)
        axes[0, 0].set_title(f'Bytes Enviados (Trace TLS) Promedio{sufijo_titulo}', fontweight='bold')

    # Bytes Received
    df_recv = resumir_bytes_metrica('bytes_received')
    if not df_recv.empty:
        axes[0, 1].barh(df_recv['grupo'], df_recv['mean'], xerr=df_recv['iqr'],
                             color=[COLORES_GRUPOS.get(g, '#999999') for g in df_recv['grupo']], alpha=0.7, capsize=5)
        axes[0, 1].set_xlabel('Bytes', fontweight='bold')
        axes[0, 1].set_title(f'Bytes Recibidos (Trace TLS) Promedio{sufijo_titulo}', fontweight='bold')
        axes[0, 1].grid(axis='x', alpha=0.3)
    else:
        axes[0, 1].text(0.5, 0.5, 'Sin datos', ha='center', va='center', transform=axes[0, 1].transAxes)
        axes[0, 1].set_title(f'Bytes Recibidos (Trace TLS) Promedio{sufijo_titulo}', fontweight='bold')

    # Handshake Overhead
    df_ovh = resumir_bytes_metrica('handshake_overhead')
    if not df_ovh.empty:
        axes[1, 0].barh(df_ovh['grupo'], df_ovh['mean'], xerr=df_ovh['iqr'],
                             color=[COLORES_GRUPOS.get(g, '#999999') for g in df_ovh['grupo']], alpha=0.7, capsize=5)
        axes[1, 0].set_xlabel('Bytes', fontweight='bold')
        axes[1, 0].set_title(f'Overhead Handshake (Trace TLS){sufijo_titulo}', fontweight='bold')
        axes[1, 0].grid(axis='x', alpha=0.3)
    else:
        axes[1, 0].text(0.5, 0.5, 'Sin datos', ha='center', va='center', transform=axes[1, 0].transAxes)
        axes[1, 0].set_title(f'Overhead Handshake (Trace TLS){sufijo_titulo}', fontweight='bold')

    # Handshake Total real (resumen OpenSSL)
    df_ovh_total = resumir_bytes_metrica('handshake_total_overhead')
    if not df_ovh_total.empty:
        axes[1, 1].barh(df_ovh_total['grupo'], df_ovh_total['mean'], xerr=df_ovh_total['iqr'],
                             color=[COLORES_GRUPOS.get(g, '#999999') for g in df_ovh_total['grupo']], alpha=0.7, capsize=5)
        axes[1, 1].set_xlabel('Bytes', fontweight='bold')
        axes[1, 1].set_title(f'Overhead Total del Handshake (OpenSSL){sufijo_titulo}', fontweight='bold')
        axes[1, 1].grid(axis='x', alpha=0.3)
    else:
        axes[1, 1].text(0.5, 0.5, 'Sin datos de handshake total', ha='center', va='center', transform=axes[1, 1].transAxes)
        axes[1, 1].set_title(f'Overhead Total del Handshake (OpenSSL){sufijo_titulo}', fontweight='bold')
    
    plt.tight_layout()
    output_path = output_dir / 'bytes_limpia.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"✓ Guardado: {output_path}")
    plt.close()

def _bh_correction(pvalues):
    """Corrección Benjamini-Hochberg (FDR) sobre una lista de p-values."""
    n = len(pvalues)
    if n == 0:
        return []
    orden = sorted(range(n), key=lambda i: pvalues[i])
    corr = [min(pvalues[orden[j]] * n / (j + 1), 1.0) for j in range(n)]
    for j in range(n - 2, -1, -1):
        corr[j] = min(corr[j], corr[j + 1])
    resultado = [0.0] * n
    for rank, idx in enumerate(orden):
        resultado[idx] = corr[rank]
    return resultado


def calcular_significancia(df, metrica_col, grupo_clasico='X25519', alpha=0.05, min_pares=10):
    """
    Wilcoxon signed-rank pareado: para cada grupo no clásico comprueba si la
    distribución de deltas (grupo - X25519) por hostname es significativamente
    distinta de cero.

    Se usa Wilcoxon (no t-test ni Mann-Whitney) porque:
    - Los datos son pareados por hostname → control del ruido de red entre hosts.
    - Las latencias no son normales → test no paramétrico.

    Aplica corrección Benjamini-Hochberg para controlar el FDR en comparaciones múltiples.

    Devuelve DataFrame con: grupo, n_pares, delta_mediana_ms, delta_media_ms,
                             p_valor, p_valor_bh, significativo, etiqueta.
    """
    from scipy.stats import wilcoxon

    host_group = _agregar_por_hostname_grupo(df, metrica_col)
    if host_group.empty:
        return pd.DataFrame()

    pivot = host_group.pivot(index='hostname', columns='grupo', values=metrica_col)
    if grupo_clasico not in pivot.columns:
        return pd.DataFrame()

    filas = []
    for grupo in [g for g in pivot.columns if g != grupo_clasico]:
        pares = pivot[[grupo_clasico, grupo]].dropna()
        n = len(pares)
        if n < min_pares:
            logger.info("Significancia: %s omitido (solo %d pares, mínimo %d)", grupo, n, min_pares)
            continue

        deltas = pares[grupo] - pares[grupo_clasico]

        if (deltas == 0).all():
            p_val = 1.0
        else:
            try:
                _, p_val = wilcoxon(deltas, zero_method='zsplit', alternative='two-sided')
            except ValueError:
                p_val = 1.0

        filas.append({
            'grupo': grupo,
            'n_pares': n,
            'delta_mediana_ms': round(float(deltas.median()), 2),
            'delta_media_ms': round(float(deltas.mean()), 2),
            'p_valor': p_val,
        })

    if not filas:
        return pd.DataFrame()

    res = pd.DataFrame(filas)
    res['p_valor_bh'] = _bh_correction(res['p_valor'].tolist())
    res['significativo'] = res['p_valor_bh'] < alpha

    def _etiqueta(p):
        if p < 0.001:
            return '***'
        if p < 0.01:
            return '**'
        if p < 0.05:
            return '*'
        return 'ns'

    res['etiqueta'] = res['p_valor_bh'].apply(_etiqueta)
    return res.sort_values('delta_mediana_ms', ascending=True).reset_index(drop=True)


def graficar_significancia(df_sig, output_dir):
    """
    Barras horizontales de delta_mediana_ms por grupo, anotadas con la
    etiqueta de significancia (*** / ** / * / ns).

    Color:
    - Verde: delta negativo significativo (grupo PQC más rápido que X25519).
    - Rojo:  delta positivo significativo (grupo PQC más lento).
    - Gris:  no significativo.
    """
    if df_sig.empty:
        return

    fig, ax = plt.subplots(figsize=(10, max(5, len(df_sig) * 0.6)))

    colores = []
    for _, row in df_sig.iterrows():
        if not row['significativo']:
            colores.append('#aaaaaa')
        elif row['delta_mediana_ms'] < 0:
            colores.append('#2ca02c')
        else:
            colores.append('#d62728')

    etiquetas_y = [
        f"{row['grupo']}  (n={row['n_pares']})"
        for _, row in df_sig.iterrows()
    ]

    bars = ax.barh(etiquetas_y, df_sig['delta_mediana_ms'], color=colores, alpha=0.8)

    for bar, (_, row) in zip(bars, df_sig.iterrows()):
        x = bar.get_width()
        offset = max(abs(df_sig['delta_mediana_ms'].max()), 1) * 0.02
        ha = 'left' if x >= 0 else 'right'
        ax.text(x + (offset if x >= 0 else -offset), bar.get_y() + bar.get_height() / 2,
                row['etiqueta'], va='center', ha=ha, fontsize=10, fontweight='bold')

    ax.axvline(0, color='black', linewidth=1)
    ax.set_xlabel('Δ mediana handshake (ms) vs X25519', fontweight='bold')
    ax.set_title(
        'Significancia estadística del overhead de latencia PQC\n'
        'Wilcoxon signed-rank pareado + corrección Benjamini-Hochberg\n'
        '*** p<0.001  ** p<0.01  * p<0.05  ns = no significativo',
        fontweight='bold'
    )
    ax.grid(axis='x', alpha=0.3)
    plt.tight_layout()

    output_path = output_dir / 'significancia_latencia.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"✓ Guardado: {output_path}")
    plt.close()


def graficar_tasas_resultado(df_total, output_dir):
    """
    Stacked bar por algoritmo: aceptado / timeout / rechazado (TLS alert) / otro error.

    Distingue explícitamente entre dos causas de fallo muy diferentes:
    - Rechazado (TLS alert): el servidor envió handshake_failure o similar → no soporta el algoritmo.
    - Timeout (>8 s): la conexión no terminó a tiempo → puede ser latencia excesiva del intercambio
      de claves PQC, no rechazo activo. Con un timeout mayor podría funcionar.

    Esta distinción es crítica para interpretar el 0% de aceptación de algoritmos como frodo640aes
    o bikel1: si su fallo viene de timeouts, la conclusión correcta es "latencia excesiva en redes
    reales", no "el servidor rechaza estos algoritmos".
    """
    if df_total.empty or 'error_category' not in df_total.columns:
        logger.warning("Sin columna error_category en df_total; omitiendo graficar_tasas_resultado")
        return

    def _clasificar(row):
        if row['connection_result'] == CONNECTION_ACCEPTED:
            return 'Aceptado'
        if row['error_category'] == ERROR_TLS_TIMEOUT:
            return 'Timeout (>8 s)'
        if row['connection_result'] == CONNECTION_REJECTED or row['error_category'] == ERROR_TLS_ALERT:
            return 'Rechazado (TLS alert)'
        return 'Otro error'

    df = df_total[df_total['grupo'].notna()].copy()
    df['resultado_clase'] = df.apply(_clasificar, axis=1)

    totals = df.groupby('grupo').size().rename('total')
    counts = df.groupby(['grupo', 'resultado_clase']).size().rename('count').reset_index()
    counts = counts.merge(totals.reset_index(), on='grupo')
    counts['porcentaje'] = (counts['count'] / counts['total'] * 100).round(1)

    clases = ['Aceptado', 'Timeout (>8 s)', 'Rechazado (TLS alert)', 'Otro error']
    pivot = counts.pivot(index='grupo', columns='resultado_clase', values='porcentaje').fillna(0.0)
    for col in clases:
        if col not in pivot.columns:
            pivot[col] = 0.0
    pivot = pivot[clases].sort_values('Aceptado', ascending=True)

    # CSV de auditoría
    csv_path = output_dir / 'tasas_resultado_por_grupo.csv'
    pivot.reset_index().to_csv(csv_path, index=False)
    logger.info(f"✓ Guardado: {csv_path}")

    # Gráfica
    colores = ['#2ca02c', '#ff7f0e', '#d62728', '#aec7e8']
    fig, ax = plt.subplots(figsize=(12, max(6, len(pivot) * 0.65)))

    left = pd.Series(0.0, index=pivot.index)
    for clase, color in zip(clases, colores):
        ax.barh(pivot.index, pivot[clase], left=left, label=clase, color=color, alpha=0.85)
        left = left + pivot[clase]

    ax.axvline(50, color='gray', linestyle='--', linewidth=0.8, alpha=0.5)
    ax.set_xlabel('% de pruebas', fontweight='bold')
    ax.set_xlim(0, 100)
    ax.set_title(
        'Resultado por algoritmo: aceptado vs timeout vs rechazado\n'
        'Timeout ≠ rechazo activo: puede indicar overhead de red del algoritmo PQC puro',
        fontweight='bold'
    )
    ax.legend(loc='lower right', fontsize=9)
    ax.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    output_path = output_dir / 'tasas_resultado_por_grupo.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"✓ Guardado: {output_path}")
    plt.close()


def main(input_path: Path = RESULTADOS_PATH, output_dir: Path = OUTPUT_DIR):
    # Crear carpeta de salida si no existe
    output_dir.mkdir(parents=True, exist_ok=True)

    # Cargar datos
    df_total, df_exitos = cargar_y_procesar(input_path)

    # Gráfica de tasas de resultado (aceptado/timeout/rechazado/otro) usando TODOS los datos
    graficar_tasas_resultado(df_total, output_dir)

    # Filtrar conexiones que necesitaron retry (latencia inflada por timeout acumulado)
    n_antes = len(df_exitos)
    df_exitos = df_exitos[df_exitos['retry'] != True].copy()
    n_filtrados = n_antes - len(df_exitos)
    if n_filtrados > 0:
        logger.info(f"Filtrados {n_filtrados} registros con retry=True de la latencia")
    
    # Limpiar outliers de forma robusta por grupo (bytes + latencia sin DNS)
    logger.info("\n🧹 Limpiando outliers por grupo (latencia + bytes)...")
    columnas_outliers = [
        'tcp_time_ms',
        METRICA_CONNECT_TLS_MS,
        'openssl_execution_time_ms',
        'tiempo_conexion_segundos',
        'bytes_sent',
        'bytes_received',
        'handshake_overhead',
        'handshake_total_overhead'
    ]
    df_exitos = remover_outliers_por_grupo(
        df_exitos,
        columnas_outliers,
        grupo_col='grupo',
        metodo='iqr',
        min_muestras_columna=4
    )
    df_exitos_ranking = df_exitos.copy()

    # Tests de significancia estadística (Wilcoxon + BH) sobre la cohorte limpia
    logger.info("\n📐 Calculando tests de significancia estadística...")
    df_sig = calcular_significancia(df_exitos_ranking, METRICA_CONNECT_TLS_MS)
    if not df_sig.empty:
        sig_csv = output_dir / 'significancia_latencia.csv'
        df_sig.to_csv(sig_csv, index=False)
        logger.info(f"✓ Guardado: {sig_csv}")
        graficar_significancia(df_sig, output_dir)
        logger.info("\nResultados de significancia:")
        for _, row in df_sig.iterrows():
            logger.info(
                "  %-22s  Δ=%+.1f ms  p=%.4f  p_BH=%.4f  %s",
                row['grupo'], row['delta_mediana_ms'],
                row['p_valor'], row['p_valor_bh'], row['etiqueta']
            )
    else:
        logger.warning("Sin pares suficientes para tests de significancia")

    # Aplicar filtro de muestras mínimas
    logger.info("\n📊 Aplicando filtro de muestras mínimas...")
    df_filtrado = filtrar_por_muestras_minimas(df_exitos, min_muestras=MIN_MUESTRAS_ANALISIS)
    # df_filtrado = df_exitos.copy() # --- IGNORE ---
    
    logger.info(f"\nDatos finales para gráficas: {len(df_filtrado)} registros de {df_filtrado['grupo'].nunique()} grupos")
    
    # Generar gráficas
    logger.info("\n📈 Generando gráficas...")
    graficar_latencia(df_filtrado, output_dir, df_ranking=df_exitos_ranking)
    graficar_bytes(df_filtrado, output_dir)

    logger.info(f"\n✅ ¡Análisis completado! Gráficas guardadas en {output_dir}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Analiza resultados de sonda PQC y genera gráficas")
    parser.add_argument("--input",  type=Path, default=RESULTADOS_PATH, help="Ruta al JSON de resultados")
    parser.add_argument("--output", type=Path, default=OUTPUT_DIR,      help="Directorio de salida para gráficas")
    args = parser.parse_args()
    configurar_logging(BASE_DIR / "resultados" / "analizar_resultados.log", to_console=True)
    main(input_path=args.input, output_dir=args.output)
