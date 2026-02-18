"""
analizar_resultados.py
-----------------------
Script de análisis y visualización de datos de sondas PQC.
Genera gráficas que comparan el impacto en latencia y overhead de bytes
entre diferentes grupos criptográficos (híbridos y puros).

Uso:
    python analizar_resultados.py --input <ruta_json> [--output <directorio_salida>]
    
Ejemplo:
    python analizar_resultados.py --input resultados/resultados_sonda_pqc.json --output imagenes/
"""

import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import warnings

# Configurar estilo y warnings
warnings.filterwarnings('ignore')
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 8)
plt.rcParams['font.size'] = 10

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================
# CONSTANTES
# ============================================
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

METRICAS_LATENCIA = [
    'dns_time_ms',
    'tcp_time_ms',
    'handshake_time_ms',
    'tiempo_conexion_segundos'
]

METRICAS_BYTES = [
    'bytes_sent',
    'bytes_received',
    'handshake_overhead',
    'response_size_bytes'
]


# ============================================
# CLASE DE ANÁLISIS
# ============================================
class AnalizadorResultados:
    """Clase para cargar, procesar y analizar resultados de sondas PQC."""
    
    def __init__(self, ruta_json: str):
        """
        Inicializa el analizador.
        
        Args:
            ruta_json: Ruta al archivo JSON de resultados
        """
        self.ruta_json = Path(ruta_json)
        self.datos_raw = None
        self.df_resultados = None
        self.df_exitos = None
        self.resumen = None
        self._cargar_datos()
    
    def _cargar_datos(self):
        """Carga y procesa los datos del JSON."""
        try:
            logger.info(f"Cargando datos desde: {self.ruta_json}")
            
            with open(self.ruta_json, 'r', encoding='utf-8') as f:
                self.datos_raw = json.load(f)
            
            self.resumen = self.datos_raw.get('resumen', {})
            
            # Procesar los datos
            self._procesar_datos()
            
            logger.info(f"✓ Datos cargados exitosamente")
            logger.info(f"  - Total de hostnames: {len(self.df_resultados['hostname'].unique())}")
            logger.info(f"  - Total de pruebas: {len(self.df_resultados)}")
            logger.info(f"  - Pruebas exitosas: {len(self.df_exitos)}")
            
        except FileNotFoundError:
            logger.error(f"Archivo no encontrado: {self.ruta_json}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Error al decodificar JSON: {self.ruta_json}")
            raise
    
    def _procesar_datos(self):
        """Convierte los datos JSON en DataFrames de pandas."""
        registros = []
        
        for host_data in self.datos_raw.get('datos', []):
            hostname = host_data['hostname']
            
            for prueba in host_data.get('pruebas', []):
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
                    'cipher_suite': prueba.get('cipher_suite'),
                    'tls_version': prueba.get('tls_version'),
                    'error_category': prueba.get('error_category'),
                }
                registros.append(registro)
        
        self.df_resultados = pd.DataFrame(registros)
        
        # Convertir a tipos numéricos
        for col in METRICAS_LATENCIA + METRICAS_BYTES:
            self.df_resultados[col] = pd.to_numeric(self.df_resultados[col], errors='coerce')
        
        # Filtrar solo pruebas exitosas
        self.df_exitos = self.df_resultados[self.df_resultados['connection_result'] == 'ACEPTADO'].copy()
    
    def obtener_estadisticas(self) -> Dict:
        """Calcula estadísticas generales."""
        stats = {
            'total_pruebas': len(self.df_resultados),
            'pruebas_exitosas': len(self.df_exitos),
            'tasa_exito': len(self.df_exitos) / len(self.df_resultados) * 100 if len(self.df_resultados) > 0 else 0,
            'grupos_probados': self.df_resultados['grupo'].nunique(),
            'hostnames_probados': self.df_resultados['hostname'].nunique(),
            'hostnames_exitosos': self.df_exitos['hostname'].nunique() if len(self.df_exitos) > 0 else 0,
        }
        return stats
    
    def obtener_resumen_por_grupo(self) -> pd.DataFrame:
        """Calcula resumen estadístico por grupo."""
        if len(self.df_exitos) == 0:
            logger.warning("No hay pruebas exitosas para analizar")
            return pd.DataFrame()
        
        resumen = self.df_exitos.groupby('grupo').agg({
            'hostname': 'count',
            'dns_time_ms': ['mean', 'std', 'min', 'max'],
            'tcp_time_ms': ['mean', 'std', 'min', 'max'],
            'handshake_time_ms': ['mean', 'std', 'min', 'max'],
            'tiempo_conexion_segundos': ['mean', 'std'],
            'bytes_sent': ['mean', 'sum'],
            'bytes_received': ['mean', 'sum'],
            'handshake_overhead': ['mean', 'std'],
            'response_size_bytes': ['mean', 'std'],
        }).round(2)
        
        resumen.columns = ['_'.join(col).strip() for col in resumen.columns.values]
        resumen = resumen.rename(columns={'hostname_count': 'total_pruebas'})
        
        return resumen.sort_values('total_pruebas', ascending=False)


# ============================================
# FUNCIONES DE VISUALIZACIÓN
# ============================================

def grafica_latencia_por_grupo(df_exitos: pd.DataFrame, output_path: Optional[Path] = None):
    """Gráfica de latencia promedio por grupo criptográfico."""
    if len(df_exitos) == 0:
        logger.warning("No hay datos para graficar latencia")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Análisis de Latencia por Grupo Criptográfico', fontsize=16, fontweight='bold')
    
    # DNS Time
    df_dns = df_exitos.groupby('grupo')['dns_time_ms'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[0, 0].barh(df_dns.index, df_dns['mean'], xerr=df_dns['std'], 
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_dns.index], alpha=0.7, capsize=5)
    axes[0, 0].set_xlabel('Tiempo (ms)', fontweight='bold')
    axes[0, 0].set_title('Tiempo de Resolución DNS', fontweight='bold')
    axes[0, 0].grid(axis='x', alpha=0.3)
    
    # TCP Time
    df_tcp = df_exitos.groupby('grupo')['tcp_time_ms'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[0, 1].barh(df_tcp.index, df_tcp['mean'], xerr=df_tcp['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_tcp.index], alpha=0.7, capsize=5)
    axes[0, 1].set_xlabel('Tiempo (ms)', fontweight='bold')
    axes[0, 1].set_title('Tiempo de Establecimiento TCP', fontweight='bold')
    axes[0, 1].grid(axis='x', alpha=0.3)
    
    # Handshake Time
    df_hs = df_exitos.groupby('grupo')['handshake_time_ms'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1, 0].barh(df_hs.index, df_hs['mean'], xerr=df_hs['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_hs.index], alpha=0.7, capsize=5)
    axes[1, 0].set_xlabel('Tiempo (ms)', fontweight='bold')
    axes[1, 0].set_title('Tiempo de Handshake TLS', fontweight='bold')
    axes[1, 0].grid(axis='x', alpha=0.3)
    
    # Tiempo Total de Conexión
    df_total = df_exitos.groupby('grupo')['tiempo_conexion_segundos'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1, 1].barh(df_total.index, df_total['mean'], xerr=df_total['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_total.index], alpha=0.7, capsize=5)
    axes[1, 1].set_xlabel('Tiempo (segundos)', fontweight='bold')
    axes[1, 1].set_title('Tiempo Total de Conexión', fontweight='bold')
    axes[1, 1].grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path / '1_latencia_por_grupo.png', dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path / '1_latencia_por_grupo.png'}")
    else:
        plt.show()
    plt.close()


def grafica_overhead_bytes(df_exitos: pd.DataFrame, output_path: Optional[Path] = None):
    """Gráfica de overhead de bytes por grupo criptográfico."""
    if len(df_exitos) == 0:
        logger.warning("No hay datos para graficar overhead")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Análisis de Overhead de Bytes por Grupo Criptográfico', fontsize=16, fontweight='bold')
    
    # Bytes Sent
    df_sent = df_exitos.groupby('grupo')['bytes_sent'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[0, 0].barh(df_sent.index, df_sent['mean'], xerr=df_sent['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_sent.index], alpha=0.7, capsize=5)
    axes[0, 0].set_xlabel('Bytes', fontweight='bold')
    axes[0, 0].set_title('Bytes Enviados Promedio', fontweight='bold')
    axes[0, 0].grid(axis='x', alpha=0.3)
    
    # Bytes Received
    df_recv = df_exitos.groupby('grupo')['bytes_received'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[0, 1].barh(df_recv.index, df_recv['mean'], xerr=df_recv['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_recv.index], alpha=0.7, capsize=5)
    axes[0, 1].set_xlabel('Bytes', fontweight='bold')
    axes[0, 1].set_title('Bytes Recibidos Promedio', fontweight='bold')
    axes[0, 1].grid(axis='x', alpha=0.3)
    
    # Handshake Overhead
    df_ovh = df_exitos.groupby('grupo')['handshake_overhead'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1, 0].barh(df_ovh.index, df_ovh['mean'], xerr=df_ovh['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_ovh.index], alpha=0.7, capsize=5)
    axes[1, 0].set_xlabel('Bytes', fontweight='bold')
    axes[1, 0].set_title('Overhead del Handshake TLS', fontweight='bold')
    axes[1, 0].grid(axis='x', alpha=0.3)
    
    # Response Size
    df_resp = df_exitos.groupby('grupo')['response_size_bytes'].agg(['mean', 'std']).sort_values('mean', ascending=False)
    axes[1, 1].barh(df_resp.index, df_resp['mean'], xerr=df_resp['std'],
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in df_resp.index], alpha=0.7, capsize=5)
    axes[1, 1].set_xlabel('Bytes', fontweight='bold')
    axes[1, 1].set_title('Tamaño de la Respuesta Promedio', fontweight='bold')
    axes[1, 1].grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path / '2_overhead_bytes.png', dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path / '2_overhead_bytes.png'}")
    else:
        plt.show()
    plt.close()


def grafica_comparativa_latencia_vs_bytes(df_exitos: pd.DataFrame, output_path: Optional[Path] = None):
    """Gráfica de scatter comparando latencia vs overhead de bytes."""
    if len(df_exitos) == 0:
        logger.warning("No hay datos para gráfica comparativa")
        return
    
    fig, ax = plt.subplots(figsize=(14, 9))
    
    # Calcular medias por grupo
    resumen_grupos = df_exitos.groupby('grupo').agg({
        'handshake_time_ms': 'mean',
        'handshake_overhead': 'mean',
        'hostname': 'count'
    }).reset_index()
    
    # Scatter plot
    for grupo in resumen_grupos['grupo']:
        datos_grupo = resumen_grupos[resumen_grupos['grupo'] == grupo]
        ax.scatter(datos_grupo['handshake_time_ms'], 
                  datos_grupo['handshake_overhead'],
                  s=300, 
                  alpha=0.6,
                  color=COLORES_GRUPOS.get(grupo, '#999999'),
                  label=grupo,
                  edgecolors='black',
                  linewidth=1.5)
        
        # Añadir etiqueta del grupo
        ax.annotate(grupo, 
                   (datos_grupo['handshake_time_ms'].values[0], 
                    datos_grupo['handshake_overhead'].values[0]),
                   fontsize=9,
                   alpha=0.7,
                   xytext=(5, 5),
                   textcoords='offset points')
    
    ax.set_xlabel('Tiempo de Handshake Promedio (ms)', fontweight='bold', fontsize=12)
    ax.set_ylabel('Overhead del Handshake Promedio (bytes)', fontweight='bold', fontsize=12)
    ax.set_title('Comparativa: Latencia vs Overhead de Bytes', fontweight='bold', fontsize=14)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path / '3_latencia_vs_bytes.png', dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path / '3_latencia_vs_bytes.png'}")
    else:
        plt.show()
    plt.close()


def grafica_distribucion_por_host(df_exitos: pd.DataFrame, output_path: Optional[Path] = None):
    """Gráfica de distribución de latencia y bytes por hostname."""
    if len(df_exitos) == 0:
        logger.warning("No hay datos para gráfica de distribución")
        return
    
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle('Distribución por Hostname (Conexiones Exitosas)', fontsize=14, fontweight='bold')
    
    # Latencia por hostname
    df_lat_host = df_exitos.groupby('hostname')['handshake_time_ms'].mean().sort_values(ascending=False)
    axes[0].barh(df_lat_host.index, df_lat_host.values, color='steelblue', alpha=0.7)
    axes[0].set_xlabel('Tiempo de Handshake (ms)', fontweight='bold')
    axes[0].set_title('Latencia Promedio por Hostname', fontweight='bold')
    axes[0].grid(axis='x', alpha=0.3)
    
    # Overhead por hostname
    df_ovh_host = df_exitos.groupby('hostname')['handshake_overhead'].mean().sort_values(ascending=False)
    axes[1].barh(df_ovh_host.index, df_ovh_host.values, color='coral', alpha=0.7)
    axes[1].set_xlabel('Overhead de Bytes', fontweight='bold')
    axes[1].set_title('Overhead Promedio por Hostname', fontweight='bold')
    axes[1].grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path / '4_distribucion_por_host.png', dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path / '4_distribucion_por_host.png'}")
    else:
        plt.show()
    plt.close()


def grafica_matriz_heatmap(df_exitos: pd.DataFrame, output_path: Optional[Path] = None):
    """Heatmap de latencia promedio entre hostnames y grupos."""
    if len(df_exitos) == 0:
        logger.warning("No hay datos para heatmap")
        return
    
    # Crear matriz de pivot
    matriz = df_exitos.pivot_table(
        values='handshake_time_ms',
        index='hostname',
        columns='grupo',
        aggfunc='mean'
    )
    
    fig, ax = plt.subplots(figsize=(16, 10))
    
    sns.heatmap(matriz, 
                cmap='YlOrRd', 
                annot=True, 
                fmt='.0f',
                cbar_kws={'label': 'Latencia (ms)'},
                ax=ax,
                linewidths=0.5,
                linecolor='gray')
    
    ax.set_title('Matriz de Latencia: Hostnames vs Grupos Criptográficos', 
                 fontweight='bold', fontsize=14, pad=20)
    ax.set_xlabel('Grupo Criptográfico', fontweight='bold')
    ax.set_ylabel('Hostname', fontweight='bold')
    
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path / '5_heatmap_latencia.png', dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path / '5_heatmap_latencia.png'}")
    else:
        plt.show()
    plt.close()


def grafica_box_plot_latencia(df_exitos: pd.DataFrame, output_path: Optional[Path] = None):
    """Box plot de distribución de latencias por grupo."""
    if len(df_exitos) == 0:
        logger.warning("No hay datos para box plot")
        return
    
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.suptitle('Distribución de Latencias por Grupo', fontsize=14, fontweight='bold')
    
    # Preparar datos ordenados
    orden_grupos = df_exitos.groupby('grupo')['handshake_time_ms'].median().sort_values().index.tolist()
    
    # Box plot - Handshake Time
    sns.boxplot(data=df_exitos, y='grupo', x='handshake_time_ms', 
                order=orden_grupos, ax=axes[0], palette=COLORES_GRUPOS)
    axes[0].set_xlabel('Tiempo de Handshake (ms)', fontweight='bold')
    axes[0].set_ylabel('Grupo Criptográfico', fontweight='bold')
    axes[0].set_title('Box Plot: Handshake Time', fontweight='bold')
    axes[0].grid(axis='x', alpha=0.3)
    
    # Box plot - Overhead
    orden_grupos_ovh = df_exitos.groupby('grupo')['handshake_overhead'].median().sort_values().index.tolist()
    sns.boxplot(data=df_exitos, y='grupo', x='handshake_overhead',
                order=orden_grupos_ovh, ax=axes[1], palette=COLORES_GRUPOS)
    axes[1].set_xlabel('Overhead del Handshake (bytes)', fontweight='bold')
    axes[1].set_ylabel('Grupo Criptográfico', fontweight='bold')
    axes[1].set_title('Box Plot: Handshake Overhead', fontweight='bold')
    axes[1].grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path / '6_boxplot_distribucion.png', dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path / '6_boxplot_distribucion.png'}")
    else:
        plt.show()
    plt.close()


def grafica_tasa_exito(df_resultados: pd.DataFrame, output_path: Optional[Path] = None):
    """Gráfica de tasa de éxito por grupo."""
    if len(df_resultados) == 0:
        logger.warning("No hay datos para gráfica de tasa de éxito")
        return
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    # Calcular tasa de éxito por grupo
    tasas = df_resultados.groupby('grupo').apply(
        lambda x: (x['connection_result'] == 'ACEPTADO').sum() / len(x) * 100
    ).sort_values(ascending=False)
    
    # Gráfica de barras
    barras = ax.barh(tasas.index, tasas.values, 
                     color=[COLORES_GRUPOS.get(g, '#999999') for g in tasas.index],
                     alpha=0.7, edgecolor='black', linewidth=1.5)
    
    # Añadir porcentajes en las barras
    for i, (grupo, valor) in enumerate(tasas.items()):
        ax.text(valor + 1, i, f'{valor:.1f}%', va='center', fontweight='bold')
    
    ax.set_xlabel('Tasa de Éxito (%)', fontweight='bold', fontsize=12)
    ax.set_ylabel('Grupo Criptográfico', fontweight='bold', fontsize=12)
    ax.set_title('Tasa de Éxito de Conexión por Grupo', fontweight='bold', fontsize=14)
    ax.set_xlim(0, 105)
    ax.grid(axis='x', alpha=0.3)
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path / '7_tasa_exito.png', dpi=300, bbox_inches='tight')
        logger.info(f"✓ Guardado: {output_path / '7_tasa_exito.png'}")
    else:
        plt.show()
    plt.close()


def generar_reporte_texto(analizador: AnalizadorResultados, output_path: Optional[Path] = None) -> str:
    """Genera un reporte en texto con estadísticas."""
    stats = analizador.obtener_estadisticas()
    resumen_grupo = analizador.obtener_resumen_por_grupo()
    
    reporte = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║           REPORTE DE ANÁLISIS DE SONDAS PQC (POST-QUANTUM)                ║
╚════════════════════════════════════════════════════════════════════════════╝

📊 ESTADÍSTICAS GENERALES
─────────────────────────────────────────────────────────────────────────────
  • Total de pruebas: {stats['total_pruebas']}
  • Pruebas exitosas: {stats['pruebas_exitosas']}
  • Tasa de éxito general: {stats['tasa_exito']:.2f}%
  • Grupos criptográficos probados: {stats['grupos_probados']}
  • Hostnames probados: {stats['hostnames_probados']}
  • Hostnames con al menos 1 éxito: {stats['hostnames_exitosos']}

🔐 RESUMEN POR GRUPO CRIPTOGRÁFICO
─────────────────────────────────────────────────────────────────────────────
"""
    
    if not resumen_grupo.empty:
        reporte += resumen_grupo.to_string()
    else:
        reporte += "No hay datos disponibles"
    
    reporte += f"""

⏱️  ANÁLISIS DE LATENCIA (Conexiones Exitosas)
─────────────────────────────────────────────────────────────────────────────
"""
    
    if len(analizador.df_exitos) > 0:
        lat_summary = analizador.df_exitos.groupby('grupo').agg({
            'handshake_time_ms': ['mean', 'min', 'max'],
            'tiempo_conexion_segundos': 'mean'
        }).round(2)
        reporte += lat_summary.to_string()
    
    reporte += f"""

📦 ANÁLISIS DE BYTES (Conexiones Exitosas)
─────────────────────────────────────────────────────────────────────────────
"""
    
    if len(analizador.df_exitos) > 0:
        bytes_summary = analizador.df_exitos.groupby('grupo').agg({
            'bytes_sent': 'mean',
            'bytes_received': 'mean',
            'handshake_overhead': 'mean'
        }).round(2)
        reporte += bytes_summary.to_string()
    
    reporte += f"""

🎯 INSIGHTS Y CONCLUSIONES
─────────────────────────────────────────────────────────────────────────────
"""
    
    if len(analizador.df_exitos) > 0:
        grupo_mas_rapido = analizador.df_exitos.groupby('grupo')['handshake_time_ms'].mean().idxmin()
        grupo_mas_lento = analizador.df_exitos.groupby('grupo')['handshake_time_ms'].mean().idxmax()
        grupo_menos_overhead = analizador.df_exitos.groupby('grupo')['handshake_overhead'].mean().idxmin()
        grupo_mas_overhead = analizador.df_exitos.groupby('grupo')['handshake_overhead'].mean().idxmax()
        
        lat_rapido = analizador.df_exitos.groupby('grupo')['handshake_time_ms'].mean()[grupo_mas_rapido]
        lat_lento = analizador.df_exitos.groupby('grupo')['handshake_time_ms'].mean()[grupo_mas_lento]
        overhead_min = analizador.df_exitos.groupby('grupo')['handshake_overhead'].mean()[grupo_menos_overhead]
        overhead_max = analizador.df_exitos.groupby('grupo')['handshake_overhead'].mean()[grupo_mas_overhead]
        
        reporte += f"""
  ⚡ Grupo más rápido: {grupo_mas_rapido} ({lat_rapido:.2f} ms)
  🐢 Grupo más lento: {grupo_mas_lento} ({lat_lento:.2f} ms)
  📉 Grupo con menor overhead: {grupo_menos_overhead} ({overhead_min:.0f} bytes)
  📈 Grupo con mayor overhead: {grupo_mas_overhead} ({overhead_max:.0f} bytes)
  
  Ratio latencia: {lat_lento/lat_rapido:.2f}x (El más lento es {lat_lento/lat_rapido:.2f} veces más lento)
  Ratio overhead: {overhead_max/overhead_min:.2f}x (El mayor tiene {overhead_max/overhead_min:.2f} veces más overhead)
"""
    
    reporte += f"""

📅 Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚════════════════════════════════════════════════════════════════════════════╝
"""
    
    if output_path:
        reporte_path = output_path / 'reporte_analisis.txt'
        with open(reporte_path, 'w', encoding='utf-8') as f:
            f.write(reporte)
        logger.info(f"✓ Guardado: {reporte_path}")
    
    return reporte


# ============================================
# FUNCIÓN PRINCIPAL
# ============================================

def main():
    """Función principal."""
    parser = argparse.ArgumentParser(
        description='Analiza resultados de sondas PQC y genera gráficas de latencia y overhead.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python analizar_resultados.py --input resultados/resultados_sonda_pqc.json
  python analizar_resultados.py --input resultados/resultados_sonda_pqc.json --output imagenes/
        """
    )
    
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Ruta al archivo JSON de resultados de la sonda'
    )
    
    parser.add_argument(
        '--output', '-o',
        default=None,
        help='Directorio de salida para las gráficas (default: imagenes/)'
    )
    
    parser.add_argument(
        '--no-show',
        action='store_true',
        help='No mostrar las gráficas, solo guardarlas'
    )
    
    args = parser.parse_args()
    
    # Determinar ruta de salida
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(__file__).parent.parent.parent / 'imagenes'
    
    # Crear directorio de salida si no existe
    output_path.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"📊 Inicializando análisis de resultados...")
    logger.info(f"   Entrada: {args.input}")
    logger.info(f"   Salida: {output_path}")
    
    try:
        # Cargar datos
        analizador = AnalizadorResultados(args.input)
        
        # Mostrar estadísticas
        stats = analizador.obtener_estadisticas()
        logger.info(f"\n📈 Estadísticas generales:")
        logger.info(f"   - Tasa de éxito: {stats['tasa_exito']:.2f}%")
        logger.info(f"   - Grupos probados: {stats['grupos_probados']}")
        logger.info(f"   - Hostnames exitosos: {stats['hostnames_exitosos']}/{stats['hostnames_probados']}")
        
        # Generar gráficas
        logger.info(f"\n📊 Generando gráficas...")
        
        grafica_latencia_por_grupo(analizador.df_exitos, output_path)
        grafica_overhead_bytes(analizador.df_exitos, output_path)
        grafica_comparativa_latencia_vs_bytes(analizador.df_exitos, output_path)
        grafica_distribucion_por_host(analizador.df_exitos, output_path)
        grafica_matriz_heatmap(analizador.df_exitos, output_path)
        grafica_box_plot_latencia(analizador.df_exitos, output_path)
        grafica_tasa_exito(analizador.df_resultados, output_path)
        
        # Generar reporte de texto
        logger.info(f"\n📝 Generando reporte de texto...")
        reporte = generar_reporte_texto(analizador, output_path)
        
        # Mostrar reporte
        print(reporte)
        
        logger.info(f"\n✅ ¡Análisis completado exitosamente!")
        logger.info(f"   Se han generado 8 gráficas y 1 reporte en: {output_path}")
        
    except Exception as e:
        logger.error(f"❌ Error durante el análisis: {str(e)}")
        raise


if __name__ == '__main__':
    main()
