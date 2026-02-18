"""
ejemplo_uso_analisis.py
-----------------------
Ejemplos de uso del script analizar_resultados.py de forma programática
(sin usar la línea de comandos).

Útil para integración con otros scripts o automatización.
"""

import sys
from pathlib import Path

# Añadir el directorio de scripts al path
sys.path.insert(0, str(Path(__file__).parent / 'ml'))

from analizar_resultados import AnalizadorResultados, (
    grafica_latencia_por_grupo,
    grafica_overhead_bytes,
    grafica_comparativa_latencia_vs_bytes,
    grafica_distribucion_por_host,
    grafica_matriz_heatmap,
    grafica_box_plot_latencia,
    grafica_tasa_exito,
    generar_reporte_texto
)


def ejemplo_1_uso_basico():
    """Ejemplo 1: Análisis básico con ubicaciones por defecto."""
    print("\n" + "="*60)
    print("EJEMPLO 1: Uso Básico")
    print("="*60)
    
    # Cargar datos
    analizador = AnalizadorResultados('resultados/resultados_sonda_pqc.json')
    
    # Obtener estadísticas
    stats = analizador.obtener_estadisticas()
    print(f"\n📊 Estadísticas:")
    print(f"  - Total de pruebas: {stats['total_pruebas']}")
    print(f"  - Tasa de éxito: {stats['tasa_exito']:.2f}%")
    print(f"  - Grupos probados: {stats['grupos_probados']}")
    
    # Generar gráficas en directorio por defecto
    output_path = Path('imagenes')
    output_path.mkdir(exist_ok=True)
    
    grafica_latencia_por_grupo(analizador.df_exitos, output_path)
    grafica_overhead_bytes(analizador.df_exitos, output_path)


def ejemplo_2_analisis_personalizado():
    """Ejemplo 2: Análisis personalizado con procesamiento adicional."""
    print("\n" + "="*60)
    print("EJEMPLO 2: Análisis Personalizado")
    print("="*60)
    
    # Cargar datos
    analizador = AnalizadorResultados('resultados/resultados_sonda_pqc.json')
    
    # Filtrar solo el grupo X25519 y variantes
    df_x25519 = analizador.df_exitos[
        analizador.df_exitos['grupo'].str.contains('X25519', na=False)
    ]
    
    print(f"\n🔐 Análisis para variantes X25519:")
    print(f"  - Pruebas encontradas: {len(df_x25519)}")
    print(f"  - Latencia promedio: {df_x25519['handshake_time_ms'].mean():.2f} ms")
    print(f"  - Overhead promedio: {df_x25519['handshake_overhead'].mean():.0f} bytes")
    
    # Estadísticas por grupo dentro de X25519
    resumen = df_x25519.groupby('grupo').agg({
        'handshake_time_ms': ['mean', 'std'],
        'handshake_overhead': ['mean'],
        'hostname': 'count'
    })
    print("\n📊 Resumen por grupo X25519:")
    print(resumen)


def ejemplo_3_comparativa_hostnames():
    """Ejemplo 3: Comparativa entre hostnames."""
    print("\n" + "="*60)
    print("EJEMPLO 3: Comparativa entre Hostnames")
    print("="*60)
    
    # Cargar datos
    analizador = AnalizadorResultados('resultados/resultados_sonda_pqc.json')
    
    # Agrupar por hostname
    print(f"\n🌐 Análisis por Hostname:")
    host_stats = analizador.df_exitos.groupby('hostname').agg({
        'handshake_time_ms': ['mean', 'count'],
        'handshake_overhead': 'mean',
        'grupo': 'nunique'
    }).round(2)
    
    print(host_stats.to_string())
    
    # Encontrar servidor más rápido
    host_mas_rapido = anadizador.df_exitos.groupby('hostname')[
        'handshake_time_ms'
    ].mean().idxmin()
    print(f"\n⚡ Servidor más rápido: {host_mas_rapido}")


def ejemplo_4_exportar_datos():
    """Ejemplo 4: Exportar datos procesados a CSV."""
    print("\n" + "="*60)
    print("EJEMPLO 4: Exportar Datos a CSV")
    print("="*60)
    
    # Cargar datos
    analizador = AnalizadorResultados('resultados/resultados_sonda_pqc.json')
    
    # Exportar conexiones exitosas
    output_csv = Path('resultados/conexiones_exitosas.csv')
    analizador.df_exitos.to_csv(output_csv, index=False)
    print(f"✓ Datos exitosos exportados a: {output_csv}")
    
    # Exportar resumen por grupo
    resumen_path = Path('resultados/resumen_grupo.csv')
    resumen = analizador.obtener_resumen_por_grupo()
    resumen.to_csv(resumen_path)
    print(f"✓ Resumen por grupo exportado a: {resumen_path}")


def ejemplo_5_generacion_completa():
    """Ejemplo 5: Generación completa de análisis (equivalent a CLI)."""
    print("\n" + "="*60)
    print("EJEMPLO 5: Generación Completa de Análisis")
    print("="*60)
    
    # Parámetros
    input_json = 'resultados/resultados_sonda_pqc.json'
    output_dir = Path('imagenes')
    
    print(f"\n📊 Generando análisis completo...")
    print(f"   Entrada: {input_json}")
    print(f"   Salida: {output_dir}")
    
    # Cargar
    analizador = AnalizadorResultados(input_json)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generar todas las gráficas
    print("\n📈 Generando gráficas...")
    grafica_latencia_por_grupo(analizador.df_exitos, output_dir)
    grafica_overhead_bytes(analizador.df_exitos, output_dir)
    grafica_comparativa_latencia_vs_bytes(analizador.df_exitos, output_dir)
    grafica_distribucion_por_host(analizador.df_exitos, output_dir)
    grafica_matriz_heatmap(analizador.df_exitos, output_dir)
    grafica_box_plot_latencia(analizador.df_exitos, output_dir)
    grafica_tasa_exito(analizador.df_resultados, output_dir)
    
    # Generar reporte
    print("\n📝 Generando reporte...")
    reporte = generar_reporte_texto(analizador, output_dir)
    print(reporte)


def ejemplo_6_filtros_avanzados():
    """Ejemplo 6: Aplicar filtros y análisis específicos."""
    print("\n" + "="*60)
    print("EJEMPLO 6: Filtros Avanzados")
    print("="*60)
    
    # Cargar datos
    analizador = AnalizadorResultados('resultados/resultados_sonda_pqc.json')
    
    # Filtro 1: Solo conexiones rápidas (< 1000ms)
    rapidas = analizador.df_exitos[analizador.df_exitos['handshake_time_ms'] < 1000]
    print(f"\n⚡ Conexiones rápidas (< 1000ms): {len(rapidas)}")
    
    # Filtro 2: Solo conexiones con bajo overhead (< 5000 bytes)
    bajo_overhead = analizador.df_exitos[
        analizador.df_exitos['handshake_overhead'] < 5000
    ]
    print(f"📉 Conexiones con bajo overhead (< 5000B): {len(bajo_overhead)}")
    
    # Filtro 3: Algoritmos post-cuánticos puros (sin hybrid)
    alg_puros = analizador.df_exitos[
        ~analizador.df_exitos['grupo'].str.contains('X25519|SecP256r1|p256', na=False)
    ]
    print(f"🔐 Algoritmos PQC puros: {len(alg_puros)}")
    
    if len(alg_puros) > 0:
        print(f"   Grupos: {alg_puros['grupo'].unique().tolist()}")
    
    # Estadísticas combinadas
    print(f"\n📊 Conexiones que cumplen TODOS los criterios:")
    combo = analizador.df_exitos[
        (analizador.df_exitos['handshake_time_ms'] < 2500) &
        (analizador.df_exitos['handshake_overhead'] < 8000)
    ]
    print(f"   Encontradas: {len(combo)}")


if __name__ == '__main__':
    print("\n" + "█"*60)
    print("█  EJEMPLOS DE USO - Análisis de Sondas PQC  " + " "*7 + "█")
    print("█"*60)
    
    try:
        # Descomentar el ejemplo que desees ejecutar:
        
        ejemplo_1_uso_basico()
        # ejemplo_2_analisis_personalizado()
        # ejemplo_3_comparativa_hostnames()
        # ejemplo_4_exportar_datos()
        # ejemplo_5_generacion_completa()
        # ejemplo_6_filtros_avanzados()
        
        print("\n" + "█"*60)
        print("✅ Ejemplos ejecutados exitosamente")
        print("█"*60 + "\n")
        
    except FileNotFoundError as e:
        print(f"\n❌ Error: Archivo no encontrado: {e}")
        print("Asegúrate de ejecutar este script desde la raíz del proyecto:")
        print("  cd /home/diego-san-roman/TFG_Diego")
        print("  python scripts/ml/ejemplo_uso_analisis.py")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
