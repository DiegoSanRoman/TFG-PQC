import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder



# ============================================
# 1. CARGA Y LIMPIEZA DE DATOS
# ============================================

def cargar_y_limpiar(ruta_csv):
    # Cargamos el CSV (asumiendo el formato de la sonda)
    df = pd.read_csv(ruta_csv)
    
    # Solo nos interesan los escaneos exitosos para el modelo de ML
    df_exito = df[df['estado'] == 'exito'].copy()
    
    if df_exito.empty:
        print("No hay suficientes datos con estado 'exito' para entrenar.")
        return None

    # Seleccionamos columnas relevantes para el modelo
    columnas_features = [
        'datos_conexion_tiempo_conexion_segundos',
        'datos_conexion_latencia_dns_ms',
        'datos_protocolo_version',
        'datos_protocolo_bits_clave',
        'datos_protocolo_perfect_forward_secrecy',
        'datos_certificado_dias_valido',
        'datos_certificado_clave_publica_algoritmo',
        'datos_certificado_clave_publica_tamaño_bits',
        'datos_seguridad_avanzada_hsts_presente',
        'datos_seguridad_avanzada_ocsp_stapling'
    ]
    
    df_ml = df_exito[columnas_features].copy()
    
    # Manejo de valores nulos (rellenar con la mediana en numéricos)
    df_ml['datos_conexion_latencia_dns_ms'] = df_ml['datos_conexion_latencia_dns_ms'].fillna(df_ml['datos_conexion_latencia_dns_ms'].median())
    
    return df_ml



# ============================================
# 2. INGENIERÍA DE CARACTERÍSTICAS (PRE-PROCESAMIENTO)
# ============================================

def preprocesar_datos(df):
    # Convertir versión de TLS a valor numérico
    # TLSv1.3 -> 3, TLSv1.2 -> 2, etc.
    tls_map = {'TLSv1.3': 3, 'TLSv1.2': 2, 'TLSv1.1': 1, 'TLSv1.0': 0}
    df['tls_version_num'] = df['datos_protocolo_version'].map(tls_map)
    
    # Codificar variables categóricas (Algoritmo de clave pública: RSA, ECDSA...)
    le = LabelEncoder()
    df['algoritmo_enc'] = le.fit_transform(df['datos_certificado_clave_publica_algoritmo'].astype(str))
    
    # Convertir Booleanos a 0/1
    df['pfs_num'] = df['datos_protocolo_perfect_forward_secrecy'].astype(int)
    df['hsts_num'] = df['datos_seguridad_avanzada_hsts_presente'].astype(int)
    df['ocsp_num'] = df['datos_seguridad_avanzada_ocsp_stapling'].astype(int)
    
    # Definimos nuestro TARGET: "¿Es un sitio con Seguridad Moderna?"
    # Definición: Usa TLS 1.3 Y tiene HSTS activo
    df['target_seguridad_alta'] = ((df['tls_version_num'] == 3) & (df['hsts_num'] == 1)).astype(int)
    
    # Eliminamos columnas originales de texto para el modelo
    df_final = df.drop(columns=[
        'datos_protocolo_version', 
        'datos_certificado_clave_publica_algoritmo',
        'datos_protocolo_perfect_forward_secrecy',
        'datos_seguridad_avanzada_hsts_presente',
        'datos_seguridad_avanzada_ocsp_stapling'
    ])
    
    return df_final



# ============================================
# 3. ENTRENAMIENTO Y EVALUACIÓN
# ============================================

def ejecutar_estudio_ml(ruta_csv):
    data = cargar_y_limpiar(ruta_csv)
    if data is None: return
    
    df_modelo = preprocesar_datos(data)

    # Ver las 10 primeras filas del DataFrame procesado con todas las columnas
    print("Datos procesados para el modelo:")
    print(df_modelo.head(10))
    
    # Dividir características (X) y objetivo (y)
    X = df_modelo.drop(columns=['target_seguridad_alta'])
    y = df_modelo['target_seguridad_alta']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Entrenar Bosque Aleatorio
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Predicciones
    y_pred = model.predict(X_test)
    
    # Resultados
    print("\n--- REPORTE DE CLASIFICACIÓN ---")
    print(classification_report(y_test, y_pred))
    print(f"Precisión Global: {accuracy_score(y_test, y_pred):.2f}")
    
    # --- VISUALIZACIONES ---
    
    # 1. Importancia de las variables
    plt.figure(figsize=(10, 6))
    importances = pd.Series(model.feature_importances_, index=X.columns)
    importances.sort_values().plot(kind='barh', color='skyblue')
    plt.title('Factores más influyentes en la Seguridad Alta')
    plt.tight_layout()
    plt.savefig('importancia_features.png')
    
    # 2. Matriz de Correlación
    plt.figure(figsize=(10, 8))
    sns.heatmap(df_modelo.corr(), annot=True, cmap='coolwarm', fmt=".2f")
    plt.title('Correlación entre variables técnicas TLS')
    plt.tight_layout()
    plt.savefig('correlacion_tls.png')
    
    print("\nGráficas guardadas como 'importancia_features.png' y 'correlacion_tls.png'")

if __name__ == "__main__":
    # Sustituye por la ruta real de tu CSV generado
    RUTA_DATOS = "ml_data/resultados_sonda_base_100_hostnames.csv" 
    ejecutar_estudio_ml(RUTA_DATOS)