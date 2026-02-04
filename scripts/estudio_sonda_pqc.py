import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


# ============================================
# 1. CARGA Y LIMPIEZA DE DATOS
# ============================================

def cargar_y_limpiar(ruta_csv):
    # Cargamos el CSV (formato de la sonda PQC)
    df = pd.read_csv(ruta_csv)

    # Nos quedamos con conexiones aceptadas para intentar adivinar el grupo
    df_exito = df[df["status"] == "ACEPTADO"].copy()

    if df_exito.empty:
        print("No hay suficientes datos con status 'ACEPTADO' para entrenar.")
        return None

    # Columnas relevantes para el modelo
    columnas_features = [
        "tiempo_conexion_segundos",
        "dns_time_ms",
        "tcp_time_ms",
        "handshake_time_ms",
        "ip_familia",
        "tls_version",
        "cipher_suite",
        "alpn",
        "cert_issuer",
        "response_size_bytes",
        "sni_difiere",
        "retry"
    ]

    df_ml = df_exito[columnas_features + ["grupo"]].copy()

    # Relleno de nulos: numéricos con mediana, categóricos con "desconocido"
    numeric_cols = df_ml.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        df_ml[col] = df_ml[col].fillna(df_ml[col].median())

    categorical_cols = df_ml.select_dtypes(exclude=[np.number]).columns
    for col in categorical_cols:
        df_ml[col] = df_ml[col].fillna("desconocido")

    return df_ml


# ============================================
# 2. INGENIERÍA DE CARACTERÍSTICAS (PRE-PROCESAMIENTO)
# ============================================

def preprocesar_datos(df):
    # One-hot para variables categóricas
    df_encoded = pd.get_dummies(df, columns=[
        "ip_familia",
        "tls_version",
        "cipher_suite",
        "alpn",
        "cert_issuer"
    ], drop_first=True)

    return df_encoded


# ============================================
# 3. ENTRENAMIENTO Y EVALUACIÓN
# ============================================

def ejecutar_estudio_ml(ruta_csv):
    data = cargar_y_limpiar(ruta_csv)
    if data is None:
        return

    df_modelo = preprocesar_datos(data)

    # Ver las 10 primeras filas del DataFrame procesado con todas las columnas
    print("Datos procesados para el modelo:")
    print(df_modelo.head(10))

    # Dividir características (X) y objetivo (y)
    X = df_modelo.drop(columns=["grupo"])
    y = df_modelo["grupo"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Entrenar Bosque Aleatorio
    model = RandomForestClassifier(n_estimators=200, random_state=42)
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
    importances.sort_values().tail(20).plot(kind="barh", color="skyblue")
    plt.title("Factores más influyentes para predecir el grupo PQC")
    plt.tight_layout()
    plt.savefig("importancia_features_pqc.png")

    # 2. Matriz de Confusión
    plt.figure(figsize=(10, 8))
    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    sns.heatmap(cm, annot=True, fmt="d", cmap="coolwarm",
                xticklabels=model.classes_, yticklabels=model.classes_)
    plt.title("Matriz de Confusión - Predicción del grupo PQC")
    plt.ylabel("Real")
    plt.xlabel("Predicho")
    plt.tight_layout()
    plt.savefig("confusion_matrix_pqc.png")

    print("\nGráficas guardadas como 'importancia_features_pqc.png' y 'confusion_matrix_pqc.png'")


if __name__ == "__main__":
    # Sustituye por la ruta real de tu CSV generado
    RUTA_DATOS = "ml_data/resultados_sonda_pqc_200_hostnames.csv"
    ejecutar_estudio_ml(RUTA_DATOS)