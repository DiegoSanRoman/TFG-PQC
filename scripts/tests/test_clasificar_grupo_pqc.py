"""
test_clasificar_grupo_pqc.py
----------------------------
Tests unitarios para scripts/ml/clasificar_grupo_pqc.py.

Cubre funciones puras y comportamiento observable sin I/O de red ni ficheros reales:
  cargar_datos, split_train_test, evaluar_experimento,
  GRUPOS_VIABLES, EXPERIMENTOS, LABEL_MAP,
  graficar_* (smoke tests con datos mínimos).
"""

import json
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.preprocessing import LabelEncoder

from clasificar_grupo_pqc import (
    EXPERIMENTOS,
    GRUPOS_VIABLES,
    LABEL_MAP,
    cargar_datos,
    evaluar_experimento,
    split_train_test,
)

# ---------------------------------------------------------------------------
# Helpers de fixture
# ---------------------------------------------------------------------------

ALL_FEATURES = [
    "dns_time_ms", "openssl_execution_time_ms",
    "bytes_sent", "bytes_received", "handshake_overhead",
    "handshake_total_bytes_sent", "handshake_total_bytes_received",
    "handshake_total_overhead",
]

GRUPOS_LIST = sorted(GRUPOS_VIABLES)


def _fila(hostname: str, grupo: str, seed: int = 0) -> dict:
    """Genera una fila de métricas sintéticas deterministas."""
    rng = np.random.default_rng(seed)
    base_bytes = 350 if grupo == "X25519" else 1500
    return {
        "hostname":                       hostname,
        "grupo":                          grupo,
        "dns_time_ms":                    float(rng.integers(5, 50)),
        "openssl_execution_time_ms":      float(rng.integers(30, 200)),
        "bytes_sent":                     base_bytes + int(rng.integers(0, 50)),
        "bytes_received":                 base_bytes // 3 + int(rng.integers(0, 30)),
        "handshake_overhead":             base_bytes + base_bytes // 3 + int(rng.integers(0, 80)),
        "handshake_total_bytes_sent":     base_bytes + int(rng.integers(50, 200)),
        "handshake_total_bytes_received": base_bytes * 3 + int(rng.integers(100, 500)),
        "handshake_total_overhead":       base_bytes * 4 + int(rng.integers(150, 700)),
        "grupo_label":                    LABEL_MAP.get(grupo, grupo),
    }


def _df_sintetico(n_hosts_por_grupo: int = 20) -> pd.DataFrame:
    """
    Crea un DataFrame sintético con n_hosts_por_grupo hostnames por grupo.
    Cada hostname tiene exactamente un registro (un grupo).
    """
    filas = []
    host_idx = 0
    for grupo in GRUPOS_LIST:
        for i in range(n_hosts_por_grupo):
            hostname = f"host{host_idx:04d}.example.com"
            filas.append(_fila(hostname, grupo, seed=host_idx))
            host_idx += 1
    return pd.DataFrame(filas)


def _json_minimo(n_hosts_por_grupo: int = 5) -> dict:
    """
    Crea la estructura JSON mínima que espera cargar_datos.
    Incluye registros ACEPTADO de grupos viables y RECHAZADO de grupos no viables.
    """
    datos = []
    host_idx = 0
    for grupo in GRUPOS_LIST:
        for _ in range(n_hosts_por_grupo):
            hostname = f"host{host_idx:04d}.example.com"
            prueba = {
                "grupo": grupo,
                "connection_result": "ACEPTADO",
                "dns_time_ms": 10.0,
                "tcp_time_ms": 20.0,
                "handshake_time_ms": 50.0,
                "bytes_sent": 350 if grupo == "X25519" else 1500,
                "bytes_received": 130 if grupo == "X25519" else 1200,
                "handshake_overhead": 480 if grupo == "X25519" else 2700,
                "handshake_total_bytes_sent": 400 if grupo == "X25519" else 1600,
                "handshake_total_bytes_received": 3000 if grupo == "X25519" else 5000,
                "handshake_total_overhead": 3400 if grupo == "X25519" else 6600,
            }
            # Añadir también un registro RECHAZADO de grupo no viable (debe ignorarse)
            prueba_rechazada = {
                "grupo": "kyber768",
                "connection_result": "RECHAZADO",
                "dns_time_ms": None,
                "tcp_time_ms": None,
                "handshake_time_ms": None,
                "bytes_sent": None,
                "bytes_received": None,
                "handshake_overhead": None,
                "handshake_total_bytes_sent": None,
                "handshake_total_bytes_received": None,
                "handshake_total_overhead": None,
            }
            datos.append({"hostname": hostname, "pruebas": [prueba, prueba_rechazada]})
            host_idx += 1
    return {"datos": datos}


# ---------------------------------------------------------------------------
# GRUPOS_VIABLES y LABEL_MAP
# ---------------------------------------------------------------------------

class TestConstantes:
    def test_grupos_viables_contiene_clasico(self):
        assert "X25519" in GRUPOS_VIABLES

    def test_grupos_viables_contiene_pqc(self):
        assert "X25519MLKEM768" in GRUPOS_VIABLES
        assert "x25519_kyber768" in GRUPOS_VIABLES
        assert "SecP256r1MLKEM768" in GRUPOS_VIABLES

    def test_label_map_cubre_todos_los_grupos_viables(self):
        for g in GRUPOS_VIABLES:
            assert g in LABEL_MAP, f"LABEL_MAP no cubre el grupo {g}"

    def test_experimentos_tienen_tres_niveles(self):
        assert len(EXPERIMENTOS) == 3

    def test_experimento_1_solo_timing(self):
        features = list(EXPERIMENTOS.values())[0]
        assert all("time" in f or "dns" in f for f in features)
        assert not any("bytes" in f or "overhead" in f for f in features)

    def test_experimento_3_es_superconjunto_de_1_y_2(self):
        exp_keys = list(EXPERIMENTOS.values())
        exp1, exp2, exp3 = exp_keys[0], exp_keys[1], exp_keys[2]
        assert set(exp1).issubset(set(exp3))
        assert set(exp2).issubset(set(exp3))


# ---------------------------------------------------------------------------
# cargar_datos
# ---------------------------------------------------------------------------

class TestCargarDatos:
    def _escribir_json(self, contenido: dict) -> Path:
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(contenido, f)
        f.close()
        return Path(f.name)

    def test_carga_registros_aceptados(self):
        path = self._escribir_json(_json_minimo(n_hosts_por_grupo=3))
        df = cargar_datos(path)
        assert len(df) == len(GRUPOS_LIST) * 3

    def test_ignora_rechazados(self):
        path = self._escribir_json(_json_minimo(n_hosts_por_grupo=3))
        df = cargar_datos(path)
        assert "kyber768" not in df["grupo"].values

    def test_ignora_grupos_no_viables(self):
        path = self._escribir_json(_json_minimo(n_hosts_por_grupo=2))
        df = cargar_datos(path)
        assert set(df["grupo"].unique()).issubset(GRUPOS_VIABLES)

    def test_columnas_presentes(self):
        path = self._escribir_json(_json_minimo(n_hosts_por_grupo=2))
        df = cargar_datos(path)
        for col in ALL_FEATURES + ["hostname", "grupo", "grupo_label"]:
            assert col in df.columns, f"Columna ausente: {col}"

    def test_dropna_por_experimento_elimina_filas_con_nulos(self):
        # cargar_datos ya no filtra globalmente: el dropna se aplica por experimento
        # en el loop de main() para no sesgar experimentos menos restrictivos.
        datos = _json_minimo(n_hosts_por_grupo=2)
        datos["datos"][0]["pruebas"][0]["handshake_time_ms"] = None
        path = self._escribir_json(datos)
        df = cargar_datos(path)
        # La fila con NaN sigue presente en el df crudo (campo JSON se carga como openssl_execution_time_ms)
        assert df["openssl_execution_time_ms"].isna().sum() == 1
        # Pero desaparece al filtrar con las columnas del experimento
        from clasificar_grupo_pqc import EXPERIMENTOS
        for features in EXPERIMENTOS.values():
            df_exp = df.dropna(subset=features)
            assert df_exp["openssl_execution_time_ms"].isna().sum() == 0

    def test_grupo_label_mapeado(self):
        path = self._escribir_json(_json_minimo(n_hosts_por_grupo=2))
        df = cargar_datos(path)
        assert df["grupo_label"].isna().sum() == 0

    def test_acepta_json_lista_directa(self):
        """También funciona si el JSON es una lista en lugar de {'datos': [...]}."""
        datos = _json_minimo(n_hosts_por_grupo=2)
        path = self._escribir_json(datos["datos"])
        df = cargar_datos(path)
        assert len(df) > 0


# ---------------------------------------------------------------------------
# split_train_test
# ---------------------------------------------------------------------------

class TestSplitTrainTest:
    def test_sin_solapamiento_de_hostnames(self):
        df = _df_sintetico(n_hosts_por_grupo=20)
        train, test = split_train_test(df, test_size=0.2, random_state=42)
        hosts_train = set(train["hostname"])
        hosts_test  = set(test["hostname"])
        assert hosts_train.isdisjoint(hosts_test)

    def test_proporcion_aproximada(self):
        df = _df_sintetico(n_hosts_por_grupo=25)
        train, test = split_train_test(df, test_size=0.2, random_state=42)
        ratio = len(test) / len(df)
        assert 0.15 <= ratio <= 0.30

    def test_union_cubre_dataset_completo(self):
        df = _df_sintetico(n_hosts_por_grupo=20)
        train, test = split_train_test(df, test_size=0.2, random_state=42)
        assert len(train) + len(test) == len(df)

    def test_ambos_splits_tienen_todas_las_clases(self):
        df = _df_sintetico(n_hosts_por_grupo=30)
        train, test = split_train_test(df, test_size=0.2, random_state=42)
        assert set(train["grupo"].unique()) == GRUPOS_VIABLES
        assert set(test["grupo"].unique()) == GRUPOS_VIABLES

    def test_reproducible_con_mismo_random_state(self):
        df = _df_sintetico(n_hosts_por_grupo=20)
        _, test1 = split_train_test(df, random_state=7)
        _, test2 = split_train_test(df, random_state=7)
        assert list(test1["hostname"]) == list(test2["hostname"])

    def test_distinto_con_diferente_random_state(self):
        df = _df_sintetico(n_hosts_por_grupo=30)
        _, test1 = split_train_test(df, random_state=1)
        _, test2 = split_train_test(df, random_state=99)
        assert set(test1["hostname"]) != set(test2["hostname"])


# ---------------------------------------------------------------------------
# evaluar_experimento
# ---------------------------------------------------------------------------

class TestEvaluarExperimento:
    """
    Usa un dataset sintético pequeño para verificar que evaluar_experimento
    devuelve la estructura esperada y entrena un modelo funcional.
    Los valores de accuracy no son relevantes con datos tan pequeños.
    """

    @pytest.fixture
    def df_train(self):
        # 10 hosts por grupo = 40 registros, suficiente para GroupKFold(2)
        return _df_sintetico(n_hosts_por_grupo=10)

    @pytest.fixture
    def le(self, df_train):
        return LabelEncoder().fit(df_train["grupo"].values)

    def test_devuelve_metricas_de_ambos_modelos(self, df_train, le):
        features = list(EXPERIMENTOS.values())[0]  # Exp 1
        res = evaluar_experimento(df_train, features, le=le, n_splits=2)
        assert "RandomForest" in res
        assert "GradientBoosting" in res

    def test_metricas_contienen_campos_requeridos(self, df_train, le):
        features = list(EXPERIMENTOS.values())[0]
        res = evaluar_experimento(df_train, features, le=le, n_splits=2)
        for modelo in ("RandomForest", "GradientBoosting"):
            assert "accuracy"    in res[modelo]
            assert "f1_macro"    in res[modelo]
            assert "f1_weighted" in res[modelo]
            assert "acc_std"     in res[modelo]

    def test_accuracy_entre_0_y_1(self, df_train, le):
        features = list(EXPERIMENTOS.values())[0]
        res = evaluar_experimento(df_train, features, le=le, n_splits=2)
        for modelo in ("RandomForest", "GradientBoosting"):
            assert 0.0 <= res[modelo]["accuracy"] <= 1.0

    def test_devuelve_mejor_modelo_entrenado(self, df_train, le):
        features = list(EXPERIMENTOS.values())[0]
        res = evaluar_experimento(df_train, features, le=le, n_splits=2)
        assert "_mejor_modelo" in res
        assert hasattr(res["_mejor_modelo"], "predict")

    def test_mejor_nombre_es_uno_de_los_modelos(self, df_train, le):
        features = list(EXPERIMENTOS.values())[0]
        res = evaluar_experimento(df_train, features, le=le, n_splits=2)
        assert res["_mejor_nombre"] in ("RandomForest", "GradientBoosting")

    def test_modelo_predice_clases_validas(self, df_train, le):
        features = list(EXPERIMENTOS.values())[0]
        res = evaluar_experimento(df_train, features, le=le, n_splits=2)
        modelo = res["_mejor_modelo"]
        X = df_train[features].values
        preds = modelo.predict(X)
        n_clases = len(le.classes_)
        assert all(0 <= p < n_clases for p in preds)

    def test_exp3_no_peor_que_exp1_en_datos_separables(self):
        """Con datos sintéticos donde bytes son muy discriminativos, Exp3 >= Exp1."""
        df = _df_sintetico(n_hosts_por_grupo=15)
        le = LabelEncoder().fit(df["grupo"].values)
        features_exp1 = list(EXPERIMENTOS.values())[0]
        features_exp3 = list(EXPERIMENTOS.values())[2]
        res1 = evaluar_experimento(df, features_exp1, le=le, n_splits=2)
        res3 = evaluar_experimento(df, features_exp3, le=le, n_splits=2)
        best1 = max(res1["RandomForest"]["f1_macro"], res1["GradientBoosting"]["f1_macro"])
        best3 = max(res3["RandomForest"]["f1_macro"], res3["GradientBoosting"]["f1_macro"])
        assert best3 >= best1 - 0.05  # margen por varianza con pocos datos


# ---------------------------------------------------------------------------
# Smoke tests de gráficas (verifican que no lanzan excepción)
# ---------------------------------------------------------------------------

class TestGraficas:
    @pytest.fixture
    def df(self):
        return _df_sintetico(n_hosts_por_grupo=10)

    def test_graficar_distribucion_no_falla(self, df, tmp_path):
        from clasificar_grupo_pqc import graficar_distribucion_features
        graficar_distribucion_features(df, tmp_path)
        assert (tmp_path / "clasificacion_distribucion_features.png").exists()

    def test_graficar_comparativa_no_falla(self, tmp_path):
        from clasificar_grupo_pqc import graficar_comparativa_experimentos
        resultados = {
            "Exp 1\nSolo timing": {
                "RandomForest":     {"accuracy": 0.6, "f1_macro": 0.4, "f1_weighted": 0.55, "acc_std": 0.02},
                "GradientBoosting": {"accuracy": 0.58, "f1_macro": 0.38, "f1_weighted": 0.53, "acc_std": 0.03},
            },
            "Exp 2\nTiming + bytes TLS": {
                "RandomForest":     {"accuracy": 0.85, "f1_macro": 0.75, "f1_weighted": 0.83, "acc_std": 0.01},
                "GradientBoosting": {"accuracy": 0.84, "f1_macro": 0.76, "f1_weighted": 0.84, "acc_std": 0.01},
            },
            "Exp 3\nTiming + bytes totales": {
                "RandomForest":     {"accuracy": 0.87, "f1_macro": 0.80, "f1_weighted": 0.86, "acc_std": 0.01},
                "GradientBoosting": {"accuracy": 0.87, "f1_macro": 0.81, "f1_weighted": 0.87, "acc_std": 0.01},
            },
        }
        graficar_comparativa_experimentos(resultados, tmp_path)
        assert (tmp_path / "clasificacion_experimentos_comparativa.png").exists()

    def test_graficar_confusion_no_falla(self, df, tmp_path):
        from sklearn.ensemble import RandomForestClassifier
        from clasificar_grupo_pqc import graficar_confusion_matrix
        le = LabelEncoder().fit(df["grupo"].values)
        features = list(EXPERIMENTOS.values())[0]
        X = df[features].values
        y = le.transform(df["grupo"].values)
        modelo = RandomForestClassifier(n_estimators=10, random_state=42)
        modelo.fit(X, y)
        graficar_confusion_matrix(modelo, le, X, y, titulo="Test", n_test=len(df), out_dir=tmp_path)
        assert (tmp_path / "clasificacion_confusion_mejor.png").exists()

    def test_graficar_importancia_no_falla(self, df, tmp_path):
        from sklearn.ensemble import RandomForestClassifier
        from clasificar_grupo_pqc import graficar_importancia_features
        le = LabelEncoder().fit(df["grupo"].values)
        features = list(EXPERIMENTOS.values())[0]
        X = df[features].values
        y = le.transform(df["grupo"].values)
        modelo = RandomForestClassifier(n_estimators=10, random_state=42)
        modelo.fit(X, y)
        graficar_importancia_features(modelo, features, "RandomForest", tmp_path)
        assert (tmp_path / "clasificacion_importancia_features.png").exists()
