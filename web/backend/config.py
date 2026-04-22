"""
Configuración de pasos del pipeline web.

Mapea cada step_id del dashboard a:
  - el script que debe ejecutarse (.sh o .py)
  - cómo se construye su línea de comandos a partir de los args del usuario
  - el schema de argumentos (con defaults, tipos y límites) — debe coincidir
    con el definido en web/frontend/src/App.jsx

Si tus scripts .sh no aceptan flags todavía, puedes cambiar `build_cmd` para
invocar directamente los .py de scripts/sondas/ con los flags de argparse.
"""

from __future__ import annotations
from pathlib import Path
from typing import Callable, Any

# Raíz del repo TFG-PQC (web/backend/config.py → ../../)
REPO_ROOT   = Path(__file__).resolve().parents[2]
RESULTS_DIR = REPO_ROOT / "resultados"
IMAGES_DIR  = REPO_ROOT / "imagenes"
DATA_DIR    = REPO_ROOT / "data"

# ──────────────────────────────────────────────────────────────
# Helpers para construir la línea de comandos de cada script
# ──────────────────────────────────────────────────────────────

def _s(v: Any) -> str:
    """Args → string siempre."""
    return str(v) if v is not None else ""

def _flag(name: str, val: Any) -> list[str]:
    """Pareja (--flag valor) si valor no está vacío; lista vacía si lo está."""
    s = _s(val).strip()
    return [name, s] if s else []


def pqc_sonda_cmd(args: dict) -> list[str]:
    return [
        "bash", "ejecutar_sonda.sh",
        *_flag("--input-csv",     args.get("input_csv", "majestic_million.csv")),
        *_flag("--max-hostnames", args.get("max_hostnames", 100)),
        *_flag("--repeticiones",  args.get("repeticiones", 3)),
        *_flag("--max-workers",   args.get("max_workers", 20)),
    ]

def pqc_analisis_cmd(args: dict) -> list[str]:
    return ["bash", "ejecutar_analisis.sh"]

def pqc_clasificacion_cmd(args: dict) -> list[str]:
    return [
        "bash", "ejecutar_clasificacion_pqc.sh",
        *_flag("--input-json", args.get("input_json", "resultados/resultados_sonda_pqc.json")),
        *_flag("--n-splits",   args.get("n_splits", 5)),
    ]

def ech_sonda_cmd(args: dict) -> list[str]:
    return [
        "bash", "ejecutar_sonda_ech.sh",
        *_flag("--input-csv",        args.get("input_csv", "data/majestic_million.csv")),
        *_flag("--max-dominios",     args.get("max_dominios", 1000)),
        *_flag("--max-concurrency",  args.get("max_concurrency", 40)),
        *_flag("--tls-client",       args.get("tls_client", "auto")),
        *_flag("--dns-timeout",      args.get("dns_timeout", 8)),
        *_flag("--tls-timeout",      args.get("tls_timeout", 20)),
    ]

def ech_latencia_ech_cmd(args: dict) -> list[str]:
    return [
        "bash", "ejecutar_sonda_latencia_ech.sh",
        *_flag("--input-csv",     args.get("input_csv", "resultados/resultados_ech_prevalencia.csv")),
        *_flag("--repeticiones",  args.get("repeticiones", 30)),
        *_flag("--concurrency",   args.get("concurrency", 10)),
        *_flag("--max-hostnames", args.get("max_hostnames", 10000)),
        *_flag("--dns-timeout",   args.get("dns_timeout", 5)),
        *_flag("--tls-timeout",   args.get("tls_timeout", 10)),
    ]

def ech_latencia_pqc_cmd(args: dict) -> list[str]:
    cmd = [
        "bash", "ejecutar_sonda_latencia_pqc.sh",
        *_flag("--input-csv",     args.get("input_csv", "resultados/resultados_ech_prevalencia.csv")),
        *_flag("--repeticiones",  args.get("repeticiones", 30)),
        *_flag("--concurrency",   args.get("concurrency", 5)),
        *_flag("--max-hostnames", args.get("max_hostnames", 10000)),
        *_flag("--dns-timeout",   args.get("dns_timeout", 5)),
        *_flag("--tls-timeout",   args.get("tls_timeout", 10)),
    ]
    grupos = _s(args.get("grupos_pqc", "")).strip()
    if grupos:
        # --grupos-pqc acepta varios valores separados por espacio
        cmd.extend(["--grupos-pqc", *grupos.split()])
    return cmd


# ──────────────────────────────────────────────────────────────
# STEPS: catálogo completo (fuente de verdad del backend).
# El schema debe coincidir con web/frontend/src/App.jsx.
# ──────────────────────────────────────────────────────────────

STEPS: dict[str, dict] = {
    "pqc_sonda": {
        "pipeline":    "pqc",
        "num":         "01",
        "label":       "Sonda PQC",
        "script":      "ejecutar_sonda.sh",
        "desc":        "Escanea dominios HTTPS reales comprobando la aceptación de 14 grupos criptográficos PQC mediante OpenSSL OQS en Docker.",
        "unlocks":     ["pqc_analisis", "pqc_clasificacion"],
        "build_cmd":   pqc_sonda_cmd,
        "args": [
            {"key": "input_csv",     "label": "--input-csv",     "type": "text",   "default": "majestic_million.csv",
             "hint": "CSV de dominios (Majestic Million o Tranco)"},
            {"key": "max_hostnames", "label": "--max-hostnames", "type": "number", "default": 100,
             "min": 1, "max": 10000, "hint": "Número máximo de dominios a probar"},
            {"key": "repeticiones",  "label": "--repeticiones",  "type": "number", "default": 3,
             "min": 1, "max": 20,    "hint": "Repeticiones por (hostname, grupo)"},
            {"key": "max_workers",   "label": "--max-workers",   "type": "number", "default": 20,
             "min": 1, "max": 50,    "hint": "Hilos concurrentes"},
        ],
    },
    "pqc_analisis": {
        "pipeline":  "pqc",  "num": "02",
        "label":     "Análisis PQC",
        "script":    "ejecutar_analisis.sh",
        "desc":      "Carga los resultados de la sonda, filtra outliers, construye cohorte justa y genera las gráficas de publicación.",
        "unlocks":   [],
        "build_cmd": pqc_analisis_cmd,
        "args":      [],
    },
    "pqc_clasificacion": {
        "pipeline":  "pqc",  "num": "03",
        "label":     "Clasificación ML",
        "script":    "ejecutar_clasificacion_pqc.sh",
        "desc":      "Clasifica el grupo PQC negociado usando solo features observables (timing y bytes). RandomForest y GradientBoosting en 3 experimentos.",
        "unlocks":   [],
        "build_cmd": pqc_clasificacion_cmd,
        "args": [
            {"key": "input_json", "label": "--input-json", "type": "text",
             "default": "resultados/resultados_sonda_pqc.json",
             "hint": "JSON de resultados de la sonda PQC"},
            {"key": "n_splits",   "label": "--n-splits",   "type": "number", "default": 5,
             "min": 2, "max": 20,
             "hint": "Folds para GroupKFold (validación cruzada sin leakage)"},
        ],
    },
    "ech_sonda": {
        "pipeline":  "ech",  "num": "01",
        "label":     "Sonda ECH",
        "script":    "ejecutar_sonda_ech.sh",
        "desc":      "Detecta dominios con ECH activo a gran escala: descubre registros HTTPS RR, decodifica ECHConfigList y mide longitud de ClientHello.",
        "unlocks":   ["ech_latencia_ech", "ech_latencia_pqc"],
        "build_cmd": ech_sonda_cmd,
        "args": [
            {"key": "input_csv",       "label": "--input-csv",       "type": "text",
             "default": "data/majestic_million.csv", "hint": "CSV de dominios de entrada"},
            {"key": "max_dominios",    "label": "--max-dominios",    "type": "number",
             "default": 1000, "min": 10, "max": 1000000, "hint": "Máximo de dominios a procesar"},
            {"key": "max_concurrency", "label": "--max-concurrency", "type": "number",
             "default": 40, "min": 1, "max": 200, "hint": "Concurrencia asyncio"},
            {"key": "tls_client",      "label": "--tls-client",      "type": "select",
             "default": "auto",
             "options": [{"value":"auto","label":"auto"},{"value":"bssl","label":"bssl"},{"value":"openssl","label":"openssl"}],
             "hint": "Cliente TLS a usar para verificar ECH"},
            {"key": "dns_timeout",     "label": "--dns-timeout",     "type": "number",
             "default": 8,  "min": 1, "max": 60,  "hint": "Timeout DNS en segundos"},
            {"key": "tls_timeout",     "label": "--tls-timeout",     "type": "number",
             "default": 20, "min": 1, "max": 120, "hint": "Timeout TLS en segundos"},
        ],
    },
    "ech_latencia_ech": {
        "pipeline":  "ech",  "num": "02",
        "label":     "Latencia ECH",
        "script":    "ejecutar_sonda_latencia_ech.sh",
        "desc":      "Mide el overhead real de ECH comparando handshakes TLS con y sin ECH activo usando bssl. Genera media y desviación típica por hostname.",
        "unlocks":   [],
        "build_cmd": ech_latencia_ech_cmd,
        "args": [
            {"key": "input_csv",     "label": "--input-csv",     "type": "text",
             "default": "resultados/resultados_ech_prevalencia.csv",
             "hint": "CSV de hostnames con ECH (salida de la sonda ECH)"},
            {"key": "repeticiones",  "label": "--repeticiones",  "type": "number", "default": 30,
             "min": 5, "max": 200, "hint": "Mediciones por hostname para media/stddev"},
            {"key": "concurrency",   "label": "--concurrency",   "type": "number", "default": 10,
             "min": 1, "max": 50,  "hint": "Hostnames en paralelo"},
            {"key": "max_hostnames", "label": "--max-hostnames", "type": "number", "default": 10000,
             "min": 1, "max": 100000, "hint": "Máximo de hostnames a procesar"},
            {"key": "dns_timeout",   "label": "--dns-timeout",   "type": "number", "default": 5,
             "min": 1, "max": 60, "hint": "Timeout DNS en segundos"},
            {"key": "tls_timeout",   "label": "--tls-timeout",   "type": "number", "default": 10,
             "min": 1, "max": 120, "hint": "Timeout por handshake TLS en segundos"},
        ],
    },
    "ech_latencia_pqc": {
        "pipeline":  "ech",  "num": "03",
        "label":     "Latencia PQC+ECH",
        "script":    "ejecutar_sonda_latencia_pqc.sh",
        "desc":      "Mide la latencia del handshake TLS para múltiples grupos PQC (bssl y OQS), combinando con ECH cuando es posible.",
        "unlocks":   [],
        "build_cmd": ech_latencia_pqc_cmd,
        "args": [
            {"key": "input_csv",     "label": "--input-csv",     "type": "text",
             "default": "resultados/resultados_ech_prevalencia.csv",
             "hint": "CSV de hostnames con ECH"},
            {"key": "repeticiones",  "label": "--repeticiones",  "type": "number", "default": 30,
             "min": 5, "max": 200, "hint": "Mediciones por combinación (hostname × grupo)"},
            {"key": "concurrency",   "label": "--concurrency",   "type": "number", "default": 5,
             "min": 1, "max": 20,  "hint": "Hostnames en paralelo"},
            {"key": "max_hostnames", "label": "--max-hostnames", "type": "number", "default": 10000,
             "min": 1, "max": 100000, "hint": "Máximo de hostnames a procesar"},
            {"key": "grupos_pqc",    "label": "--grupos-pqc",    "type": "text",
             "default": "X25519Kyber768Draft00 X25519MLKEM768",
             "hint": "Grupos bssl separados por espacio (vacío = todos los predefinidos)"},
            {"key": "dns_timeout",   "label": "--dns-timeout",   "type": "number", "default": 5,
             "min": 1, "max": 60, "hint": "Timeout DNS en segundos"},
            {"key": "tls_timeout",   "label": "--tls-timeout",   "type": "number", "default": 10,
             "min": 1, "max": 120, "hint": "Timeout por handshake en segundos"},
        ],
    },
}
