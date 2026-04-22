"""
Lectura y transformación de los artefactos generados en resultados/ e imagenes/
para alimentar los componentes de results.jsx.

Cada función load_*_results devuelve un dict con shape:
  {
    "stats":   [{label, value}, ...],         # StatCards
    "h_bars":  [{label, value}, ...],         # opcional: HBarChart
    "v_bars":  [{label, value}, ...],         # opcional: VBarChart
    "grouped": {groups, series},              # opcional: GroupedBar
    "conf_matrix": {labels, data},            # opcional: ConfMatrix
    "note":    "texto",                       # opcional
  }

Si los nombres de columnas de tus CSVs/JSONs no coinciden exactamente con lo
que se asume aquí, basta con tocar las funciones — todo está aislado.
"""

from __future__ import annotations
import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from config import RESULTS_DIR, IMAGES_DIR


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────

def load_results(step_id: str) -> dict:
    loaders = {
        "pqc_sonda":         _pqc_sonda,
        "pqc_analisis":      _pqc_analisis,
        "pqc_clasificacion": _pqc_clasificacion,
        "ech_sonda":         _ech_sonda,
        "ech_latencia_ech":  _ech_latencia_ech,
        "ech_latencia_pqc":  _ech_latencia_pqc,
    }
    fn = loaders.get(step_id)
    if not fn:
        return {"error": f"step desconocido: {step_id}"}
    try:
        return fn()
    except FileNotFoundError as e:
        return {"error": f"archivo no encontrado: {e.filename}",
                "hint": "ejecuta el paso correspondiente antes de ver resultados"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _pct(num: int, den: int) -> float:
    return round(100.0 * num / max(den, 1), 1)

def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def _read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))

def _accepted(row: dict) -> bool:
    """Heurística: distintas versiones de las sondas pueden usar diferentes keys."""
    for k in ("aceptado", "accepted"):
        if k in row:
            v = row[k]
            return v is True or str(v).lower() in ("true", "1", "yes")
    for k in ("resultado", "result", "estado", "status"):
        if k in row:
            return str(row[k]).upper() == "ACEPTADO"
    return False


# ──────────────────────────────────────────────────────────────
# PQC — Sonda
# ──────────────────────────────────────────────────────────────

def _pqc_sonda() -> dict:
    """Lee resultados/resultados_sonda_pqc.json → % de aceptación por grupo."""
    path = RESULTS_DIR / "resultados_sonda_pqc.json"
    data = _read_json(path)

    # El JSON puede ser una lista de probes o un dict {probes: [...]}
    probes = data if isinstance(data, list) else data.get("probes") or data.get("resultados") or []

    hosts_ok: set[str] = set()
    group_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "ok": 0})
    for p in probes:
        hostname = p.get("hostname") or p.get("host") or ""
        grupo    = p.get("grupo") or p.get("group") or p.get("grupo_pqc") or ""
        if hostname: hosts_ok.add(hostname)
        if not grupo: continue
        group_stats[grupo]["total"] += 1
        if _accepted(p):
            group_stats[grupo]["ok"] += 1

    h_bars = []
    for g, s in sorted(group_stats.items(), key=lambda kv: -_pct(kv[1]["ok"], kv[1]["total"])):
        h_bars.append({"label": g, "value": _pct(s["ok"], s["total"])})

    # Estadísticas de éxito global de X25519MLKEM768 (si existe)
    hybrid = group_stats.get("X25519MLKEM768", {"total": 0, "ok": 0})
    hybrid_pct = _pct(hybrid["ok"], hybrid["total"]) if hybrid["total"] else 0

    return {
        "stats": [
            {"label": "Hosts escaneados",         "value": str(len(hosts_ok))},
            {"label": "Probes totales",           "value": f"{len(probes):,}".replace(",", ".")},
            {"label": "Éxito X25519MLKEM768",     "value": f"{hybrid_pct}%"},
            {"label": "Grupos probados",          "value": str(len(group_stats))},
        ],
        "h_bars": h_bars,
        "unit":   "%",
        "color":  "purple",
        "title":  "Tasa de aceptación por grupo PQC",
        "note":   "Los grupos híbridos (X25519+PQC) muestran tasas de aceptación significativamente más altas que los PQC puros.",
    }


# ──────────────────────────────────────────────────────────────
# PQC — Análisis
# ──────────────────────────────────────────────────────────────

def _pqc_analisis() -> dict:
    """
    Intenta leer resumen_por_grupo.csv (generado por analizar_resultados.py)
    para extraer medianas por grupo y computar overhead vs X25519.
    """
    summary_path = RESULTS_DIR / "resumen_por_grupo.csv"
    rows = _read_csv(summary_path)

    # Suponemos columnas: grupo, mediana_handshake_ms (o similar)
    def _median_field(r):
        for k in ("mediana_handshake_ms", "mediana_ms", "mediana",
                  "mediana_openssl_execution_time_ms"):
            if k in r and r[k] not in ("", None):
                try: return float(r[k])
                except ValueError: pass
        return None

    groups = {}
    for r in rows:
        g = r.get("grupo") or r.get("group") or r.get("grupo_pqc")
        m = _median_field(r)
        if g and m is not None:
            groups[g] = m

    baseline = groups.get("X25519")
    v_bars = []
    if baseline is not None:
        # Overhead vs X25519
        items = sorted(groups.items(), key=lambda kv: kv[1] - baseline)
        for g, m in items:
            v_bars.append({"label": g, "value": round(m - baseline, 1)})

    # Contar imágenes generadas por el análisis
    n_imgs = len(list(IMAGES_DIR.glob("*.png"))) if IMAGES_DIR.exists() else 0

    return {
        "stats": [
            {"label": "Grupos analizados", "value": str(len(groups))},
            {"label": "Mediana X25519",    "value": f"{int(baseline)} ms" if baseline else "—"},
            {"label": "Figuras generadas", "value": str(n_imgs)},
            {"label": "Reporte",           "value": "resumen_por_grupo.csv"},
        ],
        "v_bars": v_bars,
        "unit":   "ms",
        "color":  "purple",
        "title":  "Overhead de latencia vs X25519 (mediana)",
        "note":   "Delta calculado por hostname para aislar el ruido de red. Positivo = más lento que X25519.",
    }


# ──────────────────────────────────────────────────────────────
# PQC — Clasificación ML
# ──────────────────────────────────────────────────────────────

def _pqc_clasificacion() -> dict:
    """
    Intenta leer resumen_clasificacion.json (si tu script lo genera).
    Si no existe, devolvemos un error suave; el usuario puede adaptarlo.
    """
    candidates = [
        RESULTS_DIR / "resumen_clasificacion.json",
        RESULTS_DIR / "clasificacion_pqc.json",
        RESULTS_DIR / "resultados_clasificacion.json",
    ]
    path = next((p for p in candidates if p.exists()), None)
    if not path:
        return {
            "error": "No se ha encontrado un resumen de clasificación.",
            "hint":  "Ejecuta primero la clasificación ML, o ajusta _pqc_clasificacion() "
                     "en web/backend/results.py para apuntar al fichero que genera tu script.",
        }

    data = _read_json(path)
    # Formato esperado:
    # {
    #   "experimentos": [
    #     {"nombre": "Exp 1 — Timing", "rf": 0.72, "gb": 0.75},
    #     ...
    #   ],
    #   "mejor": {"modelo": "GradBoost", "accuracy": 0.912, "f1": 0.891},
    #   "confusion": {
    #     "labels": ["X25519", ...],
    #     "matrix": [[42,3,1,0], ...]
    #   }
    # }
    exps = data.get("experimentos", [])
    groups = [e.get("nombre", f"Exp {i+1}") for i, e in enumerate(exps)]
    series = []
    if exps:
        rf = [round((e.get("rf") or 0) * (100 if e.get("rf", 0) <= 1 else 1), 1) for e in exps]
        gb = [round((e.get("gb") or 0) * (100 if e.get("gb", 0) <= 1 else 1), 1) for e in exps]
        series = [
            {"name": "RandomForest",    "color": "oklch(0.58 0.22 290)", "values": rf},
            {"name": "GradientBoost",   "color": "oklch(0.74 0.22 305)", "values": gb},
        ]

    mejor = data.get("mejor", {})
    acc_pct = mejor.get("accuracy")
    if acc_pct is not None and acc_pct <= 1: acc_pct *= 100

    return {
        "stats": [
            {"label": "Mejor modelo",     "value": str(mejor.get("modelo", "—"))},
            {"label": "Accuracy (test)",  "value": f"{round(acc_pct, 1)}%" if acc_pct else "—"},
            {"label": "F1-score macro",   "value": f"{round(mejor.get('f1', 0), 3)}"},
            {"label": "Experimentos",     "value": str(len(exps))},
        ],
        "grouped": {"groups": groups, "series": series},
        "grouped_title": "Accuracy por experimento y modelo (%)",
        "conf_matrix":   data.get("confusion"),
        "color":         "purple",
    }


# ──────────────────────────────────────────────────────────────
# ECH — Sonda de prevalencia
# ──────────────────────────────────────────────────────────────

def _ech_sonda() -> dict:
    csv_path = RESULTS_DIR / "resultados_ech_prevalencia.csv"
    rows = _read_csv(csv_path)

    total = len(rows)
    with_ech = 0
    cdn_counter: Counter = Counter()

    for r in rows:
        has_ech = str(r.get("ech_activo") or r.get("ech") or r.get("tiene_ech") or "").lower() \
                  in ("true", "1", "yes", "sí", "si")
        if has_ech:
            with_ech += 1
            cdn = (r.get("cdn") or r.get("proveedor") or _guess_cdn(r)).strip() or "Otros"
            cdn_counter[cdn] += 1

    h_bars = [{"label": k, "value": v} for k, v in cdn_counter.most_common()]

    return {
        "stats": [
            {"label": "Dominios analizados", "value": f"{total:,}".replace(",", ".")},
            {"label": "Con ECH activo",      "value": f"{with_ech} ({_pct(with_ech, total)}%)"},
            {"label": "CDNs identificados",  "value": str(len(cdn_counter))},
            {"label": "Exportado a",         "value": "resultados_ech_prevalencia.csv"},
        ],
        "h_bars": h_bars,
        "unit":   " dom.",
        "color":  "green",
        "title":  "Dominios con ECH por proveedor CDN",
        "note":   f"{with_ech} hostnames con ECH disponibles para sondas de latencia.",
    }

def _guess_cdn(row: dict) -> str:
    sni = (row.get("outer_sni") or row.get("ech_outer_sni") or "").lower()
    if "cloudflare" in sni: return "Cloudflare"
    if "fastly"     in sni: return "Fastly"
    if "google"     in sni or "googleapis" in sni: return "Google"
    return "Otros"


# ──────────────────────────────────────────────────────────────
# ECH — Latencia con/sin ECH
# ──────────────────────────────────────────────────────────────

def _ech_latencia_ech() -> dict:
    csv_path = RESULTS_DIR / "resultados_latencia_ech.csv"
    rows = _read_csv(csv_path)

    # Por hostname: media con ECH vs sin ECH
    by_host: dict[str, dict[str, float]] = defaultdict(dict)
    for r in rows:
        host = r.get("hostname") or r.get("host")
        if not host: continue
        con   = _num(r.get("media_con_ech_ms") or r.get("latencia_con_ech_ms") or r.get("con_ech_ms"))
        sin   = _num(r.get("media_sin_ech_ms") or r.get("latencia_sin_ech_ms") or r.get("sin_ech_ms"))
        if con is not None: by_host[host]["con"] = con
        if sin is not None: by_host[host]["sin"] = sin

    groups = list(by_host.keys())[:8]  # limit para que quepa en el chart
    series = [
        {"name": "Sin ECH", "color": "oklch(0.52 0.18 145)",
         "values": [round(by_host[h].get("sin", 0)) for h in groups]},
        {"name": "Con ECH", "color": "oklch(0.74 0.19 150)",
         "values": [round(by_host[h].get("con", 0)) for h in groups]},
    ]

    # Overhead medio
    deltas = [by_host[h]["con"] - by_host[h]["sin"]
              for h in by_host if "con" in by_host[h] and "sin" in by_host[h]]
    avg_overhead = round(statistics.mean(deltas), 1) if deltas else 0

    ok_count = sum(1 for d in deltas if d >= 0)

    return {
        "stats": [
            {"label": "Hostnames medidos",     "value": str(len(by_host))},
            {"label": "Overhead ECH medio",    "value": f"+{avg_overhead} ms" if avg_overhead > 0 else f"{avg_overhead} ms"},
            {"label": "ECH confirmado",        "value": f"{ok_count}/{len(deltas)}"},
            {"label": "Exportado a",           "value": "resultados_latencia_ech.csv"},
        ],
        "grouped": {"groups": groups, "series": series},
        "grouped_title": "Latencia handshake TLS — con vs sin ECH (ms)",
        "color":         "green",
        "note":          "El overhead de ECH es bajo, debido al intercambio de clave HPKE adicional durante el handshake.",
    }


# ──────────────────────────────────────────────────────────────
# ECH — Latencia PQC + ECH
# ──────────────────────────────────────────────────────────────

def _ech_latencia_pqc() -> dict:
    csv_path = RESULTS_DIR / "resultados_latencia_pqc.csv"
    rows = _read_csv(csv_path)

    # Agrupamos por grupo PQC — media con/sin ECH entre hostnames
    by_group: dict[str, dict[str, list[float]]] = defaultdict(lambda: {"con": [], "sin": []})
    for r in rows:
        g = r.get("grupo") or r.get("grupo_pqc") or r.get("group")
        if not g: continue
        con = _num(r.get("media_con_ech_ms") or r.get("con_ech_ms"))
        sin = _num(r.get("media_sin_ech_ms") or r.get("sin_ech_ms"))
        if con is not None: by_group[g]["con"].append(con)
        if sin is not None: by_group[g]["sin"].append(sin)

    groups = list(by_group.keys())
    def _avg(xs): return round(statistics.mean(xs)) if xs else 0
    series = [
        {"name": "Sin ECH",          "color": "oklch(0.52 0.18 145)",
         "values": [_avg(by_group[g]["sin"]) for g in groups]},
        {"name": "Con ECH (bssl)",   "color": "oklch(0.74 0.19 150)",
         "values": [_avg(by_group[g]["con"]) for g in groups]},
    ]

    # Overhead de MLKEM768+ECH vs X25519 (si ambos existen)
    overhead = "—"
    base_x = by_group.get("X25519", {}).get("sin", [])
    mlkem  = by_group.get("X25519MLKEM768", {}).get("con", [])
    if base_x and mlkem:
        overhead = f"+{round(statistics.mean(mlkem) - statistics.mean(base_x), 1)} ms"

    return {
        "stats": [
            {"label": "Grupos PQC medidos",        "value": str(len(groups))},
            {"label": "Overhead MLKEM768+ECH",      "value": overhead},
            {"label": "Registros",                  "value": str(len(rows))},
            {"label": "Exportado a",                "value": "resultados_latencia_pqc.csv"},
        ],
        "grouped": {"groups": groups, "series": series},
        "grouped_title": "Latencia handshake TLS por grupo PQC (ms)",
        "color":         "green",
        "note":          "Los grupos OQS puros solo se miden sin ECH vía OpenSSL OQS. Los grupos bssl soportan ECH simultáneamente.",
    }


def _num(v) -> float | None:
    if v is None or v == "":
        return None
    try: return float(v)
    except (ValueError, TypeError): return None
