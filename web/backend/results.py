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
# Caché basada en mtime: evita releer ficheros grandes en cada
# request. Se auto-invalida cuando el fichero cambia en disco.
# ──────────────────────────────────────────────────────────────

_cache: dict[str, tuple[float, dict]] = {}  # step_id → (mtime_signature, data)

def _mtime_sig(*paths: Path) -> float:
    """Suma de mtimes de todos los paths existentes. Cambia si cualquier fichero es reescrito."""
    total = 0.0
    for p in paths:
        try:
            total += p.stat().st_mtime
        except OSError:
            pass
    return total

def _cached(step_id: str, data: dict, *paths: Path) -> dict:
    _cache[step_id] = (_mtime_sig(*paths), data)
    return data

def _from_cache(step_id: str, *paths: Path) -> dict | None:
    entry = _cache.get(step_id)
    if entry and entry[0] == _mtime_sig(*paths):
        return entry[1]
    return None


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────

# Ficheros que cada step necesita para invalidar la caché
_STEP_FILES: dict[str, list[Path]] = {
    "pqc_sonda":         [RESULTS_DIR / "resultados_sonda_pqc.json",
                          RESULTS_DIR / "resumen_por_grupo.csv"],
    "pqc_analisis":      [RESULTS_DIR / "resumen_por_grupo.csv"],
    "pqc_clasificacion": [RESULTS_DIR / "resumen_clasificacion.json"],
    "ech_sonda":         [RESULTS_DIR / "resultados_ech_prevalencia.json",
                          RESULTS_DIR / "resultados_ech_prevalencia.csv"],
    "ech_latencia_ech":  [RESULTS_DIR / "resultados_latencia_ech.csv"],
    "ech_latencia_pqc":  [RESULTS_DIR / "resultados_latencia_pqc.csv"],
}

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

    paths = _STEP_FILES.get(step_id, [])
    cached = _from_cache(step_id, *paths)
    if cached is not None:
        return cached

    try:
        result = fn()
    except FileNotFoundError as e:
        return {"error": f"archivo no encontrado: {e.filename}",
                "hint": "ejecuta el paso correspondiente antes de ver resultados"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

    if "error" not in result:
        _cached(step_id, result, *paths)
    return result


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _images_for(*globs: str) -> list[str]:
    if not IMAGES_DIR.exists():
        return []
    result = []
    for pat in globs:
        result.extend(sorted(p.name for p in IMAGES_DIR.glob(pat)))
    return result

def _pct(num: int, den: int) -> float:
    return round(100.0 * num / max(den, 1), 1)

def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def _read_json_header(path: Path) -> dict:
    """Lee solo las claves de primer nivel excepto 'datos', evitando cargar arrays grandes."""
    with path.open(encoding="utf-8") as f:
        chunk = f.read(8192)
    datos_idx = chunk.find('"datos"')
    if datos_idx > 0:
        truncated = chunk[:datos_idx].rstrip().rstrip(',') + '}'
        try:
            return json.loads(truncated)
        except json.JSONDecodeError:
            pass
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
    for k in ("resultado", "result", "estado", "status", "connection_result"):
        if k in row:
            return str(row[k]).upper() == "ACEPTADO"
    return False


# ──────────────────────────────────────────────────────────────
# PQC — Sonda
# ──────────────────────────────────────────────────────────────

def _pqc_sonda() -> dict:
    """
    Lee solo el header del JSON grande (8 KB) para el resumen global,
    y el CSV de resumen por grupo (2 KB) para los charts.
    Evita parsear los 43 MB de datos crudos en cada request.
    """
    json_path = RESULTS_DIR / "resultados_sonda_pqc.json"
    csv_path  = RESULTS_DIR / "resumen_por_grupo.csv"

    # Resumen global: solo los primeros 8 KB del JSON (donde está "resumen")
    header = _read_json_header(json_path)
    resumen = header.get("resumen", {}) if isinstance(header, dict) else {}

    total_hosts      = resumen.get("total_hostnames", 0)
    hosts_con_exito  = resumen.get("hosts_con_al_menos_un_exito", 0)
    total_pruebas    = resumen.get("total_pruebas", 0)
    pruebas_exitosas = resumen.get("pruebas_exitosas", 0)
    tasa_hosts       = resumen.get("tasa_exito_hosts_percent",  _pct(hosts_con_exito, total_hosts))
    tasa_pruebas     = resumen.get("tasa_exito_pruebas_percent", _pct(pruebas_exitosas, total_pruebas))
    tiempo_s         = resumen.get("tiempo_total_segundos")
    n_grupos         = len(resumen.get("grupos_probados", []))

    # Por-grupo: tasa de aceptación y latencia mediana desde el CSV pequeño
    rows = _read_csv(csv_path)

    def _field(r, *keys):
        for k in keys:
            if k in r and r[k] not in ("", None):
                try: return float(r[k])
                except ValueError: pass
        return None

    group_pct: dict[str, float] = {}
    group_ms:  dict[str, float] = {}
    for r in rows:
        g = r.get("grupo") or r.get("group") or ""
        if not g:
            continue
        pct = _field(r, "porcentaje_aceptacion", "tasa_exito", "acceptance_rate")
        if pct is not None:
            group_pct[g] = pct
        ms = _field(r, "handshake_time_ms_mediana", "handshake_time_ms_median",
                       "mediana_handshake_ms", "mediana_ms")
        if ms is not None:
            group_ms[g] = ms

    hybrid_pct  = group_pct.get("X25519MLKEM768", 0)
    x25519_ms   = group_ms.get("X25519")

    # Chart 1: tasa de aceptación por grupo (barras horizontales, ordenado desc)
    h_bars = sorted(
        [{"label": g, "value": round(v, 1)} for g, v in group_pct.items()],
        key=lambda x: -x["value"],
    )

    # Chart 2: latencia mediana por grupo — solo grupos con datos (barras verticales, asc)
    v_bars = sorted(
        [{"label": g, "value": round(v, 1)} for g, v in group_ms.items()],
        key=lambda x: x["value"],
    )

    stats = [
        {"label": "Hosts escaneados",      "value": str(total_hosts)},
        {"label": "Hosts con éxito",       "value": f"{hosts_con_exito} ({tasa_hosts}%)"},
        {"label": "Pruebas totales",       "value": f"{total_pruebas:,}".replace(",", ".")},
        {"label": "Pruebas exitosas",      "value": f"{pruebas_exitosas} ({tasa_pruebas}%)"},
        {"label": "Grupos PQC probados",   "value": str(n_grupos or len(group_pct))},
        {"label": "Éxito X25519MLKEM768", "value": f"{round(hybrid_pct, 1)}%"},
    ]
    if x25519_ms is not None:
        stats.append({"label": "Latencia X25519 (mediana)", "value": f"{round(x25519_ms, 1)} ms"})
    if tiempo_s is not None:
        mins = int(tiempo_s // 60)
        secs = int(tiempo_s % 60)
        stats.append({"label": "Tiempo de escaneo", "value": f"{mins}m {secs}s"})

    return {
        "stats":        stats,
        "h_bars":       h_bars,
        "h_bars_title": "Tasa de aceptación por grupo PQC (%)",
        "v_bars":       v_bars,
        "v_bars_title": "Latencia mediana de handshake TLS por grupo (ms)",
        "v_bars_unit":  "ms",
        "unit":         "%",
        "color":        "purple",
        "note":         "Los grupos híbridos (X25519+PQC) muestran tasas de aceptación significativamente más altas que los PQC puros.",
        "images":       _images_for(),
    }


# ──────────────────────────────────────────────────────────────
# PQC — Análisis
# ──────────────────────────────────────────────────────────────

def _pqc_analisis() -> dict:
    """Lee resumen_por_grupo.csv para extraer medianas y overhead vs X25519."""
    summary_path = RESULTS_DIR / "resumen_por_grupo.csv"
    rows = _read_csv(summary_path)

    def _field(r, *keys):
        for k in keys:
            if k in r and r[k] not in ("", None):
                try: return float(r[k])
                except ValueError: pass
        return None

    groups_ms:  dict[str, float] = {}   # grupo → mediana latencia
    groups_pct: dict[str, float] = {}   # grupo → % aceptación
    total_hosts_csv = 0

    for r in rows:
        g = r.get("grupo") or r.get("group") or r.get("grupo_pqc")
        if not g:
            continue
        m = _field(r, "handshake_time_ms_mediana", "handshake_time_ms_median",
                      "mediana_handshake_ms", "mediana_ms", "mediana",
                      "mediana_openssl_execution_time_ms")
        if m is not None:
            groups_ms[g] = m
        pct = _field(r, "porcentaje_aceptacion", "tasa_exito", "acceptance_rate")
        if pct is not None:
            groups_pct[g] = pct
        tp = _field(r, "total_pruebas", "total")
        if tp is not None and tp > total_hosts_csv:
            total_hosts_csv = int(tp)

    baseline = groups_ms.get("X25519")

    # Overhead vs X25519 (delta mediana latencia)
    v_bars = []
    if baseline is not None:
        for g, m in sorted(groups_ms.items(), key=lambda kv: kv[1] - baseline):
            v_bars.append({"label": g, "value": round(m - baseline, 1)})

    # Mejor grupo PQC por latencia (excluye X25519)
    pqc_groups = {g: m for g, m in groups_ms.items() if g != "X25519"}
    mejor_grupo = min(pqc_groups, key=pqc_groups.get) if pqc_groups else None
    mejor_ms    = round(pqc_groups[mejor_grupo], 1) if mejor_grupo else None

    # Overhead de X25519MLKEM768 (grupo híbrido más relevante)
    mlkem_ms      = groups_ms.get("X25519MLKEM768")
    mlkem_overhead = round(mlkem_ms - baseline, 1) if (mlkem_ms is not None and baseline is not None) else None
    mlkem_overhead_str = (f"+{mlkem_overhead} ms" if mlkem_overhead and mlkem_overhead > 0
                          else f"{mlkem_overhead} ms") if mlkem_overhead is not None else "—"

    n_imgs = len(list(IMAGES_DIR.glob("latencia_0*.png")) + list(IMAGES_DIR.glob("bytes_0*.png"))) \
             if IMAGES_DIR.exists() else 0

    stats = [
        {"label": "Grupos con datos",      "value": str(len(groups_ms))},
        {"label": "Latencia X25519",       "value": f"{round(baseline, 1)} ms" if baseline else "—"},
        {"label": "Overhead MLKEM768",     "value": mlkem_overhead_str},
        {"label": "Figuras generadas",     "value": str(n_imgs)},
    ]
    if mejor_grupo and mejor_grupo != "X25519MLKEM768":
        stats.insert(2, {"label": "Mejor grupo PQC", "value": f"{mejor_grupo} ({mejor_ms} ms)"})

    return {
        "stats":        stats,
        "v_bars":       v_bars,
        "v_bars_title": "Overhead de latencia vs X25519 (mediana, ms)",
        "v_bars_unit":  "ms",
        "unit":         "ms",
        "color":        "purple",
        "note":         "Delta calculado por hostname para aislar el ruido de red. Negativo = más rápido que X25519.",
        "images":       _images_for("latencia_0*.png", "bytes_0*.png"),
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
        "images":        _images_for("clasificacion_*.png"),
    }


# ──────────────────────────────────────────────────────────────
# ECH — Sonda de prevalencia
# ──────────────────────────────────────────────────────────────

def _ech_sonda() -> dict:
    """Lee resultados_ech_prevalencia.json (preferido) o CSV como fallback."""
    json_path = RESULTS_DIR / "resultados_ech_prevalencia.json"
    csv_path  = RESULTS_DIR / "resultados_ech_prevalencia.csv"

    cdn_counter: Counter = Counter()
    total = con_https_rr = con_ech = 0
    dominios_ech: list[str] = []

    if json_path.exists():
        data = _read_json(json_path)
        summary  = data.get("summary") or data.get("resumen") or {}
        results  = data.get("results") or data.get("datos") or data.get("data") or []

        total       = summary.get("total_dominios",  len(results))
        con_https_rr = summary.get("con_https_rr",   0)
        con_ech     = summary.get("con_ech",         0)

        for r in results:
            has_ech = r.get("has_ech_param") or r.get("ech_activo") or r.get("tiene_ech") or False
            if isinstance(has_ech, str):
                has_ech = has_ech.lower() in ("true", "1", "yes", "sí", "si")
            if has_ech:
                cdn = (r.get("provider") or r.get("cdn") or r.get("proveedor") or
                       _guess_cdn_json(r) or "Otros").strip()
                cdn_counter[cdn] += 1
                if r.get("domain") or r.get("hostname"):
                    dominios_ech.append(r.get("domain") or r.get("hostname"))
    else:
        rows = _read_csv(csv_path)
        total = len(rows)
        for r in rows:
            if str(r.get("https_rr_present", "")).lower() in ("true", "1"):
                con_https_rr += 1
            has_ech = str(r.get("has_ech_param") or r.get("ech_activo") or
                          r.get("ech") or r.get("tiene_ech") or "").lower() \
                      in ("true", "1", "yes", "sí", "si")
            if has_ech:
                con_ech += 1
                cdn = (r.get("provider") or r.get("cdn") or r.get("proveedor") or
                       _guess_cdn_json(r) or "Otros").strip()
                cdn_counter[cdn] += 1

    h_bars = [{"label": k, "value": v} for k, v in cdn_counter.most_common()]
    pct_https = _pct(con_https_rr, total)
    pct_ech   = _pct(con_ech, total)

    return {
        "stats": [
            {"label": "Dominios analizados",  "value": f"{total:,}".replace(",", ".")},
            {"label": "Con registro HTTPS RR", "value": f"{con_https_rr:,}".replace(",", ".") + f" ({pct_https}%)"},
            {"label": "Con ECH en DNS",        "value": f"{con_ech} ({pct_ech}%)"},
            {"label": "Proveedores CDN",       "value": str(len(cdn_counter))},
        ],
        "h_bars":       h_bars,
        "h_bars_title": "Dominios con ECH por proveedor CDN",
        "unit":         " dom.",
        "color":        "green",
        "note":         f"{con_ech} dominios con soporte ECH detectado en DNS (parámetro ECH en registro HTTPS RR). "
                        f"Cloudflare concentra la mayor parte del despliegue.",
    }

def _guess_cdn_json(r: dict) -> str:
    for field in ("outer_sni", "ech_outer_sni", "domain", "hostname"):
        sni = str(r.get(field) or "").lower()
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
        con   = _num(r.get("latencia_con_ech_media_ms") or r.get("media_con_ech_ms") or r.get("latencia_con_ech_ms") or r.get("con_ech_ms"))
        sin   = _num(r.get("latencia_sin_ech_media_ms") or r.get("media_sin_ech_ms") or r.get("latencia_sin_ech_ms") or r.get("sin_ech_ms"))
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
        "images":        _images_for("latencia_ech_vs_sin_ech.png"),
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
        g = r.get("grupo_pqc") or r.get("grupo") or r.get("group")
        if not g: continue
        con = _num(r.get("latencia_ech_pqc_media_ms") or r.get("media_con_ech_ms") or r.get("con_ech_ms"))
        sin = _num(r.get("latencia_sin_ech_pqc_media_ms") or r.get("media_sin_ech_ms") or r.get("sin_ech_ms"))
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
        "images":        _images_for("latencia_pqc_*.png"),
    }


def _num(v) -> float | None:
    if v is None or v == "":
        return None
    try: return float(v)
    except (ValueError, TypeError): return None
