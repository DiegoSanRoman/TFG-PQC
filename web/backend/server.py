"""
Servidor Flask para el dashboard web de TFG-PQC.

Expone:
  GET  /                          → sirve el frontend (index.html)
  GET  /src/<path>                → sirve los .jsx/.js del frontend
  GET  /api/steps                 → catálogo de steps + schema de args
  POST /api/jobs/start            → arranca un job: {step_id, args} → {job_id}
  GET  /api/jobs/<id>             → estado del job
  GET  /api/jobs/<id>/stream      → SSE con las líneas del subprocess
  POST /api/jobs/<id>/stop        → cancela un job en ejecución
  GET  /api/jobs/step/<step_id>   → último job del step (si existe)
  GET  /api/results/<step_id>     → datos reales parseados de resultados/
  GET  /api/images/<filename>     → sirve imágenes de imagenes/

Arranque:
  python3 server.py           # dev, puerto 5001
  PORT=8080 python3 server.py # para cambiar puerto
"""

from __future__ import annotations
import json
import os
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory, abort
from flask_cors import CORS

from config  import STEPS, IMAGES_DIR
from jobs    import job_manager
from results import load_results


# Rutas del frontend (web/frontend/)
FRONT_ROOT = Path(__file__).resolve().parent.parent / "frontend"

app = Flask(__name__, static_folder=None)
CORS(app)   # permisivo: util para desarrollar frontend en otro puerto


# ──────────────────────────────────────────────────────────────
# Frontend estático
# ──────────────────────────────────────────────────────────────

@app.route("/")
def root():
    return send_from_directory(FRONT_ROOT, "index.html")

@app.route("/src/<path:path>")
def frontend_src(path):
    return send_from_directory(FRONT_ROOT / "src", path)

@app.route("/favicon.ico")
def favicon():
    # evitar 404 ruidosos
    return ("", 204)


# ──────────────────────────────────────────────────────────────
# API: catálogo de pasos
# ──────────────────────────────────────────────────────────────

def _step_public(step_id: str) -> dict:
    s = STEPS[step_id]
    return {
        "id":       step_id,
        "pipeline": s["pipeline"],
        "num":      s["num"],
        "label":    s["label"],
        "script":   s["script"],
        "desc":     s["desc"],
        "unlocks":  s["unlocks"],
        "args":     s["args"],
    }

@app.route("/api/steps")
def list_steps():
    return jsonify([_step_public(k) for k in STEPS.keys()])


# ──────────────────────────────────────────────────────────────
# API: jobs
# ──────────────────────────────────────────────────────────────

@app.route("/api/jobs/start", methods=["POST"])
def start_job():
    data = request.get_json(silent=True) or {}
    step_id = data.get("step_id")
    args    = data.get("args") or {}
    if not step_id:
        return jsonify({"error": "step_id requerido"}), 400
    try:
        job = job_manager.start(step_id, args)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409
    return jsonify({"job_id": job.id, "cmd": job.cmd})


@app.route("/api/jobs/<job_id>")
def job_info(job_id):
    job = job_manager.get(job_id)
    if not job: return jsonify({"error": "job no encontrado"}), 404
    return jsonify({**job.as_dict(), "logs": job.logs})


@app.route("/api/jobs/step/<step_id>")
def latest_job_for_step(step_id):
    job = job_manager.latest(step_id)
    if not job: return jsonify(None)
    return jsonify({**job.as_dict(), "logs": job.logs})


@app.route("/api/jobs/<job_id>/stream")
def stream_job(job_id):
    job = job_manager.get(job_id)
    if not job:
        return jsonify({"error": "job no encontrado"}), 404

    def gen():
        # Ping inicial para asegurarse de que el cliente ve la conexión abierta
        yield ": connected\n\n"
        for evt in job_manager.subscribe(job):
            yield f"data: {json.dumps(evt, ensure_ascii=False)}\n\n"

    # text/event-stream; Nginx y proxies suelen necesitar X-Accel-Buffering off
    headers = {
        "Cache-Control":     "no-cache",
        "X-Accel-Buffering": "no",
        "Connection":        "keep-alive",
    }
    return Response(gen(), mimetype="text/event-stream", headers=headers)


@app.route("/api/jobs/<job_id>/stop", methods=["POST"])
def stop_job(job_id):
    ok = job_manager.stop(job_id)
    return jsonify({"ok": ok})


# ──────────────────────────────────────────────────────────────
# API: resultados e imágenes
# ──────────────────────────────────────────────────────────────

@app.route("/api/results/<step_id>")
def get_results(step_id):
    if step_id not in STEPS:
        return jsonify({"error": "step desconocido"}), 404
    return jsonify(load_results(step_id))


@app.route("/api/images/<path:filename>")
def get_image(filename):
    if not IMAGES_DIR.exists():
        abort(404)
    return send_from_directory(IMAGES_DIR, filename)


@app.route("/api/images")
def list_images():
    if not IMAGES_DIR.exists():
        return jsonify([])
    return jsonify(sorted(p.name for p in IMAGES_DIR.glob("*.png")))


# ──────────────────────────────────────────────────────────────
# Arranque
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", "5001"))
    debug = os.environ.get("DEBUG", "0") == "1"
    print(f"\n  ▶ TFG-PQC Dashboard  http://localhost:{port}\n")
    # threaded=True es esencial: SSE necesita mantener la conexión abierta
    # mientras otros endpoints atienden requests nuevas.
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
