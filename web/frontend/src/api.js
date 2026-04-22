// src/api.js — cliente HTTP + SSE, expuesto como window.API
(function () {
  const BASE = ""; // mismo origen que sirve el frontend

  async function _json(r) {
    if (!r.ok) {
      let detail = "";
      try { detail = (await r.json()).error || ""; } catch (e) { /* ignore */ }
      throw new Error(`${r.status} ${r.statusText}${detail ? " — " + detail : ""}`);
    }
    return r.json();
  }

  // ── Catálogo de steps (opcional; App.jsx los tiene hardcoded) ──
  async function fetchSteps() {
    return _json(await fetch(`${BASE}/api/steps`));
  }

  // ── Jobs ──
  async function startJob(stepId, args) {
    return _json(await fetch(`${BASE}/api/jobs/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ step_id: stepId, args }),
    }));
  }

  async function stopJob(jobId) {
    return _json(await fetch(`${BASE}/api/jobs/${jobId}/stop`, { method: "POST" }));
  }

  async function fetchJob(jobId) {
    return _json(await fetch(`${BASE}/api/jobs/${jobId}`));
  }

  async function fetchLatestJob(stepId) {
    const r = await fetch(`${BASE}/api/jobs/step/${stepId}`);
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json(); // puede ser null
  }

  /**
   * streamJob(jobId, handlers) → devuelve función de limpieza.
   * handlers: { onLine(line), onState(state), onDone(state, exitCode), onError(err) }
   */
  function streamJob(jobId, handlers = {}) {
    const { onLine, onState, onDone, onError } = handlers;
    const es = new EventSource(`${BASE}/api/jobs/${jobId}/stream`);

    let lastState = null;

    es.onmessage = (ev) => {
      let payload;
      try { payload = JSON.parse(ev.data); }
      catch (e) { return; }

      if (payload.heartbeat) return;

      if (typeof payload.line === "string" && onLine) onLine(payload.line);

      if (payload.state && payload.state !== lastState) {
        lastState = payload.state;
        if (onState) onState(payload.state);
      }

      if (payload.done) {
        if (onDone) onDone(payload.state, payload.exit_code);
        es.close();
      }
    };

    es.onerror = (e) => {
      // EventSource intenta re-conectar por defecto, lo cerramos nosotros.
      // Si el job ya terminó no es un error real.
      if (es.readyState === EventSource.CLOSED) return;
      if (onError) onError(e);
    };

    return () => es.close();
  }

  // ── Resultados ──
  async function fetchResults(stepId) {
    return _json(await fetch(`${BASE}/api/results/${stepId}`));
  }

  async function fetchImages() {
    return _json(await fetch(`${BASE}/api/images`));
  }

  function imageUrl(filename) {
    return `${BASE}/api/images/${encodeURIComponent(filename)}`;
  }

  window.API = {
    fetchSteps,
    startJob, stopJob, fetchJob, fetchLatestJob, streamJob,
    fetchResults, fetchImages, imageUrl,
  };
})();
