"""
Gestor de jobs asíncronos.

Cada vez que el usuario pulsa "Ejecutar" en el dashboard se crea un Job:
  - se lanza el script correspondiente como subprocess
  - su stdout/stderr se captura línea a línea
  - cada línea va a dos sitios: una cola (para los SSE streams activos) y
    un log persistente (por si un segundo cliente se conecta a mitad)
  - cuando termina, el Job pasa a estado 'done' (exit 0), 'error' o 'cancelled'
"""

from __future__ import annotations
import os
import queue
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterator, Optional

from config import STEPS, REPO_ROOT


# ──────────────────────────────────────────────────────────────
# Modelo de Job
# ──────────────────────────────────────────────────────────────

class Job:
    def __init__(self, step_id: str, args: dict):
        self.id:         str = uuid.uuid4().hex[:12]
        self.step_id:    str = step_id
        self.args:       dict = args
        self.state:      str = "queued"  # queued | running | done | error | cancelled
        self.logs:       list[str] = []
        self.subscribers: list[queue.Queue] = []   # colas por cada cliente SSE
        self.subscribers_lock = threading.Lock()
        self.proc:       Optional[subprocess.Popen] = None
        self.exit_code:  Optional[int] = None
        self.started_at: float = time.time()
        self.ended_at:   Optional[float] = None
        self.cmd:        list[str] = []

    def as_dict(self) -> dict:
        return {
            "id":         self.id,
            "step_id":    self.step_id,
            "state":      self.state,
            "logs_count": len(self.logs),
            "exit_code":  self.exit_code,
            "started_at": self.started_at,
            "ended_at":   self.ended_at,
            "cmd":        self.cmd,
        }


# ──────────────────────────────────────────────────────────────
# Gestor singleton
# ──────────────────────────────────────────────────────────────

class JobManager:
    def __init__(self):
        self.jobs: dict[str, Job]   = {}
        self.latest_by_step: dict[str, str] = {}  # step_id → último job_id
        self.global_lock = threading.Lock()

    # — API pública —

    def start(self, step_id: str, args: dict) -> Job:
        if step_id not in STEPS:
            raise ValueError(f"step_id desconocido: {step_id}")

        # Si el step tiene un job running, no permitimos arrancar otro
        prev_id = self.latest_by_step.get(step_id)
        if prev_id:
            prev = self.jobs.get(prev_id)
            if prev and prev.state == "running":
                raise RuntimeError(f"Ya hay un job corriendo para {step_id}: {prev.id}")

        job = Job(step_id, args)
        job.cmd = STEPS[step_id]["build_cmd"](args)
        with self.global_lock:
            self.jobs[job.id] = job
            self.latest_by_step[step_id] = job.id

        t = threading.Thread(target=self._run, args=(job,), daemon=True)
        t.start()
        return job

    def stop(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if not job or job.state != "running" or not job.proc:
            return False
        try:
            # Matamos todo el process group para asegurarnos de pillar Docker
            os.killpg(os.getpgid(job.proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        job.state = "cancelled"
        self._broadcast(job, {"line": "[WARN] Job cancelado por el usuario", "state": "cancelled"})
        self._broadcast(job, None)  # sentinel de fin
        return True

    def get(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def latest(self, step_id: str) -> Optional[Job]:
        job_id = self.latest_by_step.get(step_id)
        return self.jobs.get(job_id) if job_id else None

    def subscribe(self, job: Job) -> Iterator[dict]:
        """
        Generator que emite eventos para un cliente SSE.
        Primero vuelca los logs ya acumulados; luego escucha líneas nuevas.
        """
        # 1) Snapshot de lo que ya hay
        initial = list(job.logs)
        for line in initial:
            yield {"line": line, "state": job.state}

        # 2) Si el job ya acabó, emitimos estado final y salimos
        if job.state != "running":
            yield {"state": job.state, "exit_code": job.exit_code, "done": True}
            return

        # 3) Suscripción para líneas futuras
        q: queue.Queue = queue.Queue()
        with job.subscribers_lock:
            job.subscribers.append(q)

        try:
            while True:
                try:
                    item = q.get(timeout=20)
                except queue.Empty:
                    yield {"heartbeat": True}
                    continue

                if item is None:
                    # sentinel de fin: job terminó
                    yield {"state": job.state, "exit_code": job.exit_code, "done": True}
                    break

                yield item
        finally:
            with job.subscribers_lock:
                if q in job.subscribers:
                    job.subscribers.remove(q)

    # — interno —

    def _broadcast(self, job: Job, item: Optional[dict]):
        with job.subscribers_lock:
            dead = []
            for q in job.subscribers:
                try:
                    q.put_nowait(item)
                except Exception:
                    dead.append(q)
            for q in dead:
                job.subscribers.remove(q)

    def _run(self, job: Job):
        job.state = "running"
        self._broadcast(job, {"state": "running",
                              "line": f"$ {' '.join(job.cmd)}"})
        job.logs.append(f"$ {' '.join(job.cmd)}")

        try:
            job.proc = subprocess.Popen(
                job.cmd,
                cwd=str(REPO_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid,   # crear process group (para Docker kill)
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
        except FileNotFoundError as e:
            msg = f"[ERROR] No se pudo ejecutar el comando: {e}"
            job.logs.append(msg)
            self._broadcast(job, {"line": msg, "state": "error"})
            job.state = "error"
            job.ended_at = time.time()
            self._broadcast(job, None)
            return

        # Leer stdout línea a línea
        assert job.proc.stdout is not None
        for raw in job.proc.stdout:
            line = raw.rstrip("\n")
            if not line:
                continue
            job.logs.append(line)
            self._broadcast(job, {"line": line, "state": "running"})

        job.proc.wait()
        job.exit_code = job.proc.returncode
        job.ended_at = time.time()

        if job.state == "cancelled":
            pass  # ya se puso a cancelled en stop()
        elif job.exit_code == 0:
            job.state = "done"
            job.logs.append(f"[SUCCESS] ✓ Ejecución completada (exit {job.exit_code})")
            self._broadcast(job, {"line": job.logs[-1], "state": "done"})
        else:
            job.state = "error"
            job.logs.append(f"[ERROR] Script terminó con código {job.exit_code}")
            self._broadcast(job, {"line": job.logs[-1], "state": "error"})

        # Señalizar fin a todos los subscribers
        self._broadcast(job, None)


# Singleton
job_manager = JobManager()
