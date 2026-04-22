#!/usr/bin/env bash
# ejecutar_web.sh — levanta el dashboard web de TFG-PQC
set -e

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

VENV_DIR="web/backend/.venv"
PORT="${PORT:-5001}"

# ── Crear venv si no existe ─────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
  echo "──▶ Creando venv dedicado en $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "──▶ Instalando dependencias…"
pip install -q --upgrade pip
pip install -q -r web/backend/requirements.txt

# ── Arranque ────────────────────────────────────────────────────
cat <<EOF

╭──────────────────────────────────────────────╮
│  TFG-PQC · Research Dashboard                │
│  http://localhost:${PORT}                       │
╰──────────────────────────────────────────────╯
   Backend:  web/backend/server.py
   Frontend: web/frontend/index.html
   Ctrl+C   para detener

EOF

cd web/backend
PORT="$PORT" exec python3 server.py
