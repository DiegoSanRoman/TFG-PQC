"""
conftest.py
-----------
Configuración de pytest: añade scripts/, scripts/sondas/ y scripts/ml/ al sys.path
para que los tests puedan importar módulos directamente sin manipulación manual de paths.
"""
import sys
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parents[1]
_SONDAS_DIR = _SCRIPTS_DIR / "sondas"
_ML_DIR = _SCRIPTS_DIR / "ml"

for _p in (_SCRIPTS_DIR, _SONDAS_DIR, _ML_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
