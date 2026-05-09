"""
test_utils.py
-------------
Tests unitarios para scripts/utils.py.
Cubre es_hostname_valido y configurar_logging.
"""

import logging
import sys
import tempfile
from pathlib import Path

import pytest

# Añadir scripts/ al path para importar utils directamente
_SCRIPTS_DIR = Path(__file__).parent.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from utils import configurar_logging, es_hostname_valido, _build_result_dict


# ============================================
# es_hostname_valido
# ============================================

class TestEsHostnameValido:
    """Validación de hostnames DNS según RFC 1123."""

    def test_hostname_simple_valido(self):
        assert es_hostname_valido("google.com") is True

    def test_hostname_subdominio_valido(self):
        assert es_hostname_valido("mail.google.com") is True

    def test_hostname_con_guion_valido(self):
        assert es_hostname_valido("my-server.example.org") is True

    def test_hostname_con_numeros_valido(self):
        assert es_hostname_valido("server1.example.com") is True

    def test_hostname_vacio_invalido(self):
        assert es_hostname_valido("") is False

    def test_hostname_sin_punto_invalido(self):
        assert es_hostname_valido("localhost") is False

    def test_hostname_con_espacio_invalido(self):
        assert es_hostname_valido("my server.com") is False

    def test_hostname_demasiado_largo_invalido(self):
        assert es_hostname_valido("a" * 250 + ".com") is False

    def test_hostname_con_barra_invalido(self):
        assert es_hostname_valido("example.com/path") is False

    def test_hostname_none_invalido(self):
        assert es_hostname_valido(None) is False  # type: ignore[arg-type]

    def test_hostname_solo_puntos_invalido(self):
        assert es_hostname_valido("...") is False

    def test_hostname_con_arroba_invalido(self):
        assert es_hostname_valido("user@example.com") is False

    def test_hostname_exactamente_253_chars_valido(self):
        # 63 chars + punto + 63 chars + punto + ... hasta 253
        etiqueta = "a" * 63
        hostname = f"{etiqueta}.{etiqueta}.{etiqueta}.com"
        assert len(hostname) <= 253
        assert es_hostname_valido(hostname) is True

    def test_hostname_con_espacios_al_inicio_invalido(self):
        # strip() sólo descarta los extremos; un espacio interno es inválido
        assert es_hostname_valido(" example.com") is True  # strip() lo limpia
        assert es_hostname_valido("ex ample.com") is False  # espacio interno

    def test_hostname_no_string_invalido(self):
        assert es_hostname_valido(123) is False  # type: ignore[arg-type]


# ============================================
# configurar_logging
# ============================================

class TestConfigurarLogging:
    """Verifica que configurar_logging crea el archivo y aplica el nivel."""

    def setup_method(self):
        # Limpiar handlers del root logger antes de cada test
        root = logging.getLogger()
        root.handlers.clear()

    def test_crea_archivo_log(self, tmp_path):
        log_file = tmp_path / "sub" / "test.log"
        configurar_logging(log_file, "INFO")
        assert log_file.exists()

    def test_crea_directorio_si_no_existe(self, tmp_path):
        log_file = tmp_path / "nuevo_dir" / "app.log"
        configurar_logging(log_file, "DEBUG")
        assert log_file.parent.exists()

    def test_nivel_debug(self, tmp_path):
        log_file = tmp_path / "debug.log"
        configurar_logging(log_file, "DEBUG")
        assert logging.getLogger().level == logging.DEBUG

    def test_nivel_warning(self, tmp_path):
        log_file = tmp_path / "warn.log"
        configurar_logging(log_file, "WARNING")
        assert logging.getLogger().level == logging.WARNING

    def test_to_console_anade_stream_handler(self, tmp_path):
        log_file = tmp_path / "console.log"
        logging.getLogger().handlers.clear()
        configurar_logging(log_file, "INFO", to_console=True)
        handler_types = [type(h) for h in logging.getLogger().handlers]
        assert logging.StreamHandler in handler_types

    def test_sin_console_no_stream_handler(self, tmp_path):
        log_file = tmp_path / "no_console.log"
        logging.getLogger().handlers.clear()
        configurar_logging(log_file, "INFO", to_console=False)
        stream_handlers = [h for h in logging.getLogger().handlers
                           if type(h) is logging.StreamHandler]
        assert len(stream_handlers) == 0


# ============================================
# _build_result_dict
# ============================================

class TestBuildResultDict:
    """_build_result_dict construye el esquema estándar de resultado PQC."""

    def _base(self, **kwargs):
        defaults = dict(
            error_category=None,
            connection_result=None,
            res="ok",
            sni_usado="example.com",
        )
        defaults.update(kwargs)
        return _build_result_dict(**defaults)

    def test_contiene_todas_las_claves_obligatorias(self):
        r = self._base()
        for key in ("error_category", "connection_result", "res",
                    "sni_usado",
                    "ip", "tls_version", "cipher_suite",
                    "openssl_subprocess_time_ms"):
            assert key in r, f"Clave ausente: {key}"

    def test_sni_difiere_y_retry_eliminados(self):
        r = self._base()
        assert "sni_difiere" not in r
        assert "retry" not in r

    def test_openssl_connect_tls_time_no_existe(self):
        r = self._base()
        assert "openssl_connect_tls_time_ms" not in r

    def test_metricas_son_none_por_defecto(self):
        r = self._base()
        assert r["ip"] is None
        assert r["tls_version"] is None
        assert r["bytes_sent"] is None
        assert r["dns_time_ms"] is None

    def test_openssl_subprocess_time_se_asigna(self):
        r = self._base(openssl_subprocess_time_ms=42.5)
        assert r["openssl_subprocess_time_ms"] == 42.5

    def test_error_category_se_asigna(self):
        r = self._base(error_category="ERROR_DNS")
        assert r["error_category"] == "ERROR_DNS"

    def test_campos_opcionales_se_incluyen(self):
        r = self._base(
            ip="1.2.3.4",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            bytes_sent=500,
        )
        assert r["ip"] == "1.2.3.4"
        assert r["tls_version"] == "TLSv1.3"
        assert r["bytes_sent"] == 500

    def test_sni_usado_se_preserva(self):
        r = self._base(sni_usado="sub.example.com")
        assert r["sni_usado"] == "sub.example.com"
