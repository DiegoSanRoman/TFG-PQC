"""
test_sonda_latencia_ech.py
--------------------------
Tests unitarios para scripts/sondas/sonda_latencia_ech.py.

Cubre funciones puras y comportamiento observable sin I/O de red real:
  _parsear_bssl, _extraer_error, _agregar,
  ResultadoLatenciaECH, exportar_csv, construir_parser,
  _run_cmd (con subproceso real mínimo),
  procesar_hostname (con mocks de DNS y TLS).
"""

import asyncio
import csv
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_SCRIPTS_DIR = Path(__file__).parent.parent
_SONDAS_DIR = _SCRIPTS_DIR / "sondas"
for _p in (_SCRIPTS_DIR, _SONDAS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from sonda_latencia_ech import (
    DEFAULT_CONCURRENCY,
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_MAX_HOSTNAMES,
    DEFAULT_REPETICIONES,
    DEFAULT_TLS_TIMEOUT,
    ResultadoLatenciaECH,
    _agregar,
    _extraer_error,
    _parsear_bssl,
    _run_cmd,
    construir_parser,
    exportar_csv,
    procesar_hostname,
)


# ============================================
# _parsear_bssl
# ============================================

class TestParsearBssl:
    def test_detecta_cipher(self):
        stderr = "  Cipher: TLS_AES_128_GCM_SHA256\n  Version: TLSv1.3"
        cipher, _ = _parsear_bssl(stderr)
        assert cipher == "TLS_AES_128_GCM_SHA256"

    def test_detecta_ech_aceptado_yes(self):
        stderr = "  Encrypted ClientHello: yes\n  Cipher: TLS_AES_128_GCM_SHA256"
        _, ech = _parsear_bssl(stderr)
        assert ech is True

    def test_detecta_ech_aceptado_no(self):
        stderr = "  Encrypted ClientHello: no\n"
        _, ech = _parsear_bssl(stderr)
        assert ech is False

    def test_ech_case_insensitive(self):
        stderr = "  Encrypted ClientHello: YES\n"
        _, ech = _parsear_bssl(stderr)
        assert ech is True

    def test_sin_cipher_devuelve_none(self):
        stderr = "  Version: TLSv1.3\n  Handshake done."
        cipher, _ = _parsear_bssl(stderr)
        assert cipher is None

    def test_sin_ech_devuelve_none(self):
        stderr = "  Cipher: TLS_AES_256_GCM_SHA384\n"
        _, ech = _parsear_bssl(stderr)
        assert ech is None

    def test_salida_vacia(self):
        cipher, ech = _parsear_bssl("")
        assert cipher is None
        assert ech is None

    def test_ambos_campos_en_salida_real(self):
        stderr = (
            "Connecting to 1.2.3.4:443\n"
            "Handshake done.\n"
            "Connected.\n"
            "  Version: TLSv1.3\n"
            "  Resumed session: no\n"
            "  Cipher: TLS_AES_128_GCM_SHA256\n"
            "  ECDHE group: X25519\n"
            "  Encrypted ClientHello: yes\n"
        )
        cipher, ech = _parsear_bssl(stderr)
        assert cipher == "TLS_AES_128_GCM_SHA256"
        assert ech is True

    def test_ignora_lineas_irrelevantes(self):
        stderr = "  ECDHE group: X25519\n  Signature algorithm: ecdsa_secp256r1_sha256\n"
        cipher, ech = _parsear_bssl(stderr)
        assert cipher is None
        assert ech is None


# ============================================
# _extraer_error
# ============================================

class TestExtraerError:
    def test_timeout_devuelve_timeout(self):
        assert _extraer_error("", "", 124) == "TIMEOUT"

    def test_prioriza_lineas_con_error(self):
        stderr = "Connecting...\nHandshake started.\nSSL alert: error handshake failure\nDone."
        result = _extraer_error("", stderr, 1)
        assert "error" in result.lower() or "alert" in result.lower()

    def test_prioriza_lineas_con_fail(self):
        stderr = "line1\nconnection failed: timeout\nline3"
        result = _extraer_error("", stderr, 1)
        assert "fail" in result.lower()

    def test_sin_lineas_error_usa_ultimas_lineas(self):
        stderr = "line1\nline2\nlast line"
        result = _extraer_error("", stderr, 1)
        assert "last line" in result

    def test_stderr_vacio_usa_stdout(self):
        result = _extraer_error("stdout error info", "", 1)
        assert "stdout error info" in result

    def test_ambos_vacios_devuelve_fallido(self):
        result = _extraer_error("", "", 1)
        assert result == "HANDSHAKE_FALLIDO"

    def test_trunca_a_400_caracteres(self):
        stderr = "error: " + "x" * 500
        result = _extraer_error("", stderr, 1)
        assert len(result) <= 400

    def test_ultimas_tres_lineas_relevantes(self):
        stderr = "err1\nerr2\nerr3\nerr4"
        result = _extraer_error("", stderr, 1)
        # Debe incluir alguna de las últimas líneas
        assert any(f"err{i}" in result for i in range(1, 5))


# ============================================
# _agregar
# ============================================

class TestAgregar:
    def test_lista_vacia_devuelve_nones(self):
        assert _agregar([]) == (None, None)

    def test_un_elemento_stddev_cero(self):
        media, stddev = _agregar([42.0])
        assert media == 42.0
        assert stddev == 0.0

    def test_media_correcta(self):
        media, _ = _agregar([10.0, 20.0, 30.0])
        assert media == 20.0

    def test_stddev_correcta(self):
        # stdev([10, 20, 30]) = sqrt(200/2) = 10.0  (corrección de Bessel, n-1)
        _, stddev = _agregar([10.0, 20.0, 30.0])
        assert abs(stddev - 10.0) < 0.01

    def test_valores_iguales_stddev_cero(self):
        _, stddev = _agregar([5.0, 5.0, 5.0])
        assert stddev == 0.0

    def test_redondeo_dos_decimales(self):
        media, stddev = _agregar([1.111, 2.222, 3.333])
        assert media == round(media, 2)
        assert stddev == round(stddev, 2)

    def test_un_elemento_media_igual_al_valor(self):
        media, _ = _agregar([99.5])
        assert media == 99.5


# ============================================
# ResultadoLatenciaECH (dataclass)
# ============================================

class TestResultadoLatenciaECH:
    def _hacer_resultado(self, **kwargs) -> ResultadoLatenciaECH:
        defaults = dict(
            hostname="example.com",
            timestamp="2026-01-01T00:00:00+00:00",
            ech_config_disponible=True,
            conexion_ech_exitosa=True,
            conexion_sin_ech_exitosa=True,
            ech_aceptado=True,
            cipher_con_ech="TLS_AES_128_GCM_SHA256",
            cipher_sin_ech="TLS_AES_128_GCM_SHA256",
            latencia_dns_ms=5.0,
            n_mediciones=3,
            latencia_con_ech_media_ms=25.0,
            latencia_con_ech_stddev_ms=1.5,
            latencia_sin_ech_media_ms=20.0,
            latencia_sin_ech_stddev_ms=0.8,
            delta_medio_ms=-5.0,
            cliente_tls="bssl",
            outer_sni="cloudflare-ech.com",
            error_ech=None,
            error_sin_ech=None,
            dns_error=None,
            ip_pop=None,
        )
        defaults.update(kwargs)
        return ResultadoLatenciaECH(**defaults)

    def test_creacion_basica(self):
        r = self._hacer_resultado()
        assert r.hostname == "example.com"
        assert r.ech_aceptado is True
        assert r.delta_medio_ms == -5.0

    def test_campos_opcionales_aceptan_none(self):
        r = self._hacer_resultado(
            ech_aceptado=None,
            cipher_con_ech=None,
            latencia_con_ech_media_ms=None,
            delta_medio_ms=None,
        )
        assert r.ech_aceptado is None
        assert r.delta_medio_ms is None

    def test_asdict_incluye_todos_los_campos(self):
        r = self._hacer_resultado()
        d = asdict(r)
        campos_esperados = {
            "hostname", "timestamp", "ech_config_disponible",
            "conexion_ech_exitosa", "conexion_sin_ech_exitosa",
            "ech_aceptado", "cipher_con_ech", "cipher_sin_ech",
            "latencia_dns_ms", "n_mediciones",
            "latencia_con_ech_media_ms", "latencia_con_ech_stddev_ms",
            "latencia_sin_ech_media_ms", "latencia_sin_ech_stddev_ms",
            "delta_medio_ms", "cliente_tls", "outer_sni",
            "error_ech", "error_sin_ech", "dns_error",
            "ip_pop",
        }
        assert campos_esperados == set(d.keys())

    def test_n_mediciones_entero(self):
        r = self._hacer_resultado(n_mediciones=5)
        assert isinstance(r.n_mediciones, int)
        assert r.n_mediciones == 5


# ============================================
# exportar_csv
# ============================================

class TestExportarCsv:
    def _resultado_ejemplo(self) -> ResultadoLatenciaECH:
        return ResultadoLatenciaECH(
            hostname="wpguardian.com",
            timestamp="2026-01-01T12:00:00+00:00",
            ech_config_disponible=True,
            conexion_ech_exitosa=True,
            conexion_sin_ech_exitosa=True,
            ech_aceptado=True,
            cipher_con_ech="TLS_AES_128_GCM_SHA256",
            cipher_sin_ech="TLS_AES_128_GCM_SHA256",
            latencia_dns_ms=3.5,
            n_mediciones=3,
            latencia_con_ech_media_ms=25.0,
            latencia_con_ech_stddev_ms=1.2,
            latencia_sin_ech_media_ms=20.0,
            latencia_sin_ech_stddev_ms=0.5,
            delta_medio_ms=-5.0,
            cliente_tls="bssl",
            outer_sni="cloudflare-ech.com",
            error_ech=None,
            error_sin_ech=None,
            dns_error=None,
            ip_pop="1.2.3.4",
        )

    def test_crea_archivo(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.csv"
            exportar_csv([self._resultado_ejemplo()], path)
            assert path.exists()

    def test_cabeceras_correctas(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.csv"
            exportar_csv([self._resultado_ejemplo()], path)
            with path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                assert "ech_aceptado" in reader.fieldnames
                assert "cipher_con_ech" in reader.fieldnames
                assert "latencia_dns_ms" in reader.fieldnames
                assert "latencia_con_ech_media_ms" in reader.fieldnames
                assert "latencia_con_ech_stddev_ms" in reader.fieldnames
                assert "delta_medio_ms" in reader.fieldnames
                assert "n_mediciones" in reader.fieldnames
                assert "ip_pop" in reader.fieldnames

    def test_una_fila_por_resultado(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.csv"
            exportar_csv([self._resultado_ejemplo(), self._resultado_ejemplo()], path)
            with path.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            assert len(rows) == 2

    def test_valores_en_fila(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.csv"
            exportar_csv([self._resultado_ejemplo()], path)
            with path.open(newline="", encoding="utf-8") as fh:
                row = next(csv.DictReader(fh))
            assert row["hostname"] == "wpguardian.com"
            assert row["cipher_con_ech"] == "TLS_AES_128_GCM_SHA256"
            assert row["delta_medio_ms"] == "-5.0"
            assert row["n_mediciones"] == "3"

    def test_lista_vacia_solo_cabeceras(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.csv"
            exportar_csv([], path)
            with path.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            assert rows == []

    def test_crea_directorio_si_no_existe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "subdir" / "out.csv"
            exportar_csv([], path)
            assert path.exists()


# ============================================
# construir_parser
# ============================================

class TestConstruirParser:
    def test_valores_por_defecto_repeticiones(self):
        parser = construir_parser()
        args = parser.parse_args([])
        assert args.repeticiones == DEFAULT_REPETICIONES

    def test_valores_por_defecto_timeouts(self):
        args = construir_parser().parse_args([])
        assert args.dns_timeout == DEFAULT_DNS_TIMEOUT
        assert args.tls_timeout == DEFAULT_TLS_TIMEOUT

    def test_valores_por_defecto_concurrencia(self):
        args = construir_parser().parse_args([])
        assert args.concurrency == DEFAULT_CONCURRENCY

    def test_valores_por_defecto_max_hostnames(self):
        args = construir_parser().parse_args([])
        assert args.max_hostnames == DEFAULT_MAX_HOSTNAMES

    def test_argumento_repeticiones(self):
        args = construir_parser().parse_args(["--repeticiones", "10"])
        assert args.repeticiones == 10

    def test_argumento_tls_timeout(self):
        args = construir_parser().parse_args(["--tls-timeout", "20.0"])
        assert args.tls_timeout == 20.0

    def test_argumento_concurrency(self):
        args = construir_parser().parse_args(["--concurrency", "50"])
        assert args.concurrency == 50

    def test_argumento_input_csv(self):
        args = construir_parser().parse_args(["--input-csv", "mi_fichero.csv"])
        assert args.input_csv == "mi_fichero.csv"

    def test_argumento_log_level(self):
        args = construir_parser().parse_args(["--log-level", "DEBUG"])
        assert args.log_level == "DEBUG"

    def test_seed_por_defecto_none(self):
        args = construir_parser().parse_args([])
        assert args.seed is None

    def test_argumento_seed(self):
        args = construir_parser().parse_args(["--seed", "42"])
        assert args.seed == 42


# ============================================
# _run_cmd
# ============================================

class TestRunCmd:
    def test_comando_exitoso_devuelve_rc_cero(self):
        rc, stdout, stderr = asyncio.run(_run_cmd(["true"], timeout=5.0))
        assert rc == 0

    def test_comando_fallido_devuelve_rc_no_cero(self):
        rc, _, _ = asyncio.run(_run_cmd(["false"], timeout=5.0))
        assert rc != 0

    def test_captura_stdout(self):
        rc, stdout, _ = asyncio.run(_run_cmd(["echo", "hola"], timeout=5.0))
        assert "hola" in stdout

    def test_captura_stderr(self):
        rc, _, stderr = asyncio.run(
            _run_cmd(["sh", "-c", "echo err >&2"], timeout=5.0)
        )
        assert "err" in stderr

    def test_timeout_devuelve_rc_124(self):
        rc, _, stderr = asyncio.run(_run_cmd(["sleep", "60"], timeout=0.1))
        assert rc == 124
        assert "TIMEOUT" in stderr

    def test_input_data_llega_al_proceso(self):
        rc, stdout, _ = asyncio.run(
            _run_cmd(["cat"], timeout=5.0, input_data=b"prueba\n")
        )
        assert "prueba" in stdout


# ============================================
# procesar_hostname (con mocks)
# ============================================

_BSSL_FAKE = "/fake/bssl"

_PARSED_CONFIGS = [{"public_name": "cloudflare-ech.com", "kem_id": 32}]
_ECH_VALUE = "AAAA"  # valor ficticio, no se decodifica porque mockeamos _medir_intercalado


class TestProcesarHostnameSinEch:
    """Casos donde el hostname no tiene configuración ECH disponible."""

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_resolver(self):
        return MagicMock()

    def _make_semaphore(self):
        return asyncio.Semaphore(1)

    def test_sin_https_rr(self):
        with patch(
            "sonda_latencia_ech.descubrir_https_rr",
            new=AsyncMock(return_value=(False, None, None, None)),
        ), patch("sonda_latencia_ech.resolver_cliente_tls", return_value=("bssl", _BSSL_FAKE, None)):
            r = self._run(procesar_hostname(
                "snapchat.com", self._make_resolver(), self._make_semaphore(), 5.0, 10.0, 3
            ))
        assert r.ech_config_disponible is False
        assert r.conexion_ech_exitosa is False
        assert "Sin HTTPS RR" in (r.error_ech or "")

    def test_https_rr_sin_parametro_ech(self):
        with patch(
            "sonda_latencia_ech.descubrir_https_rr",
            new=AsyncMock(return_value=(True, None, None, None)),
        ), patch("sonda_latencia_ech.resolver_cliente_tls", return_value=("bssl", _BSSL_FAKE, None)):
            r = self._run(procesar_hostname(
                "google.com", self._make_resolver(), self._make_semaphore(), 5.0, 10.0, 3
            ))
        assert r.ech_config_disponible is False
        assert "Sin parámetro ECH" in (r.error_ech or "")

    def test_sin_bssl(self):
        with patch(
            "sonda_latencia_ech.descubrir_https_rr",
            new=AsyncMock(return_value=(True, _ECH_VALUE, _PARSED_CONFIGS, None)),
        ), patch("sonda_latencia_ech.resolver_cliente_tls", return_value=("bssl", None, None)):
            r = self._run(procesar_hostname(
                "example.com", self._make_resolver(), self._make_semaphore(), 5.0, 10.0, 3
            ))
        assert r.ech_config_disponible is False
        assert "bssl no disponible" in (r.error_ech or "")

    def test_dns_error_se_propaga(self):
        with patch(
            "sonda_latencia_ech.descubrir_https_rr",
            new=AsyncMock(return_value=(False, None, None, "NXDOMAIN")),
        ), patch("sonda_latencia_ech.resolver_cliente_tls", return_value=("bssl", _BSSL_FAKE, None)):
            r = self._run(procesar_hostname(
                "nxdomain.test", self._make_resolver(), self._make_semaphore(), 5.0, 10.0, 3
            ))
        assert r.dns_error == "NXDOMAIN"


class TestProcesarHostnameConEch:
    """Casos donde ECH está disponible y se intenta la conexión."""

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_semaphore(self):
        return asyncio.Semaphore(1)

    def _mock_dns_ok(self):
        return patch(
            "sonda_latencia_ech.descubrir_https_rr",
            new=AsyncMock(return_value=(True, _ECH_VALUE, _PARSED_CONFIGS, None)),
        )

    def _mock_bssl(self):
        return patch(
            "sonda_latencia_ech.resolver_cliente_tls",
            return_value=("bssl", _BSSL_FAKE, None),
        )

    def test_ech_falla_sin_ech_se_mide_igual(self):
        with self._mock_dns_ok(), self._mock_bssl(), patch(
            "sonda_latencia_ech._medir_intercalado",
            new=AsyncMock(return_value=(
                False, True, [], [20.0, 21.0],
                "CONNECTION_REFUSED", None, None, None, "TLS_AES_128_GCM_SHA256",
            )),
        ):
            r = self._run(procesar_hostname(
                "example.com", MagicMock(), self._make_semaphore(), 5.0, 10.0, 3
            ))
        assert r.conexion_ech_exitosa is False
        assert r.conexion_sin_ech_exitosa is True
        assert r.error_ech == "CONNECTION_REFUSED"
        assert r.latencia_sin_ech_media_ms is not None

    def test_exito_completo(self):
        with self._mock_dns_ok(), self._mock_bssl(), patch(
            "sonda_latencia_ech._medir_intercalado",
            new=AsyncMock(return_value=(
                True, True, [25.0, 26.0, 24.0], [20.0, 21.0, 19.0],
                None, None, True, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256",
            )),
        ):
            r = self._run(procesar_hostname(
                "wpguardian.com", MagicMock(), self._make_semaphore(), 5.0, 10.0, 3
            ))
        assert r.conexion_ech_exitosa is True
        assert r.conexion_sin_ech_exitosa is True
        assert r.ech_aceptado is True
        assert r.cipher_con_ech == "TLS_AES_128_GCM_SHA256"
        assert r.n_mediciones == 3
        assert r.latencia_con_ech_media_ms == 25.0
        assert r.delta_medio_ms is not None

    def test_delta_es_sin_ech_menos_con_ech(self):
        with self._mock_dns_ok(), self._mock_bssl(), patch(
            "sonda_latencia_ech._medir_intercalado",
            new=AsyncMock(return_value=(
                True, True, [30.0], [20.0],
                None, None, True, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256",
            )),
        ):
            r = self._run(procesar_hostname(
                "example.com", MagicMock(), self._make_semaphore(), 5.0, 10.0, 1
            ))
        # delta = sin_ech - con_ech = 20 - 30 = -10
        assert r.delta_medio_ms == -10.0

    def test_outer_sni_se_captura(self):
        with self._mock_dns_ok(), self._mock_bssl(), patch(
            "sonda_latencia_ech._medir_intercalado",
            new=AsyncMock(return_value=(
                True, True, [25.0], [20.0],
                None, None, True, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256",
            )),
        ):
            r = self._run(procesar_hostname(
                "example.com", MagicMock(), self._make_semaphore(), 5.0, 10.0, 1
            ))
        assert r.outer_sni == "cloudflare-ech.com"

    def test_latencia_dns_se_mide(self):
        with self._mock_dns_ok(), self._mock_bssl(), patch(
            "sonda_latencia_ech._medir_intercalado",
            new=AsyncMock(return_value=(
                True, True, [25.0], [20.0],
                None, None, True, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256",
            )),
        ):
            r = self._run(procesar_hostname(
                "example.com", MagicMock(), self._make_semaphore(), 5.0, 10.0, 1
            ))
        assert r.latencia_dns_ms is not None
        assert r.latencia_dns_ms >= 0.0

    def test_sin_ech_falla_delta_es_none(self):
        with self._mock_dns_ok(), self._mock_bssl(), patch(
            "sonda_latencia_ech._medir_intercalado",
            new=AsyncMock(return_value=(
                True, False, [25.0], [],
                None, "TIMEOUT", True, "TLS_AES_128_GCM_SHA256", None,
            )),
        ):
            r = self._run(procesar_hostname(
                "example.com", MagicMock(), self._make_semaphore(), 5.0, 10.0, 1
            ))
        assert r.conexion_ech_exitosa is True
        assert r.conexion_sin_ech_exitosa is False
        assert r.delta_medio_ms is None
        assert r.error_sin_ech == "TIMEOUT"
