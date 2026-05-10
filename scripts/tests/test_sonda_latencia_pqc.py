"""
test_sonda_latencia_pqc.py
--------------------------
Tests unitarios para scripts/sondas/sonda_latencia_pqc.py.

Cubre funciones puras y comportamiento observable sin I/O de red real:
  ResultadoLatenciaPQC, BSSL_CURVE_MAP,
  exportar_csv, construir_parser,
  procesar_hostname_grupo (con mocks de _medir_bssl y _medir_oqs),
  procesar_hostname (con mocks de DNS y TLS).
"""

import asyncio
import csv
import tempfile
from dataclasses import asdict
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sonda_latencia_pqc import (
    BSSL_CURVE_MAP,
    DEFAULT_CONCURRENCY,
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_MAX_HOSTNAMES,
    DEFAULT_OQS_BIN,
    DEFAULT_REPETICIONES,
    DEFAULT_TLS_TIMEOUT,
    ResultadoLatenciaPQC,
    construir_parser,
    exportar_csv,
    procesar_hostname,
    procesar_hostname_grupo,
)

_BSSL_FAKE = "/fake/bssl"
_OQS_FAKE = "/fake/openssl"
_ECH_VALUE = "AAAA"
_PARSED_CONFIGS = [{"public_name": "cloudflare-ech.com", "kem_id": 32}]

# Retornos mock estándar: (ok, latencias, error, ech_aceptado, cipher)
_BSSL_OK = (True, [25.0, 26.0, 24.0], None, True, "TLS_AES_128_GCM_SHA256")
_BSSL_OK_SIN_ECH = (True, [20.0, 21.0, 19.0], None, None, "TLS_AES_128_GCM_SHA256")
_BSSL_FAIL = (False, [], "CONNECTION_REFUSED", None, None)
# Retornos mock OQS: (ok, latencias, error, cipher)
_OQS_OK = (True, [30.0, 31.0, 29.0], None, "TLS_AES_256_GCM_SHA384")
_OQS_FAIL = (False, [], "OQS_ERROR", None)


# ============================================
# ResultadoLatenciaPQC (dataclass)
# ============================================

class TestResultadoLatenciaPQC:
    def _hacer_resultado(self, **kwargs) -> ResultadoLatenciaPQC:
        defaults = dict(
            hostname="example.com",
            timestamp="2026-01-01T00:00:00+00:00",
            grupo_pqc="X25519MLKEM768",
            cliente_pqc="bssl",
            ech_config_disponible=True,
            ech_soportado_por_grupo=True,
            conexion_ech_pqc_exitosa=True,
            latencia_ech_pqc_media_ms=25.0,
            latencia_ech_pqc_stddev_ms=1.0,
            ech_aceptado_pqc=True,
            cipher_ech_pqc="TLS_AES_128_GCM_SHA256",
            error_ech_pqc=None,
            conexion_sin_ech_pqc_exitosa=True,
            latencia_sin_ech_pqc_media_ms=20.0,
            latencia_sin_ech_pqc_stddev_ms=0.5,
            cipher_sin_ech_pqc="TLS_AES_128_GCM_SHA256",
            error_sin_ech_pqc=None,
            delta_ech_pqc_ms=-5.0,
            n_mediciones=3,
            latencia_dns_ms=5.0,
            outer_sni="cloudflare-ech.com",
            dns_error=None,
        )
        defaults.update(kwargs)
        return ResultadoLatenciaPQC(**defaults)

    def test_creacion_basica(self):
        r = self._hacer_resultado()
        assert r.hostname == "example.com"
        assert r.grupo_pqc == "X25519MLKEM768"
        assert r.ech_aceptado_pqc is True
        assert r.delta_ech_pqc_ms == -5.0

    def test_campos_opcionales_aceptan_none(self):
        r = self._hacer_resultado(
            latencia_ech_pqc_media_ms=None,
            ech_aceptado_pqc=None,
            delta_ech_pqc_ms=None,
            outer_sni=None,
            dns_error=None,
        )
        assert r.latencia_ech_pqc_media_ms is None
        assert r.delta_ech_pqc_ms is None

    def test_asdict_incluye_todos_los_campos(self):
        r = self._hacer_resultado()
        d = asdict(r)
        campos_esperados = {
            "hostname", "timestamp", "grupo_pqc", "cliente_pqc",
            "ech_config_disponible", "ech_soportado_por_grupo",
            "conexion_ech_pqc_exitosa",
            "latencia_ech_pqc_media_ms", "latencia_ech_pqc_stddev_ms",
            "ech_aceptado_pqc", "cipher_ech_pqc", "error_ech_pqc",
            "conexion_sin_ech_pqc_exitosa",
            "latencia_sin_ech_pqc_media_ms", "latencia_sin_ech_pqc_stddev_ms",
            "cipher_sin_ech_pqc", "error_sin_ech_pqc",
            "delta_ech_pqc_ms",
            "n_mediciones", "latencia_dns_ms", "outer_sni", "dns_error",
        }
        assert campos_esperados == set(d.keys())

    def test_no_contiene_campos_clasicos(self):
        r = self._hacer_resultado()
        d = asdict(r)
        assert "conexion_clasico_exitosa" not in d
        assert "latencia_clasico_media_ms" not in d
        assert "delta_pqc_vs_clasico_ms" not in d

    def test_cliente_pqc_oqs(self):
        r = self._hacer_resultado(
            grupo_pqc="mlkem768",
            cliente_pqc="openssl_oqs",
            ech_soportado_por_grupo=False,
            conexion_ech_pqc_exitosa=False,
        )
        assert r.cliente_pqc == "openssl_oqs"
        assert r.ech_soportado_por_grupo is False


# ============================================
# BSSL_CURVE_MAP
# ============================================

class TestBsslCurveMap:
    def test_grupos_bssl_estan_en_el_mapa(self):
        assert "X25519Kyber768Draft00" in BSSL_CURVE_MAP
        assert "X25519MLKEM768" in BSSL_CURVE_MAP

    def test_grupos_oqs_no_estan_en_el_mapa(self):
        for grupo in ["mlkem768", "kyber768", "SecP256r1MLKEM768",
                      "x25519_mlkem512", "x25519_kyber512",
                      "x25519_bikel1", "x25519_hqc128"]:
            assert grupo not in BSSL_CURVE_MAP

    def test_valores_son_nombres_de_curva_bssl(self):
        for valor in BSSL_CURVE_MAP.values():
            assert isinstance(valor, str)
            assert len(valor) > 0


# ============================================
# exportar_csv
# ============================================

class TestExportarCsv:
    def _resultado_ejemplo(self) -> ResultadoLatenciaPQC:
        return ResultadoLatenciaPQC(
            hostname="example.com",
            timestamp="2026-01-01T12:00:00+00:00",
            grupo_pqc="X25519MLKEM768",
            cliente_pqc="bssl",
            ech_config_disponible=True,
            ech_soportado_por_grupo=True,
            conexion_ech_pqc_exitosa=True,
            latencia_ech_pqc_media_ms=25.0,
            latencia_ech_pqc_stddev_ms=1.2,
            ech_aceptado_pqc=True,
            cipher_ech_pqc="TLS_AES_128_GCM_SHA256",
            error_ech_pqc=None,
            conexion_sin_ech_pqc_exitosa=True,
            latencia_sin_ech_pqc_media_ms=20.0,
            latencia_sin_ech_pqc_stddev_ms=0.5,
            cipher_sin_ech_pqc="TLS_AES_128_GCM_SHA256",
            error_sin_ech_pqc=None,
            delta_ech_pqc_ms=-5.0,
            n_mediciones=3,
            latencia_dns_ms=3.5,
            outer_sni="cloudflare-ech.com",
            dns_error=None,
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
                nombres = set(reader.fieldnames)
            assert "grupo_pqc" in nombres
            assert "cliente_pqc" in nombres
            assert "ech_aceptado_pqc" in nombres
            assert "latencia_ech_pqc_media_ms" in nombres
            assert "latencia_sin_ech_pqc_media_ms" in nombres
            assert "delta_ech_pqc_ms" in nombres
            assert "n_mediciones" in nombres

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
            assert row["hostname"] == "example.com"
            assert row["grupo_pqc"] == "X25519MLKEM768"
            assert row["delta_ech_pqc_ms"] == "-5.0"
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
        args = construir_parser().parse_args([])
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

    def test_valor_por_defecto_oqs_bin(self):
        args = construir_parser().parse_args([])
        assert args.oqs_bin == DEFAULT_OQS_BIN

    def test_grupos_pqc_none_por_defecto(self):
        args = construir_parser().parse_args([])
        assert args.grupos_pqc is None

    def test_argumento_repeticiones(self):
        args = construir_parser().parse_args(["--repeticiones", "10"])
        assert args.repeticiones == 10

    def test_argumento_oqs_bin(self):
        args = construir_parser().parse_args(["--oqs-bin", "/custom/openssl"])
        assert args.oqs_bin == "/custom/openssl"

    def test_argumento_grupos_pqc(self):
        args = construir_parser().parse_args(["--grupos-pqc", "X25519MLKEM768", "mlkem768"])
        assert args.grupos_pqc == ["X25519MLKEM768", "mlkem768"]

    def test_argumento_input_csv(self):
        args = construir_parser().parse_args(["--input-csv", "mi_fichero.csv"])
        assert args.input_csv == "mi_fichero.csv"

    def test_argumento_tls_timeout(self):
        args = construir_parser().parse_args(["--tls-timeout", "20.0"])
        assert args.tls_timeout == 20.0


# ============================================
# procesar_hostname_grupo (con mocks)
# ============================================

def _run(coro):
    return asyncio.run(coro)


def _make_semaphore():
    return asyncio.Semaphore(1)


def _kwargs_base(**extra):
    """Argumentos comunes para procesar_hostname_grupo. extra sobreescribe los defaults."""
    defaults = dict(
        hostname="example.com",
        grupo_pqc="X25519MLKEM768",
        resolver=MagicMock(),
        semaphore=_make_semaphore(),
        dns_timeout=5.0,
        tls_timeout=10.0,
        repeticiones=3,
        bssl_path=_BSSL_FAKE,
        oqs_bin=_OQS_FAKE,
        https_present=True,
        ech_value=_ECH_VALUE,
        parsed_configs=_PARSED_CONFIGS,
        dns_error=None,
        latencia_dns_ms=7.5,
    )
    defaults.update(extra)
    return defaults


class TestProcesarHostnameGrupoBssl:
    """Grupos que usan bssl (X25519MLKEM768, X25519Kyber768Draft00)."""

    def test_exito_con_ech_y_sin_ech(self):
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(side_effect=[
            _BSSL_OK_SIN_ECH,  # sinECH+PQC
            _BSSL_OK,          # ECH+PQC
        ])):
            r = _run(procesar_hostname_grupo(**_kwargs_base()))
        assert r.conexion_sin_ech_pqc_exitosa is True
        assert r.conexion_ech_pqc_exitosa is True
        assert r.ech_aceptado_pqc is True
        assert r.cliente_pqc == "bssl"
        assert r.ech_soportado_por_grupo is True

    def test_delta_es_sin_ech_pqc_menos_ech_pqc(self):
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(side_effect=[
            (True, [20.0], None, None, "TLS_AES_128_GCM_SHA256"),  # sinECH
            (True, [30.0], None, True, "TLS_AES_128_GCM_SHA256"),  # ECH
        ])):
            r = _run(procesar_hostname_grupo(**_kwargs_base()))
        # delta = sinECH_pqc - ECH_pqc = 20 - 30 = -10
        assert r.delta_ech_pqc_ms == -10.0

    def test_delta_none_cuando_ech_falla(self):
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(side_effect=[
            _BSSL_OK_SIN_ECH,  # sinECH+PQC exitoso
            _BSSL_FAIL,        # ECH+PQC falla
        ])):
            r = _run(procesar_hostname_grupo(**_kwargs_base()))
        assert r.conexion_sin_ech_pqc_exitosa is True
        assert r.conexion_ech_pqc_exitosa is False
        assert r.delta_ech_pqc_ms is None

    def test_sin_config_ech_no_mide_ech(self):
        kwargs = _kwargs_base(https_present=False, ech_value=None, parsed_configs=None)
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)):
            r = _run(procesar_hostname_grupo(**kwargs))
        assert r.ech_config_disponible is False
        assert r.conexion_ech_pqc_exitosa is False
        assert r.delta_ech_pqc_ms is None
        assert "Sin HTTPS RR" in (r.error_ech_pqc or "")

    def test_ech_disponible_pero_sin_parsed_configs_reporta_parse_error(self):
        kwargs = _kwargs_base(
            https_present=True, ech_value=_ECH_VALUE, parsed_configs=None,
            dns_error="ECH_PARSE_ERROR:bad data",
        )
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)):
            r = _run(procesar_hostname_grupo(**kwargs))
        assert r.ech_config_disponible is False
        assert r.conexion_ech_pqc_exitosa is False

    def test_outer_sni_capturado(self):
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)):
            r = _run(procesar_hostname_grupo(**_kwargs_base()))
        assert r.outer_sni == "cloudflare-ech.com"

    def test_latencia_dns_propagada(self):
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)):
            r = _run(procesar_hostname_grupo(**_kwargs_base(latencia_dns_ms=12.34)))
        assert r.latencia_dns_ms == 12.34

    def test_sin_ech_falla_error_propagado(self):
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(side_effect=[
            _BSSL_FAIL,   # sinECH falla
            _BSSL_OK,     # ECH (no llegará a medirse si sinECH falla primero)
        ])):
            r = _run(procesar_hostname_grupo(**_kwargs_base()))
        assert r.conexion_sin_ech_pqc_exitosa is False
        assert r.error_sin_ech_pqc == "CONNECTION_REFUSED"

    def test_n_mediciones_refleja_repeticiones(self):
        with patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(side_effect=[
            (True, [20.0, 21.0, 22.0], None, None, "TLS_AES_128_GCM_SHA256"),
            (True, [25.0, 26.0, 24.0], None, True, "TLS_AES_128_GCM_SHA256"),
        ])):
            r = _run(procesar_hostname_grupo(**_kwargs_base()))
        assert r.n_mediciones == 3


class TestProcesarHostnameGrupoOqs:
    """Grupos que usan OpenSSL OQS (sin soporte ECH)."""

    def _kwargs_oqs(self, **extra):
        return _kwargs_base(grupo_pqc="mlkem768", **extra)

    def test_grupo_oqs_usa_openssl_oqs(self):
        with patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            r = _run(procesar_hostname_grupo(**self._kwargs_oqs()))
        assert r.cliente_pqc == "openssl_oqs"

    def test_grupo_oqs_no_soporta_ech(self):
        with patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            r = _run(procesar_hostname_grupo(**self._kwargs_oqs()))
        assert r.ech_soportado_por_grupo is False
        assert r.conexion_ech_pqc_exitosa is False

    def test_grupo_oqs_delta_ech_es_none(self):
        with patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            r = _run(procesar_hostname_grupo(**self._kwargs_oqs()))
        assert r.delta_ech_pqc_ms is None

    def test_grupo_oqs_exitoso(self):
        with patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            r = _run(procesar_hostname_grupo(**self._kwargs_oqs()))
        assert r.conexion_sin_ech_pqc_exitosa is True
        assert r.latencia_sin_ech_pqc_media_ms == 30.0

    def test_grupo_oqs_falla_error_propagado(self):
        with patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_FAIL)):
            r = _run(procesar_hostname_grupo(**self._kwargs_oqs()))
        assert r.conexion_sin_ech_pqc_exitosa is False
        assert r.error_sin_ech_pqc == "OQS_ERROR"

    def test_grupo_oqs_no_llama_a_medir_bssl(self):
        mock_bssl = AsyncMock()
        with patch("sonda_latencia_pqc._medir_bssl", mock_bssl), \
             patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            _run(procesar_hostname_grupo(**self._kwargs_oqs()))
        mock_bssl.assert_not_called()


# ============================================
# procesar_hostname (nivel alto, con mocks DNS)
# ============================================

class TestProcesarHostname:
    def _mock_dns_ok(self):
        return patch(
            "sonda_latencia_pqc.descubrir_https_rr",
            new=AsyncMock(return_value=(True, _ECH_VALUE, _PARSED_CONFIGS, None)),
        )

    def _mock_dns_fail(self):
        return patch(
            "sonda_latencia_pqc.descubrir_https_rr",
            new=AsyncMock(return_value=(False, None, None, "NXDOMAIN")),
        )

    def test_devuelve_una_fila_por_grupo(self):
        grupos = ["X25519MLKEM768", "mlkem768"]
        with self._mock_dns_ok(), \
             patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)), \
             patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            resultados = _run(procesar_hostname(
                "example.com", grupos, MagicMock(), _make_semaphore(),
                5.0, 10.0, 3, _BSSL_FAKE, _OQS_FAKE,
            ))
        assert len(resultados) == 2
        grupos_resultado = {r.grupo_pqc for r in resultados}
        assert grupos_resultado == set(grupos)

    def test_dns_error_se_propaga_a_todos_los_grupos(self):
        grupos = ["X25519MLKEM768", "mlkem768"]
        with self._mock_dns_fail(), \
             patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)), \
             patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            resultados = _run(procesar_hostname(
                "nxdomain.test", grupos, MagicMock(), _make_semaphore(),
                5.0, 10.0, 3, _BSSL_FAKE, _OQS_FAKE,
            ))
        assert all(r.dns_error == "NXDOMAIN" for r in resultados)

    def test_dns_se_llama_una_sola_vez(self):
        grupos = ["X25519MLKEM768", "X25519Kyber768Draft00", "mlkem768"]
        mock_dns = AsyncMock(return_value=(True, _ECH_VALUE, _PARSED_CONFIGS, None))
        with patch("sonda_latencia_pqc.descubrir_https_rr", mock_dns), \
             patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)), \
             patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            _run(procesar_hostname(
                "example.com", grupos, MagicMock(), _make_semaphore(),
                5.0, 10.0, 3, _BSSL_FAKE, _OQS_FAKE,
            ))
        assert mock_dns.call_count == 1

    def test_hostname_se_asigna_en_cada_fila(self):
        grupos = ["X25519MLKEM768", "mlkem768"]
        with self._mock_dns_ok(), \
             patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)), \
             patch("sonda_latencia_pqc._medir_oqs", new=AsyncMock(return_value=_OQS_OK)):
            resultados = _run(procesar_hostname(
                "midominio.com", grupos, MagicMock(), _make_semaphore(),
                5.0, 10.0, 3, _BSSL_FAKE, _OQS_FAKE,
            ))
        assert all(r.hostname == "midominio.com" for r in resultados)

    def test_lista_grupos_vacia_devuelve_lista_vacia(self):
        with self._mock_dns_ok(), \
             patch("sonda_latencia_pqc._medir_bssl", new=AsyncMock(return_value=_BSSL_OK_SIN_ECH)):
            resultados = _run(procesar_hostname(
                "example.com", [], MagicMock(), _make_semaphore(),
                5.0, 10.0, 3, _BSSL_FAKE, _OQS_FAKE,
            ))
        assert resultados == []
