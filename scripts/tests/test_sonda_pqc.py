"""
test_sonda_pqc.py
-----------------
Tests unitarios para scripts/sondas/sonda_pqc_final.py.
Cubre funciones puras: es_cipher_debil, tiene_pfs (importadas desde sonda_base),
parse_trace_bytes, _build_result, generar_estadisticas_por_grupo,
exportar_estadisticas_csv, _flatten_stats_entry,
TLSOutputParser, ProbeResults y PQCProbe.
"""

import csv
import tempfile
from typing import Any, Dict

import pytest

from constants import CONNECTION_ACCEPTED, CONNECTION_REJECTED, ERROR_DNS, ERROR_TLS_ALERT
from exceptions import (
    PQCError,
    PQCValidationError,
    PQCDNSError,
    PQCTCPRefusedError,
    PQCTCPTimeoutError,
    PQCTCPError,
    PQCTLSTimeoutError,
    PQCTLSAlertError,
)
from sonda_pqc_final import (
    _build_result,
    _flatten_stats_entry,
    exportar_estadisticas_csv,
    generar_estadisticas_por_grupo,
    leer_hostnames_csv,
    parse_trace_bytes,
    TLSOutputParser,
    ProbeResults,
    PQCProbe,
    cargar_progreso_pqc,
    _append_progress_jsonl,
    _escribir_resultados_atomico,
)


# ============================================
# parse_trace_bytes
# ============================================

class TestParseTraceBytes:
    def test_sin_trace_devuelve_unknown(self):
        result = parse_trace_bytes("")
        assert result["measurement_method"] == "unknown"
        assert result["bytes_sent"] is None
        assert result["bytes_received"] is None

    def test_detecta_bytes_enviados_y_recibidos(self):
        trace = (
            "Sent TLS Record\n"
            "  Content Type = handshake\n"
            "  Length = 200\n"
            "Received TLS Record\n"
            "  Content Type = handshake\n"
            "  Length = 300\n"
        )
        result = parse_trace_bytes(trace)
        assert result["measurement_method"] == "traced"
        # +5 bytes de cabecera TLS por cada registro
        assert result["bytes_sent"] == 205
        assert result["bytes_received"] == 305
        assert result["handshake_overhead"] == 510

    def test_solo_enviados_es_partial(self):
        trace = (
            "Sent TLS Record\n"
            "  Content Type = handshake\n"
            "  Length = 100\n"
        )
        result = parse_trace_bytes(trace)
        assert result["measurement_method"] == "partial"

    def test_openssl_summary_se_parsea(self):
        trace = "SSL handshake has read 1500 bytes and written 800 bytes"
        result = parse_trace_bytes(trace)
        assert result["handshake_total_bytes_received"] == 1500
        assert result["handshake_total_bytes_sent"] == 800
        assert result["handshake_total_overhead"] == 2300
        assert result["measurement_method_total"] == "openssl_summary"

    def test_application_data_excluido(self):
        # Los registros de application_data con longitud > max_record_length no se cuentan
        trace = (
            "Sent TLS Record\n"
            "  Content Type = application_data\n"
            "  Length = 99999\n"
        )
        result = parse_trace_bytes(trace)
        assert result["bytes_sent"] is None  # No cumple criterios → unknown

    def test_no_handshake_content_type_excluido(self):
        trace = (
            "Sent TLS Record\n"
            "  Content Type = alert\n"
            "  Length = 50\n"
        )
        # alert SÍ está en handshake_content_types
        result = parse_trace_bytes(trace)
        assert result["measurement_method"] == "partial"
        assert result["bytes_sent"] == 55


# ============================================
# _build_result
# ============================================

class TestBuildResult:
    def _base(self, **kwargs) -> Dict[str, Any]:
        defaults = dict(
            error_category=None,
            connection_result=None,
            res="ok",
            sni_usado="example.com",
        )
        defaults.update(kwargs)
        return _build_result(**defaults)

    def test_contiene_todas_las_claves_obligatorias(self):
        r = self._base()
        for key in ("error_category", "connection_result", "res", "sni_usado",
                    "ip", "tls_version", "cipher_suite"):
            assert key in r

    def test_error_category_se_asigna(self):
        r = self._base(error_category=ERROR_DNS)
        assert r["error_category"] == ERROR_DNS

    def test_connection_result_aceptado(self):
        r = self._base(connection_result=CONNECTION_ACCEPTED)
        assert r["connection_result"] == CONNECTION_ACCEPTED

    def test_metricas_none_por_defecto(self):
        r = self._base()
        assert r["ip"] is None
        assert r["tls_version"] is None
        assert r["bytes_sent"] is None

    def test_openssl_connect_tls_time_no_existe(self):
        r = self._base(openssl_subprocess_time_ms=42.5)
        assert "openssl_connect_tls_time_ms" not in r


def _intento(connection_result=CONNECTION_ACCEPTED, openssl_subprocess_time_ms=100.0,
             dns_time_ms=10.0, grupo="X25519", **kwargs) -> Dict[str, Any]:
    base = dict(
        error_category=None,
        connection_result=connection_result,
        res="ok",
        sni_usado="example.com",
        ip="1.2.3.4",
        ip_familia="IPv4",
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        alpn=None,
        tls_alert=None,
        cert_issuer="CN=Test",
        cert_not_before=None,
        cert_not_after=None,
        cert_san=None,
        cert_fingerprint_sha256=None,
        bytes_sent=100,
        bytes_received=200,
        handshake_overhead=300,
        handshake_total_bytes_sent=100,
        handshake_total_bytes_received=200,
        handshake_total_overhead=300,
        measurement_method="traced",
        measurement_method_total="openssl_summary",
        tiempo_conexion_segundos=0.5,
        openssl_subprocess_time_ms=openssl_subprocess_time_ms,
        dns_time_ms=dns_time_ms,
        grupo=grupo,
    )
    base.update(kwargs)
    return base


# ============================================
# generar_estadisticas_por_grupo
# ============================================

class TestGenerarEstadisticasPorGrupo:
    def _resultado_host(self, hostname="example.com", grupo="X25519",
                        connection_result=CONNECTION_ACCEPTED):
        prueba = _intento(grupo=grupo, connection_result=connection_result)
        prueba["grupo"] = grupo
        return {"hostname": hostname, "pruebas": [prueba]}

    def test_lista_vacia_devuelve_vacia(self):
        result = generar_estadisticas_por_grupo([], ["X25519"])
        assert result == []

    def test_un_grupo_un_host(self):
        lista = [self._resultado_host()]
        result = generar_estadisticas_por_grupo(lista, ["X25519"])
        assert len(result) == 1
        assert result[0]["grupo"] == "X25519"

    def test_conteo_aceptados(self):
        lista = [
            self._resultado_host(connection_result=CONNECTION_ACCEPTED),
            self._resultado_host(hostname="b.com", connection_result=CONNECTION_REJECTED),
        ]
        result = generar_estadisticas_por_grupo(lista, ["X25519"])
        assert result[0]["aceptados"] == 1
        assert result[0]["rechazados"] == 1

    def test_porcentaje_aceptacion(self):
        lista = [self._resultado_host()] * 4
        result = generar_estadisticas_por_grupo(lista, ["X25519"])
        assert result[0]["porcentaje_aceptacion"] == 100.0

    def test_grupo_sin_resultados_omitido(self):
        lista = [self._resultado_host(grupo="X25519")]
        result = generar_estadisticas_por_grupo(lista, ["X25519", "mlkem768"])
        grupos = [r["grupo"] for r in result]
        assert "mlkem768" not in grupos

    def test_stats_handshake_calculadas(self):
        lista = [self._resultado_host()]
        result = generar_estadisticas_por_grupo(lista, ["X25519"])
        stats = result[0]["openssl_subprocess_time_ms"]
        assert stats["media"] is not None
        assert stats["mediana"] is not None


# ============================================
# _flatten_stats_entry / exportar_estadisticas_csv
# ============================================

class TestFlattenStatsEntry:
    def _entry(self):
        return {
            "grupo": "X25519",
            "total_pruebas": 10,
            "aceptados": 8,
            "openssl_subprocess_time_ms": {"media": 50.0, "mediana": 48.0, "desv_std": 5.0, "min": 40.0, "max": 65.0},
            "categorias_error": {"ERROR_TLS_ALERT": 2},
        }

    def test_campos_escalares_se_copian(self):
        flat = _flatten_stats_entry(self._entry())
        assert flat["grupo"] == "X25519"
        assert flat["total_pruebas"] == 10

    def test_sub_dict_se_expande(self):
        flat = _flatten_stats_entry(self._entry())
        assert flat["openssl_subprocess_time_ms_media"] == 50.0
        assert flat["openssl_subprocess_time_ms_mediana"] == 48.0

    def test_categorias_error_serializado_como_json(self):
        flat = _flatten_stats_entry(self._entry())
        # categorias_error debe estar presente como JSON compacto, no expandido
        assert "categorias_error" in flat
        assert flat["categorias_error"] == '{"ERROR_TLS_ALERT": 2}'
        # No deben aparecer claves expandidas tipo "categorias_error_ERROR_TLS_ALERT"
        assert not any(k.startswith("categorias_error_") for k in flat)


class TestExportarEstadisticasCsv:
    def _stats(self, grupo="X25519"):
        return {
            "grupo": grupo,
            "total_pruebas": 5,
            "aceptados": 4,
            "rechazados": 1,
            "errores": 0,
            "porcentaje_aceptacion": 80.0,
            "porcentaje_rechazo": 20.0,
            "porcentaje_error": 0.0,
            "openssl_subprocess_time_ms": {"media": 100.0, "mediana": 95.0, "desv_std": 10.0, "min": 80.0, "max": 120.0},
            "dns_time_ms": {"media": 5.0, "mediana": 5.0, "desv_std": 1.0, "min": 4.0, "max": 6.0},
            "bytes_sent": {"media": 200.0, "mediana": 200.0, "desv_std": 0.0, "min": 200.0, "max": 200.0},
            "bytes_received": {"media": 400.0, "mediana": 400.0, "desv_std": 0.0, "min": 400.0, "max": 400.0},
            "handshake_overhead": {"media": 600.0, "mediana": 600.0, "desv_std": 0.0, "min": 600.0, "max": 600.0},
            "handshake_total_overhead": {"media": 700.0, "mediana": 700.0, "desv_std": 0.0, "min": 700.0, "max": 700.0},
            "categorias_error": {},
        }

    def test_crea_archivo(self, tmp_path):
        out = tmp_path / "stats.csv"
        exportar_estadisticas_csv([self._stats()], out)
        assert out.exists()

    def test_lista_vacia_no_crea_archivo(self, tmp_path):
        out = tmp_path / "stats.csv"
        exportar_estadisticas_csv([], out)
        assert not out.exists()

    def test_cabeceras_derivadas_de_datos(self, tmp_path):
        out = tmp_path / "stats.csv"
        exportar_estadisticas_csv([self._stats()], out)
        with out.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
        # Cabeceras dinámicas deben incluir expansiones del sub-dict
        assert "grupo" in headers
        assert "openssl_subprocess_time_ms_media" in headers
        assert "dns_time_ms_mediana" in headers
        # categorias_error debe estar presente como columna JSON compacta (no expandida)
        assert "categorias_error" in headers
        assert not any(h.startswith("categorias_error_") for h in headers)

    def test_datos_correctos_en_fila(self, tmp_path):
        out = tmp_path / "stats.csv"
        exportar_estadisticas_csv([self._stats("mlkem768")], out)
        with out.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["grupo"] == "mlkem768"
        assert float(rows[0]["porcentaje_aceptacion"]) == 80.0

    def test_multiples_grupos(self, tmp_path):
        out = tmp_path / "stats.csv"
        exportar_estadisticas_csv([self._stats("X25519"), self._stats("mlkem768")], out)
        with out.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2


# ============================================
# leer_hostnames_csv
# ============================================

class TestLeerHostnamesCsv:
    def test_formato_tranco(self, tmp_path):
        csv_file = tmp_path / "tranco.csv"
        csv_file.write_text("1,google.com\n2,github.com\n3,example.com\n", encoding="utf-8")
        result = leer_hostnames_csv(csv_file, 10)
        assert "google.com" in result
        assert "github.com" in result

    def test_limite_max_hostnames(self, tmp_path):
        csv_file = tmp_path / "tranco.csv"
        lines = "\n".join(f"{i},host{i}.com" for i in range(1, 20))
        csv_file.write_text(lines, encoding="utf-8")
        result = leer_hostnames_csv(csv_file, 5)
        assert len(result) == 5

    def test_formato_majestic_million(self, tmp_path):
        csv_file = tmp_path / "majestic.csv"
        csv_file.write_text(
            "GlobalRank,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTLDRank,PrevRefSubNets,PrevRefIPs\n"
            "1,google.com,1000,500,google.com,com,1,1,900,450\n"
            "2,youtube.com,800,400,youtube.com,com,2,2,700,380\n",
            encoding="utf-8"
        )
        result = leer_hostnames_csv(csv_file, 10)
        assert "google.com" in result
        assert "youtube.com" in result

    def test_archivo_inexistente_devuelve_lista_vacia(self, tmp_path):
        result = leer_hostnames_csv(tmp_path / "noexiste.csv", 10)
        assert result == []

    def test_hostnames_invalidos_se_filtran(self, tmp_path):
        csv_file = tmp_path / "mixed.csv"
        csv_file.write_text(
            "1,valid.com\n2,invalid hostname\n3,another.valid.org\n",
            encoding="utf-8"
        )
        result = leer_hostnames_csv(csv_file, 10)
        assert "valid.com" in result
        assert "another.valid.org" in result
        assert "invalid hostname" not in result

    def test_columna_especificada_manualmente(self, tmp_path):
        # La primera fila debe empezar por dígito para no ser tratada como encabezado
        csv_file = tmp_path / "custom.csv"
        csv_file.write_text("1,target.com\n2,other.org\n", encoding="utf-8")
        result = leer_hostnames_csv(csv_file, 10, domain_column=1)
        assert "target.com" in result
        assert "other.org" in result


# ============================================
# TLSOutputParser
# ============================================

class TestTLSOutputParser:
    """TLSOutputParser debe delegar en parse_trace_bytes y cachear el resultado."""

    def test_parse_equivalente_a_funcion(self):
        trace = (
            "Sent TLS Record\n"
            "  Content Type = handshake\n"
            "  Length = 200\n"
            "Received TLS Record\n"
            "  Content Type = handshake\n"
            "  Length = 300\n"
        )
        via_clase = TLSOutputParser(trace).parse()
        via_funcion = parse_trace_bytes(trace)
        assert via_clase == via_funcion

    def test_parse_cachea_resultado(self):
        trace = "SSL handshake has read 1500 bytes and written 800 bytes"
        parser = TLSOutputParser(trace)
        r1 = parser.parse()
        r2 = parser.parse()
        assert r1 is r2  # mismo objeto — resultado cacheado

    def test_from_subprocess_combina_stdout_stderr(self):
        stdout = "Sent TLS Record\n  Content Type = handshake\n  Length = 100\n"
        stderr = "Received TLS Record\n  Content Type = handshake\n  Length = 200\n"
        result = TLSOutputParser.from_subprocess(stdout, stderr).parse()
        assert result["bytes_sent"] == 105
        assert result["bytes_received"] == 205

    def test_entrada_vacia_devuelve_unknown(self):
        result = TLSOutputParser("").parse()
        assert result["measurement_method"] == "unknown"

    def test_openssl_summary_en_stderr(self):
        stderr = "SSL handshake has read 2000 bytes and written 1000 bytes"
        result = TLSOutputParser.from_subprocess("", stderr).parse()
        assert result["handshake_total_bytes_received"] == 2000
        assert result["measurement_method_total"] == "openssl_summary"


# ============================================
# ProbeResults
# ============================================

class TestProbeResults:
    def _make(self, **kwargs) -> ProbeResults:
        base = dict(
            error_category=None,
            connection_result=CONNECTION_ACCEPTED,
            res="ok",
            sni_usado="example.com",
            ip="1.2.3.4",
            ip_familia="IPv4",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            alpn=None,
            tls_alert=None,
            cert_issuer="CN=Test",
            cert_not_before=None,
            cert_not_after=None,
            cert_san=None,
            cert_fingerprint_sha256=None,
            bytes_sent=100,
            bytes_received=200,
            handshake_overhead=300,
            handshake_total_bytes_sent=100,
            handshake_total_bytes_received=200,
            handshake_total_overhead=300,
            measurement_method="traced",
            measurement_method_total="openssl_summary",
            tiempo_conexion_segundos=0.5,
            openssl_subprocess_time_ms=80.0,
            dns_time_ms=10.0,
        )
        base.update(kwargs)
        return ProbeResults(data=base)

    def test_is_accepted_true(self):
        r = self._make(connection_result=CONNECTION_ACCEPTED)
        assert r.is_accepted is True

    def test_is_accepted_false_cuando_rechazado(self):
        r = self._make(connection_result=CONNECTION_REJECTED)
        assert r.is_accepted is False

    def test_is_accepted_false_cuando_error(self):
        r = self._make(connection_result=None, error_category=ERROR_DNS)
        assert r.is_accepted is False

    def test_tls_version_property(self):
        r = self._make(tls_version="TLSv1.3")
        assert r.tls_version == "TLSv1.3"

    def test_handshake_time_ms_property(self):
        r = self._make(openssl_subprocess_time_ms=55.5)
        assert r.handshake_time_ms == 55.5

    def test_acceso_por_clave(self):
        r = self._make()
        assert r["ip"] == "1.2.3.4"

    def test_get_con_default(self):
        r = self._make()
        assert r.get("campo_inexistente", "X") == "X"

    def test_to_dict_es_copia(self):
        r = self._make()
        d = r.to_dict()
        assert isinstance(d, dict)
        d["ip"] = "mutado"
        assert r["ip"] == "1.2.3.4"  # el original no se modifica

    def test_error_category_property(self):
        r = self._make(error_category=ERROR_DNS)
        assert r.error_category == ERROR_DNS


# ============================================
# PQCProbe
# ============================================

class TestPQCProbe:
    def test_hostname_invalido_lanza_PQCValidationError(self):
        probe = PQCProbe()
        with pytest.raises(PQCValidationError):
            probe.run("hostname_sin_punto")

    def test_hostname_vacio_lanza_PQCValidationError(self):
        probe = PQCProbe()
        with pytest.raises(PQCValidationError):
            probe.run("")

    def test_hostname_con_espacios_lanza_PQCValidationError(self):
        probe = PQCProbe()
        with pytest.raises(PQCValidationError):
            probe.run("host name.com")

    def test_PQCValidationError_es_subclase_de_PQCError(self):
        with pytest.raises(PQCError):
            PQCProbe().run("sin_punto")

    def test_run_devuelve_ProbeResults(self, monkeypatch):
        from sonda_pqc_final import sonda_pqc as _sonda
        dummy = dict(
            error_category=None,
            connection_result=CONNECTION_ACCEPTED,
            res="ok",
            sni_usado="example.com",
            ip="1.2.3.4",
            ip_familia="IPv4",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            alpn=None, tls_alert=None,
            cert_issuer=None, cert_not_before=None, cert_not_after=None,
            cert_san=None, cert_fingerprint_sha256=None,
            bytes_sent=100, bytes_received=200, handshake_overhead=300,
            handshake_total_bytes_sent=100, handshake_total_bytes_received=200,
            handshake_total_overhead=300,
            measurement_method="traced", measurement_method_total="openssl_summary",
            tiempo_conexion_segundos=0.5, openssl_subprocess_time_ms=80.0,
            dns_time_ms=10.0,
        )
        import sonda_pqc_final as _mod
        monkeypatch.setattr(_mod, "sonda_pqc", lambda *a, **kw: dummy)
        probe = PQCProbe()
        result = probe.run("example.com", group="X25519")
        assert isinstance(result, ProbeResults)
        assert result.is_accepted is True

    def test_openssl_bin_se_pasa_a_sonda_pqc(self, monkeypatch):
        llamadas = []
        def fake_sonda(hostname, group=None, openssl_bin=None, proc_semaphore=None):
            llamadas.append(openssl_bin)
            return dict(
                error_category=None, connection_result=CONNECTION_ACCEPTED,
                res="ok", sni_usado=hostname,
                ip=None, ip_familia=None, tls_version=None, cipher_suite=None,
                alpn=None, tls_alert=None, cert_issuer=None, cert_not_before=None,
                cert_not_after=None, cert_san=None, cert_fingerprint_sha256=None,
                bytes_sent=None, bytes_received=None, handshake_overhead=None,
                handshake_total_bytes_sent=None, handshake_total_bytes_received=None,
                handshake_total_overhead=None, measurement_method=None,
                measurement_method_total=None, tiempo_conexion_segundos=None,
                openssl_subprocess_time_ms=None, dns_time_ms=None,
            )
        import sonda_pqc_final as _mod
        monkeypatch.setattr(_mod, "sonda_pqc", fake_sonda)
        PQCProbe(openssl_bin="/custom/openssl").run("example.com")
        assert llamadas == ["/custom/openssl"]


# ============================================
# Jerarquía de excepciones
# ============================================

class TestExceptions:
    def test_PQCError_es_Exception(self):
        assert issubclass(PQCError, Exception)

    def test_todas_heredan_de_PQCError(self):
        for cls in (PQCValidationError, PQCDNSError, PQCTCPRefusedError,
                    PQCTCPTimeoutError, PQCTCPError, PQCTLSTimeoutError,
                    PQCTLSAlertError):
            assert issubclass(cls, PQCError), f"{cls.__name__} no hereda de PQCError"

    def test_se_pueden_instanciar_con_mensaje(self):
        for cls in (PQCValidationError, PQCDNSError, PQCTCPRefusedError,
                    PQCTCPTimeoutError, PQCTCPError, PQCTLSTimeoutError,
                    PQCTLSAlertError):
            e = cls("mensaje de prueba")
            assert str(e) == "mensaje de prueba"

    def test_captura_por_base_PQCError(self):
        with pytest.raises(PQCError):
            raise PQCTLSAlertError("handshake failure")

    def test_PQCValidationError_no_es_PQCDNSError(self):
        assert not issubclass(PQCValidationError, PQCDNSError)


# ============================================
# cargar_progreso_pqc
# ============================================

class TestCargarProgresoPqc:
    def test_archivo_inexistente_devuelve_vacios(self, tmp_path):
        lista, completados = cargar_progreso_pqc(tmp_path / "noexiste.jsonl")
        assert lista == []
        assert completados == set()

    def test_carga_una_entrada(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        p.write_text('{"hostname": "a.com", "pruebas": []}\n', encoding="utf-8")
        lista, completados = cargar_progreso_pqc(p)
        assert len(lista) == 1
        assert "a.com" in completados

    def test_dedup_mismo_hostname(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        p.write_text(
            '{"hostname": "a.com", "pruebas": []}\n'
            '{"hostname": "a.com", "pruebas": []}\n',
            encoding="utf-8",
        )
        lista, completados = cargar_progreso_pqc(p)
        assert len(lista) == 1
        assert len(completados) == 1

    def test_linea_corrupta_ignorada(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        p.write_text(
            '{"hostname": "a.com", "pruebas": []}\n'
            'ESTO_NO_ES_JSON\n'
            '{"hostname": "b.com", "pruebas": []}\n',
            encoding="utf-8",
        )
        lista, completados = cargar_progreso_pqc(p)
        assert len(lista) == 2
        assert completados == {"a.com", "b.com"}

    def test_linea_sin_hostname_ignorada(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        p.write_text('{"pruebas": []}\n', encoding="utf-8")
        lista, completados = cargar_progreso_pqc(p)
        assert lista == []
        assert completados == set()

    def test_multiples_hostnames(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        lineas = "\n".join(f'{{"hostname": "host{i}.com", "pruebas": []}}' for i in range(5))
        p.write_text(lineas + "\n", encoding="utf-8")
        lista, completados = cargar_progreso_pqc(p)
        assert len(lista) == 5
        assert len(completados) == 5


# ============================================
# _append_progress_jsonl
# ============================================

class TestAppendProgressJsonl:
    def test_crea_archivo_si_no_existe(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        _append_progress_jsonl({"hostname": "a.com"}, p)
        assert p.exists()

    def test_contenido_es_json_valido(self, tmp_path):
        import json as _json
        p = tmp_path / "progress.jsonl"
        _append_progress_jsonl({"hostname": "a.com", "pruebas": []}, p)
        linea = p.read_text(encoding="utf-8").strip()
        d = _json.loads(linea)
        assert d["hostname"] == "a.com"

    def test_acumula_multiples_entradas(self, tmp_path):
        import json as _json
        p = tmp_path / "progress.jsonl"
        _append_progress_jsonl({"hostname": "a.com"}, p)
        _append_progress_jsonl({"hostname": "b.com"}, p)
        lineas = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lineas) == 2
        hostnames = {_json.loads(l)["hostname"] for l in lineas}
        assert hostnames == {"a.com", "b.com"}

    def test_crea_directorio_padre_si_no_existe(self, tmp_path):
        p = tmp_path / "subdir" / "progress.jsonl"
        _append_progress_jsonl({"hostname": "x.com"}, p)
        assert p.exists()


# ============================================
# _escribir_resultados_atomico
# ============================================

class TestEscribirResultadosAtomico:
    def _lista_resultados(self):
        prueba = _intento(connection_result=CONNECTION_ACCEPTED, grupo="X25519")
        prueba["grupo"] = "X25519"
        return [{"hostname": "a.com", "pruebas": [prueba]}]

    def test_crea_json(self, tmp_path):
        json_path = tmp_path / "resultados.json"
        csv_path = tmp_path / "stats.csv"
        _escribir_resultados_atomico(
            self._lista_resultados(), ["X25519"], json_path, csv_path, __import__("time").time()
        )
        assert json_path.exists()

    def test_json_contiene_resumen_y_datos(self, tmp_path):
        import json as _json
        json_path = tmp_path / "resultados.json"
        csv_path = tmp_path / "stats.csv"
        _escribir_resultados_atomico(
            self._lista_resultados(), ["X25519"], json_path, csv_path, __import__("time").time()
        )
        with json_path.open(encoding="utf-8") as fh:
            doc = _json.load(fh)
        assert "resumen" in doc
        assert "datos" in doc
        assert doc["resumen"]["total_hostnames"] == 1

    def test_crea_csv_estadisticas(self, tmp_path):
        json_path = tmp_path / "resultados.json"
        csv_path = tmp_path / "stats.csv"
        _escribir_resultados_atomico(
            self._lista_resultados(), ["X25519"], json_path, csv_path, __import__("time").time()
        )
        assert csv_path.exists()

    def test_retorna_resumen_con_campos_esperados(self, tmp_path):
        json_path = tmp_path / "resultados.json"
        csv_path = tmp_path / "stats.csv"
        resumen = _escribir_resultados_atomico(
            self._lista_resultados(), ["X25519"], json_path, csv_path, __import__("time").time()
        )
        for campo in ("total_hostnames", "hosts_con_al_menos_un_exito",
                      "total_pruebas", "pruebas_exitosas", "grupos_probados"):
            assert campo in resumen

    def test_lista_vacia_resumen_cero(self, tmp_path):
        json_path = tmp_path / "resultados.json"
        csv_path = tmp_path / "stats.csv"
        resumen = _escribir_resultados_atomico(
            [], ["X25519"], json_path, csv_path, __import__("time").time()
        )
        assert resumen["total_hostnames"] == 0
        assert resumen["hosts_con_al_menos_un_exito"] == 0

    def test_no_deja_archivo_tmp(self, tmp_path):
        json_path = tmp_path / "resultados.json"
        csv_path = tmp_path / "stats.csv"
        _escribir_resultados_atomico(
            self._lista_resultados(), ["X25519"], json_path, csv_path, __import__("time").time()
        )
        assert not (tmp_path / "resultados.tmp").exists()
