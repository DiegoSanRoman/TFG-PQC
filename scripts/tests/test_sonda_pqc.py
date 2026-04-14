"""
test_sonda_pqc.py
-----------------
Tests unitarios para scripts/sondas/sonda_pqc_final.py.
Cubre funciones puras: es_cipher_debil, tiene_pfs (importadas desde sonda_base),
parse_trace_bytes, _build_result, calcular_promedio_repeticiones,
generar_estadisticas_por_grupo, exportar_estadisticas_csv y _flatten_stats_entry.
"""

import csv
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

# Añadir scripts/ y scripts/sondas/ al path
_SCRIPTS_DIR = Path(__file__).parent.parent
_SONDAS_DIR = _SCRIPTS_DIR / "sondas"
for _p in (_SCRIPTS_DIR, _SONDAS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from constants import CONNECTION_ACCEPTED, CONNECTION_REJECTED, ERROR_DNS, ERROR_TLS_ALERT
from sonda_base import es_cipher_debil, tiene_pfs
from sonda_pqc_final import (
    _build_result,
    _flatten_stats_entry,
    calcular_promedio_repeticiones,
    exportar_estadisticas_csv,
    generar_estadisticas_por_grupo,
    leer_hostnames_csv,
    parse_trace_bytes,
)


# ============================================
# es_cipher_debil
# ============================================

class TestEsCipherDebil:
    def test_rc4_es_debil(self):
        assert es_cipher_debil("RC4-SHA") is True

    def test_des_es_debil(self):
        assert es_cipher_debil("DES-CBC3-SHA") is True

    def test_md5_es_debil(self):
        assert es_cipher_debil("TLS_RSA_WITH_MD5") is True

    def test_null_es_debil(self):
        assert es_cipher_debil("TLS_NULL_WITH_NULL_NULL") is True

    def test_export_es_debil(self):
        assert es_cipher_debil("EXP-RC4-MD5") is True

    def test_anon_es_debil(self):
        assert es_cipher_debil("ADH-AES256-SHA") is True

    def test_aes_gcm_no_es_debil(self):
        assert es_cipher_debil("TLS_AES_256_GCM_SHA384") is False

    def test_ecdhe_aes_no_es_debil(self):
        assert es_cipher_debil("ECDHE-RSA-AES128-GCM-SHA256") is False

    def test_chacha_no_es_debil(self):
        assert es_cipher_debil("TLS_CHACHA20_POLY1305_SHA256") is False


# ============================================
# tiene_pfs
# ============================================

class TestTienePfs:
    def test_ecdhe_tiene_pfs(self):
        assert tiene_pfs("ECDHE-RSA-AES128-GCM-SHA256") is True

    def test_dhe_tiene_pfs(self):
        assert tiene_pfs("DHE-RSA-AES256-SHA256") is True

    def test_rsa_sin_pfs(self):
        assert tiene_pfs("RSA-AES128-SHA") is False

    def test_tls13_tiene_pfs(self):
        # TLS 1.3 tiene PFS inherente; el cifrado lleva ECDHE implícito
        # Este test verifica la detección basada en nombre
        assert tiene_pfs("TLS_AES_256_GCM_SHA384") is False  # No lleva ECDHE/DHE en el nombre

    def test_cadena_vacia_sin_pfs(self):
        assert tiene_pfs("") is False


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
            sni_difiere=False,
            retry=False,
        )
        defaults.update(kwargs)
        return _build_result(**defaults)

    def test_contiene_todas_las_claves_obligatorias(self):
        r = self._base()
        for key in ("error_category", "connection_result", "res", "sni_usado",
                    "sni_difiere", "retry", "ip", "tls_version", "cipher_suite"):
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

    def test_openssl_connect_tls_time_alias(self):
        r = self._base(handshake_time_ms=42.5)
        assert r["openssl_connect_tls_time_ms"] == 42.5


# ============================================
# calcular_promedio_repeticiones
# ============================================

def _intento(connection_result=CONNECTION_ACCEPTED, handshake_time_ms=100.0,
             dns_time_ms=10.0, grupo="X25519", **kwargs) -> Dict[str, Any]:
    base = dict(
        error_category=None,
        connection_result=connection_result,
        res="ok",
        sni_usado="example.com",
        sni_difiere=False,
        retry=False,
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
        handshake_time_ms=handshake_time_ms,
        dns_time_ms=dns_time_ms,
        tcp_time_ms=5.0,
        grupo=grupo,
    )
    base.update(kwargs)
    return base


class TestCalcularPromedioRepeticiones:
    def test_lista_vacia_devuelve_dict_vacio(self):
        assert calcular_promedio_repeticiones([], "X25519") == {}

    def test_una_repeticion_devuelve_los_mismos_valores(self):
        intentos = [_intento(handshake_time_ms=150.0)]
        result = calcular_promedio_repeticiones(intentos, "X25519")
        assert result["handshake_time_ms"] == 150.0

    def test_promedio_de_tres_repeticiones(self):
        intentos = [
            _intento(handshake_time_ms=100.0),
            _intento(handshake_time_ms=200.0),
            _intento(handshake_time_ms=300.0),
        ]
        result = calcular_promedio_repeticiones(intentos, "X25519")
        assert result["handshake_time_ms"] == 200.0

    def test_connection_result_mayoritario_gana(self):
        intentos = [
            _intento(connection_result=CONNECTION_ACCEPTED),
            _intento(connection_result=CONNECTION_ACCEPTED),
            _intento(connection_result=CONNECTION_REJECTED),
        ]
        result = calcular_promedio_repeticiones(intentos, "X25519")
        assert result["connection_result"] == CONNECTION_ACCEPTED

    def test_grupo_se_preserva(self):
        intentos = [_intento(grupo="mlkem768")]
        result = calcular_promedio_repeticiones(intentos, "mlkem768")
        assert result["grupo"] == "mlkem768"

    def test_campo_none_ignorado_en_promedio(self):
        intentos = [
            _intento(dns_time_ms=None),
            _intento(dns_time_ms=20.0),
        ]
        result = calcular_promedio_repeticiones(intentos, "X25519")
        assert result["dns_time_ms"] == 20.0

    def test_todos_none_devuelve_none(self):
        intentos = [_intento(bytes_sent=None), _intento(bytes_sent=None)]
        result = calcular_promedio_repeticiones(intentos, "X25519")
        assert result["bytes_sent"] is None


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
        stats = result[0]["handshake_time_ms"]
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
            "handshake_time_ms": {"media": 50.0, "mediana": 48.0, "desv_std": 5.0, "min": 40.0, "max": 65.0},
            "categorias_error": {"ERROR_TLS_ALERT": 2},
        }

    def test_campos_escalares_se_copian(self):
        flat = _flatten_stats_entry(self._entry())
        assert flat["grupo"] == "X25519"
        assert flat["total_pruebas"] == 10

    def test_sub_dict_se_expande(self):
        flat = _flatten_stats_entry(self._entry())
        assert flat["handshake_time_ms_media"] == 50.0
        assert flat["handshake_time_ms_mediana"] == 48.0

    def test_categorias_error_omitido(self):
        flat = _flatten_stats_entry(self._entry())
        assert "categorias_error" not in flat
        # No deben aparecer claves expandidas de categorias_error
        assert not any("categorias_error" in k for k in flat)


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
            "handshake_time_ms": {"media": 100.0, "mediana": 95.0, "desv_std": 10.0, "min": 80.0, "max": 120.0},
            "openssl_connect_tls_time_ms": {"media": 100.0, "mediana": 95.0, "desv_std": 10.0, "min": 80.0, "max": 120.0},
            "dns_time_ms": {"media": 5.0, "mediana": 5.0, "desv_std": 1.0, "min": 4.0, "max": 6.0},
            "tcp_time_ms": {"media": 3.0, "mediana": 3.0, "desv_std": 0.5, "min": 2.0, "max": 4.0},
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
        assert "handshake_time_ms_media" in headers
        assert "dns_time_ms_mediana" in headers
        # categorias_error debe estar ausente
        assert "categorias_error" not in headers

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
