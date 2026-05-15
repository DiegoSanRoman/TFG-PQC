"""
test_sonda_ech_prevalencia.py
-----------------------------
Tests unitarios para scripts/sondas/sonda_ech_prevalencia.py.

Cubre únicamente las funciones puras (sin I/O de red ni subprocesos):
  _limpiar_valor_ech, _decode_ech_base64, _normalizar_target,
  _target_parece_dominio, _split_host_port, clasificar_proveedor,
  detectar_padding, extraer_longitud_client_hello,
  detectar_handshake_completo, clasificar_estado_negociacion,
  _parse_ech_config_contents, parse_ech_config_list.
"""

import base64
from pathlib import Path

import pytest

import json

from tls_utils import decode_ech_base64 as _decode_ech_base64
from sonda_ech_prevalencia import (
    STATUS_CLIENTE_SIN_SOPORTE,
    STATUS_EXITO_OUTER_CH,
    STATUS_FALLBACK,
    STATUS_FALLO_NEGOCIACION,
    STATUS_NEGOCIACION_OK_SIN_CONFIRMAR,
    DominioECHResultado,
    _limpiar_valor_ech,
    _normalizar_target,
    _parse_ech_config_contents,
    _split_host_port,
    _target_parece_dominio,
    clasificar_estado_negociacion,
    clasificar_proveedor,
    detectar_handshake_completo,
    detectar_padding,
    extraer_longitud_client_hello,
    parse_ech_config_list,
    _cargar_hostnames_ech_existentes,
    _añadir_hostname_ech_csv,
    _cargar_progreso_ech,
    _append_progress_ech_jsonl,
)


# ============================================
# Helpers para construir blobs ECH en tests
# ============================================

def _make_ech_contents(
    config_id: int = 0x42,
    kem_id: int = 0x0020,
    public_key: bytes = bytes(32),
    suites: list[tuple[int, int]] | None = None,
    max_name_length: int = 0,
    public_name: bytes = b"cloudflare.com",
    extensions: bytes = b"",
) -> bytes:
    """Construye el payload interno de un ECHConfig (sin cabecera versión/longitud)."""
    if suites is None:
        suites = [(0x0001, 0x0001)]

    result = bytearray()
    result += bytes([config_id])
    result += kem_id.to_bytes(2, "big")
    result += len(public_key).to_bytes(2, "big")
    result += public_key
    suite_bytes = b"".join(k.to_bytes(2, "big") + a.to_bytes(2, "big") for k, a in suites)
    result += len(suite_bytes).to_bytes(2, "big")
    result += suite_bytes
    result += bytes([max_name_length])
    result += bytes([len(public_name)])
    result += public_name
    result += len(extensions).to_bytes(2, "big")
    result += extensions
    return bytes(result)


def _make_ech_config_list(contents: bytes, version: int = 0xFE0D) -> bytes:
    """Envuelve un ECHConfig contents en un ECHConfigList completo."""
    inner = version.to_bytes(2, "big") + len(contents).to_bytes(2, "big") + contents
    return len(inner).to_bytes(2, "big") + inner


# ============================================
# _limpiar_valor_ech
# ============================================

class TestLimpiarValorEch:
    def test_elimina_comillas_dobles(self):
        assert _limpiar_valor_ech('"abc=="') == "abc=="

    def test_elimina_comillas_simples(self):
        assert _limpiar_valor_ech("'abc=='") == "abc=="

    def test_elimina_espacios(self):
        assert _limpiar_valor_ech("  abc==  ") == "abc=="

    def test_elimina_espacios_internos(self):
        # Los espacios internos también deben eliminarse
        assert _limpiar_valor_ech("ab c==") == "abc=="

    def test_cadena_vacia(self):
        assert _limpiar_valor_ech("") == ""

    def test_valor_limpio_no_se_modifica(self):
        assert _limpiar_valor_ech("abc123==") == "abc123=="


# ============================================
# _decode_ech_base64
# ============================================

class TestDecodeEchBase64:
    def test_decodifica_base64_estandar(self):
        original = b"hello world"
        encoded = base64.b64encode(original).decode()
        assert _decode_ech_base64(encoded) == original

    def test_decodifica_sin_padding(self):
        original = b"test"
        encoded = base64.b64encode(original).decode().rstrip("=")
        assert _decode_ech_base64(encoded) == original

    def test_decodifica_con_comillas(self):
        original = b"data"
        encoded = '"' + base64.b64encode(original).decode() + '"'
        assert _decode_ech_base64(encoded) == original

    def test_url_safe_caracteres(self):
        # Reemplaza - y _ por + y / antes de decodificar
        original = b"\xfb\xff"
        encoded = base64.b64encode(original).decode().replace("+", "-").replace("/", "_")
        assert _decode_ech_base64(encoded) == original


# ============================================
# _normalizar_target
# ============================================

class TestNormalizarTarget:
    def test_dominio_simple(self):
        assert _normalizar_target("example.com") == "example.com"

    def test_elimina_esquema_https(self):
        assert _normalizar_target("https://example.com") == "example.com"

    def test_elimina_esquema_http(self):
        assert _normalizar_target("http://example.com") == "example.com"

    def test_elimina_ruta(self):
        assert _normalizar_target("https://example.com/path/to/page") == "example.com"

    def test_elimina_espacios(self):
        assert _normalizar_target("  example.com  ") == "example.com"

    def test_elimina_comillas(self):
        assert _normalizar_target('"example.com"') == "example.com"

    def test_cadena_vacia(self):
        assert _normalizar_target("") == ""

    def test_solo_espacios(self):
        assert _normalizar_target("   ") == ""

    def test_subdominio(self):
        assert _normalizar_target("https://sub.example.com/page") == "sub.example.com"


# ============================================
# _target_parece_dominio
# ============================================

class TestTargetPareceDominio:
    def test_dominio_valido(self):
        assert _target_parece_dominio("example.com") is True

    def test_subdominio(self):
        assert _target_parece_dominio("sub.example.com") is True

    def test_cadena_vacia(self):
        assert _target_parece_dominio("") is False

    def test_solo_numeros(self):
        assert _target_parece_dominio("12345") is False

    def test_sin_letras(self):
        assert _target_parece_dominio("192.168.1.1") is False

    def test_localhost(self):
        assert _target_parece_dominio("localhost") is True

    def test_host_con_puerto(self):
        assert _target_parece_dominio("example.com:8443") is True


# ============================================
# _split_host_port
# ============================================

class TestSplitHostPort:
    def test_host_sin_puerto_usa_443(self):
        host, port = _split_host_port("example.com")
        assert host == "example.com"
        assert port == 443

    def test_host_con_puerto(self):
        host, port = _split_host_port("example.com:8443")
        assert host == "example.com"
        assert port == 8443

    def test_puerto_443_explicito(self):
        host, port = _split_host_port("example.com:443")
        assert host == "example.com"
        assert port == 443

    def test_texto_no_numerico_como_puerto_ignora_split(self):
        # "host:abc" no es un puerto válido → se trata como host sin puerto
        host, port = _split_host_port("example.com:abc")
        assert port == 443

    def test_host_sin_dominio(self):
        host, port = _split_host_port("localhost")
        assert host == "localhost"
        assert port == 443


# ============================================
# clasificar_proveedor
# ============================================

class TestClasificarProveedor:
    def test_cloudflare(self):
        assert clasificar_proveedor("cloudflare.com") == "Cloudflare"

    def test_cloudflare_subdominio(self):
        assert clasificar_proveedor("ech.cloudflare.com") == "Cloudflare"

    def test_fastly(self):
        assert clasificar_proveedor("dualstack.fastly.net") == "Fastly"

    def test_defo(self):
        assert clasificar_proveedor("defo.ie") == "DEfO"

    def test_otro_proveedor(self):
        assert clasificar_proveedor("akamai.net") == "OTRO"

    def test_none_devuelve_desconocido(self):
        assert clasificar_proveedor(None) == "DESCONOCIDO"

    def test_cadena_vacia_devuelve_desconocido(self):
        assert clasificar_proveedor("") == "DESCONOCIDO"


# ============================================
# detectar_padding
# ============================================

class TestDetectarPadding:
    def test_none_devuelve_false(self):
        detected, profile = detectar_padding(None, "Cloudflare")
        assert detected is False
        assert profile is None

    def test_longitud_1925_detectada(self):
        detected, profile = detectar_padding(1925, "OTRO")
        assert detected is True
        assert profile == "PADDING_1925"

    def test_longitud_1920_detectada(self):
        detected, profile = detectar_padding(1920, "OTRO")
        assert detected is True
        assert profile == "PADDING_1920"

    def test_rango_cloudflare(self):
        detected, profile = detectar_padding(1919, "Cloudflare")
        assert detected is True
        assert profile == "PADDING_RANGO_CLOUDFLARE"

    def test_rango_defo(self):
        detected, profile = detectar_padding(1918, "DEfO")
        assert detected is True
        assert profile == "PADDING_RANGO_DEFO"

    def test_longitud_fuera_de_rango(self):
        detected, profile = detectar_padding(500, "Cloudflare")
        assert detected is False
        assert profile is None

    def test_cloudflare_limite_superior(self):
        detected, profile = detectar_padding(1930, "Cloudflare")
        assert detected is True

    def test_cloudflare_fuera_del_limite(self):
        detected, profile = detectar_padding(1931, "Cloudflare")
        assert detected is False


# ============================================
# extraer_longitud_client_hello
# ============================================

class TestExtraerLongitudClientHello:
    def test_formato_coma_length(self):
        output = "ClientHello , Length = 512"
        assert extraer_longitud_client_hello(output) == 512

    def test_formato_bracket_hex(self):
        # 0x1f4 = 500; la función usa int(value, 16) si el valor contiene letras
        output = "[length 1f4] , ClientHello"
        assert extraer_longitud_client_hello(output) == 500

    def test_formato_client_hello_length_igual(self):
        output = "client_hello_length = 1024"
        assert extraer_longitud_client_hello(output) == 1024

    def test_sin_patron_devuelve_none(self):
        output = "SSL handshake has read 1500 bytes and written 800 bytes"
        assert extraer_longitud_client_hello(output) is None

    def test_cadena_vacia_devuelve_none(self):
        assert extraer_longitud_client_hello("") is None

    def test_insensible_a_mayusculas(self):
        output = "CLIENTHELLO , LENGTH = 300"
        assert extraer_longitud_client_hello(output) == 300


# ============================================
# detectar_handshake_completo
# ============================================

class TestDetectarHandshakeCompleto:
    def test_codigo_1_con_marcadores_de_exito_devuelve_true(self):
        # openssl s_client devuelve 1 cuando el servidor cierra limpiamente sin datos HTTP:
        # comportamiento normal y esperable, debe considerarse handshake exitoso.
        assert detectar_handshake_completo("Verify return code: 0 (ok)", 1) is True

    def test_codigo_distinto_de_0_y_1_devuelve_false(self):
        # Códigos distintos de 0 y 1 sí indican error real
        assert detectar_handshake_completo("Verify return code: 0 (ok)", 2) is False

    def test_verification_ok(self):
        assert detectar_handshake_completo("Verification: OK\nSome other stuff", 0) is True

    def test_ssl_session(self):
        assert detectar_handshake_completo("SSL-Session:\n    Protocol: TLSv1.3", 0) is True

    def test_nuevo_tlsv13(self):
        assert detectar_handshake_completo("New, TLSv1.3, Cipher ...", 0) is True

    def test_sin_marcadores_devuelve_false(self):
        output = "Connect error: connection refused"
        assert detectar_handshake_completo(output, 0) is False

    def test_handshake_done(self):
        assert detectar_handshake_completo("handshake done.", 0) is True


# ============================================
# clasificar_estado_negociacion
# ============================================

class TestClasificarEstadoNegociacion:
    def test_openssl_siempre_sin_soporte(self):
        output = "Verification: OK\nNew, TLSv1.3"
        status, tls_ok, handshake = clasificar_estado_negociacion(output, 0, "openssl")
        assert status == STATUS_CLIENTE_SIN_SOPORTE

    def test_openssl_tls_ok_con_handshake(self):
        output = "Verification: OK\nNew, TLSv1.3"
        _, tls_ok, _ = clasificar_estado_negociacion(output, 0, "openssl")
        assert tls_ok is True

    def test_ech_accepted_indicator(self):
        output = "ECH accepted\nVerification: OK"
        status, tls_ok, _ = clasificar_estado_negociacion(output, 0, "boringssl")
        assert status == STATUS_EXITO_OUTER_CH
        assert tls_ok is True

    def test_ech_rejected_fallback(self):
        output = "ECH rejected: retry configs available"
        status, _, _ = clasificar_estado_negociacion(output, 0, "boringssl")
        assert status == STATUS_FALLBACK

    def test_encrypted_clienthello_yes(self):
        output = "encrypted ClientHello: yes"
        status, _, _ = clasificar_estado_negociacion(output, 0, "boringssl")
        assert status == STATUS_EXITO_OUTER_CH

    def test_encrypted_clienthello_no_fallback(self):
        output = "encrypted ClientHello: no"
        status, _, _ = clasificar_estado_negociacion(output, 0, "boringssl")
        assert status == STATUS_FALLBACK

    def test_tls_ok_sin_indicadores_ech(self):
        output = "Verification: OK\nNew, TLSv1.3, Cipher..."
        status, tls_ok, _ = clasificar_estado_negociacion(output, 0, "boringssl")
        assert status == STATUS_NEGOCIACION_OK_SIN_CONFIRMAR
        assert tls_ok is True

    def test_fallo_handshake_boringssl(self):
        output = "connect: connection refused"
        status, tls_ok, _ = clasificar_estado_negociacion(output, 1, "boringssl")
        assert status == STATUS_FALLO_NEGOCIACION
        assert tls_ok is False


# ============================================
# _parse_ech_config_contents
# ============================================

class TestParseEchConfigContents:
    def _valid_contents(self, public_name=b"cloudflare.com") -> bytes:
        return _make_ech_contents(
            config_id=0x42,
            kem_id=0x0020,
            public_key=bytes(32),
            suites=[(0x0001, 0x0001)],
            max_name_length=0,
            public_name=public_name,
            extensions=b"",
        )

    def test_config_id_correcto(self):
        result = _parse_ech_config_contents(self._valid_contents(), 0xFE0D)
        assert result["config_id"] == 0x42

    def test_kem_id_correcto(self):
        result = _parse_ech_config_contents(self._valid_contents(), 0xFE0D)
        assert result["kem_id"] == 0x0020

    def test_public_name_correcto(self):
        result = _parse_ech_config_contents(self._valid_contents(b"example.com"), 0xFE0D)
        assert result["public_name"] == "example.com"

    def test_version_en_resultado(self):
        result = _parse_ech_config_contents(self._valid_contents(), 0xFE0D)
        assert result["version"] == "0xfe0d"

    def test_hpke_suites_formato(self):
        result = _parse_ech_config_contents(self._valid_contents(), 0xFE0D)
        assert len(result["hpke_suites"]) == 1
        assert "kdf=" in result["hpke_suites"][0]
        assert "aead=" in result["hpke_suites"][0]

    def test_public_key_length(self):
        result = _parse_ech_config_contents(self._valid_contents(), 0xFE0D)
        assert result["public_key_length"] == 32

    def test_datos_demasiado_cortos_lanza_error(self):
        with pytest.raises(ValueError):
            _parse_ech_config_contents(b"\x00\x01", 0xFE0D)

    def test_pk_len_invalido_lanza_error(self):
        # pk_len que supera los datos disponibles
        bad = bytearray()
        bad += bytes([0x01])           # config_id
        bad += (0x0020).to_bytes(2, "big")  # kem_id
        bad += (9999).to_bytes(2, "big")    # pk_len = 9999 (demasiado grande)
        bad += bytes(10)               # solo 10 bytes disponibles
        with pytest.raises(ValueError, match="inválida"):
            _parse_ech_config_contents(bytes(bad), 0xFE0D)

    def test_multiples_suites(self):
        contents = _make_ech_contents(
            suites=[(0x0001, 0x0001), (0x0001, 0x0002)],
        )
        result = _parse_ech_config_contents(contents, 0xFE0D)
        assert len(result["hpke_suites"]) == 2


# ============================================
# parse_ech_config_list
# ============================================

class TestParseEchConfigList:
    def _valid_list(self, public_name=b"cloudflare.com") -> bytes:
        contents = _make_ech_contents(public_name=public_name)
        return _make_ech_config_list(contents)

    def test_devuelve_lista_con_una_config(self):
        result = parse_ech_config_list(self._valid_list())
        assert len(result) == 1

    def test_public_name_en_resultado(self):
        result = parse_ech_config_list(self._valid_list(b"example.com"))
        assert result[0]["public_name"] == "example.com"

    def test_kem_id_correcto(self):
        result = parse_ech_config_list(self._valid_list())
        assert result[0]["kem_id"] == 0x0020

    def test_datos_vacios_lanza_error(self):
        with pytest.raises(ValueError):
            parse_ech_config_list(b"")

    def test_longitud_inconsistente_lanza_error(self):
        # total_len dice que hay 9999 bytes pero solo hay 4
        bad = (9999).to_bytes(2, "big") + bytes(4)
        with pytest.raises(ValueError, match="inconsistente"):
            parse_ech_config_list(bad)

    def test_cabecera_incompleta_lanza_error(self):
        with pytest.raises(ValueError):
            parse_ech_config_list(b"\x00")

    def test_multiples_configs_en_lista(self):
        contents1 = _make_ech_contents(config_id=0x01, public_name=b"a.com")
        contents2 = _make_ech_contents(config_id=0x02, public_name=b"b.com")
        inner = (
            (0xFE0D).to_bytes(2, "big") + len(contents1).to_bytes(2, "big") + contents1
            + (0xFE0D).to_bytes(2, "big") + len(contents2).to_bytes(2, "big") + contents2
        )
        raw = len(inner).to_bytes(2, "big") + inner
        result = parse_ech_config_list(raw)
        assert len(result) == 2
        public_names = {r["public_name"] for r in result}
        assert public_names == {"a.com", "b.com"}


# ============================================
# Helper
# ============================================

def _hacer_dominio_resultado(**kwargs) -> DominioECHResultado:
    defaults = dict(
        domain="example.com",
        https_rr_present=True,
        has_ech_param=True,
        outer_sni="cloudflare.com",
        provider="Cloudflare",
        tls_client_used="boringssl",
        ech_negotiation_status="EXITO_OUTER_CLIENT_HELLO",
        handshake_completed=True,
        tls_connected=True,
        client_hello_length=512,
        padding_detected=False,
        padding_profile=None,
        ech_version="0xfe0d",
        kem_id=32,
        hpke_suites=["kdf=1,aead=1"],
        ech_config_id=0x42,
        public_key_length=32,
        dns_error=None,
        tls_error=None,
        notes=None,
    )
    defaults.update(kwargs)
    return DominioECHResultado(**defaults)


# ============================================
# _cargar_hostnames_ech_existentes
# ============================================

class TestCargarHostnamesEchExistentes:
    def test_archivo_inexistente_devuelve_set_vacio(self, tmp_path):
        resultado = _cargar_hostnames_ech_existentes(tmp_path / "noexiste.csv")
        assert resultado == set()

    def test_carga_hostnames_del_csv(self, tmp_path):
        p = tmp_path / "hostnames_ech.csv"
        p.write_text("hostname\nkali.org\ncloudflare.com\n", encoding="utf-8")
        resultado = _cargar_hostnames_ech_existentes(p)
        assert "kali.org" in resultado
        assert "cloudflare.com" in resultado

    def test_saltea_fila_de_encabezado(self, tmp_path):
        p = tmp_path / "hostnames_ech.csv"
        p.write_text("hostname\nexample.com\n", encoding="utf-8")
        resultado = _cargar_hostnames_ech_existentes(p)
        assert "hostname" not in resultado
        assert "example.com" in resultado

    def test_archivo_solo_con_encabezado_devuelve_vacio(self, tmp_path):
        p = tmp_path / "hostnames_ech.csv"
        p.write_text("hostname\n", encoding="utf-8")
        resultado = _cargar_hostnames_ech_existentes(p)
        assert resultado == set()

    def test_elimina_espacios_en_blanco(self, tmp_path):
        p = tmp_path / "hostnames_ech.csv"
        p.write_text("hostname\n  example.com  \n", encoding="utf-8")
        resultado = _cargar_hostnames_ech_existentes(p)
        assert "example.com" in resultado
        assert "  example.com  " not in resultado


# ============================================
# _añadir_hostname_ech_csv
# ============================================

class TestAñadirHostnameEchCsv:
    def test_crea_archivo_con_encabezado_si_no_existe(self, tmp_path):
        p = tmp_path / "hostnames_ech.csv"
        existentes: set = set()
        _añadir_hostname_ech_csv("kali.org", p, existentes)
        assert p.exists()
        lineas = p.read_text(encoding="utf-8").splitlines()
        assert lineas[0] == "hostname"
        assert "kali.org" in lineas

    def test_añade_hostname_al_set_en_memoria(self, tmp_path):
        p = tmp_path / "hostnames_ech.csv"
        existentes: set = set()
        _añadir_hostname_ech_csv("kali.org", p, existentes)
        assert "kali.org" in existentes

    def test_idempotente_no_duplica(self, tmp_path):
        p = tmp_path / "hostnames_ech.csv"
        existentes: set = set()
        _añadir_hostname_ech_csv("kali.org", p, existentes)
        _añadir_hostname_ech_csv("kali.org", p, existentes)
        lineas = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert lineas.count("kali.org") == 1

    def test_no_elimina_entradas_existentes(self, tmp_path):
        p = tmp_path / "hostnames_ech.csv"
        p.write_text("hostname\nexistente.com\n", encoding="utf-8")
        existentes = {"existente.com"}
        _añadir_hostname_ech_csv("nuevo.com", p, existentes)
        contenido = p.read_text(encoding="utf-8")
        assert "existente.com" in contenido
        assert "nuevo.com" in contenido

    def test_crea_directorio_padre_si_no_existe(self, tmp_path):
        p = tmp_path / "subdir" / "hostnames_ech.csv"
        existentes: set = set()
        _añadir_hostname_ech_csv("x.com", p, existentes)
        assert p.exists()


# ============================================
# _cargar_progreso_ech
# ============================================

class TestCargarProgresoEch:
    def test_archivo_inexistente_devuelve_vacios(self, tmp_path):
        lista, completados = _cargar_progreso_ech(tmp_path / "noexiste.jsonl")
        assert lista == []
        assert completados == set()

    def test_carga_una_entrada(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        r = _hacer_dominio_resultado(domain="kali.org")
        from dataclasses import asdict
        p.write_text(json.dumps(asdict(r)) + "\n", encoding="utf-8")
        lista, completados = _cargar_progreso_ech(p)
        assert len(lista) == 1
        assert "kali.org" in completados

    def test_dedup_mismo_dominio(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        from dataclasses import asdict
        r = _hacer_dominio_resultado(domain="kali.org")
        linea = json.dumps(asdict(r)) + "\n"
        p.write_text(linea + linea, encoding="utf-8")
        lista, completados = _cargar_progreso_ech(p)
        assert len(lista) == 1

    def test_linea_corrupta_ignorada(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        from dataclasses import asdict
        r = _hacer_dominio_resultado(domain="a.com")
        p.write_text(
            json.dumps(asdict(r)) + "\n"
            "ESTO_NO_ES_JSON\n"
            + json.dumps(asdict(_hacer_dominio_resultado(domain="b.com"))) + "\n",
            encoding="utf-8",
        )
        lista, completados = _cargar_progreso_ech(p)
        assert len(lista) == 2
        assert completados == {"a.com", "b.com"}

    def test_reconstruye_dataclass(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        from dataclasses import asdict
        r = _hacer_dominio_resultado(domain="test.org", has_ech_param=True)
        p.write_text(json.dumps(asdict(r)) + "\n", encoding="utf-8")
        lista, _ = _cargar_progreso_ech(p)
        assert isinstance(lista[0], DominioECHResultado)
        assert lista[0].domain == "test.org"
        assert lista[0].has_ech_param is True


# ============================================
# _append_progress_ech_jsonl
# ============================================

class TestAppendProgressEchJsonl:
    def test_crea_archivo_si_no_existe(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        r = _hacer_dominio_resultado()
        _append_progress_ech_jsonl(r, p)
        assert p.exists()

    def test_contenido_es_json_valido(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        r = _hacer_dominio_resultado(domain="kali.org")
        _append_progress_ech_jsonl(r, p)
        linea = p.read_text(encoding="utf-8").strip()
        d = json.loads(linea)
        assert d["domain"] == "kali.org"

    def test_acumula_multiples_entradas(self, tmp_path):
        p = tmp_path / "progress.jsonl"
        _append_progress_ech_jsonl(_hacer_dominio_resultado(domain="a.com"), p)
        _append_progress_ech_jsonl(_hacer_dominio_resultado(domain="b.com"), p)
        lineas = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lineas) == 2
        dominios = {json.loads(l)["domain"] for l in lineas}
        assert dominios == {"a.com", "b.com"}

    def test_crea_directorio_padre_si_no_existe(self, tmp_path):
        p = tmp_path / "subdir" / "progress.jsonl"
        _append_progress_ech_jsonl(_hacer_dominio_resultado(), p)
        assert p.exists()
