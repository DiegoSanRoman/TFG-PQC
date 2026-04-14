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
import sys
from pathlib import Path

import pytest

# Añadir scripts/ y scripts/sondas/ al path
_SCRIPTS_DIR = Path(__file__).parent.parent
_SONDAS_DIR = _SCRIPTS_DIR / "sondas"
for _p in (_SCRIPTS_DIR, _SONDAS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from sonda_ech_prevalencia import (
    STATUS_CLIENTE_SIN_SOPORTE,
    STATUS_EXITO_OUTER_CH,
    STATUS_FALLBACK,
    STATUS_FALLO_NEGOCIACION,
    STATUS_NEGOCIACION_OK_SIN_CONFIRMAR,
    _decode_ech_base64,
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
    def test_codigo_no_cero_devuelve_false(self):
        assert detectar_handshake_completo("Verify return code: 0 (ok)", 1) is False

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
