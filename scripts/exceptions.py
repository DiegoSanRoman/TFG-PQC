"""
exceptions.py
-------------
Jerarquía de excepciones personalizadas del proyecto TFG-PQC.

Todas las excepciones heredan de PQCError, permitiendo capturar cualquier
error del proyecto con un único ``except PQCError``.
"""


class PQCError(Exception):
    """Excepción base para todos los errores del proyecto PQC."""


class PQCValidationError(PQCError):
    """Entrada inválida: hostname mal formado, ruta inexistente, parámetro fuera de rango, etc."""


class PQCDNSError(PQCError):
    """Fallo en la resolución DNS del hostname objetivo."""


class PQCTCPRefusedError(PQCError):
    """Conexión TCP rechazada: el puerto está cerrado o el servidor la rechaza activamente."""


class PQCTCPTimeoutError(PQCError):
    """Timeout durante el establecimiento de la conexión TCP."""


class PQCTCPError(PQCError):
    """Error genérico de red o transporte TCP (OSError, etc.)."""


class PQCTLSTimeoutError(PQCError):
    """Timeout durante el handshake TLS/PQC."""


class PQCTLSAlertError(PQCError):
    """Alert TLS recibido del servidor durante el handshake (handshake failure, etc.)."""
