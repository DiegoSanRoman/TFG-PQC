"""
constants.py
------------
Constantes compartidas entre las sondas y el análisis del proyecto TFG-PQC.

Centralizar aquí los valores de clasificación evita que cada módulo defina
sus propias cadenas literales y que analizar_resultados.py tenga que saber
de memoria los strings exactos que producen las sondas.
"""

# ============================================
# CATEGORÍAS DE ERROR (sonda PQC)
# ============================================
# Se asignan en el campo "error_category" del resultado de sonda_pqc()

ERROR_DNS          = "ERROR_DNS"           # Fallo en resolución DNS
ERROR_TCP_REFUSED  = "ERROR_TCP_REFUSED"   # Puerto cerrado o conexión rechazada
ERROR_TCP_TIMEOUT  = "ERROR_TCP_TIMEOUT"   # Timeout en conexión TCP
ERROR_TCP_OTHER    = "ERROR_TCP_OTHER"     # Otros errores TCP/red
ERROR_TLS_TIMEOUT  = "ERROR_TLS_TIMEOUT"   # Timeout durante handshake TLS
ERROR_TLS_ALERT    = "ERROR_TLS_ALERT"     # Alert TLS recibido del servidor
ERROR_UNKNOWN      = "ERROR_UNKNOWN"       # Error desconocido o inesperado

# Conjunto de todas las categorías de error, útil para validaciones
ALL_ERROR_CATEGORIES = frozenset({
    ERROR_DNS,
    ERROR_TCP_REFUSED,
    ERROR_TCP_TIMEOUT,
    ERROR_TCP_OTHER,
    ERROR_TLS_TIMEOUT,
    ERROR_TLS_ALERT,
    ERROR_UNKNOWN,
})

# ============================================
# RESULTADOS DE CONEXIÓN (sonda PQC)
# ============================================
# Se asignan en el campo "connection_result" del resultado de sonda_pqc()

CONNECTION_ACCEPTED = "ACEPTADO"   # Handshake TLS completado con éxito
CONNECTION_REJECTED = "RECHAZADO"  # Servidor rechazó el handshake explícitamente
