# Sistema de Clasificación de Errores - Sonda PQC

## Estructura de Resultados

Cada resultado de prueba ahora contiene dos campos principales:

### 1. `error_category` (Categoría de Error)
Campo normalizado que clasifica el tipo de error ocurrido. Valores posibles:

- **`null`**: No hubo error (conexión exitosa)
- **`ERROR_DNS`**: Fallo en la resolución DNS del hostname
- **`ERROR_TCP_REFUSED`**: Puerto 443 cerrado o conexión rechazada a nivel TCP
- **`ERROR_TCP_TIMEOUT`**: Timeout durante la conexión TCP inicial
- **`ERROR_TCP_OTHER`**: Otros errores de red/TCP (unreachable, etc.)
- **`ERROR_TLS_TIMEOUT`**: Timeout durante el handshake TLS
- **`ERROR_TLS_ALERT`**: El servidor envió un TLS Alert rechazando el handshake
- **`ERROR_UNKNOWN`**: Error inesperado o desconocido

### 2. `connection_result` (Resultado de Conexión)
Indica si el handshake TLS fue exitoso o rechazado. Valores posibles:

- **`ACEPTADO`**: El servidor aceptó la conexión y completó el handshake TLS exitosamente
- **`RECHAZADO`**: El servidor rechazó explícitamente el handshake (incompatibilidad de grupos, protocolo, etc.)
- **`null`**: No aplicable (hubo un error antes del handshake TLS)

### 3. `res` (Detalles)
Campo de texto libre con información adicional sobre el resultado o error.

## Matriz de Clasificación

| error_category      | connection_result | Significado                                                    |
|---------------------|-------------------|----------------------------------------------------------------|
| `null`              | `ACEPTADO`        | ✅ Conexión exitosa                                            |
| `ERROR_TLS_ALERT`   | `RECHAZADO`       | ⚠️ Servidor rechazó el handshake (ej: grupo no soportado)     |
| `ERROR_DNS`         | `null`            | ❌ No se pudo resolver el hostname                             |
| `ERROR_TCP_REFUSED` | `null`            | ❌ Puerto 443 cerrado o firewall                               |
| `ERROR_TCP_TIMEOUT` | `null`            | ❌ Timeout en conexión TCP                                     |
| `ERROR_TCP_OTHER`   | `null`            | ❌ Otro error de red (unreachable, etc.)                       |
| `ERROR_TLS_TIMEOUT` | `null`            | ❌ Timeout durante handshake TLS                               |
| `ERROR_UNKNOWN`     | `null`            | ❌ Error inesperado                                            |

## Ejemplos de Resultados

### ✅ Conexión Exitosa
```json
{
    "error_category": null,
    "connection_result": "ACEPTADO",
    "res": "Server Temp Key: X25519 MLKEM768, 256 bits",
    "grupo": "X25519MLKEM768",
    ...
}
```

### ⚠️ Servidor Rechazó el Grupo PQC
```json
{
    "error_category": "ERROR_TLS_ALERT",
    "connection_result": "RECHAZADO",
    "res": "TLS alert: handshake failure",
    "grupo": "mlkem768",
    ...
}
```

### ❌ Error de Infraestructura (DNS)
```json
{
    "error_category": "ERROR_DNS",
    "connection_result": null,
    "res": "DNS no resolvió",
    "grupo": "X25519MLKEM768",
    ...
}
```

### ❌ Timeout
```json
{
    "error_category": "ERROR_TLS_TIMEOUT",
    "connection_result": null,
    "res": "Timeout durante handshake TLS",
    "grupo": "frodo640aes",
    ...
}
```

## Análisis de Resultados

### Filtrar solo conexiones exitosas:
```python
exitosas = [p for p in pruebas if p["connection_result"] == "ACEPTADO"]
```

### Filtrar por tipo de error:
```python
errores_dns = [p for p in pruebas if p["error_category"] == "ERROR_DNS"]
rechazos_tls = [p for p in pruebas if p["connection_result"] == "RECHAZADO"]
```

### Estadísticas por categoría:
```python
from collections import Counter

# Contar errores por categoría
error_stats = Counter(p["error_category"] for p in pruebas)

# Contar resultados de conexión
connection_stats = Counter(p["connection_result"] for p in pruebas)
```

## Beneficios

1. **Normalización**: Los errores están clasificados de forma consistente
2. **Análisis**: Facilita la agregación y análisis estadístico
3. **Separación**: Distingue claramente entre errores de infraestructura y rechazo activo del servidor
4. **Compatibilidad**: El campo `res` mantiene información detallada para debugging
