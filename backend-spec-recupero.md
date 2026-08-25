# Backend Spec Recupero

## Mapeo final de estados

El backend preserva dos ejes distintos:

- `estado`: eje operativo principal del candidato.
- `resultado_gestion`: sub-resultado detallado de la gestión.

La spec visible para Recupero colapsa estados únicamente desde `estado` y los resultados finales:

| condición actual | estado_colapsado |
|---|---|
| `estado = 'disponible'` | `pendiente` |
| `estado = 'en_gestion'` | `en_gestion` |
| `resultado_gestion = 'venta'` | `recuperado` |
| `resultado_gestion = 'rechazo'` | `rechazado` |

## Regla de detalle preservado

- `resultado_gestion` se preserva intacto como sub-campo de detalle.
- No se aplana ni se pierde información.
- `resultado_gestion = 'nuevo'` no es un estado alternativo: representa asignado/sin gestión tipificada todavía.
- Un candidato con `estado = 'en_gestion'` y `resultado_gestion = 'nuevo'` sigue perteneciendo al estado colapsado `en_gestion`.

Valores actuales preservados de `resultado_gestion`:

- `nuevo`
- `no_contesta`
- `rellamar`
- `seguimiento`
- `dato_erroneo`
- `venta`
- `rechazo`

## Regla de effectiveness

- `effectiveness_pct = recuperado / (recuperado + rechazado)`
- `dato_erroneo` queda excluido del denominador.
- `pendiente` y `en_gestion` tampoco participan del denominador.

## Regla de conteos

- `falta_recuperar = pendiente + en_gestion`
- `gestionados_cerrados = recuperado + rechazado`
