#!/usr/bin/env bash
# Prueba de punta a punta (contra local-server.mjs + Postgres local) de los
# 3 modos de vendedor (seller_mode: logueado/asignado/externo) y de la
# validacion de fecha de venta no futura, agregados para que un supervisor
# pueda cargar una venta que vino de un vendedor externo o de otro vendedor
# interno sin que quede atribuida al usuario logueado (ver resolveSaleSeller
# en index.mjs y CLAUDE.md).
#
# Corre contra /leads/:id/management porque es el unico de los 4 caminos que
# registran ventas (POST /contacts, Recupero, /leads/:id/management) que NO
# depende de sale_items -- esa tabla diverge de produccion en local
# (falta product_name_snapshot/price, ver CLAUDE.md) y bloquea a los otros 3
# caminos hasta que se escriba y confirme la migracion 077. Los mismos 4
# caminos comparten resolveSaleSeller/validateFechaVentaNotFuture, asi que
# validar la logica en este camino cubre la parte de negocio pedida; falta
# repetir el mismo chequeo en POST /contacts y Recupero una vez resuelto
# sale_items.
#
# Requisitos para correr:
# - Postgres local con las migraciones 071-076 aplicadas (rednacrem db).
# - local-server.mjs corriendo en :3001 (`node local-server.mjs` desde
#   rednacrem-backend/, con .env.local cargado).
# - Los IDs de usuarios/leads de abajo son de datos ya sembrados en local;
#   si se resembra la base, hay que confirmarlos de nuevo con psql (ver los
#   SELECT comentados junto a cada escenario).
#
# Uso: bash tests/venta_vendedor_fecha.sh

set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:3001}"
SUPERVISOR_EMAIL="supervisor@renacrem.com"     # Rednacrem, org 9223d62d-f558-4f4c-b9bd-9dcea9888a0e
VENDEDOR_INTERNO_ID="4162e68c-a0b6-4a8a-9791-a9283f16053b"   # Matias Decker, vendedor Rednacrem
VENDEDOR_OTRA_ORG_ID="f948e949-d5e6-4cd6-965e-16129105e07e"  # admin@local.test, SU Emergencia (org distinta)
PRODUCT_ID="4c80dfda-0611-49ef-9750-127daf573329"            # "Plan Prueba", ya existente en local

# Leads de organization_id=9223d62d... con telefono UNICO en la tabla (no
# compartido con otro lead) para no chocar con isSamePersonForPhoneMatch al
# recrear el mismo contacto entre escenarios. Si hace falta elegir otros:
#   psql -d rednacrem -t -c "SELECT telefono, count(*), array_agg(id) FROM datos_para_trabajar WHERE organization_id='9223d62d-f558-4f4c-b9bd-9dcea9888a0e' GROUP BY telefono HAVING count(*)=1 LIMIT 10;"
LEAD_EXTERNO="ac2c52c9-8c1c-4449-b528-a306c8a2e505"
LEAD_ASIGNADO="eb0f9f03-5009-481c-89b8-1b45c29f2fce"
LEAD_LOGUEADO="55550001-0001-4001-8001-000000000001"
LEAD_FUTURO="91c6683f-00d5-415b-8139-8ff42860ae9b"
LEAD_CROSS_ORG="11cbdac5-b86a-414f-8f05-e38a1076fbbe"

TODAY=$(date +%Y-%m-%d)
HACE_5_DIAS=$(date -v-5d +%Y-%m-%d 2>/dev/null || date -d "-5 days" +%Y-%m-%d)
FUTURA=$(date -v+5d +%Y-%m-%d 2>/dev/null || date -d "+5 days" +%Y-%m-%d)

req() {
  local lead_id="$1"; shift
  curl -s -w "\nHTTP_STATUS:%{http_code}\n" -X POST "$BASE_URL/leads/$lead_id/management" \
    -H "Content-Type: application/json" \
    -H "x-dev-auth: true" \
    -H "x-dev-user-email: $SUPERVISOR_EMAIL" \
    -H "x-dev-user-role: supervisor" \
    -H "x-dev-user-sub: local-dev-supervisor" \
    -d "$1"
}

echo "=== 1) Vendedor externo 'Matías Decker', fecha de venta hace 5 dias ==="
req "$LEAD_EXTERNO" "{
  \"status\": \"venta\",
  \"contact\": {\"documento\": \"22222222\", \"nombre\": \"Lead\", \"apellido\": \"Idempotente\"},
  \"seller_mode\": \"externo\",
  \"vendedor_nombre\": \"Matías Decker\",
  \"product\": {\"id\": \"$PRODUCT_ID\", \"nombre\": \"Plan Prueba\", \"precio\": 100, \"fecha_alta\": \"$HACE_5_DIAS\"},
  \"medio_pago\": \"efectivo\"
}"
echo

echo "=== 2) Vendedor asignado explicito (otro usuario de la misma org) ==="
req "$LEAD_ASIGNADO" "{
  \"status\": \"venta\",
  \"contact\": {\"documento\": \"33333333\", \"nombre\": \"Lead\", \"apellido\": \"Idempotente\"},
  \"seller_mode\": \"asignado\",
  \"vendedor_id\": \"$VENDEDOR_INTERNO_ID\",
  \"product\": {\"id\": \"$PRODUCT_ID\", \"nombre\": \"Plan Prueba\", \"precio\": 100, \"fecha_alta\": \"$TODAY\"},
  \"medio_pago\": \"efectivo\"
}"
echo

echo "=== 3) Usuario logueado, fecha de hoy ==="
req "$LEAD_LOGUEADO" "{
  \"status\": \"venta\",
  \"contact\": {\"documento\": \"55555555\", \"nombre\": \"Test\", \"apellido\": \"Logueado\"},
  \"seller_mode\": \"logueado\",
  \"product\": {\"id\": \"$PRODUCT_ID\", \"nombre\": \"Plan Prueba\", \"precio\": 100, \"fecha_alta\": \"$TODAY\"},
  \"medio_pago\": \"efectivo\"
}"
echo

echo "=== 4) Fecha futura -- se espera 400 ==="
req "$LEAD_FUTURO" "{
  \"status\": \"venta\",
  \"contact\": {\"documento\": \"66666666\", \"nombre\": \"Test\", \"apellido\": \"Futuro\"},
  \"seller_mode\": \"logueado\",
  \"product\": {\"id\": \"$PRODUCT_ID\", \"nombre\": \"Plan Prueba\", \"precio\": 100, \"fecha_alta\": \"$FUTURA\"},
  \"medio_pago\": \"efectivo\"
}"
echo

echo "=== 5) Vendedor asignado de OTRA organizacion -- se espera 400 ==="
req "$LEAD_CROSS_ORG" "{
  \"status\": \"venta\",
  \"contact\": {\"documento\": \"77777777\", \"nombre\": \"Test\", \"apellido\": \"CrossOrg\"},
  \"seller_mode\": \"asignado\",
  \"vendedor_id\": \"$VENDEDOR_OTRA_ORG_ID\",
  \"product\": {\"id\": \"$PRODUCT_ID\", \"nombre\": \"Plan Prueba\", \"precio\": 100, \"fecha_alta\": \"$TODAY\"},
  \"medio_pago\": \"efectivo\"
}"
echo

echo "=== Filas resultantes en sales (de los 3 escenarios que sí escriben) ==="
psql -d rednacrem -c "
  SELECT s.id, s.seller_user_id, u.nombre AS seller_nombre, u.apellido AS seller_apellido,
         s.seller_name_snapshot, s.seller_origin, s.fecha_venta, s.registrada_por_user_id,
         ru.nombre AS registrada_por_nombre, ru.apellido AS registrada_por_apellido
  FROM sales s
  LEFT JOIN users u ON u.id = s.seller_user_id
  LEFT JOIN users ru ON ru.id = s.registrada_por_user_id
  WHERE s.contact_id IN (
    SELECT id FROM contacts WHERE documento IN ('22222222','33333333','55555555')
  )
  ORDER BY s.created_at;
"

echo "=== Filas resultantes en contact_products (mismos 3 escenarios) ==="
psql -d rednacrem -c "
  SELECT cp.contact_id, cp.seller_user_id, cp.seller_name_snapshot, cp.seller_origin, cp.fecha_alta
  FROM contact_products cp
  JOIN contacts c ON c.id = cp.contact_id
  WHERE c.documento IN ('22222222','33333333','55555555')
  ORDER BY cp.created_at;
"
