# Tri — Contexto para Claude Code

## Reglas de arquitectura (obligatorias)
1. **Multi-tenant sin excepciones**: toda consulta, `UPDATE` o `DELETE` sobre datos
   de negocio filtra por `organization_id` de forma incondicional. Prohibido
   `${organizationId ? ... : ''}` y `$1::uuid IS NULL OR ...` — son exactamente el
   patrón que permite que datos de una organización se mezclen con los de otra.
   Si `organization_id` no se logra resolver, el endpoint corta ahí mismo con
   403, nunca sigue de largo con un filtro ausente. Todo `INSERT` setea
   `organization_id` explícito, sin dejarlo para un backfill posterior.
2. **El esquema de producción es la fuente de verdad**: no agregar nuevas
   detecciones de columnas en runtime (`columnExists`, `getTableColumns`,
   `has*Col` y variantes). Si una columna existe en producción pero falta en
   local, se agrega a local con una migración — el código se escribe asumiendo
   el esquema de producción, no al revés.
3. **Migraciones**: idempotentes siempre. Nunca `CREATE TABLE IF NOT EXISTS`
   sobre una tabla que podría ya existir con otra forma en producción sin
   verificar antes contra RDS. Tienen que ser no-op en los entornos donde ya
   se aplicaron, y el agente nunca las corre contra producción — eso lo hace
   Damián.
4. **Una operación de negocio, una función**: antes de escribir lógica nueva
   para alta de contacto, registro de venta, baja de producto, alta de lead o
   de candidato de Recupero, buscar si ya existe una función que resuelva eso
   y reutilizarla. Si aparece lógica duplicada entre endpoints, avisar en vez
   de sumar una copia más.
5. **Identidad de personas**: compartir un teléfono no implica que sea la
   misma persona (`isSamePersonForPhoneMatch`). El documento sí identifica a
   una persona de forma confiable, siempre evaluado dentro de la misma
   organización.
6. **Errores legibles**: toda respuesta 4xx devuelve un `message` legible en
   español, nunca solo un código o un campo `error` suelto sin `message`.
7. **Los scripts de prueba no se borran**: los que cubren flujos críticos se
   guardan en `tests/` (aunque todavía no haya un runner configurado), con
   instrucciones de cómo correrlos.
8. **Divergencias de esquema**: cualquier diferencia entre local y producción
   que se descubra se documenta en el momento en la lista de este archivo,
   no se deja para después.
9. **Antes de tocar la base de datos**: correr `node scripts/compare-schema.mjs`
   contra el esquema de producción exportado en `docs/prod-schema/` antes de
   escribir cualquier migración nueva. No confiar solo en divergencias ya
   documentadas — pueden quedar desactualizadas.
10. **Contenido largo pegado por Damián** (base64, dumps de CSV, salidas de
    `psql`, etc.): nunca se transcribe a mano. Un pegado de varios miles de
    caracteres en la conversación puede llegar recortado, reordenado o con el
    prompt de la terminal mezclado adentro (ya pasó con un export de esquema
    en base64: dos "partes" resultaron ser fragmentos de dos streams gzip
    distintos, no continuación una de la otra). Si hace falta el contenido
    exacto, Damián lo deja en disco (o lo pega como archivo) y se copia con
    `cp`/`Read`, verificando tamaño en bytes y `shasum -a 256` contra el
    original antes de confiar en la copia.

## Qué es esto
Tri es un CRM SaaS multi-tenant (antes "Rednacrem") que sirve a cuatro organizaciones:
Rednacrem, Global Assist, SU Emergencia y Club del Adulto Mayor. Cada organización
tiene aislamiento de datos estricto (multi-tenant) — cualquier cambio en endpoints
que tocan `organization_id` requiere doble chequeo.

## Stack
- Backend: Node.js en AWS Lambda, monolítico en `index.mjs`
- Frontend: React + Vite, entrada en `src/main.jsx`
- DB: PostgreSQL en Aurora RDS
- Auth: AWS Cognito
- Hosting/CI: Amplify + GitHub Actions
- Automatizaciones: n8n (ingestión de leads Meta/Google Sheets, SMS vía Dinstar)

## Rol de Claude en este proyecto
Claude Code es el agente de código principal (ya no se usa Codex). Claude se encarga de:
- Auditorías read-only del código antes de tocar cambios grandes o sensibles
- Implementación directa de los cambios — backend y frontend siempre en commits/tareas
  separadas, nunca mezclados
- Revisar el diff completo antes de commitear
- Investigación y debugging de bugs de producción

## Reglas de base de datos — CRÍTICO
- El schema local **diverge** del de producción. Divergencias conocidas confirmadas
  contra RDS (no asumir que la lista está completa):
  - `lead_contact_status.organization_id` existe en producción pero no en local.
  - `manual_tickets.organization_id` existe en producción pero no en local.
  - `contact_products.organization_id`, `sales.organization_id` y
    `datos_para_trabajar.contact_id` existen en producción pero no existían en
    local (confirmado contra RDS en el PASO 0 de la segunda ronda de fixes de
    POST /contacts) — corregido en local por
    `sql/migrations/072_add_missing_org_id_contact_id_columns.sql`. Sin esas
    3 columnas, las ramas `hasContactIdCol`/`hasContactProductOrgId`/
    `organizationId` de `index.mjs` que SÍ corren en producción nunca se
    ejercitaban en pruebas locales. Importante: `datos_para_trabajar.contact_id`
    referencia `contacts(id)` (igual que `sales.contact_id` y
    `contact_products.contact_id`) — no confundir con `lead_contact_status.contact_id`,
    que referencia `datos_para_trabajar(id)`, no `contacts(id)`.
  - `contact_products_motivo_baja_check` (el `CHECK` de `motivo_baja`) tiene una
    lista de valores **distinta** en producción (`'voluntaria'`, `'baja_bps'`,
    `'sin_pago_bps'`, `'baja_antel'`, `'sin_liquidez'`, `'fallecimiento'`,
    `'falta_de_pago'`, `'auditoria'`, `'error_activacion'`, `'administrativa'`,
    `'no_llamar'`, `'otro_servicio'` — todo minúscula, sin tildes) que la que define
    `sql/migrations/048_update_motivo_baja_constraint.sql` en este repo (`'Auditoría'`,
    `'Medio de pago'`, `'Voluntaria'`, etc., capitalizado). Esa migración solo corrió
    en local — nunca escribas `motivo_baja` basándote en el valor de la 048 sin
    confirmar antes contra RDS. **Corregido en local por
    `sql/migrations/080_fix_motivo_baja_check_to_match_prod.sql`** (remapea las
    filas locales existentes y reemplaza el `CHECK` por la lista real de
    arriba) — sin esto, cualquier baja real con el código actual (que siempre
    escribe un slug en minúscula) fallaba en local contra el `CHECK` viejo de
    la 048. **SOLO LOCAL, no-op en producción** (prod ya tiene el `CHECK`
    correcto) — no se corre ahí.
  - Los índices únicos de `contacts.documento` y `contacts.email` tenían alcance
    **distinto** entre local y producción (confirmado por Damián, corregido en local
    por `sql/migrations/071_align_contacts_unique_indexes_with_prod.sql`):
    - `documento`: local tenía `contacts_documento_unique_idx` **UNIQUE global**;
      producción usa `idx_contacts_documento`, que **no es único** (la unicidad
      dentro de una organización la impone la aplicación, no Postgres — ver
      `findDuplicateContactByDocumentoInOrganization`).
    - `email`: local tenía `contacts_email_unique_idx` **UNIQUE global**;
      producción usa `contacts_email_org_unique_idx`, **UNIQUE por organización**
      (`organization_id, lower(email)`). Un índice único global rompía el caso real
      de una misma persona siendo cliente de dos organizaciones distintas.
  - `sales` en local tenía columnas renombradas y varias faltantes respecto a
    producción (confirmado contra RDS por Damián: columnas, constraints e índices
    exactos de la tabla). Corregido en local por
    `sql/migrations/075_align_sales_with_prod.sql` (`seller_id`→`seller_user_id`,
    `fecha`→`fecha_venta`, y agrega `notes`, `documento_cobranza`,
    `sale_group_id`, `parent_sale_id`, `gestion_id`, `titular_contact_id`,
    `relation`, `product_id`, `payment_method_id` con sus FKs e índices). Con esto,
    `insertSaleRecord` en `index.mjs` ya no detecta columnas en runtime — asume
    directamente el esquema de producción (regla 2). **SOLO LOCAL, no-op en
    producción** (confirmado columna por columna contra
    `docs/prod-schema/prod_columns.csv`) — Damián confirmó que no se corrió en
    el deploy de este feature.
  - `sales.registrada_por_user_id` (uuid, FK a `users`) es una columna **nueva**,
    agregada en local por `sql/migrations/076_add_sales_registrada_por.sql`.
    Guarda siempre al usuario logueado que cargó la venta (ver `resolveSaleSeller`
    en `index.mjs`), independientemente de quién sea el vendedor. **Esta SÍ se
    corrió en producción** (Damián, COMMIT confirmado) — a diferencia de
    074/075/077/078, no era no-op: sin ella las ventas fallan en cuanto se
    despliega el backend nuevo.
  - `products.organization_id` **no existía en local** (`createProductAndSale`
    ya filtraba `products` por esa columna de forma incondicional, sin gateo de
    metadata — solo podía funcionar así si producción la tiene). Aprobada por
    Damián para aplicar en local por
    `sql/migrations/074_add_products_organization_id.sql` (solo `ADD COLUMN IF
    NOT EXISTS`, sin FK ni `NOT NULL`) para poder probar de punta a punta el
    alta manual de clientes. **SOLO LOCAL, no-op en producción** (la columna ya
    existe ahí idéntica) — no se corrió en el deploy de este feature.
  - `sale_items` en local tenía `cantidad`/`precio_unitario` (con sus CHECK) en
    vez de `product_name_snapshot`/`price`/`organization_id`, y `product_id`
    era `NOT NULL` (en producción es nullable). Confirmado contra RDS por
    Damián y corregido en local por
    `sql/migrations/077_align_sale_items_and_create_payment_methods.sql`:
    agrega las columnas de producción, relaja `product_id`, agrega la FK de
    `organization_id`, y dropea `cantidad`/`precio_unitario` (confirmado por
    grep que ningún camino de `index.mjs` las usa — todos ya asumían
    `product_name_snapshot`/`price`, la misma señal que con `sales`/`products`:
    si producción no tuviera esas columnas, ese código preexistente nunca
    podría haber funcionado ahí). Los índices y las FKs de `sale_id`/
    `product_id` ya coincidían con producción. **SOLO LOCAL, no-op en
    producción** (las 8 columnas de `sale_items` y las 5 de `payment_methods`
    ya existen ahí idénticas) — no se corrió en el deploy de este feature.
  - `public.payment_methods` **no existía en absoluto en local** (ni vacía) —
    descubierto al escribir la migración 075. El endpoint `GET /payment-methods`
    y el `LEFT JOIN payment_methods` de `getClientDetailData` ya asumían su
    existencia (código correcto para producción), así que el selector de "Medio
    de pago" del wizard venía fallando en local independientemente de cualquier
    cambio de esta sesión. Creada en local, igual a producción (columnas,
    constraints e índice único `(lower(nombre), organization_id)`), por la
    misma migración 077. Con esto, `sales_payment_method_id_fkey` (que 075
    había dejado sin agregar porque no había a qué tabla apuntar) también se
    agrega en 077. El seed de datos de `payment_methods` (los medios de pago
    reales de Rednacrem/Global Assist) vive aparte, en
    `sql/seeds/payment_methods_local.sql` — un seed nunca va en una migración.
  - **Esquema de producción exportado**: `docs/prod-schema/prod_columns.csv`
    (columnas de las 84 tablas reales de producción, exportado 2026-09-30) es
    la fuente de verdad para comparar contra local — nunca se edita a mano
    (ver regla 10). `scripts/compare-schema.mjs` compara local contra ese CSV
    y reporta tablas/columnas faltantes, diferencias de tipo/nulabilidad/
    default, y lo que sobra en local; correrlo antes de cualquier migración
    nueva (regla 9). Con ese reporte se escribió
    `sql/migrations/078_add_missing_columns_from_prod.sql`: agrega las 44
    columnas de producción que faltaban en local (con dos excepciones
    deliberadas a la nulabilidad — `client_document_events.contact_id` y
    `.tipo` son `NOT NULL` en producción pero se agregaron nullable porque la
    tabla local ya tenía filas) y crea `contact_relations` (la única de las 25
    tablas de producción ausentes en local que el alta de clientes usa de
    verdad, en el `INSERT` de familiares — columnas, constraints e índices
    calcados de RDS, incluida la `UNIQUE (contact_id_a, contact_id_b)` que usa
    su `ON CONFLICT`). **SOLO LOCAL, no-op en producción** en sus dos partes
    (las 44 columnas ya existen ahí, `contact_relations` ya existe ahí con
    esos mismos constraints/índices) — no se corrió en el deploy de este
    feature.
  - **Pendiente para una reconstrucción completa de la base local (fase 1,
    fuera del alcance de esta sesión)**: las 178 diferencias de tipo/
    nulabilidad/default entre columnas que ya existen en ambos lados
    (mayormente `timestamp without time zone` vs `timestamptz`, y varias
    tablas — `roles`, `su_*`, `user_role_history`, `user_status_history`,
    `vendor_registration_requests` — con `id bigint`/serial en local en vez
    de `uuid` como en producción), y crear estas 20 tablas de producción que
    el código también usa pero que no bloqueaban el feature de vendedor
    externo/fecha de venta: `datos_para_trabajar_import_jobs`,
    `lead_batch_rr_cursor`, `lead_coding_audit`, `module_states`,
    `no_call_entries_audit`, `origen_dato_catalog`, `sellers`,
    `sms_connections`, `sms_log`, `sms_templates`, `su_equipos_biomedicos`,
    `su_materiales_catalogo`, `su_materiales_movimientos`,
    `su_materiales_stock`, `su_servicios`, `su_servicios_dotacion`,
    `su_servicios_historia_clinica`, `su_turnos`,
    `su_vehiculos_equipamiento_checklist`, `su_vehiculos_mantenimiento`.
    (Las otras 4 tablas ausentes — `contact_products_dedupe_backup_20260723`,
    `contact_products_dedupe_map_20260723`, `schema_migrations`,
    `su_empresas_contratistas` — no las usa ningún camino de `index.mjs`, no
    hace falta crearlas en local.)
- **Nunca** verifiques ni asumas el schema contra la base local.
- Toda verificación de schema se hace vía `psql` contra RDS producción, y la corre
  Damián directamente — no Claude contra una copia local.
- Si necesitás confirmar una columna, tabla o constraint, pedile a Damián que lo
  chequee en producción antes de asumir nada.

## Workflow estándar
1. Auditoría read-only del código relevante
2. Implementar el cambio — backend y frontend en tareas/commits separados
3. Revisar el diff completo generado
4. Validar con `node --check` (backend) y `npm run build` (frontend)
5. Commit

## Organizaciones (IDs de referencia)
- Rednacrem: `9223d62d-f558-4f4c-b9bd-9dcea9888a0e`
- Global Assist: `b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8`

## Infraestructura de referencia
- API Gateway: `kzfibrikb4.execute-api.us-east-2.amazonaws.com`
- Cognito User Pool: `us-east-2_Jy8mPM6NJ`
- Dominios: `callcenter.tri.uy` (Rednacrem) y `globalassist.tri.uy` (Global Assist),
  vía `window.location.origin` dinámico en config de Cognito
- DNS gestionado por Antel (no Route 53)

## Cuidado especial
- Cualquier endpoint que toque `organization_id` es candidato a bug de aislamiento
  multi-tenant — ya hubo leaks de datos cross-org en el pasado (`GET /clients`,
  `upsertContact()`). Al auditar código nuevo o existente, verificar explícitamente
  el filtro por organización en cada query.
- Antes de tocar `processRecuperoImportJob` o el flujo de import CSV de Recupero,
  revisar el estado de la auditoría de agosto 2026 (dedupe, `ON CONFLICT`, columna
  PRECIO) para no reintroducir bugs ya identificados.
- **Toda baja de `contact_products` que ocurre AHORA sobre un producto activo
  pasa por `aplicarBajaContactProduct`** (única función que hace el `UPDATE`,
  la auditoría en `contact_product_baja_audit`, `recupero_alerts` y el alta en
  `recupero_candidatos` con dedup vía `idx_recupero_dedup`) — la usan la baja
  individual (`POST /contacts/:contactId/products/:productId/baja`), la baja
  masiva, y `closeManualTicket` cuando un ticket `solicitud_baja` se cierra con
  `outcome='baja_confirmada'` (antes hacía su propio `UPDATE` sin pasar por
  Recupero — bug reportado y corregido). El motivo de baja en ese caso sale de
  `ticket.resumen` (único texto libre que carga `solicitud_baja`, no tiene
  columna de motivo propia) mapeado con `resolverMotivoBajaSlug`, con
  `'voluntaria'` como fallback.
  - **`'otro'` NO es un slug válido** de `contact_products_motivo_baja_check`
    en producción (ver lista de slugs arriba) — dos caminos lo escribían
    hardcodeado (`processClientImportBatch`, import CSV de contactos, y
    `createProductAndSale` de `POST /contacts` cuando un producto del payload
    ya trae `estado` distinto de alta/activo) y hubieran fallado en prod.
    Corregido: ambos usan `resolverMotivoBajaSlug` sobre el estado
    crudo, con `'voluntaria'` como fallback.
  - **Los productos que nacen YA en baja al importarse** (CSV de contactos,
    o el alta manual con un producto retroactivo en estado no-alta) quedan
    **deliberadamente afuera** del alta automática en `recupero_candidatos`
    — son datos históricos, no un cliente que churnea ahora; mandarlos a
    Recupero inundaría la cola con candidatos viejos no accionables. Para
    bajas históricas existe el importador propio de Recupero.
- **Pendiente (no urgente)**: relevar cuántos strings de `index.mjs` tienen
  caracteres dañados por mojibake (ej. `"vï¿½lido"`, `"telï¿½fono"` en
  mensajes de validación — encontrado de pasada en la auditoría de roles de
  2026-10, sin tocar). Son mensajes que ve el usuario final, no solo logs.