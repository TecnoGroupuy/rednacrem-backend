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
    confirmar antes contra RDS.
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