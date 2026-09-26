# Tri — Contexto para Claude Code

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
  - `manual_tickets.organization_id` y `contact_products.organization_id` existen
    en producción pero no en local.
  - `contact_products_motivo_baja_check` (el `CHECK` de `motivo_baja`) tiene una
    lista de valores **distinta** en producción (`'voluntaria'`, `'baja_bps'`,
    `'sin_pago_bps'`, `'baja_antel'`, `'sin_liquidez'`, `'fallecimiento'`,
    `'falta_de_pago'`, `'auditoria'`, `'error_activacion'`, `'administrativa'`,
    `'no_llamar'`, `'otro_servicio'` — todo minúscula, sin tildes) que la que define
    `sql/migrations/048_update_motivo_baja_constraint.sql` en este repo (`'Auditoría'`,
    `'Medio de pago'`, `'Voluntaria'`, etc., capitalizado). Esa migración solo corrió
    en local — nunca escribas `motivo_baja` basándote en el valor de la 048 sin
    confirmar antes contra RDS.
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