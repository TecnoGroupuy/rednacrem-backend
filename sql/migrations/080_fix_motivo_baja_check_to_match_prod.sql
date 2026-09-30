-- SOLO LOCAL -- NO-OP EN PRODUCCION -- NO EJECUTAR EN PRODUCCION.
--
-- La migracion 048 (sql/migrations/048_update_motivo_baja_constraint.sql)
-- ya advertia que su lista de motivo_baja ('Auditoría', 'Medio de pago',
-- 'Voluntaria', etc., capitalizada) NO es la real de produccion -- esa
-- advertencia quedo confirmada contra RDS y documentada en CLAUDE.md: el
-- CHECK real usa slugs en minuscula sin tilde ('voluntaria', 'baja_bps',
-- 'sin_pago_bps', 'baja_antel', 'sin_liquidez', 'fallecimiento',
-- 'falta_de_pago', 'auditoria', 'error_activacion', 'administrativa',
-- 'no_llamar', 'otro_servicio' -- exactamente CONTACT_PRODUCT_BAJA_SLUGS en
-- index.mjs).
--
-- Encontrada al validar en local aplicarBajaContactProduct /
-- closeManualTicket / la 079: con el CHECK viejo de 048, CUALQUIER baja
-- real (que siempre escribe uno de los slugs en minuscula) fallaba en
-- local con "violates check constraint contact_products_motivo_baja_check"
-- -- bloqueaba probar el codigo real, no solo un caso de borde.
--
-- Remapea las 5 filas locales existentes con 'Voluntaria' (capitalizado) a
-- 'voluntaria' (el slug real) antes de aplicar el CHECK nuevo, para no
-- dejar datos que violen el propio constraint que se esta agregando.

-- El DROP tiene que ir ANTES del UPDATE: el CHECK viejo (048) tampoco
-- acepta 'voluntaria' en minuscula (solo 'Voluntaria' capitalizado), asi
-- que el remapeo fallaria contra el constraint viejo si se hiciera primero.
ALTER TABLE contact_products
DROP CONSTRAINT IF EXISTS contact_products_motivo_baja_check;

UPDATE contact_products SET motivo_baja = 'voluntaria' WHERE motivo_baja = 'Voluntaria';

ALTER TABLE contact_products
ADD CONSTRAINT contact_products_motivo_baja_check
CHECK (
  motivo_baja IS NULL OR motivo_baja = ANY (ARRAY[
    'voluntaria', 'baja_bps', 'sin_pago_bps', 'baja_antel', 'sin_liquidez',
    'fallecimiento', 'falta_de_pago', 'auditoria', 'error_activacion',
    'administrativa', 'no_llamar', 'otro_servicio'
  ])
);
