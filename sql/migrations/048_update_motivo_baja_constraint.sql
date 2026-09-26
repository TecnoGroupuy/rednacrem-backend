-- ADVERTENCIA (confirmado contra RDS): el CHECK real de producción para
-- motivo_baja usa una lista completamente distinta a la de este archivo —
-- valores en minúscula sin tilde ('voluntaria', 'baja_bps', 'sin_pago_bps',
-- 'baja_antel', 'sin_liquidez', 'fallecimiento', 'falta_de_pago', 'auditoria',
-- 'error_activacion', 'administrativa', 'no_llamar', 'otro_servicio'), nada
-- que ver con 'Auditoría'/'Medio de pago'/'Voluntaria'/etc. Esta migración
-- solo corrió contra el Postgres local — no confíes en su lista para escribir
-- motivo_baja desde código sin confirmar antes contra RDS (ver CLAUDE.md).
--
-- Migrate old motivo_baja values
ALTER TABLE contact_products
DROP CONSTRAINT IF EXISTS contact_products_motivo_baja_check;

UPDATE contact_products SET motivo_baja = 'Auditoría' WHERE motivo_baja = 'no_pasa_auditoria';
UPDATE contact_products SET motivo_baja = 'Voluntaria' WHERE motivo_baja = 'otro';

-- Update check constraint
ALTER TABLE contact_products
ADD CONSTRAINT contact_products_motivo_baja_check
CHECK (
  motivo_baja IS NULL OR motivo_baja = ANY (ARRAY[
    'Auditoría', 'Medio de pago', 'Voluntaria', 'Antel',
    'BPS', 'Fallecido', 'Administrativa', 'Deuda'
  ])
);
