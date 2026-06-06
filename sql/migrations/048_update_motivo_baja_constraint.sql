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
