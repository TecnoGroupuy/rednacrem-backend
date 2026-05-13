-- Permitir registrar reasignaciones en el historial sin romper el constraint existente.

ALTER TABLE public.lead_management_history
  DROP CONSTRAINT IF EXISTS lead_management_resultado_check;

ALTER TABLE public.lead_management_history
  ADD CONSTRAINT lead_management_resultado_check
  CHECK (resultado IN (
    'no_contesta',
    'seguimiento',
    'rellamar',
    'rechazo',
    'dato_erroneo',
    'venta',
    'reasignado'
  ));

