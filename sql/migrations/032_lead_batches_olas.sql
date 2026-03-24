ALTER TABLE public.lead_batches
  ADD COLUMN IF NOT EXISTS franja_ola1_inicio time DEFAULT '10:00',
  ADD COLUMN IF NOT EXISTS franja_ola1_fin time DEFAULT '13:00',
  ADD COLUMN IF NOT EXISTS franja_ola2_inicio time DEFAULT '17:00',
  ADD COLUMN IF NOT EXISTS franja_ola2_fin time DEFAULT '20:00',
  ADD COLUMN IF NOT EXISTS dias_entre_olas integer DEFAULT 1;

ALTER TABLE public.lead_contact_status
  ADD COLUMN IF NOT EXISTS ultimo_intento_at timestamp without time zone,
  ADD COLUMN IF NOT EXISTS ola_actual integer DEFAULT 1;

ALTER TABLE public.lead_batches
  DROP CONSTRAINT IF EXISTS lead_batches_estado_check;

ALTER TABLE public.lead_batches
  ADD CONSTRAINT lead_batches_estado_check
  CHECK (estado IN ('sin_asignar', 'asignado', 'activo', 'finalizado'));
