ALTER TABLE IF EXISTS public.lead_management_history
ADD COLUMN IF NOT EXISTS es_correccion_supervisor boolean DEFAULT false;
