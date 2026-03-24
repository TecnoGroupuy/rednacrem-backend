ALTER TABLE public.lead_batches
  ADD COLUMN IF NOT EXISTS seller_id uuid NULL REFERENCES public.users(id),
  ADD COLUMN IF NOT EXISTS max_intentos integer NOT NULL DEFAULT 3,
  ADD COLUMN IF NOT EXISTS fecha_vencimiento timestamp without time zone NULL,
  ADD COLUMN IF NOT EXISTS criterios jsonb NULL;

CREATE INDEX IF NOT EXISTS lead_batches_seller_idx
  ON public.lead_batches (seller_id);
