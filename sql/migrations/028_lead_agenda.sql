CREATE TABLE IF NOT EXISTS public.lead_agenda (
  id SERIAL PRIMARY KEY,
  contact_id uuid NOT NULL REFERENCES public.datos_para_trabajar(id) ON DELETE CASCADE,
  seller_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  batch_id uuid NOT NULL REFERENCES public.lead_batches(id) ON DELETE CASCADE,
  fecha_agenda timestamp without time zone NOT NULL,
  nota text,
  cumplida boolean NOT NULL DEFAULT false,
  created_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS lead_agenda_seller_fecha_idx
  ON public.lead_agenda (seller_id, fecha_agenda);
