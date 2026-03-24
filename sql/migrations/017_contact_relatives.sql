CREATE TABLE IF NOT EXISTS public.contact_relatives (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  nombre text,
  apellido text,
  telefono text,
  parentesco text,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS contact_relatives_contact_id_idx
  ON public.contact_relatives (contact_id);

DROP TRIGGER IF EXISTS contact_relatives_set_updated_at ON public.contact_relatives;
CREATE TRIGGER contact_relatives_set_updated_at
BEFORE UPDATE ON public.contact_relatives
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
