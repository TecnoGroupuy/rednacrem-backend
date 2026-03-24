CREATE TABLE IF NOT EXISTS public.lead_batches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nombre text NOT NULL,
  estado text NOT NULL DEFAULT 'sin_asignar',
  asignado_a uuid NULL REFERENCES public.users(id),
  created_by uuid NULL REFERENCES public.users(id),
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT lead_batches_estado_check
    CHECK (estado IN ('sin_asignar', 'asignado', 'finalizado'))
);

CREATE INDEX IF NOT EXISTS lead_batches_estado_idx
  ON public.lead_batches (estado);

CREATE TABLE IF NOT EXISTS public.lead_batch_contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id uuid NOT NULL REFERENCES public.lead_batches(id) ON DELETE CASCADE,
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  UNIQUE (batch_id, contact_id)
);

CREATE INDEX IF NOT EXISTS lead_batch_contacts_batch_idx
  ON public.lead_batch_contacts (batch_id);

CREATE INDEX IF NOT EXISTS lead_batch_contacts_contact_idx
  ON public.lead_batch_contacts (contact_id);

CREATE TABLE IF NOT EXISTS public.lead_contact_status (
  contact_id uuid PRIMARY KEY REFERENCES public.contacts(id) ON DELETE CASCADE,
  estado_venta text NOT NULL DEFAULT 'nuevo',
  intentos integer NOT NULL DEFAULT 0,
  proxima_accion timestamp without time zone NULL,
  batch_id uuid NULL REFERENCES public.lead_batches(id) ON DELETE SET NULL,
  assigned_to uuid NULL REFERENCES public.users(id) ON DELETE SET NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT lead_contact_status_estado_check
    CHECK (estado_venta IN ('nuevo', 'no_contesta', 'seguimiento', 'rellamar', 'rechazo', 'dato_erroneo', 'venta'))
);

CREATE INDEX IF NOT EXISTS lead_contact_status_batch_idx
  ON public.lead_contact_status (batch_id);

CREATE INDEX IF NOT EXISTS lead_contact_status_assigned_idx
  ON public.lead_contact_status (assigned_to);

CREATE TABLE IF NOT EXISTS public.lead_management_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  batch_id uuid NULL REFERENCES public.lead_batches(id) ON DELETE SET NULL,
  user_id uuid NULL REFERENCES public.users(id) ON DELETE SET NULL,
  resultado text NOT NULL,
  nota text,
  fecha_gestion timestamp without time zone NOT NULL DEFAULT now(),
  proxima_accion timestamp without time zone NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT lead_management_resultado_check
    CHECK (resultado IN ('no_contesta', 'seguimiento', 'rellamar', 'rechazo', 'dato_erroneo', 'venta'))
);

CREATE INDEX IF NOT EXISTS lead_management_contact_idx
  ON public.lead_management_history (contact_id);

DROP TRIGGER IF EXISTS lead_batches_set_updated_at ON public.lead_batches;
CREATE TRIGGER lead_batches_set_updated_at
BEFORE UPDATE ON public.lead_batches
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS lead_batch_contacts_set_updated_at ON public.lead_batch_contacts;
CREATE TRIGGER lead_batch_contacts_set_updated_at
BEFORE UPDATE ON public.lead_batch_contacts
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS lead_contact_status_set_updated_at ON public.lead_contact_status;
CREATE TRIGGER lead_contact_status_set_updated_at
BEFORE UPDATE ON public.lead_contact_status
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
