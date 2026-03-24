CREATE TABLE IF NOT EXISTS public.manual_tickets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cliente_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  tipo_solicitud text NOT NULL,
  tipo_solicitud_manual text,
  resumen text NOT NULL,
  prioridad text NOT NULL DEFAULT 'media',
  estado text NOT NULL DEFAULT 'nueva',
  producto_contrato_id uuid NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT manual_tickets_prioridad_check
    CHECK (prioridad IN ('baja', 'media', 'alta')),
  CONSTRAINT manual_tickets_estado_check
    CHECK (estado IN ('nueva', 'en_proceso', 'finalizada'))
);

CREATE INDEX IF NOT EXISTS manual_tickets_cliente_id_idx
  ON public.manual_tickets (cliente_id, created_at DESC);

CREATE INDEX IF NOT EXISTS manual_tickets_producto_contrato_id_idx
  ON public.manual_tickets (producto_contrato_id);

DROP TRIGGER IF EXISTS manual_tickets_set_updated_at ON public.manual_tickets;
CREATE TRIGGER manual_tickets_set_updated_at
BEFORE UPDATE ON public.manual_tickets
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
