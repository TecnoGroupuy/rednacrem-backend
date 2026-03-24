CREATE TABLE IF NOT EXISTS public.no_call_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  numero text NOT NULL,
  fuente text NOT NULL,
  departamento text,
  localidad text,
  fecha_carga date NOT NULL DEFAULT now()::date,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT no_call_entries_fuente_check
    CHECK (fuente IN ('celular', 'tel_fijo'))
);

CREATE UNIQUE INDEX IF NOT EXISTS no_call_entries_numero_unique_idx
  ON public.no_call_entries (numero);

DROP TRIGGER IF EXISTS no_call_entries_set_updated_at ON public.no_call_entries;
CREATE TRIGGER no_call_entries_set_updated_at
BEFORE UPDATE ON public.no_call_entries
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
