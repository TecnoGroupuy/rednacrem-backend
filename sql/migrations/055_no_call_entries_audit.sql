CREATE TABLE IF NOT EXISTS public.no_call_entries_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  no_call_entry_id uuid NOT NULL REFERENCES public.no_call_entries(id) ON DELETE CASCADE,
  numero text NOT NULL,
  authorized_by uuid NOT NULL REFERENCES public.users(id),
  motivo text NOT NULL,
  organization_id uuid,
  created_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS no_call_entries_audit_numero_idx
  ON public.no_call_entries_audit (numero);
