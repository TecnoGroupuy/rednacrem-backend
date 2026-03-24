CREATE TABLE IF NOT EXISTS public.manual_ticket_closures (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id uuid NOT NULL REFERENCES public.manual_tickets(id) ON DELETE CASCADE,
  resultado text NOT NULL,
  usuario text,
  note text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS manual_ticket_closures_ticket_id_idx
  ON public.manual_ticket_closures (ticket_id, created_at DESC);
