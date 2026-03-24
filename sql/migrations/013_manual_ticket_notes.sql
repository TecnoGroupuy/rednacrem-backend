CREATE TABLE IF NOT EXISTS public.manual_ticket_notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id uuid NOT NULL REFERENCES public.manual_tickets(id) ON DELETE CASCADE,
  autor text,
  texto text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS manual_ticket_notes_ticket_id_idx
  ON public.manual_ticket_notes (ticket_id, created_at DESC);
