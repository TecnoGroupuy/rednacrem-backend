CREATE TABLE IF NOT EXISTS public.lead_batch_rr_cursor (
  batch_id uuid PRIMARY KEY REFERENCES public.lead_batches(id) ON DELETE CASCADE,
  last_assigned_index integer NOT NULL DEFAULT -1,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS lead_batch_rr_cursor_updated_at_idx
  ON public.lead_batch_rr_cursor (updated_at);

