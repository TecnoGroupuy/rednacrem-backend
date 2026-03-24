CREATE TABLE IF NOT EXISTS public.client_document_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  user_id uuid REFERENCES public.users(id),
  event text NOT NULL,
  origin text,
  template text,
  lang text,
  channel text,
  note text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT client_document_events_event_check
    CHECK (event IN ('download_pdf', 'sent_document')),
  CONSTRAINT client_document_events_channel_check
    CHECK (channel IS NULL OR channel IN ('whatsapp', 'email'))
);

CREATE INDEX IF NOT EXISTS client_document_events_client_id_idx
  ON public.client_document_events (client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS client_document_events_user_id_idx
  ON public.client_document_events (user_id, created_at DESC);
