CREATE TABLE IF NOT EXISTS public.lead_batch_sellers (
  id BIGSERIAL PRIMARY KEY,
  batch_id uuid NOT NULL REFERENCES public.lead_batches(id) ON DELETE CASCADE,
  seller_id uuid NOT NULL REFERENCES public.users(id),
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  UNIQUE (batch_id, seller_id)
);

CREATE INDEX IF NOT EXISTS lead_batch_sellers_batch_idx
  ON public.lead_batch_sellers (batch_id);

CREATE INDEX IF NOT EXISTS lead_batch_sellers_seller_idx
  ON public.lead_batch_sellers (seller_id);
