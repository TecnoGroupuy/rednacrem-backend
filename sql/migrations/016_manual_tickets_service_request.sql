ALTER TABLE public.manual_tickets
ADD COLUMN IF NOT EXISTS service_request jsonb;
