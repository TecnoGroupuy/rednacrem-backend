CREATE SEQUENCE IF NOT EXISTS public.manual_tickets_numero_seq;

ALTER TABLE public.manual_tickets
ADD COLUMN IF NOT EXISTS numero integer;

ALTER TABLE public.manual_tickets
ALTER COLUMN numero SET DEFAULT nextval('public.manual_tickets_numero_seq');

UPDATE public.manual_tickets
SET numero = nextval('public.manual_tickets_numero_seq')
WHERE numero IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS manual_tickets_numero_unique_idx
  ON public.manual_tickets (numero);
