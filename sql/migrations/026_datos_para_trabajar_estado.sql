ALTER TABLE public.datos_para_trabajar
  ADD COLUMN IF NOT EXISTS estado text;

ALTER TABLE public.datos_para_trabajar
  DROP CONSTRAINT IF EXISTS datos_para_trabajar_estado_check;

ALTER TABLE public.datos_para_trabajar
  ADD CONSTRAINT datos_para_trabajar_estado_check
  CHECK (estado IN ('nuevo', 'trabajado', 'bloqueado'));

UPDATE public.datos_para_trabajar d
SET estado = 'bloqueado'
FROM public.no_call_entries n
WHERE n.numero = regexp_replace(COALESCE(d.celular, d.telefono, ''), '\D', '', 'g');

UPDATE public.datos_para_trabajar
SET estado = 'nuevo'
WHERE estado IS NULL;

ALTER TABLE public.datos_para_trabajar
  ALTER COLUMN estado SET DEFAULT 'nuevo';