ALTER TABLE public.contacts
ADD COLUMN IF NOT EXISTS fecha_nacimiento date,
ADD COLUMN IF NOT EXISTS direccion text,
ADD COLUMN IF NOT EXISTS departamento text,
ADD COLUMN IF NOT EXISTS pais text;

UPDATE public.contacts
SET pais = COALESCE(NULLIF(BTRIM(pais), ''), 'Uruguay')
WHERE pais IS NULL OR BTRIM(pais) = '';

ALTER TABLE public.contacts
ALTER COLUMN pais SET DEFAULT 'Uruguay';
