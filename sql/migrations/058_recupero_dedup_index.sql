DROP INDEX IF EXISTS public.idx_recupero_dedup;

CREATE UNIQUE INDEX IF NOT EXISTS idx_recupero_dedup
ON public.recupero_candidatos (
  organization_id,
  documento,
  lower(trim(nombre)),
  lower(trim(apellido))
)
WHERE documento IS NOT NULL AND estado <> 'recuperado';
