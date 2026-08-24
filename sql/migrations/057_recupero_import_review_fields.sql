ALTER TABLE public.recupero_candidatos
  ADD COLUMN IF NOT EXISTS requiere_revision boolean NOT NULL DEFAULT false;

ALTER TABLE public.recupero_import_jobs
  ADD COLUMN IF NOT EXISTS clientes_activos_rows integer NOT NULL DEFAULT 0;

ALTER TABLE public.recupero_import_jobs
  ADD COLUMN IF NOT EXISTS requiere_revision_rows integer NOT NULL DEFAULT 0;
