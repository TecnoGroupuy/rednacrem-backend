ALTER TABLE public.recupero_import_jobs
  ADD COLUMN IF NOT EXISTS organization_id uuid NULL REFERENCES public.organizations(id);

CREATE INDEX IF NOT EXISTS recupero_import_jobs_organization_id_idx
  ON public.recupero_import_jobs (organization_id);

