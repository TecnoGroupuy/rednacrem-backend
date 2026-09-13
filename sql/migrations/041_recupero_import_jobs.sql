CREATE TABLE IF NOT EXISTS public.recupero_import_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_name text NOT NULL,
  file_hash text NOT NULL,
  delimiter text NULL,
  status text NOT NULL DEFAULT 'queued',
  total_rows integer NOT NULL DEFAULT 0,
  processed_rows integer NOT NULL DEFAULT 0,
  updated_rows integer NOT NULL DEFAULT 0,
  error_rows integer NOT NULL DEFAULT 0,
  duplicate_rows integer NOT NULL DEFAULT 0,
  invalid_rows integer NOT NULL DEFAULT 0,
  not_found_rows integer NOT NULL DEFAULT 0,
  error_message text NULL,
  csv_text text NOT NULL,
  error_rows_detail jsonb NULL,
  error_report_csv text NULL,
  created_by uuid NULL REFERENCES public.users(id),
  started_at timestamptz NULL,
  finished_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT recupero_import_jobs_status_check
    CHECK (status IN ('queued', 'processing', 'done', 'failed'))
);

CREATE INDEX IF NOT EXISTS recupero_import_jobs_status_idx
  ON public.recupero_import_jobs (status);

CREATE INDEX IF NOT EXISTS recupero_import_jobs_created_at_idx
  ON public.recupero_import_jobs (created_at DESC);

CREATE INDEX IF NOT EXISTS recupero_import_jobs_file_hash_idx
  ON public.recupero_import_jobs (file_hash);

DROP TRIGGER IF EXISTS recupero_import_jobs_set_updated_at ON public.recupero_import_jobs;
CREATE TRIGGER recupero_import_jobs_set_updated_at
BEFORE UPDATE ON public.recupero_import_jobs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
