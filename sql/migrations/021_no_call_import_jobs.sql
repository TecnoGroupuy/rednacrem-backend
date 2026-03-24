CREATE TABLE IF NOT EXISTS public.no_call_import_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_name text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  total_rows integer NOT NULL DEFAULT 0,
  processed_rows integer NOT NULL DEFAULT 0,
  inserted_rows integer NOT NULL DEFAULT 0,
  skipped_rows integer NOT NULL DEFAULT 0,
  error_message text,
  csv_text text NOT NULL,
  created_by uuid NULL REFERENCES public.users(id),
  started_at timestamp without time zone NULL,
  completed_at timestamp without time zone NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT no_call_import_jobs_status_check
    CHECK (status IN ('queued', 'processing', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS no_call_import_jobs_status_idx
  ON public.no_call_import_jobs (status);

DROP TRIGGER IF EXISTS no_call_import_jobs_set_updated_at ON public.no_call_import_jobs;
CREATE TRIGGER no_call_import_jobs_set_updated_at
BEFORE UPDATE ON public.no_call_import_jobs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
