ALTER TABLE public.no_call_import_jobs
  ADD COLUMN IF NOT EXISTS numero_tramite text,
  ADD COLUMN IF NOT EXISTS fecha_consulta date;
