-- Marca los datasets de Recupero creados automáticamente por el sistema
-- ("Prioritario — 0 a 3 meses" / "General de recupero", uno por
-- organización) para distinguirlos de forma inequívoca de los que crea un
-- supervisor a mano (ad-hoc o vía import de CSV) — así el frontend puede
-- ocultar acciones de borrado/edición para estos sin depender de comparar
-- nombres, que un supervisor podría reutilizar por accidente.
ALTER TABLE public.recupero_import_jobs
  ADD COLUMN IF NOT EXISTS is_system_dataset boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS recupero_import_jobs_system_dataset_idx
  ON public.recupero_import_jobs (organization_id, is_system_dataset);

-- Protección real contra duplicados por organización, no solo la
-- comprobación "check-then-insert" del aprovisionamiento en JS (que cubre
-- llamadas secuenciales pero no dos requests concurrentes).
CREATE UNIQUE INDEX IF NOT EXISTS recupero_import_jobs_system_dataset_unique_idx
  ON public.recupero_import_jobs (organization_id, dataset_name)
  WHERE is_system_dataset = true;
