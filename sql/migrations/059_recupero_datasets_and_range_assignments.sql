CREATE EXTENSION IF NOT EXISTS btree_gist;

ALTER TABLE public.recupero_import_jobs
  ADD COLUMN IF NOT EXISTS dataset_name text,
  ADD COLUMN IF NOT EXISTS dataset_source text NOT NULL DEFAULT 'clientes.bajas',
  ADD COLUMN IF NOT EXISTS churn_window_from date,
  ADD COLUMN IF NOT EXISTS churn_window_to date,
  ADD COLUMN IF NOT EXISTS max_attempts jsonb NOT NULL DEFAULT '{"calls": 3, "whatsapp": 1}'::jsonb,
  ADD COLUMN IF NOT EXISTS offer text,
  ADD COLUMN IF NOT EXISTS expires_on date,
  ADD COLUMN IF NOT EXISTS dataset_status text NOT NULL DEFAULT 'activo',
  ADD COLUMN IF NOT EXISTS goal integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS clientes_sync_at timestamptz;

UPDATE public.recupero_import_jobs
SET
  dataset_name = COALESCE(NULLIF(trim(dataset_name), ''), file_name),
  dataset_source = COALESCE(NULLIF(trim(dataset_source), ''), 'clientes.bajas'),
  dataset_status = COALESCE(NULLIF(trim(dataset_status), ''), 'activo')
WHERE dataset_name IS NULL
   OR dataset_source IS NULL
   OR dataset_status IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'recupero_import_jobs_dataset_source_check'
  ) THEN
    ALTER TABLE public.recupero_import_jobs
      ADD CONSTRAINT recupero_import_jobs_dataset_source_check
      CHECK (dataset_source IN ('clientes.bajas', 'legacy'));
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'recupero_import_jobs_dataset_status_check'
  ) THEN
    ALTER TABLE public.recupero_import_jobs
      ADD CONSTRAINT recupero_import_jobs_dataset_status_check
      CHECK (dataset_status IN ('activo', 'pausado', 'cerrado'));
  END IF;
END $$;

ALTER TABLE public.recupero_candidatos
  ADD COLUMN IF NOT EXISTS dataset_id uuid,
  ADD COLUMN IF NOT EXISTS row_number integer;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'recupero_candidatos_dataset_id_fkey'
  ) THEN
    ALTER TABLE public.recupero_candidatos
      ADD CONSTRAINT recupero_candidatos_dataset_id_fkey
      FOREIGN KEY (dataset_id)
      REFERENCES public.recupero_import_jobs(id)
      ON DELETE SET NULL;
  END IF;
END $$;

WITH candidate_job_match AS (
  SELECT
    rc.id AS candidato_id,
    rij.id AS dataset_id,
    ROW_NUMBER() OVER (
      PARTITION BY rc.id
      ORDER BY
        ABS(EXTRACT(EPOCH FROM (
          COALESCE(rc.importado_at, rc.created_at)
          - COALESCE(rij.finished_at, rij.updated_at, rij.created_at)
        ))) ASC,
        rij.created_at DESC,
        rij.id ASC
    ) AS match_rank
  FROM public.recupero_candidatos rc
  JOIN public.recupero_import_jobs rij
    ON rij.organization_id = rc.organization_id
   AND COALESCE(rc.importado_por, '00000000-0000-0000-0000-000000000000'::uuid)
       = COALESCE(rij.created_by, '00000000-0000-0000-0000-000000000000'::uuid)
   AND COALESCE(rc.importado_at, rc.created_at)
       BETWEEN COALESCE(rij.started_at, rij.created_at) - interval '15 minutes'
           AND COALESCE(rij.finished_at, rij.updated_at, rij.created_at) + interval '15 minutes'
)
UPDATE public.recupero_candidatos rc
SET dataset_id = cjm.dataset_id
FROM candidate_job_match cjm
WHERE rc.id = cjm.candidato_id
  AND cjm.match_rank = 1
  AND rc.dataset_id IS NULL;

WITH orphan_orgs AS (
  SELECT
    rc.organization_id,
    COUNT(*)::int AS orphan_rows
  FROM public.recupero_candidatos rc
  WHERE rc.dataset_id IS NULL
    AND rc.organization_id IS NOT NULL
  GROUP BY rc.organization_id
),
inserted_synthetic_datasets AS (
  INSERT INTO public.recupero_import_jobs (
    file_name,
    file_hash,
    delimiter,
    status,
    total_rows,
    processed_rows,
    updated_rows,
    error_rows,
    duplicate_rows,
    invalid_rows,
    not_found_rows,
    error_message,
    csv_text,
    error_rows_detail,
    error_report_csv,
    created_by,
    started_at,
    finished_at,
    created_at,
    updated_at,
    organization_id,
    dataset_name,
    dataset_source,
    churn_window_from,
    churn_window_to,
    max_attempts,
    offer,
    expires_on,
    dataset_status,
    goal,
    clientes_sync_at
  )
  SELECT
    'historico_sin_origen_conocido.csv',
    md5('recupero-historico-sin-origen-conocido:' || orphan_orgs.organization_id::text),
    NULL,
    'done',
    orphan_orgs.orphan_rows,
    orphan_orgs.orphan_rows,
    0,
    0,
    0,
    0,
    0,
    NULL,
    '',
    NULL,
    NULL,
    NULL,
    now(),
    now(),
    now(),
    now(),
    orphan_orgs.organization_id,
    'Histórico sin origen conocido',
    'legacy',
    NULL,
    NULL,
    '{"calls": 3, "whatsapp": 1}'::jsonb,
    NULL,
    NULL,
    'activo',
    0,
    NULL
  FROM orphan_orgs
  WHERE NOT EXISTS (
    SELECT 1
    FROM public.recupero_import_jobs rij
    WHERE rij.organization_id = orphan_orgs.organization_id
      AND rij.dataset_source = 'legacy'
      AND rij.dataset_name = 'Histórico sin origen conocido'
  )
  RETURNING id, organization_id
),
synthetic_datasets AS (
  SELECT
    rij.id,
    rij.organization_id
  FROM public.recupero_import_jobs rij
  WHERE rij.dataset_source = 'legacy'
    AND rij.dataset_name = 'Histórico sin origen conocido'
)
UPDATE public.recupero_candidatos rc
SET dataset_id = sd.id
FROM synthetic_datasets sd
WHERE rc.dataset_id IS NULL
  AND rc.organization_id = sd.organization_id;

WITH ranked_candidates AS (
  SELECT
    id,
    ROW_NUMBER() OVER (
      PARTITION BY dataset_id
      ORDER BY COALESCE(importado_at, created_at) ASC, id ASC
    ) AS next_row_number
  FROM public.recupero_candidatos
  WHERE dataset_id IS NOT NULL
)
UPDATE public.recupero_candidatos rc
SET row_number = ranked_candidates.next_row_number
FROM ranked_candidates
WHERE rc.id = ranked_candidates.id
  AND rc.row_number IS NULL;

CREATE INDEX IF NOT EXISTS recupero_import_jobs_dataset_status_idx
  ON public.recupero_import_jobs (dataset_status, created_at DESC);

CREATE INDEX IF NOT EXISTS recupero_candidatos_dataset_row_idx
  ON public.recupero_candidatos (dataset_id, row_number);

CREATE INDEX IF NOT EXISTS recupero_candidatos_dataset_estado_idx
  ON public.recupero_candidatos (dataset_id, estado, resultado_gestion);

CREATE INDEX IF NOT EXISTS recupero_candidatos_dataset_seller_idx
  ON public.recupero_candidatos (dataset_id, seller_id, estado, resultado_gestion);

CREATE TABLE IF NOT EXISTS public.recupero_asignaciones_rango (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  dataset_id uuid NOT NULL REFERENCES public.recupero_import_jobs(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL,
  seller_id uuid NOT NULL REFERENCES public.users(id),
  row_from integer NOT NULL,
  row_to integer NOT NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  assigned_by uuid NULL REFERENCES public.users(id),
  released_at timestamptz NULL,
  released_by uuid NULL REFERENCES public.users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT recupero_asignaciones_rango_bounds_check
    CHECK (row_from > 0 AND row_to > row_from)
);

DROP TRIGGER IF EXISTS recupero_asignaciones_rango_set_updated_at ON public.recupero_asignaciones_rango;
CREATE TRIGGER recupero_asignaciones_rango_set_updated_at
BEFORE UPDATE ON public.recupero_asignaciones_rango
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'recupero_asignaciones_rango_no_overlap'
  ) THEN
    ALTER TABLE public.recupero_asignaciones_rango
      ADD CONSTRAINT recupero_asignaciones_rango_no_overlap
      EXCLUDE USING gist (
        dataset_id WITH =,
        int4range(row_from, row_to + 1, '[)') WITH &&
      )
      WHERE (released_at IS NULL);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS recupero_asignaciones_rango_dataset_active_idx
  ON public.recupero_asignaciones_rango (dataset_id, released_at, row_from, row_to);

CREATE INDEX IF NOT EXISTS recupero_asignaciones_rango_seller_active_idx
  ON public.recupero_asignaciones_rango (seller_id, released_at, dataset_id);
