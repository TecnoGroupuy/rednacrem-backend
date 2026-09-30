-- RRHH SU Emergencia: nombre de uso, regimen 'suplente', y varias bases por
-- persona (su_personal_bases), para el rediseño de la tarjeta de personal.
--
-- Esta migracion es NUEVA de punta a punta (como la 070) -- no existe nada
-- de esto en produccion todavia. Damian la corre a mano contra RDS; el
-- agente no la ejecuta contra produccion.
--
-- Sin FKs fuera de su_*/organizations, mismo criterio que el resto del
-- modulo de Operaciones.

ALTER TABLE public.su_personal
  ADD COLUMN IF NOT EXISTS nombre_uso text NULL;

-- regimen_turno: 'fijo' | 'turnante' | 'suplente' | NULL (antes solo
-- admitia 'fijo'/'turnante' -- ver migracion 069). DROP + ADD con el mismo
-- nombre de constraint para que sea idempotente sin duplicar el CHECK.
ALTER TABLE public.su_personal
  DROP CONSTRAINT IF EXISTS su_personal_regimen_turno_check;

ALTER TABLE public.su_personal
  ADD CONSTRAINT su_personal_regimen_turno_check
  CHECK (regimen_turno IS NULL OR regimen_turno IN ('fijo', 'turnante', 'suplente'));

CREATE TABLE IF NOT EXISTS public.su_personal_bases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  personal_id uuid NOT NULL REFERENCES public.su_personal(id) ON DELETE CASCADE,
  base_id uuid NOT NULL REFERENCES public.su_bases(id),
  es_principal boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT su_personal_bases_personal_base_unique UNIQUE (personal_id, base_id)
);

-- Una sola base principal por persona (indice unico parcial).
CREATE UNIQUE INDEX IF NOT EXISTS su_personal_bases_una_principal_idx
  ON public.su_personal_bases (personal_id)
  WHERE es_principal;

CREATE INDEX IF NOT EXISTS su_personal_bases_organization_id_idx
  ON public.su_personal_bases (organization_id);

CREATE INDEX IF NOT EXISTS su_personal_bases_base_id_idx
  ON public.su_personal_bases (base_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'su_personal_bases_set_updated_at'
  ) THEN
    CREATE TRIGGER su_personal_bases_set_updated_at
    BEFORE UPDATE ON public.su_personal_bases
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END $$;

-- Backfill: cada su_personal con base_id ya seteado pasa a tener esa misma
-- base como principal en la tabla nueva. ON CONFLICT DO NOTHING hace esto
-- repetible si la migracion se corre mas de una vez.
INSERT INTO public.su_personal_bases (organization_id, personal_id, base_id, es_principal)
SELECT organization_id, id, base_id, true
FROM public.su_personal
WHERE base_id IS NOT NULL
ON CONFLICT (personal_id, base_id) DO NOTHING;
