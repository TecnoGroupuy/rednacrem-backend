-- Licencias de personal (RRHH de SU Emergencia) -- registro con fechas de
-- las licencias de cada funcionario (maternal, certificacion medica,
-- reglamentaria, sin goce, otra), para diferenciar visualmente
-- "en licencia" de "activo" en la jerarquia y saber cuando vuelve.
--
-- A diferencia de las migraciones 069/manual_tickets.organization_id, esta
-- SI es nueva de punta a punta -- no existe todavia en produccion. Damian
-- la corre a mano contra RDS con el mismo procedimiento de siempre; esta
-- migracion NO se ejecuta automaticamente contra produccion.
--
-- Sin FKs fuera de su_*/organizations, mismo criterio que el resto del
-- modulo de Operaciones.
CREATE TABLE IF NOT EXISTS public.su_personal_licencias (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  personal_id uuid NOT NULL REFERENCES public.su_personal(id) ON DELETE CASCADE,
  tipo text NOT NULL,
  fecha_desde date NOT NULL,
  fecha_hasta date NULL,
  observaciones text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT su_personal_licencias_tipo_check
    CHECK (tipo IN ('maternal', 'certificacion_medica', 'reglamentaria', 'sin_goce', 'otra')),
  -- NULL en fecha_hasta = sin fecha de regreso todavia (licencia abierta).
  CONSTRAINT su_personal_licencias_fechas_check
    CHECK (fecha_hasta IS NULL OR fecha_hasta >= fecha_desde)
);

CREATE INDEX IF NOT EXISTS su_personal_licencias_personal_id_idx
  ON public.su_personal_licencias (personal_id);

CREATE INDEX IF NOT EXISTS su_personal_licencias_organization_id_idx
  ON public.su_personal_licencias (organization_id);

-- Para resolver rapido "licencia vigente hoy" en el listado/detalle de
-- personal (fecha_desde <= hoy AND (fecha_hasta IS NULL OR fecha_hasta >= hoy)).
CREATE INDEX IF NOT EXISTS su_personal_licencias_vigencia_idx
  ON public.su_personal_licencias (personal_id, fecha_desde, fecha_hasta);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'su_personal_licencias_set_updated_at'
  ) THEN
    CREATE TRIGGER su_personal_licencias_set_updated_at
    BEFORE UPDATE ON public.su_personal_licencias
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END $$;
