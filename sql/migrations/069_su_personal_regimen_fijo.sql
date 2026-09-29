-- Régimen fijo de enfermeros (RRHH de SU Emergencia, organization_id
-- ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd): móvil y franja de 6hs del titular,
-- más el ancla del ciclo de franco 4x1. Ya aplicada en producción vía psql
-- el 29/09/2026 (22 enfermeros fijos cargados, uno de economato con
-- fecha_ref_descanso pero sin móvil/franja) -- esta migración NO se corre
-- contra producción, solo documenta lo que ya existe ahí y deja el mismo
-- estado disponible en cualquier base nueva (local, otro ambiente).
--
-- regimen_turno tampoco tenía ninguna migración versionada (se agregó a
-- producción de la misma forma no documentada, como manual_tickets.
-- organization_id) -- se incluye acá para que quede una sola migración de
-- referencia con las columnas reales de la tabla.
--
-- Significado de las columnas nuevas:
--   vehiculo_id / franja_turno: el móvil y la franja fija de 6hs del
--     enfermero titular. Solo tiene sentido cuando regimen_turno = 'fijo'
--     (no se agrega un CHECK cruzado para esto -- el enforcement queda del
--     lado del backend/frontend, igual que el resto de los campos
--     opcionales de su_personal).
--   fecha_ref_descanso: una fecha de franco cualquiera del ciclo 4x1 (ancla
--     del régimen). Fórmula: es_franco(fecha) = ((fecha - fecha_ref_descanso)
--     mod 5) = 0 -- ese día descansa, los 4 siguientes trabaja, se repite
--     cada 5 días. Puede quedar NULL (licencia, o ciclo sin definir).
--
-- Todo con ADD COLUMN IF NOT EXISTS y los CHECK creados solo si no existen
-- por nombre en pg_constraint, para poder correrla más de una vez sin
-- romper nada.

ALTER TABLE public.su_personal
  ADD COLUMN IF NOT EXISTS regimen_turno text NULL,
  ADD COLUMN IF NOT EXISTS vehiculo_id uuid NULL REFERENCES public.su_vehiculos(id),
  ADD COLUMN IF NOT EXISTS franja_turno text NULL,
  ADD COLUMN IF NOT EXISTS fecha_ref_descanso date NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'su_personal_regimen_turno_check'
  ) THEN
    ALTER TABLE public.su_personal
      ADD CONSTRAINT su_personal_regimen_turno_check
      CHECK (regimen_turno IS NULL OR regimen_turno IN ('fijo', 'turnante'));
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'su_personal_franja_turno_check'
  ) THEN
    ALTER TABLE public.su_personal
      ADD CONSTRAINT su_personal_franja_turno_check
      CHECK (franja_turno IS NULL OR franja_turno IN ('00-06', '06-12', '12-18', '18-00'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS su_personal_vehiculo_id_idx ON public.su_personal (vehiculo_id);
