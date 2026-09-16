-- El CHECK constraint de recupero_candidatos_historial.tipo_evento en
-- producción solo permitía ('asignacion', 'gestion') — confirmado vía
-- psql contra RDS (pg_get_constraintdef). Esto rompía tres endpoints que
-- insertan valores no contemplados en esa lista:
--   - POST /recovery/datasets/:id/assignments (rango), ya en producción,
--     inserta 'asignacion_rango' (bug latente).
--   - POST /recovery/datasets/:id/direct-assignments, ya en producción,
--     inserta 'asignacion_directa' (bug latente).
--   - POST /recovery/datasets/:id/finalize (nuevo), inserta
--     'finalizacion_lote' — esta migración es lo que faltaba para que
--     funcione en producción (local no tiene este constraint, por eso no
--     se detectó en la validación de esa tarea).
-- Los dos primeros son latentes porque, aparentemente, nunca se ejercitó
-- ese camino en producción todavía (si se hubiera usado, habría fallado
-- igual que /finalize).
ALTER TABLE public.recupero_candidatos_historial
  DROP CONSTRAINT IF EXISTS recupero_candidatos_historial_tipo_evento_check;

ALTER TABLE public.recupero_candidatos_historial
  ADD CONSTRAINT recupero_candidatos_historial_tipo_evento_check
  CHECK (tipo_evento = ANY (ARRAY[
    'asignacion'::text,
    'gestion'::text,
    'asignacion_rango'::text,
    'asignacion_directa'::text,
    'finalizacion_lote'::text
  ]));
