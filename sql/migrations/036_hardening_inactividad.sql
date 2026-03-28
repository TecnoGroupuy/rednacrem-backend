DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_estado_agente_actual_tipo'
      AND conrelid = 'estado_agente_actual'::regclass
  ) THEN
    ALTER TABLE estado_agente_actual
    ADD CONSTRAINT chk_estado_agente_actual_tipo
    CHECK (tipo IN ('TRABAJO', 'INACTIVO', 'DESCANSO', 'SUPERVISOR', 'BAÑO', 'BANO', 'LOGOUT'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_eventos_turno_agente_inicio
ON eventos_turno (agente_id, inicio);

CREATE INDEX IF NOT EXISTS idx_eventos_turno_agente_inicio_desc
ON eventos_turno (agente_id, inicio DESC);
