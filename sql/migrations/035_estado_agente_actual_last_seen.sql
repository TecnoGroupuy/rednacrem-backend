ALTER TABLE estado_agente_actual
ADD COLUMN IF NOT EXISTS last_seen_at timestamptz NULL;

CREATE INDEX IF NOT EXISTS idx_estado_agente_actual_last_seen_at
ON estado_agente_actual (last_seen_at);
