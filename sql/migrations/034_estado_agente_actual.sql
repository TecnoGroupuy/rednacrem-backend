CREATE TABLE IF NOT EXISTS estado_agente_actual (
  agente_id uuid PRIMARY KEY,
  tipo varchar(30) NOT NULL,
  inicio timestamptz NOT NULL,
  session_id uuid NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_estado_agente_actual_tipo
ON estado_agente_actual (tipo);

CREATE INDEX IF NOT EXISTS idx_estado_agente_actual_updated_at
ON estado_agente_actual (updated_at);
