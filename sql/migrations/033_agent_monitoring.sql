CREATE TABLE IF NOT EXISTS agentes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nombre VARCHAR(100) NOT NULL,
  iniciales VARCHAR(3) NOT NULL,
  turno_inicio TIME NOT NULL,
  turno_fin TIME NOT NULL,
  activo BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS eventos_turno (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agente_id UUID REFERENCES agentes(id),
  tipo VARCHAR(20) NOT NULL,
  inicio TIMESTAMPTZ NOT NULL,
  fin TIMESTAMPTZ,
  fecha DATE NOT NULL,
  excedido BOOLEAN DEFAULT false,
  exceso_minutos INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS llamadas (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agente_id UUID REFERENCES agentes(id),
  cliente_nombre VARCHAR(100),
  cliente_telefono VARCHAR(20),
  inicio TIMESTAMPTZ NOT NULL,
  duracion_segundos INT,
  resultado VARCHAR(20) NOT NULL,
  fecha DATE NOT NULL,
  corta BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS configuracion (
  clave VARCHAR(50) PRIMARY KEY,
  valor VARCHAR(100) NOT NULL
);

INSERT INTO configuracion (clave, valor) VALUES
  ('limite_bano_minutos', '10'),
  ('limite_descanso_minutos', '15'),
  ('conversion_minima_porcentaje', '10'),
  ('conversion_excelente_porcentaje', '16'),
  ('meta_llamadas_dia', '40'),
  ('meta_ventas_dia', '6')
ON CONFLICT (clave) DO NOTHING;

CREATE TABLE IF NOT EXISTS alertas (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agente_id UUID REFERENCES agentes(id),
  tipo VARCHAR(50) NOT NULL,
  subtipo VARCHAR(50),
  descripcion TEXT,
  hora_evento TIMESTAMPTZ,
  duracion_minutos INT,
  limite_minutos INT,
  exceso_minutos INT,
  veces_en_semana INT DEFAULT 0,
  fecha DATE NOT NULL,
  resuelta BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_eventos_turno_agente_fecha
  ON eventos_turno (agente_id, fecha);

CREATE INDEX IF NOT EXISTS idx_llamadas_agente_fecha
  ON llamadas (agente_id, fecha);

CREATE INDEX IF NOT EXISTS idx_alertas_agente_fecha_resuelta
  ON alertas (agente_id, fecha, resuelta);
