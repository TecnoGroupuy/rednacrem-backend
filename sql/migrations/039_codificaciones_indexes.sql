CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS lead_management_history_fecha_gestion_desc_idx
ON lead_management_history (fecha_gestion DESC);

CREATE INDEX IF NOT EXISTS lead_management_history_user_fecha_gestion_desc_idx
ON lead_management_history (user_id, fecha_gestion DESC);

CREATE INDEX IF NOT EXISTS datos_para_trabajar_telefono_trgm_idx
ON datos_para_trabajar USING GIN (telefono gin_trgm_ops);

CREATE INDEX IF NOT EXISTS datos_para_trabajar_celular_trgm_idx
ON datos_para_trabajar USING GIN (celular gin_trgm_ops);
