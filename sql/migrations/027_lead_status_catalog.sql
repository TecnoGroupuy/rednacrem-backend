CREATE TABLE IF NOT EXISTS public.lead_status_catalog (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(50) UNIQUE NOT NULL,
  es_final BOOLEAN NOT NULL DEFAULT FALSE,
  libera_al_cerrar BOOLEAN NOT NULL DEFAULT FALSE
);

INSERT INTO public.lead_status_catalog (nombre, es_final, libera_al_cerrar)
VALUES
  ('nuevo', FALSE, FALSE),
  ('no_contesta', FALSE, TRUE),
  ('rellamar', FALSE, TRUE),
  ('seguimiento', TRUE, FALSE),
  ('rechazo', TRUE, FALSE),
  ('dato_erroneo', TRUE, FALSE),
  ('venta', TRUE, FALSE)
ON CONFLICT (nombre) DO UPDATE
SET
  es_final = EXCLUDED.es_final,
  libera_al_cerrar = EXCLUDED.libera_al_cerrar;
