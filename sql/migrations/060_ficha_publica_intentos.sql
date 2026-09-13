-- Rate-limit de la busqueda publica de ficha de personal (sin Cognito).
-- Una fila por intento fallido de GET /publico/ficha-personal/buscar.
-- El backend bloquea al llegar a FICHA_PUBLICA_MAX_INTENTOS (5) intentos
-- fallidos desde la misma IP dentro de FICHA_PUBLICA_INTENTOS_WINDOW
-- (15 minutos). No se guarda ningun dato de la persona ni del documento
-- probado, solo IP y timestamp.
--
-- Es la primera migracion versionada de una tabla nueva del modulo de
-- Operaciones/RRHH: el resto de las tablas su_* se crearon directo en
-- produccion. Damian corre este archivo contra RDS.

CREATE TABLE IF NOT EXISTS public.ficha_publica_intentos (
  id         bigserial PRIMARY KEY,
  ip         text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ficha_publica_intentos_ip_created_idx
  ON public.ficha_publica_intentos (ip, created_at);
