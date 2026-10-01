-- Documentacion del personal (RRHH SU Emergencia): archivos subidos por el
-- funcionario via el link publico o por un admin de RRHH desde la ficha
-- interna, con revision (pendiente/validado/rechazado).
--
-- Los archivos en si NUNCA viven en este repo ni en Postgres -- esta tabla
-- solo guarda la referencia (s3_key) al bucket PRIVADO nuevo
-- (rednacrem-documentos-personal, creado a mano por Damian en AWS, sin
-- CORS porque la subida/descarga esta mediada por el backend, nunca habla
-- el navegador directo con S3). Los datos "de negocio" de cada documento
-- (numero, fecha_vencimiento, etc.) siguen viviendo en las tablas
-- existentes su_personal_habilitaciones / su_personal_carnet_salud /
-- su_personal_capacitaciones -- esta tabla solo agrega la revision y el
-- archivo en si, referenciando esa fila via entidad_tipo/entidad_id cuando
-- corresponde (ci_frente/ci_dorso no tienen fila asociada, quedan NULL).
--
-- revisado_por es un uuid SIN FK a proposito (regla del modulo de
-- Operaciones: nada fuera de su_*/organizations).
--
-- Esta migracion es NUEVA de punta a punta -- no existe nada de esto en
-- produccion todavia. Damian la corre a mano contra RDS; el agente no la
-- ejecuta contra produccion.

CREATE TABLE IF NOT EXISTS public.su_personal_archivos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  personal_id uuid NOT NULL REFERENCES public.su_personal(id) ON DELETE CASCADE,
  categoria text NOT NULL CHECK (categoria IN (
    'ci_frente', 'ci_dorso', 'carne_salud', 'titulo', 'registro_msp', 'libreta_conducir', 'curso'
  )),
  entidad_tipo text NULL CHECK (entidad_tipo IN ('habilitacion', 'carnet_salud', 'capacitacion')),
  entidad_id uuid NULL,
  nombre_archivo text NOT NULL,
  s3_key text NOT NULL,
  content_type text NOT NULL,
  tamano integer NOT NULL,
  origen text NOT NULL CHECK (origen IN ('publico', 'interno')),
  estado_revision text NOT NULL DEFAULT 'pendiente' CHECK (estado_revision IN ('pendiente', 'validado', 'rechazado')),
  motivo_rechazo text NULL,
  revisado_por uuid NULL,
  revisado_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Un solo documento vigente por categoria singleton (reemplazar borra el
-- anterior de S3 y pisa esta fila) -- excepto 'curso', que es repetible
-- (multiples cursos por persona, nunca se pisan entre si).
CREATE UNIQUE INDEX IF NOT EXISTS su_personal_archivos_singleton_idx
  ON public.su_personal_archivos (personal_id, categoria)
  WHERE categoria <> 'curso';

CREATE INDEX IF NOT EXISTS su_personal_archivos_organization_id_idx
  ON public.su_personal_archivos (organization_id);

CREATE INDEX IF NOT EXISTS su_personal_archivos_personal_id_idx
  ON public.su_personal_archivos (personal_id);

CREATE INDEX IF NOT EXISTS su_personal_archivos_estado_revision_idx
  ON public.su_personal_archivos (estado_revision)
  WHERE estado_revision = 'pendiente';
