CREATE TABLE IF NOT EXISTS public.datos_para_trabajar (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nombre text,
  apellido text,
  documento text,
  fecha_nacimiento date,
  telefono text,
  celular text,
  correo_electronico text,
  direccion text,
  departamento text,
  pais text,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS datos_para_trabajar_documento_idx
  ON public.datos_para_trabajar (documento);

DROP TRIGGER IF EXISTS datos_para_trabajar_set_updated_at ON public.datos_para_trabajar;
CREATE TRIGGER datos_para_trabajar_set_updated_at
BEFORE UPDATE ON public.datos_para_trabajar
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
