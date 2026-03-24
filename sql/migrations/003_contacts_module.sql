CREATE TABLE IF NOT EXISTS public.contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nombre text NOT NULL,
  apellido text,
  email text,
  telefono text,
  documento text,
  status text NOT NULL DEFAULT 'activo',
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT contacts_status_check
    CHECK (status IN ('activo', 'bloqueado'))
);

CREATE UNIQUE INDEX IF NOT EXISTS contacts_email_unique_idx
  ON public.contacts (lower(email))
  WHERE email IS NOT NULL AND btrim(email) <> '';

CREATE INDEX IF NOT EXISTS contacts_status_idx
  ON public.contacts (status);

CREATE TABLE IF NOT EXISTS public.contact_products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  nombre_producto text NOT NULL,
  plan text,
  precio numeric(12,2) NOT NULL DEFAULT 0,
  medio_pago text,
  fecha_alta date NOT NULL,
  cuotas_pagas integer NOT NULL DEFAULT 0,
  carencia_cuotas integer NOT NULL DEFAULT 0,
  estado text NOT NULL DEFAULT 'alta',
  motivo_baja text,
  motivo_baja_detalle text,
  fecha_baja date,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT contact_products_estado_check
    CHECK (estado IN ('alta', 'baja')),
  CONSTRAINT contact_products_motivo_baja_check
    CHECK (
      motivo_baja IS NULL OR
      motivo_baja IN ('no_pasa_auditoria', 'error_medio_pago', 'fallecido', 'otro')
    ),
  CONSTRAINT contact_products_cuotas_check
    CHECK (cuotas_pagas >= 0 AND carencia_cuotas >= 0),
  CONSTRAINT contact_products_baja_consistency_check
    CHECK (
      (estado = 'alta' AND motivo_baja IS NULL AND fecha_baja IS NULL)
      OR
      (estado = 'baja' AND motivo_baja IS NOT NULL AND fecha_baja IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS contact_products_contact_id_idx
  ON public.contact_products (contact_id);

CREATE INDEX IF NOT EXISTS contact_products_estado_idx
  ON public.contact_products (estado);

CREATE INDEX IF NOT EXISTS contact_products_fecha_alta_idx
  ON public.contact_products (fecha_alta);

CREATE OR REPLACE VIEW public.contact_customer_summary AS
SELECT
  c.id,
  c.nombre,
  c.apellido,
  c.email,
  c.telefono,
  c.documento,
  c.status AS contacto_estado,
  COUNT(cp.id) AS productos_total,
  COUNT(*) FILTER (WHERE cp.estado = 'alta') AS productos_activos,
  CASE
    WHEN COUNT(cp.id) = 0 THEN 'contacto'
    WHEN COUNT(*) FILTER (WHERE cp.estado = 'alta') > 0 THEN 'cliente_actual'
    ELSE 'cliente_historico'
  END AS tipo_persona,
  c.created_at,
  c.updated_at
FROM public.contacts c
LEFT JOIN public.contact_products cp
  ON cp.contact_id = c.id
GROUP BY
  c.id,
  c.nombre,
  c.apellido,
  c.email,
  c.telefono,
  c.documento,
  c.status,
  c.created_at,
  c.updated_at;

CREATE OR REPLACE VIEW public.calling_base AS
SELECT
  id,
  nombre,
  apellido,
  email,
  telefono,
  documento,
  contacto_estado,
  productos_total,
  productos_activos,
  tipo_persona,
  created_at,
  updated_at
FROM public.contact_customer_summary
WHERE contacto_estado = 'activo'
  AND tipo_persona IN ('contacto', 'cliente_historico');
