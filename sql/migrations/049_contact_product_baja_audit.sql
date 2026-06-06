CREATE TABLE IF NOT EXISTS public.contact_product_baja_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  product_id uuid NOT NULL REFERENCES public.contact_products(id) ON DELETE CASCADE,
  organization_id uuid,
  nombre_producto text,
  precio_producto numeric(12,2),
  fecha_alta_producto date,
  medio_pago text,
  motivo_baja text NOT NULL,
  motivo_baja_detalle text,
  fecha_baja timestamptz NOT NULL DEFAULT now(),
  gestionado_por uuid REFERENCES public.users(id),
  gestionado_por_nombre text,
  gestionado_por_email text,
  seller_user_id uuid REFERENCES public.users(id),
  seller_nombre text,
  genero_recupero_alert boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.contact_product_baja_audit
  ADD COLUMN IF NOT EXISTS organization_id uuid,
  ADD COLUMN IF NOT EXISTS nombre_producto text,
  ADD COLUMN IF NOT EXISTS precio_producto numeric(12,2),
  ADD COLUMN IF NOT EXISTS fecha_alta_producto date,
  ADD COLUMN IF NOT EXISTS medio_pago text,
  ADD COLUMN IF NOT EXISTS motivo_baja_detalle text,
  ADD COLUMN IF NOT EXISTS gestionado_por uuid REFERENCES public.users(id),
  ADD COLUMN IF NOT EXISTS gestionado_por_nombre text,
  ADD COLUMN IF NOT EXISTS gestionado_por_email text,
  ADD COLUMN IF NOT EXISTS seller_user_id uuid REFERENCES public.users(id),
  ADD COLUMN IF NOT EXISTS seller_nombre text,
  ADD COLUMN IF NOT EXISTS genero_recupero_alert boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS contact_product_baja_audit_contact_id_idx
  ON public.contact_product_baja_audit (contact_id, fecha_baja DESC);

CREATE INDEX IF NOT EXISTS contact_product_baja_audit_product_id_idx
  ON public.contact_product_baja_audit (product_id, fecha_baja DESC);

CREATE INDEX IF NOT EXISTS contact_product_baja_audit_org_id_idx
  ON public.contact_product_baja_audit (organization_id, fecha_baja DESC);

CREATE INDEX IF NOT EXISTS contact_product_baja_audit_seller_user_id_idx
  ON public.contact_product_baja_audit (seller_user_id, fecha_baja DESC);
