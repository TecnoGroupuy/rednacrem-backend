CREATE TABLE IF NOT EXISTS public.contact_product_baja_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  product_id uuid NOT NULL REFERENCES public.contact_products(id) ON DELETE CASCADE,
  motivo_baja text NOT NULL,
  observacion text,
  fecha_baja timestamptz NOT NULL DEFAULT now(),
  user_id uuid,
  organization_id uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS contact_product_baja_audit_contact_id_idx
  ON public.contact_product_baja_audit (contact_id, fecha_baja DESC);

CREATE INDEX IF NOT EXISTS contact_product_baja_audit_product_id_idx
  ON public.contact_product_baja_audit (product_id, fecha_baja DESC);

CREATE INDEX IF NOT EXISTS contact_product_baja_audit_org_id_idx
  ON public.contact_product_baja_audit (organization_id, fecha_baja DESC);

