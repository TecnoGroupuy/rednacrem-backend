CREATE TABLE IF NOT EXISTS public.sales (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  seller_id uuid NOT NULL REFERENCES public.users(id),
  fecha date NOT NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sales_contact_id_idx
  ON public.sales (contact_id);

CREATE INDEX IF NOT EXISTS sales_seller_id_idx
  ON public.sales (seller_id);

CREATE INDEX IF NOT EXISTS sales_fecha_idx
  ON public.sales (fecha);

CREATE TABLE IF NOT EXISTS public.sale_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sale_id uuid NOT NULL REFERENCES public.sales(id) ON DELETE CASCADE,
  product_id uuid NOT NULL REFERENCES public.products(id),
  cantidad integer NOT NULL DEFAULT 1,
  precio_unitario numeric(12,2) NOT NULL DEFAULT 0,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT sale_items_cantidad_check
    CHECK (cantidad > 0),
  CONSTRAINT sale_items_precio_unitario_check
    CHECK (precio_unitario >= 0)
);

CREATE INDEX IF NOT EXISTS sale_items_sale_id_idx
  ON public.sale_items (sale_id);

CREATE INDEX IF NOT EXISTS sale_items_product_id_idx
  ON public.sale_items (product_id);

DROP TRIGGER IF EXISTS sales_set_updated_at ON public.sales;
CREATE TRIGGER sales_set_updated_at
BEFORE UPDATE ON public.sales
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS sale_items_set_updated_at ON public.sale_items;
CREATE TRIGGER sale_items_set_updated_at
BEFORE UPDATE ON public.sale_items
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
