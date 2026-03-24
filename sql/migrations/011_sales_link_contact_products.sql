ALTER TABLE public.sales
  ALTER COLUMN seller_id DROP NOT NULL;

ALTER TABLE public.sales
  ADD COLUMN IF NOT EXISTS seller_name_snapshot text NULL,
  ADD COLUMN IF NOT EXISTS seller_origin text NOT NULL DEFAULT 'interno';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE constraint_name = 'sales_seller_origin_check'
      AND table_name = 'sales'
      AND table_schema = 'public'
  ) THEN
    ALTER TABLE public.sales
    ADD CONSTRAINT sales_seller_origin_check
    CHECK (seller_origin IN ('interno', 'externo', 'importado'));
  END IF;
END $$;

ALTER TABLE public.contact_products
  ADD COLUMN IF NOT EXISTS sale_id uuid NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE constraint_name = 'contact_products_sale_id_fkey'
      AND table_name = 'contact_products'
      AND table_schema = 'public'
  ) THEN
    ALTER TABLE public.contact_products
    ADD CONSTRAINT contact_products_sale_id_fkey
    FOREIGN KEY (sale_id)
    REFERENCES public.sales(id)
    ON DELETE SET NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS contact_products_sale_id_idx
  ON public.contact_products (sale_id);

WITH product_names AS (
  SELECT DISTINCT
    COALESCE(NULLIF(BTRIM(nombre_producto), ''), NULLIF(BTRIM(plan), ''), 'Producto') AS nombre,
    COALESCE(precio, 0)::numeric(12,2) AS precio
  FROM public.contact_products
)
INSERT INTO public.products (nombre, categoria, precio, activo)
SELECT pn.nombre, 'General', pn.precio, true
FROM product_names pn
WHERE NOT EXISTS (
  SELECT 1
  FROM public.products p
  WHERE lower(p.nombre) = lower(pn.nombre)
);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'contact_products'
      AND column_name = 'medio_pago'
  ) THEN
    CREATE TEMP TABLE contact_products_sales_map AS
    SELECT
      cp.id AS contact_product_id,
      gen_random_uuid() AS sale_id,
      cp.contact_id,
      cp.seller_user_id,
      cp.fecha_alta AS fecha,
      cp.medio_pago,
      cp.seller_name_snapshot,
      cp.seller_origin,
      cp.created_at,
      cp.updated_at,
      COALESCE(NULLIF(BTRIM(cp.nombre_producto), ''), NULLIF(BTRIM(cp.plan), ''), 'Producto') AS product_name,
      COALESCE(cp.precio, 0)::numeric(12,2) AS precio_unitario
    FROM public.contact_products cp
    WHERE cp.sale_id IS NULL;

    INSERT INTO public.sales (
      id,
      contact_id,
      seller_id,
      fecha,
      medio_pago,
      seller_name_snapshot,
      seller_origin,
      created_at,
      updated_at
    )
    SELECT
      sale_id,
      contact_id,
      seller_user_id,
      fecha,
      medio_pago,
      seller_name_snapshot,
      seller_origin,
      COALESCE(created_at, now()),
      COALESCE(updated_at, now())
    FROM contact_products_sales_map;

    UPDATE public.contact_products cp
    SET sale_id = m.sale_id
    FROM contact_products_sales_map m
    WHERE cp.id = m.contact_product_id;

    INSERT INTO public.sale_items (
      sale_id,
      product_id,
      cantidad,
      precio_unitario,
      created_at,
      updated_at
    )
    SELECT
      m.sale_id,
      p.id,
      1,
      m.precio_unitario,
      m.created_at,
      m.updated_at
    FROM contact_products_sales_map m
    JOIN public.products p
      ON lower(p.nombre) = lower(m.product_name);

    DROP TABLE contact_products_sales_map;
  END IF;
END $$;

ALTER TABLE public.contact_products
  DROP COLUMN IF EXISTS medio_pago;
