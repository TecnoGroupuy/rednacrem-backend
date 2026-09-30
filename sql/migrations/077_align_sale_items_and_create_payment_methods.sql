-- Alinea local.sale_items con la definicion EXACTA de produccion (columnas,
-- constraints e indices, confirmados contra RDS por Damian) y crea
-- public.payment_methods, que no existia en absoluto en local.
--
-- sale_items en local tenia un diseño distinto (cantidad/precio_unitario,
-- con sus propios CHECK) que producción nunca tuvo -- confirmado por grep en
-- index.mjs: ningun INSERT/SELECT/UPDATE del codigo usa esas dos columnas,
-- todos ya asumian product_name_snapshot/price (la misma señal que con
-- sales/products: si prod no tuviera esas columnas, ese codigo preexistente
-- nunca podria haber funcionado ahi). Se dropean sin backfill -- no hay a
-- donde migrar esos valores porque prod nunca tuvo ese concepto de
-- "cantidad" en sale_items.
--
-- Pensada para ser no-op en produccion. No aplicar en produccion -- la corre
-- Damian.

-- 1) sale_items: agregar columnas de produccion que faltan.
ALTER TABLE public.sale_items
  ADD COLUMN IF NOT EXISTS product_name_snapshot text,
  ADD COLUMN IF NOT EXISTS organization_id uuid;

ALTER TABLE public.sale_items
  ADD COLUMN IF NOT EXISTS price numeric NOT NULL DEFAULT 0;

-- product_id es NULLABLE en produccion (sale_items sobrevive aunque el
-- producto original se borre); local lo tenia NOT NULL.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'sale_items'
      AND column_name = 'product_id' AND is_nullable = 'NO'
  ) THEN
    ALTER TABLE public.sale_items ALTER COLUMN product_id DROP NOT NULL;
  END IF;
END $$;

-- 2) sale_items: sacar columnas (y sus CHECK, que Postgres dropea solo al
-- dropear la columna) que produccion nunca tuvo y que el codigo no usa.
ALTER TABLE public.sale_items
  DROP COLUMN IF EXISTS cantidad,
  DROP COLUMN IF EXISTS precio_unitario;

-- 3) sale_items: FK de organization_id que falta.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sale_items_organization_id_fkey') THEN
    ALTER TABLE public.sale_items
      ADD CONSTRAINT sale_items_organization_id_fkey
      FOREIGN KEY (organization_id) REFERENCES public.organizations(id);
  END IF;
END $$;

-- Los indices (sale_items_pkey, sale_items_sale_id_idx,
-- sale_items_product_id_idx) y las FKs de sale_id/product_id ya coincidian
-- con produccion -- no hace falta tocarlos.

-- 4) payment_methods: no existia en absoluto en local. Confirmado que no
-- existe (ni vacia) antes de este CREATE -- no es el caso general de "CREATE
-- TABLE IF NOT EXISTS sobre una tabla que podria ya existir con otra forma"
-- que prohibe la regla 3 de CLAUDE.md, porque se verifico su ausencia total.
CREATE TABLE IF NOT EXISTS public.payment_methods (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nombre text NOT NULL,
  organization_id uuid NOT NULL,
  activo boolean NOT NULL DEFAULT true,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT payment_methods_pkey PRIMARY KEY (id)
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'payment_methods_organization_id_fkey') THEN
    ALTER TABLE public.payment_methods
      ADD CONSTRAINT payment_methods_organization_id_fkey
      FOREIGN KEY (organization_id) REFERENCES public.organizations(id);
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS payment_methods_nombre_org_idx
  ON public.payment_methods (lower(nombre), organization_id);

-- Ahora sales.payment_method_id (agregada en 075 sin FK porque esta tabla no
-- existia) puede tener su FK real.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_payment_method_id_fkey') THEN
    ALTER TABLE public.sales
      ADD CONSTRAINT sales_payment_method_id_fkey
      FOREIGN KEY (payment_method_id) REFERENCES public.payment_methods(id);
  END IF;
END $$;
