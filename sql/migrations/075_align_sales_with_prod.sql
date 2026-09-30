-- Alinea local.sales con la definicion EXACTA de produccion (columnas,
-- constraints e indices, confirmados contra RDS -- ver mensaje de Damian).
-- No solo renombra: agrega todas las columnas que faltaban. Pensada para
-- ser no-op en produccion (ahi ya existe todo con estos nombres exactos).
--
-- Con esto se puede sacar la deteccion dinamica de columnas de sales en
-- insertSaleRecord (salesCols.has("seller_user_id") ? ... : ...) -- regla
-- 2 de CLAUDE.md, el codigo pasa a asumir el esquema de produccion
-- directamente.
--
-- Divergencia real encontrada al escribir esta migracion, documentada en
-- CLAUDE.md: la tabla public.payment_methods NO EXISTE en local (ni
-- siquiera vacia) -- el endpoint GET /payment-methods y el JOIN de
-- getClientDetailData ya la esperaban, asi que el selector de "Medio de
-- pago" del wizard viene fallando en local independientemente de este
-- cambio. Por eso sales.payment_method_id se agrega SIN su FK (no hay a
-- que tabla apuntar todavia) -- crear payment_methods es un cambio aparte,
-- fuera del alcance de esta migracion.

-- 1) Renombres: solo si la columna vieja existe y la nueva todavia no.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'sales' AND column_name = 'seller_id'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'sales' AND column_name = 'seller_user_id'
  ) THEN
    ALTER TABLE public.sales RENAME COLUMN seller_id TO seller_user_id;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'sales' AND column_name = 'fecha'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'sales' AND column_name = 'fecha_venta'
  ) THEN
    ALTER TABLE public.sales RENAME COLUMN fecha TO fecha_venta;
  END IF;
END $$;

-- Un RENAME COLUMN no renombra los nombres de constraints/indices que
-- dependen de esa columna (Postgres los referencia por atnum, no por
-- nombre) -- se renombran aparte para que coincidan con prod exactamente.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_seller_id_fkey')
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_seller_user_id_fkey') THEN
    ALTER TABLE public.sales RENAME CONSTRAINT sales_seller_id_fkey TO sales_seller_user_id_fkey;
  END IF;
END $$;

-- 2) Columnas que faltan (nullable, sin default salvo lo que ya tenia
-- prod -- ninguna de estas tiene default en prod).
ALTER TABLE public.sales
  ADD COLUMN IF NOT EXISTS notes text,
  ADD COLUMN IF NOT EXISTS documento_cobranza text,
  ADD COLUMN IF NOT EXISTS sale_group_id uuid,
  ADD COLUMN IF NOT EXISTS parent_sale_id uuid,
  ADD COLUMN IF NOT EXISTS gestion_id uuid,
  ADD COLUMN IF NOT EXISTS titular_contact_id uuid,
  ADD COLUMN IF NOT EXISTS relation character varying,
  ADD COLUMN IF NOT EXISTS product_id uuid,
  ADD COLUMN IF NOT EXISTS payment_method_id uuid;

-- 3) FKs que faltan (gateadas por nombre, no-op si ya existen).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_gestion_id_fkey') THEN
    ALTER TABLE public.sales
      ADD CONSTRAINT sales_gestion_id_fkey
      FOREIGN KEY (gestion_id) REFERENCES public.lead_management_history(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_titular_contact_id_fkey') THEN
    ALTER TABLE public.sales
      ADD CONSTRAINT sales_titular_contact_id_fkey
      FOREIGN KEY (titular_contact_id) REFERENCES public.contacts(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_product_id_fkey') THEN
    ALTER TABLE public.sales
      ADD CONSTRAINT sales_product_id_fkey
      FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_organization_id_fkey') THEN
    ALTER TABLE public.sales
      ADD CONSTRAINT sales_organization_id_fkey
      FOREIGN KEY (organization_id) REFERENCES public.organizations(id);
  END IF;
END $$;

-- sales_payment_method_id_fkey NO se agrega: public.payment_methods no
-- existe en local (ver nota arriba). Si el dia de mañana se crea esa
-- tabla en local, agregar esta FK en una migracion aparte.

-- 4) Indices: sacar los que prod NO tiene (nombres locales viejos, ya sin
-- sentido tras el rename) y agregar los que si tiene prod.
DROP INDEX IF EXISTS public.sales_fecha_idx;
DROP INDEX IF EXISTS public.sales_seller_id_idx;

CREATE INDEX IF NOT EXISTS idx_sales_gestion_id
  ON public.sales (gestion_id) WHERE gestion_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_sales_titular_contact_id
  ON public.sales (titular_contact_id) WHERE titular_contact_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS sales_seller_user_id_fecha_venta_idx
  ON public.sales (seller_user_id, fecha_venta);
