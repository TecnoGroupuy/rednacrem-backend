ALTER TABLE public.contact_products
ADD COLUMN IF NOT EXISTS seller_user_id uuid NULL,
ADD COLUMN IF NOT EXISTS seller_name_snapshot text NULL,
ADD COLUMN IF NOT EXISTS seller_origin text NOT NULL DEFAULT 'interno';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE constraint_name = 'contact_products_seller_user_id_fkey'
      AND table_name = 'contact_products'
      AND table_schema = 'public'
  ) THEN
    ALTER TABLE public.contact_products
    ADD CONSTRAINT contact_products_seller_user_id_fkey
    FOREIGN KEY (seller_user_id)
    REFERENCES public.users(id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE constraint_name = 'contact_products_seller_origin_check'
      AND table_name = 'contact_products'
      AND table_schema = 'public'
  ) THEN
    ALTER TABLE public.contact_products
    ADD CONSTRAINT contact_products_seller_origin_check
    CHECK (seller_origin IN ('interno', 'externo', 'importado'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS contact_products_seller_user_id_idx
  ON public.contact_products (seller_user_id);

CREATE UNIQUE INDEX IF NOT EXISTS contacts_documento_unique_idx
  ON public.contacts (documento)
  WHERE documento IS NOT NULL AND btrim(documento) <> '';

CREATE TABLE IF NOT EXISTS public.contact_import_batches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_name text NOT NULL,
  status text NOT NULL DEFAULT 'uploaded',
  import_type text NOT NULL DEFAULT 'clientes',
  total_rows integer NOT NULL DEFAULT 0,
  valid_rows integer NOT NULL DEFAULT 0,
  error_rows integer NOT NULL DEFAULT 0,
  created_by uuid NULL REFERENCES public.users(id),
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT contact_import_batches_status_check
    CHECK (status IN ('uploaded', 'validated', 'processed', 'failed')),
  CONSTRAINT contact_import_batches_type_check
    CHECK (import_type IN ('clientes', 'no_llamar', 'resultados'))
);

ALTER TABLE public.contact_import_batches
ADD COLUMN IF NOT EXISTS import_type text NOT NULL DEFAULT 'clientes';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE constraint_name = 'contact_import_batches_type_check'
      AND table_name = 'contact_import_batches'
      AND table_schema = 'public'
  ) THEN
    ALTER TABLE public.contact_import_batches
    ADD CONSTRAINT contact_import_batches_type_check
    CHECK (import_type IN ('clientes', 'no_llamar', 'resultados'));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.contact_import_rows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id uuid NOT NULL REFERENCES public.contact_import_batches(id) ON DELETE CASCADE,
  row_number integer NOT NULL,
  nombre text,
  apellido text,
  email text,
  telefono text,
  documento text,
  contacto_estado text,
  producto_nombre text,
  plan text,
  precio numeric(12,2),
  medio_pago text,
  fecha_alta date,
  cuotas_pagas integer,
  carencia_cuotas integer,
  producto_estado text,
  motivo_baja text,
  motivo_baja_detalle text,
  fecha_baja date,
  vendedor_nombre text,
  vendedor_email text,
  import_status text NOT NULL DEFAULT 'pending',
  error_detail text,
  raw_payload jsonb,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT contact_import_rows_status_check
    CHECK (import_status IN ('pending', 'validated', 'error', 'imported'))
);

ALTER TABLE public.contact_import_rows
ADD COLUMN IF NOT EXISTS fecha_venta date,
ADD COLUMN IF NOT EXISTS documento_beneficiario text,
ADD COLUMN IF NOT EXISTS documento_cobranza text,
ADD COLUMN IF NOT EXISTS telefono_venta text,
ADD COLUMN IF NOT EXISTS telefono_fijo text,
ADD COLUMN IF NOT EXISTS telefono_celular text,
ADD COLUMN IF NOT EXISTS telefono_alternativo text,
ADD COLUMN IF NOT EXISTS consulta_estado text,
ADD COLUMN IF NOT EXISTS evaluacion text,
ADD COLUMN IF NOT EXISTS auditoria_ok text,
ADD COLUMN IF NOT EXISTS auditoria_comentario text,
ADD COLUMN IF NOT EXISTS nombre_asesor text,
ADD COLUMN IF NOT EXISTS fecha_nacimiento date,
ADD COLUMN IF NOT EXISTS departamento_residencia text,
ADD COLUMN IF NOT EXISTS nombre_familiar text,
ADD COLUMN IF NOT EXISTS apellido_familiar text,
ADD COLUMN IF NOT EXISTS telefono_familiar text,
ADD COLUMN IF NOT EXISTS parentesco text,
ADD COLUMN IF NOT EXISTS resolved_contact_id uuid NULL,
ADD COLUMN IF NOT EXISTS resolved_seller_user_id uuid NULL;

CREATE INDEX IF NOT EXISTS contact_import_rows_batch_id_idx
  ON public.contact_import_rows (batch_id);

CREATE INDEX IF NOT EXISTS contact_import_rows_import_status_idx
  ON public.contact_import_rows (import_status);
