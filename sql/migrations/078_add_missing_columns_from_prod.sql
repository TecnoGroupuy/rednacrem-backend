-- SOLO LOCAL -- NO-OP EN PRODUCCION -- NO EJECUTAR EN PRODUCCION.
-- Las 44 columnas se sacaron directamente de prod_columns.csv (ya existen
-- en produccion) y contact_relations se armo con los constraints/indices
-- reales de RDS que paso Damian -- ambas partes son no-op en prod. Damian
-- confirmo que en el deploy de este feature NO se corrio en prod.
--
-- Agrega a local las 44 columnas que existen en produccion y faltaban en
-- local, confirmadas contra docs/prod-schema/prod_columns.csv (ver
-- scripts/compare-schema.mjs). Alcance ACOTADO a lo que bloquea el feature
-- de vendedor externo / fecha de venta -- las 178 diferencias de tipo,
-- nulabilidad y default entre columnas que YA EXISTEN en ambos lados
-- quedan para una reconstruccion completa de la base local mas adelante,
-- no se tocan aca.
--
-- Todas con tipo/default exactos de prod. Dos excepciones deliberadas a la
-- nulabilidad de prod (documentadas abajo, en el bloque de
-- client_document_events): en prod son NOT NULL sin default, pero la tabla
-- local ya tiene filas (2) sin esas columnas -- agregarlas NOT NULL
-- rompería esas filas. Se agregan nullable; si en el futuro se quiere
-- exigir NOT NULL en local, hace falta backfillear esas 2 filas primero.
--
-- Ninguna de estas columnas tiene FK en esta migracion -- prod_columns.csv
-- no trae constraints, y agregar una FK a ciegas seria inventar una
-- relacion que no esta confirmada contra RDS (ver CLAUDE.md, regla 4 y la
-- instruccion de no inventar PKs/UNIQUE/FKs).
--
-- Pensada para ser no-op en produccion. No aplicar en produccion -- la
-- corre Damian.

-- client_document_events: contact_id y tipo son NOT NULL en prod, pero la
-- tabla local ya tiene 2 filas -- se agregan nullable (ver nota arriba).
ALTER TABLE public.client_document_events
  ADD COLUMN IF NOT EXISTS contact_id uuid,
  ADD COLUMN IF NOT EXISTS tipo text,
  ADD COLUMN IF NOT EXISTS detalle text,
  ADD COLUMN IF NOT EXISTS created_by uuid;

ALTER TABLE public.contact_import_batches
  ADD COLUMN IF NOT EXISTS organization_id uuid;

ALTER TABLE public.contact_import_rows
  ADD COLUMN IF NOT EXISTS organization_id uuid;

ALTER TABLE public.contact_product_baja_audit
  ADD COLUMN IF NOT EXISTS nombre_producto text,
  ADD COLUMN IF NOT EXISTS precio_producto numeric,
  ADD COLUMN IF NOT EXISTS fecha_alta_producto date,
  ADD COLUMN IF NOT EXISTS medio_pago text,
  ADD COLUMN IF NOT EXISTS motivo_baja_detalle text,
  ADD COLUMN IF NOT EXISTS gestionado_por uuid,
  ADD COLUMN IF NOT EXISTS gestionado_por_nombre text,
  ADD COLUMN IF NOT EXISTS gestionado_por_email text,
  ADD COLUMN IF NOT EXISTS seller_user_id uuid,
  ADD COLUMN IF NOT EXISTS seller_nombre text,
  ADD COLUMN IF NOT EXISTS genero_recupero_alert boolean DEFAULT false;

ALTER TABLE public.contact_products
  ADD COLUMN IF NOT EXISTS product_id uuid;

ALTER TABLE public.contact_relatives
  ADD COLUMN IF NOT EXISTS organization_id uuid;

ALTER TABLE public.datos_para_trabajar
  ADD COLUMN IF NOT EXISTS import_job_id uuid,
  ADD COLUMN IF NOT EXISTS ingresado_por uuid,
  ADD COLUMN IF NOT EXISTS campaign_name character varying(255),
  ADD COLUMN IF NOT EXISTS form_name character varying(255);

ALTER TABLE public.external_connections
  ADD COLUMN IF NOT EXISTS payment_method_override text;

ALTER TABLE public.lead_batch_contacts
  ADD COLUMN IF NOT EXISTS tipo_origen text DEFAULT 'lead'::text,
  ADD COLUMN IF NOT EXISTS client_contact_id uuid;

ALTER TABLE public.lead_management_history
  ADD COLUMN IF NOT EXISTS organization_id uuid,
  ADD COLUMN IF NOT EXISTS es_correccion_supervisor boolean DEFAULT false;

ALTER TABLE public.manual_tickets
  ADD COLUMN IF NOT EXISTS organization_id uuid;

ALTER TABLE public.no_call_entries
  ADD COLUMN IF NOT EXISTS telefono text,
  ADD COLUMN IF NOT EXISTS motivo text,
  ADD COLUMN IF NOT EXISTS created_by uuid;

ALTER TABLE public.organization_users
  ADD COLUMN IF NOT EXISTS id uuid NOT NULL DEFAULT gen_random_uuid();

ALTER TABLE public.products
  ADD COLUMN IF NOT EXISTS disponible_venta boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS coberturas text[] DEFAULT '{}'::text[];

ALTER TABLE public.recupero_candidatos
  ADD COLUMN IF NOT EXISTS contact_id uuid,
  ADD COLUMN IF NOT EXISTS estado_administrativo text NOT NULL DEFAULT 'activo'::text;

ALTER TABLE public.recupero_candidatos_historial
  ADD COLUMN IF NOT EXISTS batch_id uuid;

ALTER TABLE public.su_bases
  ADD COLUMN IF NOT EXISTS telefono text,
  ADD COLUMN IF NOT EXISTS moviles_minimos_habilitados integer DEFAULT 1;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS extension text,
  ADD COLUMN IF NOT EXISTS department text,
  ADD COLUMN IF NOT EXISTS motivo_pausa text,
  ADD COLUMN IF NOT EXISTS pausado_at timestamp without time zone;

-- =========================================================================
-- Parte 2/2: crear contact_relations, la UNICA de las 25 tablas de prod
-- ausentes en local que el flujo de alta de clientes usa de verdad (INSERT
-- en el alta de familiares, ver index.mjs). Las otras 20 tablas usadas por
-- el resto del codigo (sellers, sms_*, su_*, etc.) quedan pendientes para
-- la reconstruccion completa de la base local (fase 1) -- ver CLAUDE.md.
--
-- Columnas de docs/prod-schema/prod_columns.csv; constraints e indices
-- confirmados contra RDS por Damian hoy -- calcados tal cual, incluida la
-- UNIQUE que contact_relations usa en su ON CONFLICT (contact_id_a,
-- contact_id_b) en index.mjs.
--
-- Se verifico que la tabla no existe en absoluto en local antes de este
-- CREATE TABLE IF NOT EXISTS (confirmado por compare-schema.mjs) -- no es
-- el caso que prohibe la regla 3 de CLAUDE.md (tabla que podria ya existir
-- con otra forma).
CREATE TABLE IF NOT EXISTS public.contact_relations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  contact_id_a uuid NOT NULL,
  contact_id_b uuid NOT NULL,
  relation character varying(50),
  source character varying(20) NOT NULL DEFAULT 'manual'::character varying,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  organization_id uuid,
  CONSTRAINT contact_relations_pkey PRIMARY KEY (id),
  CONSTRAINT no_self_relation CHECK (contact_id_a <> contact_id_b),
  CONSTRAINT unique_relation UNIQUE (contact_id_a, contact_id_b),
  CONSTRAINT contact_relations_contact_id_a_fkey FOREIGN KEY (contact_id_a) REFERENCES public.contacts(id) ON DELETE CASCADE,
  CONSTRAINT contact_relations_contact_id_b_fkey FOREIGN KEY (contact_id_b) REFERENCES public.contacts(id) ON DELETE CASCADE,
  CONSTRAINT contact_relations_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id)
);

-- contact_relations_pkey y unique_relation ya crean su propio indice unico
-- via el PRIMARY KEY / UNIQUE de arriba -- solo faltan los dos btree planos.
CREATE INDEX IF NOT EXISTS idx_contact_relations_a ON public.contact_relations (contact_id_a);
CREATE INDEX IF NOT EXISTS idx_contact_relations_b ON public.contact_relations (contact_id_b);
