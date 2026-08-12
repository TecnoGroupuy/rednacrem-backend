-- BEGIN 006_products_catalog.sql
CREATE TABLE IF NOT EXISTS public.products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nombre text NOT NULL,
  categoria text NOT NULL DEFAULT 'General',
  descripcion text,
  observaciones text,
  precio numeric(12,2) NOT NULL DEFAULT 0,
  activo boolean NOT NULL DEFAULT true,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS products_nombre_unique_idx
  ON public.products (lower(nombre));

DROP TRIGGER IF EXISTS products_set_updated_at ON public.products;
CREATE TRIGGER products_set_updated_at
BEFORE UPDATE ON public.products
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- END 006_products_catalog.sql

-- BEGIN 008_client_document_events.sql
CREATE TABLE IF NOT EXISTS public.client_document_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  user_id uuid REFERENCES public.users(id),
  event text NOT NULL,
  origin text,
  template text,
  lang text,
  channel text,
  note text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT client_document_events_event_check
    CHECK (event IN ('download_pdf', 'sent_document')),
  CONSTRAINT client_document_events_channel_check
    CHECK (channel IS NULL OR channel IN ('whatsapp', 'email'))
);

CREATE INDEX IF NOT EXISTS client_document_events_client_id_idx
  ON public.client_document_events (client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS client_document_events_user_id_idx
  ON public.client_document_events (user_id, created_at DESC);

-- END 008_client_document_events.sql

-- BEGIN 009_sales_module.sql
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

-- END 009_sales_module.sql

-- BEGIN 012_manual_tickets.sql
CREATE TABLE IF NOT EXISTS public.manual_tickets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cliente_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  tipo_solicitud text NOT NULL,
  tipo_solicitud_manual text,
  resumen text NOT NULL,
  prioridad text NOT NULL DEFAULT 'media',
  estado text NOT NULL DEFAULT 'nueva',
  producto_contrato_id uuid NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT manual_tickets_prioridad_check
    CHECK (prioridad IN ('baja', 'media', 'alta')),
  CONSTRAINT manual_tickets_estado_check
    CHECK (estado IN ('nueva', 'en_proceso', 'finalizada'))
);

CREATE INDEX IF NOT EXISTS manual_tickets_cliente_id_idx
  ON public.manual_tickets (cliente_id, created_at DESC);

CREATE INDEX IF NOT EXISTS manual_tickets_producto_contrato_id_idx
  ON public.manual_tickets (producto_contrato_id);

DROP TRIGGER IF EXISTS manual_tickets_set_updated_at ON public.manual_tickets;
CREATE TRIGGER manual_tickets_set_updated_at
BEFORE UPDATE ON public.manual_tickets
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- END 012_manual_tickets.sql

-- BEGIN 013_manual_ticket_notes.sql
CREATE TABLE IF NOT EXISTS public.manual_ticket_notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id uuid NOT NULL REFERENCES public.manual_tickets(id) ON DELETE CASCADE,
  autor text,
  texto text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS manual_ticket_notes_ticket_id_idx
  ON public.manual_ticket_notes (ticket_id, created_at DESC);

-- END 013_manual_ticket_notes.sql

-- BEGIN 015_manual_ticket_closures.sql
CREATE TABLE IF NOT EXISTS public.manual_ticket_closures (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id uuid NOT NULL REFERENCES public.manual_tickets(id) ON DELETE CASCADE,
  resultado text NOT NULL,
  usuario text,
  note text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS manual_ticket_closures_ticket_id_idx
  ON public.manual_ticket_closures (ticket_id, created_at DESC);

-- END 015_manual_ticket_closures.sql

-- BEGIN 017_contact_relatives.sql
CREATE TABLE IF NOT EXISTS public.contact_relatives (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  nombre text,
  apellido text,
  telefono text,
  parentesco text,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS contact_relatives_contact_id_idx
  ON public.contact_relatives (contact_id);

DROP TRIGGER IF EXISTS contact_relatives_set_updated_at ON public.contact_relatives;
CREATE TRIGGER contact_relatives_set_updated_at
BEFORE UPDATE ON public.contact_relatives
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- END 017_contact_relatives.sql

-- BEGIN 020_no_call_entries.sql
CREATE TABLE IF NOT EXISTS public.no_call_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  numero text NOT NULL,
  fuente text NOT NULL,
  departamento text,
  localidad text,
  fecha_carga date NOT NULL DEFAULT now()::date,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT no_call_entries_fuente_check
    CHECK (fuente IN ('celular', 'tel_fijo'))
);

CREATE UNIQUE INDEX IF NOT EXISTS no_call_entries_numero_unique_idx
  ON public.no_call_entries (numero);

DROP TRIGGER IF EXISTS no_call_entries_set_updated_at ON public.no_call_entries;
CREATE TRIGGER no_call_entries_set_updated_at
BEFORE UPDATE ON public.no_call_entries
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- END 020_no_call_entries.sql

-- BEGIN 021_no_call_import_jobs.sql
CREATE TABLE IF NOT EXISTS public.no_call_import_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_name text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  total_rows integer NOT NULL DEFAULT 0,
  processed_rows integer NOT NULL DEFAULT 0,
  inserted_rows integer NOT NULL DEFAULT 0,
  skipped_rows integer NOT NULL DEFAULT 0,
  error_message text,
  csv_text text NOT NULL,
  created_by uuid NULL REFERENCES public.users(id),
  started_at timestamp without time zone NULL,
  completed_at timestamp without time zone NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT no_call_import_jobs_status_check
    CHECK (status IN ('queued', 'processing', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS no_call_import_jobs_status_idx
  ON public.no_call_import_jobs (status);

DROP TRIGGER IF EXISTS no_call_import_jobs_set_updated_at ON public.no_call_import_jobs;
CREATE TRIGGER no_call_import_jobs_set_updated_at
BEFORE UPDATE ON public.no_call_import_jobs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- END 021_no_call_import_jobs.sql

-- BEGIN 022_commercial_leads.sql
CREATE TABLE IF NOT EXISTS public.lead_batches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nombre text NOT NULL,
  estado text NOT NULL DEFAULT 'sin_asignar',
  asignado_a uuid NULL REFERENCES public.users(id),
  created_by uuid NULL REFERENCES public.users(id),
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT lead_batches_estado_check
    CHECK (estado IN ('sin_asignar', 'asignado', 'finalizado'))
);

CREATE INDEX IF NOT EXISTS lead_batches_estado_idx
  ON public.lead_batches (estado);

CREATE TABLE IF NOT EXISTS public.lead_batch_contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id uuid NOT NULL REFERENCES public.lead_batches(id) ON DELETE CASCADE,
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  UNIQUE (batch_id, contact_id)
);

CREATE INDEX IF NOT EXISTS lead_batch_contacts_batch_idx
  ON public.lead_batch_contacts (batch_id);

CREATE INDEX IF NOT EXISTS lead_batch_contacts_contact_idx
  ON public.lead_batch_contacts (contact_id);

CREATE TABLE IF NOT EXISTS public.lead_contact_status (
  contact_id uuid PRIMARY KEY REFERENCES public.contacts(id) ON DELETE CASCADE,
  estado_venta text NOT NULL DEFAULT 'nuevo',
  intentos integer NOT NULL DEFAULT 0,
  proxima_accion timestamp without time zone NULL,
  batch_id uuid NULL REFERENCES public.lead_batches(id) ON DELETE SET NULL,
  assigned_to uuid NULL REFERENCES public.users(id) ON DELETE SET NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT lead_contact_status_estado_check
    CHECK (estado_venta IN ('nuevo', 'no_contesta', 'seguimiento', 'rellamar', 'rechazo', 'dato_erroneo', 'venta'))
);

CREATE INDEX IF NOT EXISTS lead_contact_status_batch_idx
  ON public.lead_contact_status (batch_id);

CREATE INDEX IF NOT EXISTS lead_contact_status_assigned_idx
  ON public.lead_contact_status (assigned_to);

CREATE TABLE IF NOT EXISTS public.lead_management_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NOT NULL REFERENCES public.contacts(id) ON DELETE CASCADE,
  batch_id uuid NULL REFERENCES public.lead_batches(id) ON DELETE SET NULL,
  user_id uuid NULL REFERENCES public.users(id) ON DELETE SET NULL,
  resultado text NOT NULL,
  nota text,
  fecha_gestion timestamp without time zone NOT NULL DEFAULT now(),
  proxima_accion timestamp without time zone NULL,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  CONSTRAINT lead_management_resultado_check
    CHECK (resultado IN ('no_contesta', 'seguimiento', 'rellamar', 'rechazo', 'dato_erroneo', 'venta'))
);

CREATE INDEX IF NOT EXISTS lead_management_contact_idx
  ON public.lead_management_history (contact_id);

DROP TRIGGER IF EXISTS lead_batches_set_updated_at ON public.lead_batches;
CREATE TRIGGER lead_batches_set_updated_at
BEFORE UPDATE ON public.lead_batches
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS lead_batch_contacts_set_updated_at ON public.lead_batch_contacts;
CREATE TRIGGER lead_batch_contacts_set_updated_at
BEFORE UPDATE ON public.lead_batch_contacts
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS lead_contact_status_set_updated_at ON public.lead_contact_status;
CREATE TRIGGER lead_contact_status_set_updated_at
BEFORE UPDATE ON public.lead_contact_status
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- END 022_commercial_leads.sql

-- BEGIN 023_datos_para_trabajar.sql
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

-- END 023_datos_para_trabajar.sql

-- BEGIN 027_lead_status_catalog.sql
CREATE TABLE IF NOT EXISTS public.lead_status_catalog (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(50) UNIQUE NOT NULL,
  es_final BOOLEAN NOT NULL DEFAULT FALSE,
  libera_al_cerrar BOOLEAN NOT NULL DEFAULT FALSE
);

INSERT INTO public.lead_status_catalog (nombre, es_final, libera_al_cerrar)
VALUES
  ('nuevo', FALSE, FALSE),
  ('no_contesta', FALSE, TRUE),
  ('rellamar', FALSE, TRUE),
  ('seguimiento', TRUE, FALSE),
  ('rechazo', TRUE, FALSE),
  ('dato_erroneo', TRUE, FALSE),
  ('venta', TRUE, FALSE)
ON CONFLICT (nombre) DO UPDATE
SET
  es_final = EXCLUDED.es_final,
  libera_al_cerrar = EXCLUDED.libera_al_cerrar;

-- END 027_lead_status_catalog.sql

-- BEGIN 028_lead_agenda.sql
CREATE TABLE IF NOT EXISTS public.lead_agenda (
  id SERIAL PRIMARY KEY,
  contact_id uuid NOT NULL REFERENCES public.datos_para_trabajar(id) ON DELETE CASCADE,
  seller_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  batch_id uuid NOT NULL REFERENCES public.lead_batches(id) ON DELETE CASCADE,
  fecha_agenda timestamp without time zone NOT NULL,
  nota text,
  cumplida boolean NOT NULL DEFAULT false,
  created_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS lead_agenda_seller_fecha_idx
  ON public.lead_agenda (seller_id, fecha_agenda);

-- END 028_lead_agenda.sql

-- BEGIN 031_lead_batch_sellers.sql
CREATE TABLE IF NOT EXISTS public.lead_batch_sellers (
  id BIGSERIAL PRIMARY KEY,
  batch_id uuid NOT NULL REFERENCES public.lead_batches(id) ON DELETE CASCADE,
  seller_id uuid NOT NULL REFERENCES public.users(id),
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  UNIQUE (batch_id, seller_id)
);

CREATE INDEX IF NOT EXISTS lead_batch_sellers_batch_idx
  ON public.lead_batch_sellers (batch_id);

CREATE INDEX IF NOT EXISTS lead_batch_sellers_seller_idx
  ON public.lead_batch_sellers (seller_id);

-- END 031_lead_batch_sellers.sql

-- BEGIN 045_contact_product_baja_audit.sql
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

-- END 045_contact_product_baja_audit.sql

-- BEGIN 055_no_call_entries_audit.sql
CREATE TABLE IF NOT EXISTS public.no_call_entries_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  no_call_entry_id uuid NOT NULL REFERENCES public.no_call_entries(id) ON DELETE CASCADE,
  numero text NOT NULL,
  authorized_by uuid NOT NULL REFERENCES public.users(id),
  motivo text NOT NULL,
  organization_id uuid,
  created_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS no_call_entries_audit_numero_idx
  ON public.no_call_entries_audit (numero);

-- END 055_no_call_entries_audit.sql

