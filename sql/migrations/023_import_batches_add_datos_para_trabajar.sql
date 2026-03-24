ALTER TABLE public.contact_import_batches
  DROP CONSTRAINT IF EXISTS contact_import_batches_type_check;

ALTER TABLE public.contact_import_batches
  ADD CONSTRAINT contact_import_batches_type_check
  CHECK (import_type IN ('clientes', 'no_llamar', 'resultados', 'datos_para_trabajar'));

