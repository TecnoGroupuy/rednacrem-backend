ALTER TABLE public.contact_import_batches
ADD COLUMN IF NOT EXISTS rejected_missing_documento integer NOT NULL DEFAULT 0;
