ALTER TABLE public.contact_import_batches
ADD COLUMN IF NOT EXISTS report_products_detected integer NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS report_products_created integer NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS report_sellers_detected integer NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS report_payment_methods_detected integer NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS report_new_contacts integer NOT NULL DEFAULT 0;
