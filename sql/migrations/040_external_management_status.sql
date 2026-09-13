CREATE TABLE IF NOT EXISTS external_management_status (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid NULL REFERENCES contacts(id) ON DELETE SET NULL,
  documento text NULL,
  estado_raw text NULL,
  estado_normalizado text NULL,
  motivo_baja text NULL,
  fuente text NOT NULL DEFAULT 'csv',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS external_management_status_documento_uidx
ON external_management_status (documento);

CREATE INDEX IF NOT EXISTS external_management_status_contact_idx
ON external_management_status (contact_id);

CREATE INDEX IF NOT EXISTS external_management_status_updated_at_idx
ON external_management_status (updated_at DESC);
