CREATE TABLE IF NOT EXISTS lead_coding_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  management_id uuid NOT NULL REFERENCES lead_management_history(id) ON DELETE CASCADE,
  contact_id uuid NOT NULL REFERENCES datos_para_trabajar(id) ON DELETE CASCADE,
  batch_id uuid NULL REFERENCES lead_batches(id) ON DELETE SET NULL,
  resultado_original text NOT NULL,
  resultado_corregido text NOT NULL,
  motivo text NULL,
  corrected_by uuid NOT NULL REFERENCES users(id),
  corrected_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS lead_coding_audit_management_idx
ON lead_coding_audit (management_id);

CREATE INDEX IF NOT EXISTS lead_coding_audit_contact_idx
ON lead_coding_audit (contact_id);

CREATE INDEX IF NOT EXISTS lead_coding_audit_corrected_at_desc_idx
ON lead_coding_audit (corrected_at DESC);

CREATE INDEX IF NOT EXISTS lead_coding_audit_corrected_by_idx
ON lead_coding_audit (corrected_by);

CREATE INDEX IF NOT EXISTS lead_coding_audit_management_corrected_at_desc_idx
ON lead_coding_audit (management_id, corrected_at DESC);
