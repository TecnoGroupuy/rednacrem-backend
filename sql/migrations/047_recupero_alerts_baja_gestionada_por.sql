ALTER TABLE contact_products
ADD COLUMN IF NOT EXISTS baja_gestionada_por uuid REFERENCES users(id);

CREATE TABLE IF NOT EXISTS recupero_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id uuid REFERENCES contacts(id),
  product_id uuid REFERENCES contact_products(id),
  seller_user_id uuid REFERENCES users(id),
  motivo_baja text,
  fecha_baja timestamptz DEFAULT now(),
  gestionado_por uuid REFERENCES users(id),
  atendido boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);
