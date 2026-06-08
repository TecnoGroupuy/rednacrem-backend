CREATE TABLE IF NOT EXISTS external_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid REFERENCES organizations(id),
  nombre text NOT NULL,
  url text NOT NULL,
  api_key text NOT NULL,
  activa boolean DEFAULT true,
  product_ids uuid[] DEFAULT '{}',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS external_connection_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  connection_id uuid REFERENCES external_connections(id),
  contact_id uuid REFERENCES contacts(id),
  payload jsonb,
  response_status int,
  response_body jsonb,
  error text,
  created_at timestamptz DEFAULT now()
);
