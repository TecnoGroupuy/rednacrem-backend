INSERT INTO roles (key, label, priority, is_active)
VALUES
  ('superadministrador', 'Superadministrador', 100, TRUE),
  ('director', 'Director', 90, TRUE),
  ('supervisor', 'Supervisor', 80, TRUE),
  ('operaciones', 'Operaciones', 70, TRUE),
  ('vendedor', 'Vendedor', 60, TRUE),
  ('atencion_cliente', 'Atencion al cliente', 50, TRUE)
ON CONFLICT (key) DO UPDATE
SET
  label = EXCLUDED.label,
  priority = EXCLUDED.priority,
  is_active = EXCLUDED.is_active,
  updated_at = NOW();