-- Divergencia NUEVA, encontrada al probar el codigo del Punto A/B (segunda
-- ronda de fixes de POST /contacts) con la migracion 072 aplicada en local:
-- local.products NO tiene organization_id, a diferencia de produccion.
--
-- Evidencia de que produccion SI la tiene: el codigo pre-existente de
-- createProductAndSale ya hace
--   INSERT INTO products (nombre, categoria, precio, activo, organization_id)
-- de forma INCONDICIONAL (sin gatear por metadata de columna) -- si
-- production.products no tuviera esa columna, esa insercion fallaria
-- siempre en produccion, lo cual contradice que el alta de "Nuevo cliente"
-- ya funciona ahi (el caso real de Patricia, primer contacto exitoso).
--
-- No confirmado todavia contra RDS -- a diferencia de las migraciones
-- 071/072, esta todavia no tiene el visto bueno de Damian. NO aplicar en
-- ningun entorno (ni local) hasta que lo confirme.
--
-- Solo agrega la columna (ADD COLUMN IF NOT EXISTS), sin FK ni NOT NULL,
-- pensada para ser no-op en produccion.

ALTER TABLE public.products
  ADD COLUMN IF NOT EXISTS organization_id uuid;
