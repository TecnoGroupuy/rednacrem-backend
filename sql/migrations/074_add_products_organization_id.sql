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
-- Aprobada por Damian para aplicar en LOCAL (para poder probar de punta a
-- punta el feature de vendedor/fecha de venta, que sin esto no arranca:
-- createProductAndSale ya filtraba products por organization_id de forma
-- incondicional). Sigue sin correr contra produccion -- eso lo hace Damian
-- si RDS todavia no tiene esta columna.
--
-- Solo agrega la columna (ADD COLUMN IF NOT EXISTS), sin FK ni NOT NULL,
-- pensada para ser no-op en produccion.

ALTER TABLE public.products
  ADD COLUMN IF NOT EXISTS organization_id uuid;
