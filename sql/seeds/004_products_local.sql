-- SOLO PARA LOCAL. No toca los productos existentes (varios con
-- organization_id NULL desde antes de la migracion 074 -- eso queda igual,
-- "solo hacia adelante"). Sin al menos un producto con organization_id
-- seteado, el paso "Productos" del wizard de alta manual queda vacio para
-- Rednacrem/Global Assist en local: listProducts() ya filtraba
-- incondicionalmente por organization_id (codigo preexistente, correcto
-- para produccion), y esa columna recien empezo a existir en local con 074.
--
-- Nombres nuevos (no pisa productos existentes -- products.nombre tiene un
-- indice unico GLOBAL en local, ver CLAUDE.md).

INSERT INTO public.products (nombre, categoria, precio, activo, organization_id)
SELECT v.nombre, 'General', v.precio, true, v.organization_id
FROM (
  VALUES
    ('Plan Básico Rednacrem (local)', 100::numeric, '9223d62d-f558-4f4c-b9bd-9dcea9888a0e'::uuid),
    ('Plan Básico Global Assist (local)', 100::numeric, 'b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8'::uuid)
) AS v(nombre, precio, organization_id)
WHERE EXISTS (SELECT 1 FROM public.organizations o WHERE o.id = v.organization_id)
  AND NOT EXISTS (SELECT 1 FROM public.products p WHERE lower(p.nombre) = lower(v.nombre))
ON CONFLICT DO NOTHING;
