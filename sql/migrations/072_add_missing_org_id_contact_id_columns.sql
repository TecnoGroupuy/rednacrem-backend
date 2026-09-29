-- Alinea el esquema local con columnas que ya existen en produccion (ver
-- PASO 0 de la segunda ronda de fixes de POST /contacts, confirmado por
-- Damian contra RDS). Sin estas 3 columnas, las ramas hasContactIdCol /
-- hasContactProductOrgId / (sales) organizationId de index.mjs que SI
-- corren en produccion nunca se ejercitaban en pruebas locales.
--
-- Solo agrega columnas (ADD COLUMN IF NOT EXISTS), sin FK ni NOT NULL --
-- exactamente lo que hace falta para poder probar en local el mismo
-- camino de codigo que produccion, sin inventar constraints que
-- produccion no tiene. No-op en produccion (las 3 columnas ya existen
-- ahi).
--
--   sales.organization_id            uuid, nullable
--   contact_products.organization_id uuid, nullable
--   datos_para_trabajar.contact_id   uuid, nullable
--     (guarda el id de contacts -- confirmado via sales.contact_id_fkey /
--     contact_products.contact_id_fkey, que SI referencian contacts(id);
--     lead_contact_status.contact_id es un caso aparte, ese referencia
--     datos_para_trabajar(id), no contacts(id))

ALTER TABLE public.sales
  ADD COLUMN IF NOT EXISTS organization_id uuid;

ALTER TABLE public.contact_products
  ADD COLUMN IF NOT EXISTS organization_id uuid;

ALTER TABLE public.datos_para_trabajar
  ADD COLUMN IF NOT EXISTS contact_id uuid;
