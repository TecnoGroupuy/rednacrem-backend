-- Alinea los indices de contacts.documento y contacts.email del entorno
-- local con los que ya existen en produccion (ver Punto E, segunda ronda
-- de fixes de POST /contacts). Local tenia ambos como UNIQUE GLOBAL
-- (heredado de una version mas vieja del esquema):
--   - contacts_documento_unique_idx  UNIQUE (documento)
--   - contacts_email_unique_idx      UNIQUE (lower(email))
-- lo que bloqueaba dar de alta a la misma persona (mismo documento o email)
-- en mas de una organizacion -- exactamente el escenario real de "cliente
-- de Global Assist que tambien es cliente de Rednacrem".
--
-- Definiciones exactas de produccion (confirmadas por Damian contra RDS):
--   idx_contacts_documento:
--     CREATE INDEX ... ON public.contacts USING btree (documento)
--     WHERE ((documento IS NOT NULL) AND (documento <> ''::text))
--   contacts_email_org_unique_idx:
--     CREATE UNIQUE INDEX ... ON public.contacts USING btree (organization_id, lower(email))
--     WHERE ((email IS NOT NULL) AND (btrim(email) <> ''::text))
-- Notar que el WHERE de documento usa documento <> '' (sin btrim), a
-- diferencia del de email que si usa btrim -- se respeta la diferencia tal
-- cual esta en produccion, no se normaliza a un criterio comun.
--
-- En produccion no existen contacts_documento_unique_idx ni
-- contacts_email_unique_idx bajo esos nombres, asi que los DROP de abajo
-- son no-op ahi. Esta migracion es idempotente y pensada para ser un
-- no-op completo en produccion (los indices objetivo ya existen ahi con
-- estos nombres y definiciones exactas). Se corre en LOCAL para poder
-- probar el flujo multi-organizacion tal como se comporta en produccion
-- -- no se aplico todavia, queda pendiente de aprobacion explicita antes
-- de correrla en cualquier entorno.

DROP INDEX IF EXISTS public.contacts_documento_unique_idx;

CREATE INDEX IF NOT EXISTS idx_contacts_documento
  ON public.contacts (documento)
  WHERE documento IS NOT NULL AND documento <> '';

DROP INDEX IF EXISTS public.contacts_email_unique_idx;

CREATE UNIQUE INDEX IF NOT EXISTS contacts_email_org_unique_idx
  ON public.contacts (organization_id, lower(email))
  WHERE email IS NOT NULL AND btrim(email) <> '';
