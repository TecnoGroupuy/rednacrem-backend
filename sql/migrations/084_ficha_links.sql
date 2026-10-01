-- Link corto para completar ficha (RRHH): reemplaza el token largo en la
-- URL que se comparte por WhatsApp/SMS (https://<dominio>/f/<codigo>, 8
-- caracteres) por POST /operaciones/personal/link-autocompletado. El
-- mecanismo viejo (token JWT-like firmado, query string ?token=) sigue
-- funcionando sin cambios para los links ya enviados antes de este cambio
-- -- esta tabla es un mecanismo ADICIONAL, no un reemplazo de
-- verifyFichaPublicaToken/generateFichaPublicaToken.
--
-- codigo es un string opaco (no autocontenido como el JWT viejo): la unica
-- forma de resolverlo a una organizacion es esta tabla, por eso no hace
-- falta firmar nada -- la fila en si misma es la fuente de verdad de
-- validez (revoked_at / expires_at).
--
-- created_by es un uuid SIN FK a proposito (regla del modulo de
-- Operaciones: nada fuera de su_*/organizations).
--
-- Esta migracion es NUEVA de punta a punta -- no existe nada de esto en
-- produccion todavia. Damian la corre a mano contra RDS; el agente no la
-- ejecuta contra produccion.

CREATE TABLE IF NOT EXISTS public.ficha_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  codigo text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_by uuid NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ficha_links_codigo_unique UNIQUE (codigo)
);

CREATE INDEX IF NOT EXISTS ficha_links_organization_id_idx
  ON public.ficha_links (organization_id);

-- Para el listado de "vigentes" (GET .../links-autocompletado): no vencido,
-- no revocado -- filtro parcial, el indice solo cubre las filas que ese
-- GET realmente consulta (la tabla crece indefinidamente, las filas viejas
-- vencidas/revocadas no necesitan estar en este indice).
CREATE INDEX IF NOT EXISTS ficha_links_vigentes_idx
  ON public.ficha_links (organization_id, expires_at)
  WHERE revoked_at IS NULL;
