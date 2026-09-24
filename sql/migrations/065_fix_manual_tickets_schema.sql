-- manual_tickets en producción nunca tuvo el esquema que el código espera.
-- Diagnóstico completo (sesión de auditoría de Atención al cliente, ver
-- hallazgo confirmado por Damián contra RDS): la tabla real tenía columnas
-- de un sistema de tickets genérico anterior (titulo, descripcion, estado
-- default 'abierto', created_by, assigned_to) que no está en el historial
-- de este repo — no se sabe de dónde salió. La migración 012_manual_tickets
-- que "crea" el esquema nuevo usa CREATE TABLE IF NOT EXISTS, así que contra
-- esa tabla vieja ya existente fue un no-op total desde el primer deploy:
-- nunca agregó cliente_id/tipo_solicitud/tipo_solicitud_manual/resumen/
-- producto_contrato_id, que es exactamente lo que el INSERT de
-- createManualTicket() (index.mjs) necesita. Solo las migraciones 014 y 016
-- (ALTER TABLE ADD COLUMN IF NOT EXISTS, sobre cualquier tabla que ya
-- existiera) lograron pegar numero y service_request.
--
-- Resultado: crear o editar un ticket (POST/PUT /manual-tickets) falla
-- siempre con "column ... does not exist" — nunca funcionó, no es una
-- regresión. Confirmado contra RDS: la tabla tiene 0 filas, tanto del
-- esquema viejo como del nuevo, así que no hay ningún dato real que migrar,
-- resguardar ni backfillear. Es seguro llevar la tabla directamente al
-- esquema que define 012, sin pasos intermedios.
--
-- Las columnas viejas (titulo, descripcion, created_by, assigned_to) se
-- eliminan porque ningún código las lee ni las escribe — confirmado de
-- nuevo en esta tarea (grep sobre todo index.mjs y sobre el resto del
-- repo backend, cero referencias) antes de escribir el DROP.
--
-- titulo era NOT NULL en la tabla vieja y el código nunca lo completa —
-- eliminar la columna se lleva puesta esa restricción de paso, así que no
-- hace falta un ALTER aparte para eso.

ALTER TABLE public.manual_tickets
  DROP COLUMN IF EXISTS titulo,
  DROP COLUMN IF EXISTS descripcion,
  DROP COLUMN IF EXISTS created_by,
  DROP COLUMN IF EXISTS assigned_to;

-- created_at/updated_at: no confirmados como ya presentes en producción
-- (la comparación de columnas de Damián no los mencionó explícitamente) —
-- IF NOT EXISTS los deja como no-op si ya estaban, y los crea si no.
ALTER TABLE public.manual_tickets
  ADD COLUMN IF NOT EXISTS cliente_id uuid REFERENCES public.contacts(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS tipo_solicitud text,
  ADD COLUMN IF NOT EXISTS tipo_solicitud_manual text,
  ADD COLUMN IF NOT EXISTS resumen text,
  ADD COLUMN IF NOT EXISTS producto_contrato_id uuid NULL,
  ADD COLUMN IF NOT EXISTS created_at timestamp without time zone NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at timestamp without time zone NOT NULL DEFAULT now();

-- cliente_id/tipo_solicitud/resumen deben ser NOT NULL (igual que en 012),
-- pero ADD COLUMN ... NOT NULL sin DEFAULT falla si la tabla ya tuviera
-- filas. Con 0 filas confirmadas no hace falta ese resguardo, pero se
-- separa en un segundo ALTER para que sea explícito y no dependa de que
-- ADD COLUMN y SET NOT NULL se acepten juntos en la misma cláusula.
ALTER TABLE public.manual_tickets
  ALTER COLUMN cliente_id SET NOT NULL,
  ALTER COLUMN tipo_solicitud SET NOT NULL,
  ALTER COLUMN resumen SET NOT NULL;

-- estado: la tabla vieja tenía default 'abierto', que no es uno de los tres
-- valores que valida el backend (validateManualTicketPayload /
-- normalizeManualTicketPatch, index.mjs) ni que la migración 012 original
-- definía. Se corrige el default y se agrega el CHECK que 012 nunca llegó
-- a aplicar contra esta tabla.
ALTER TABLE public.manual_tickets
  ALTER COLUMN estado SET DEFAULT 'nueva';

ALTER TABLE public.manual_tickets
  DROP CONSTRAINT IF EXISTS manual_tickets_estado_check;
ALTER TABLE public.manual_tickets
  ADD CONSTRAINT manual_tickets_estado_check
  CHECK (estado IN ('nueva', 'en_proceso', 'finalizada'));

ALTER TABLE public.manual_tickets
  ALTER COLUMN prioridad SET DEFAULT 'media';

ALTER TABLE public.manual_tickets
  DROP CONSTRAINT IF EXISTS manual_tickets_prioridad_check;
ALTER TABLE public.manual_tickets
  ADD CONSTRAINT manual_tickets_prioridad_check
  CHECK (prioridad IN ('baja', 'media', 'alta'));

CREATE INDEX IF NOT EXISTS manual_tickets_cliente_id_idx
  ON public.manual_tickets (cliente_id, created_at DESC);

CREATE INDEX IF NOT EXISTS manual_tickets_producto_contrato_id_idx
  ON public.manual_tickets (producto_contrato_id);

-- Mismo trigger que define 012 — si ya existía (poco probable dado que
-- CREATE TABLE fue no-op, pero el resto del archivo pudo haber corrido
-- parcialmente) esto lo deja en el mismo estado sin duplicar.
DROP TRIGGER IF EXISTS manual_tickets_set_updated_at ON public.manual_tickets;
CREATE TRIGGER manual_tickets_set_updated_at
BEFORE UPDATE ON public.manual_tickets
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
