-- manual_ticket_notes y manual_ticket_closures tienen en producción el mismo
-- problema que manual_tickets (ver migración 065): las tablas ya existían
-- con un esquema de un sistema de tickets anterior antes de que este repo
-- las "creara" con CREATE TABLE IF NOT EXISTS (013_manual_ticket_notes y
-- 015_manual_ticket_closures), así que esas dos migraciones fueron un no-op
-- total contra ellas. Confirmado por Damián con \d contra RDS:
--
--   manual_ticket_notes:    tiene nota/created_by      -> el código espera autor/texto
--   manual_ticket_closures: tiene motivo/created_by    -> el código espera resultado/usuario/note
--
-- Consecuencia: GET /manual-tickets falla siempre con "column autor does not
-- exist" (getManualTicketsForOrganization / getManualTicketById, index.mjs),
-- y agregar una nota o cerrar un ticket manual falla igual por las mismas
-- columnas — no es una regresión, nunca funcionó contra este esquema real.
--
-- Confirmado contra RDS: ambas tablas tienen 0 filas, así que no hay nada
-- que migrar, resguardar ni backfillear — se lleva cada tabla directamente
-- al esquema que definen 013/015, igual que hizo 065 con manual_tickets.
--
-- nota/motivo/created_by no los lee ni los escribe ningún código (grep
-- completo sobre index.mjs y sobre el resto del repo backend antes de
-- escribir el DROP, cero referencias) — se eliminan sin resguardo.
--
-- created_at: en producción quedó como timestamp without time zone (el
-- esquema viejo lo tenía así), pero 013/015 lo definen timestamptz. Con 0
-- filas no hay datos que reinterpretar; el USING es solo para que el ALTER
-- sea válido sintácticamente.

ALTER TABLE public.manual_ticket_notes
  DROP COLUMN IF EXISTS nota,
  DROP COLUMN IF EXISTS created_by;

ALTER TABLE public.manual_ticket_notes
  ADD COLUMN IF NOT EXISTS autor text,
  ADD COLUMN IF NOT EXISTS texto text;

ALTER TABLE public.manual_ticket_notes
  ALTER COLUMN texto SET NOT NULL;

ALTER TABLE public.manual_ticket_notes
  ALTER COLUMN created_at TYPE timestamptz USING created_at AT TIME ZONE 'UTC';

CREATE INDEX IF NOT EXISTS manual_ticket_notes_ticket_id_idx
  ON public.manual_ticket_notes (ticket_id, created_at DESC);

ALTER TABLE public.manual_ticket_closures
  DROP COLUMN IF EXISTS motivo,
  DROP COLUMN IF EXISTS created_by;

ALTER TABLE public.manual_ticket_closures
  ADD COLUMN IF NOT EXISTS resultado text,
  ADD COLUMN IF NOT EXISTS usuario text,
  ADD COLUMN IF NOT EXISTS note text;

ALTER TABLE public.manual_ticket_closures
  ALTER COLUMN resultado SET NOT NULL;

ALTER TABLE public.manual_ticket_closures
  ALTER COLUMN created_at TYPE timestamptz USING created_at AT TIME ZONE 'UTC';

CREATE INDEX IF NOT EXISTS manual_ticket_closures_ticket_id_idx
  ON public.manual_ticket_closures (ticket_id, created_at DESC);
