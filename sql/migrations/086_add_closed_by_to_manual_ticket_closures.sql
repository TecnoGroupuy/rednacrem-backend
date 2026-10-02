-- Tab "Cerrados" de Retención (auditoría 2026-10): manual_ticket_closures
-- no tiene forma confiable de filtrar por quién cerró un ticket --
-- `usuario` es texto libre (nombre tal cual lo mandó el cliente al cerrar,
-- ver fix en index.mjs closeManualTicket), no un id. Se agrega closed_by
-- (uuid, FK a users) para poder filtrar/mostrar de forma confiable.
--
-- Nullable: las filas históricas no la tienen hasta correr el backfill
-- (scripts/backfill_manual_ticket_closures_closed_by.mjs, con mapeo
-- explícito por email aprobado por Damián -- no por coincidencia de texto).
--
-- Orden de deploy acordado: esta migración y su backfill corren en prod
-- ANTES del push del backend -- el código nuevo de closeManualTicket
-- escribe closed_by en cada cierre nuevo, así que la columna tiene que
-- existir primero.
--
-- IF NOT EXISTS: idempotente si ya se corrió.

ALTER TABLE manual_ticket_closures
  ADD COLUMN IF NOT EXISTS closed_by uuid REFERENCES users(id);

CREATE INDEX IF NOT EXISTS manual_ticket_closures_closed_by_idx
  ON manual_ticket_closures (closed_by);
