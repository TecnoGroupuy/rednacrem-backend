-- Módulo "Retención" — un supervisor asigna un ticket de solicitud_baja a un
-- vendedor específico, que lo gestiona y lo cierra (retenido/baja_confirmada).
-- Con propósito real desde el arranque, a diferencia de la columna
-- assigned_to vieja que sacó la migración 065 por no tener ningún uso: acá
-- sí hay endpoints que la leen y la escriben (GET /manual-tickets con
-- ?unassigned=true/?assignedTo=, PUT /manual-tickets/:id, y el chequeo de
-- "solo el asignado puede cerrar" en closeManualTicket).
ALTER TABLE public.manual_tickets
  ADD COLUMN IF NOT EXISTS assigned_to uuid REFERENCES public.users(id);

CREATE INDEX IF NOT EXISTS manual_tickets_assigned_to_idx
  ON public.manual_tickets (assigned_to);
