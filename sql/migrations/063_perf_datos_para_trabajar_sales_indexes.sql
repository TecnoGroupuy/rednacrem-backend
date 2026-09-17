-- Incidente de rendimiento del 17/09 — ráfaga de consultas lentas contra
-- rednacrem-db (wait_event DataFileRead/BufferIo, 20-70+s por consulta,
-- saturación visible en "Carga de base de datos" de RDS). La consulta
-- disparadora, entre otras, era la de "manual_ventas" de
-- GET /api/supervisor/sellers-summary:
--
--   SELECT s.seller_user_id AS user_id, lb.tipo, COUNT(*)::int AS manual_ventas
--   FROM sales s
--   JOIN contacts c ON c.id = s.contact_id
--   JOIN datos_para_trabajar d ON d.contact_id = c.id
--   JOIN lead_contact_status lcs ON lcs.contact_id = d.id
--   JOIN lead_batches lb ON lb.id = lcs.batch_id
--   WHERE s.seller_user_id = ANY($1::uuid[])
--     AND (COALESCE(s.fecha_venta, s.created_at) AT TIME ZONE 'America/Montevideo')::date = $2::date
--     AND lb.organization_id = $3
--   GROUP BY s.seller_user_id, lb.tipo
--
-- Con EXPLAIN (ANALYZE, BUFFERS) real contra producción, el costo bajó de
-- 17.669 a 3.017 (sin Seq Scan en ningún punto del plan) después de crear
-- estos dos índices. Se crearon ya directamente por psql contra producción
-- durante el incidente (no corriendo este archivo) — esta migración solo
-- deja registrado en el repo lo que efectivamente se aplicó, con
-- IF NOT EXISTS para que correrla ahí no falle ni reintente construirlos.
--
-- Nota: la primera versión de este archivo proponía un índice sobre
-- lead_management_history(user_id, fecha_gestion) en base a un análisis
-- estructural hecho ANTES de tener el EXPLAIN real — resultó innecesario:
-- esa tabla ya tenía lead_management_history_user_fecha_gestion_desc_idx,
-- confirmado contra producción. Se reemplaza por los dos índices que
-- realmente resolvieron el incidente.
--
-- CONCURRENTLY porque en su momento se aplicaron con la base en vivo bajo
-- incidente — no tomar un lock que bloquee escrituras mientras se
-- construye el índice. No correr esto dentro de una transacción
-- (CONCURRENTLY no lo permite).
CREATE INDEX CONCURRENTLY IF NOT EXISTS datos_para_trabajar_contact_id_idx
  ON public.datos_para_trabajar (contact_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS sales_seller_user_id_fecha_venta_idx
  ON public.sales (seller_user_id, fecha_venta);
