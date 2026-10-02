-- Backfill de manual_ticket_closures.closed_by (migración 086) a partir de
-- un mapeo EXPLÍCITO usuario(texto) -> email, aprobado por Damián -- NO por
-- coincidencia automática de texto (el intento de matchear por
-- nombre+apellido/email solo resolvía 3 de 12 cierres, porque `usuario`
-- en producción guarda nomás el NOMBRE DE PILA).
--
-- 'Marcos' y 'Agente' quedan deliberadamente SIN resolver -- no hay forma
-- de determinar con certeza quién fue (y "Agente" es el texto genérico que
-- quedaba cuando el body no mandaba actorName, ver el fix de
-- closeManualTicket en index.mjs que ya no depende del body para esto).
-- closed_by sigue NULL para esos dos; la pestaña "Cerrados" los muestra
-- como "Sin identificar" y permite filtrar por ese estado.
--
-- users.email tiene constraint UNIQUE global (users_email_key) -- no hace
-- falta filtrar por organización para resolver el id.
--
-- Corrida: psql ... -f scripts/backfill_manual_ticket_closures_closed_by.sql
-- Termina en BEGIN sin COMMIT a propósito -- revisar la verificación del
-- final y commitear a mano (o ROLLBACK) según corresponda. Si falta
-- alguno de los 3 emails esperados, el DO $$ de abajo corta todo con
-- RAISE EXCEPTION antes de tocar ninguna fila.

BEGIN;

DO $$
DECLARE
  v_missing text;
BEGIN
  SELECT string_agg(expected.email, ', ')
  INTO v_missing
  FROM (VALUES
    ('prebollar@globalassist.com.uy'),
    ('personal@globalcontact.com.uy'),
    ('alencina@globalassist.com.uy')
  ) AS expected(email)
  WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.email = expected.email);

  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'Faltan usuarios por email, backfill cancelado sin tocar nada: %', v_missing;
  END IF;
END $$;

UPDATE manual_ticket_closures mc
SET closed_by = u.id
FROM users u
WHERE u.email = 'prebollar@globalassist.com.uy'
  AND btrim(mc.usuario) = 'Paola'
  AND mc.closed_by IS NULL;

UPDATE manual_ticket_closures mc
SET closed_by = u.id
FROM users u
WHERE u.email = 'personal@globalcontact.com.uy'
  AND btrim(mc.usuario) = 'Karen'
  AND mc.closed_by IS NULL;

UPDATE manual_ticket_closures mc
SET closed_by = u.id
FROM users u
WHERE u.email = 'alencina@globalassist.com.uy'
  AND btrim(mc.usuario) = 'Anthony'
  AND mc.closed_by IS NULL;

-- Verificación: cuántos cierres hay por cada texto de `usuario` y cuántos
-- de esos ya tienen closed_by. 'Marcos' y 'Agente' (y cualquier otro texto
-- no contemplado en el mapeo de arriba) tienen que quedar en 0 bajo
-- con_closed_by -- si alguno de los 3 mapeados no llega a su total
-- esperado, algo no matcheó como se esperaba y conviene ROLLBACK.
SELECT
  btrim(usuario) AS usuario,
  count(*) AS total_cierres,
  count(closed_by) AS con_closed_by
FROM manual_ticket_closures
GROUP BY btrim(usuario)
ORDER BY usuario;

-- Sin COMMIT: revisar el resultado de la verificación de arriba y decidir
-- COMMIT o ROLLBACK.
