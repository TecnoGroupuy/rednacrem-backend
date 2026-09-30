-- Backfill de organization_id en lead_batches, datos_para_trabajar y
-- lead_contact_status (segunda ronda de fixes de POST /contacts). Origen de
-- los NULL: getFallbackBatch, insertLeadFromFields y linkLeadSaleFromPrincipal
-- no seteaban organization_id -- ya corregido en el commit a100b4e, que
-- todavia NO esta pusheado. Este backfill tiene que correr en producción
-- ANTES de pushear a100b4e (si no, el filtro estricto por organization_id
-- que trae ese commit ocultaria estas filas en vez de mostrarlas).
--
-- Basado en el diagnostico ya corrido contra RDS (no se reinterpreta aca):
--   datos_para_trabajar: 105 NULL (54 sin ningun camino; 23 via estado->
--     Rednacrem; 12 via contacto->Global Assist; 8 via contacto y estado->
--     Rednacrem; 6 via contacto->Rednacrem; 2 via estado->Global Assist; sin
--     conflictos).
--   lead_contact_status: 70 NULL (52 sin camino, colgados de lotes NULL; 12
--     via contacto del lead->Global Assist; 6->Rednacrem).
--   lead_batches: 7 NULL, los 7 son "Ventas manuales" de getFallbackBatch.
--
-- Estructura: BEGIN, pasos en orden, verificacion, SIN COMMIT -- lo hace
-- Damian a mano despues de revisar los numeros. Todos los UPDATE llevan
-- "AND organization_id IS NULL" (no se toca una fila que ya tiene org).

BEGIN;

-- ============================================================
-- PASO 1 -- lead_batches, por id explicito (los 7 NULL son "Ventas
-- manuales" de getFallbackBatch).
-- ============================================================

DO $$
DECLARE v_rows integer;
BEGIN
  UPDATE lead_batches
  SET organization_id = '9223d62d-f558-4f4c-b9bd-9dcea9888a0e' -- Rednacrem
  WHERE id IN (
    '1a8ecf2f-e71b-4860-b7d3-f931c0fce873',
    '5330c3b2-b504-4609-9e74-a4d5b6694733'
  )
  AND organization_id IS NULL;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RAISE NOTICE 'PASO 1 (lead_batches -> Rednacrem): % filas actualizadas', v_rows;
END $$;

DO $$
DECLARE v_rows integer;
BEGIN
  UPDATE lead_batches
  SET organization_id = 'b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8' -- Global Assist
  WHERE id IN (
    '855cd1f1-fd32-4b50-b446-6b9fc9fde660',
    '2fa5f7a4-9a0d-45fa-9ab8-2031d8924c25',
    '28c6f770-b383-4393-9b8f-24c8f540189b',
    '10c8d4ed-e737-4c13-936f-2d929e17d27f',
    '6a8ec688-d8e0-46d2-982a-c157c8cf40b5' -- lote mezclado, ver PASO 1b
  )
  AND organization_id IS NULL;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RAISE NOTICE 'PASO 1 (lead_batches -> Global Assist): % filas actualizadas', v_rows;
END $$;

-- ============================================================
-- PASO 1b -- lote mezclado 6a8ec688-d8e0-46d2-982a-c157c8cf40b5: 29 leads,
-- 28 de Global Assist (correcto, ya quedo con esa organization_id arriba) y
-- 1 de Rednacrem (se colo por el bug de getFallbackBatch sin filtro de
-- organizacion -- el vendedor del lote, Luciano Rodriguez
-- 99c47d03-ff98-4609-8a69-9d921fd27dc7, pertenece solo a Global Assist).
--
-- Se saca esa fila de lead_contact_status del lote por completo
-- (batch_id = NULL) y se le setea su propia organization_id = Rednacrem
-- directo, en vez de dejar que arrastre la organizacion del lote. Con esto,
-- los pasos 2b y 3b ya no necesitan excluir el lote: su organization_id
-- (Global Assist) ya es correcta para los otros 28 leads.
--
-- EXCEPCION DELIBERADA a "solo tocar organization_id IS NULL": en
-- produccion esa fila puntual YA tiene organization_id seteado (no NULL,
-- arrastrado del lote antes de este backfill) -- si el chequeo exigiera
-- IS NULL, el conteo daria 0 y el RAISE frenaria todo sin necesidad. Esta
-- es la UNICA fila de todo el backfill que se corrige sin ese filtro,
-- justamente porque esta identificada y validada por conteo exacto (1),
-- no por "esta en NULL". Si ya fuera Rednacrem, el UPDATE no le cambia el
-- valor; si tuviera otra cosa, la corrige. batch_id siempre pasa a NULL.
--
-- Chequeo de seguridad primero (sin efectos): tiene que ser EXACTAMENTE 1
-- fila. Si no, se corta todo con RAISE EXCEPTION antes de tocar nada.
-- ============================================================

DO $$
DECLARE v_count integer;
BEGIN
  SELECT count(*) INTO v_count
  FROM lead_contact_status lcs
  JOIN datos_para_trabajar dpt ON dpt.id = lcs.contact_id
  LEFT JOIN contacts c ON c.id = dpt.contact_id
  WHERE lcs.batch_id = '6a8ec688-d8e0-46d2-982a-c157c8cf40b5'
    AND COALESCE(dpt.organization_id, c.organization_id) = '9223d62d-f558-4f4c-b9bd-9dcea9888a0e';

  IF v_count <> 1 THEN
    RAISE EXCEPTION 'PASO 1b: se esperaba exactamente 1 fila de Rednacrem en el lote mezclado 6a8ec688, se encontraron %', v_count;
  END IF;
END $$;

-- Recien si el chequeo de arriba no exploto: mismo WHERE que el count
-- (sin tocar nada todavia), para que no puedan desalinearse. Se guardan
-- organization_id y batch_id PREVIOS en una tabla temporal (vive solo
-- dentro de esta transaccion), para poder mostrar antes/despues en la
-- verificacion del final.
CREATE TEMP TABLE tmp_paso1b_lead AS
SELECT
  lcs.contact_id AS lead_id,
  lcs.batch_id AS batch_id_previo,
  lcs.organization_id AS organization_id_previo
FROM lead_contact_status lcs
JOIN datos_para_trabajar dpt ON dpt.id = lcs.contact_id
LEFT JOIN contacts c ON c.id = dpt.contact_id
WHERE lcs.batch_id = '6a8ec688-d8e0-46d2-982a-c157c8cf40b5'
  AND COALESCE(dpt.organization_id, c.organization_id) = '9223d62d-f558-4f4c-b9bd-9dcea9888a0e';

-- El UPDATE matchea por el lead_id ya capturado en la tabla temporal (no
-- repite el WHERE de arriba) -- asi queda garantizado que toca exactamente
-- esa fila y ninguna otra, pase lo que pase con su organization_id actual.
DO $$
DECLARE v_rows integer;
BEGIN
  UPDATE lead_contact_status lcs
  SET batch_id = NULL,
      organization_id = '9223d62d-f558-4f4c-b9bd-9dcea9888a0e' -- Rednacrem
  FROM tmp_paso1b_lead t
  WHERE lcs.contact_id = t.lead_id;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RAISE NOTICE 'PASO 1b (lead_contact_status del lote mezclado -> Rednacrem, batch_id a NULL): % filas actualizadas', v_rows;
END $$;

-- ============================================================
-- PASO 2 -- datos_para_trabajar con organization_id NULL.
-- ============================================================

-- 2a) via contact_id -> contacts.organization_id.
DO $$
DECLARE v_rows integer;
BEGIN
  UPDATE datos_para_trabajar dpt
  SET organization_id = c.organization_id
  FROM contacts c
  WHERE c.id = dpt.contact_id
    AND dpt.organization_id IS NULL
    AND c.organization_id IS NOT NULL;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RAISE NOTICE 'PASO 2a (datos_para_trabajar via contacto): % filas actualizadas', v_rows;
END $$;

-- 2b) lo que quede: via lead_contact_status.batch_id -> lead_batches.organization_id
-- Y via lead_batch_contacts.batch_id -> lead_batches.organization_id. Se
-- combinan ambos caminos por lead y solo se actualiza si TODOS los caminos
-- disponibles coinciden en una unica organizacion (si hay mas de una
-- organizacion distinta entre los caminos, se deja NULL a proposito).
DO $$
DECLARE v_rows integer;
BEGIN
  WITH candidatos AS (
    SELECT dpt.id AS dpt_id, lb.organization_id AS org
    FROM datos_para_trabajar dpt
    JOIN lead_contact_status lcs ON lcs.contact_id = dpt.id
    JOIN lead_batches lb ON lb.id = lcs.batch_id
    WHERE dpt.organization_id IS NULL
      AND lb.organization_id IS NOT NULL

    UNION ALL

    SELECT dpt.id AS dpt_id, lb.organization_id AS org
    FROM datos_para_trabajar dpt
    JOIN lead_batch_contacts lbc ON lbc.contact_id = dpt.id
    JOIN lead_batches lb ON lb.id = lbc.batch_id
    WHERE dpt.organization_id IS NULL
      AND lb.organization_id IS NOT NULL
  ),
  resuelto AS (
    -- uuid no tiene MIN/MAX agregado -- (array_agg(org))[1] alcanza porque
    -- el HAVING ya garantiza que todos los org del grupo son iguales.
    SELECT dpt_id, (array_agg(org))[1] AS org
    FROM candidatos
    GROUP BY dpt_id
    HAVING COUNT(DISTINCT org) = 1
  )
  UPDATE datos_para_trabajar dpt
  SET organization_id = r.org
  FROM resuelto r
  WHERE r.dpt_id = dpt.id
    AND dpt.organization_id IS NULL;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RAISE NOTICE 'PASO 2b (datos_para_trabajar via lote, unica organizacion): % filas actualizadas', v_rows;
END $$;

-- ============================================================
-- PASO 3 -- lead_contact_status con organization_id NULL.
-- ============================================================

-- 3a) via su propio contact_id -> datos_para_trabajar.organization_id (la
-- organizacion del lead manda). Si el lote (via batch_id) tiene una
-- organizacion DISTINTA a la del lead, no se toca esa fila -- queda para
-- revision manual (ver el SELECT de conflictos en la verificacion).
DO $$
DECLARE v_rows integer;
BEGIN
  UPDATE lead_contact_status lcs
  SET organization_id = dpt.organization_id
  FROM datos_para_trabajar dpt
  WHERE dpt.id = lcs.contact_id
    AND lcs.organization_id IS NULL
    AND dpt.organization_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM lead_batches lb
      WHERE lb.id = lcs.batch_id
        AND lb.organization_id IS NOT NULL
        AND lb.organization_id <> dpt.organization_id
    );
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RAISE NOTICE 'PASO 3a (lead_contact_status via lead): % filas actualizadas', v_rows;
END $$;

-- 3b) lo que quede (el lead no tiene organizacion resuelta): via batch_id ->
-- lead_batches.organization_id. Las filas dejadas afuera a proposito por
-- conflicto en 3a (lead con organizacion distinta a la del lote) tambien
-- quedan afuera de este paso -- un conflicto ya detectado no se resuelve
-- "de rebote" por el lado del lote.
DO $$
DECLARE v_rows integer;
BEGIN
  UPDATE lead_contact_status lcs
  SET organization_id = lb.organization_id
  FROM lead_batches lb
  WHERE lb.id = lcs.batch_id
    AND lcs.organization_id IS NULL
    AND lb.organization_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM datos_para_trabajar dpt
      WHERE dpt.id = lcs.contact_id
        AND dpt.organization_id IS NOT NULL
        AND dpt.organization_id <> lb.organization_id
    );
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RAISE NOTICE 'PASO 3b (lead_contact_status via lote): % filas actualizadas', v_rows;
END $$;

-- ============================================================
-- VERIFICACIÓN (solo lectura, no modifica nada más)
-- ============================================================

-- NULLs restantes por tabla.
SELECT 'lead_batches' AS tabla, count(*) AS nulls_restantes FROM lead_batches WHERE organization_id IS NULL
UNION ALL
SELECT 'datos_para_trabajar', count(*) FROM datos_para_trabajar WHERE organization_id IS NULL
UNION ALL
SELECT 'lead_contact_status', count(*) FROM lead_contact_status WHERE organization_id IS NULL;

-- datos_para_trabajar que sigue en NULL: cantidad y rango de created_at
-- (esperado: la mayoría de los 54 "sin ningún camino").
SELECT count(*) AS cantidad, min(created_at) AS desde, max(created_at) AS hasta
FROM datos_para_trabajar
WHERE organization_id IS NULL;

-- Filas excluidas por conflicto en el PASO 3a (lead con organizacion
-- resuelta, pero el lote asociado tiene una organizacion DISTINTA -- no se
-- tocaron, quedan en NULL a proposito).
SELECT
  lcs.contact_id AS lead_id,
  lcs.batch_id,
  dpt.organization_id AS lead_org,
  lb.organization_id AS batch_org
FROM lead_contact_status lcs
JOIN datos_para_trabajar dpt ON dpt.id = lcs.contact_id
JOIN lead_batches lb ON lb.id = lcs.batch_id
WHERE lcs.organization_id IS NULL
  AND dpt.organization_id IS NOT NULL
  AND lb.organization_id IS NOT NULL
  AND lb.organization_id <> dpt.organization_id;

-- Detalle de la fila del PASO 1b: lead, quien la tenia asignada, y el
-- antes/despues de organization_id y batch_id (para confirmar a ojo que el
-- unico cambio real es el batch_id a NULL cuando organization_id ya era
-- Rednacrem).
SELECT
  dpt.id AS lead_id,
  dpt.nombre,
  dpt.apellido,
  dpt.documento,
  lcs.estado_venta,
  t.organization_id_previo,
  lcs.organization_id AS organization_id_nuevo,
  t.batch_id_previo,
  lcs.batch_id AS batch_id_nuevo_deberia_ser_null,
  lcs.assigned_to,
  u.nombre || ' ' || u.apellido AS assigned_to_nombre
FROM tmp_paso1b_lead t
JOIN datos_para_trabajar dpt ON dpt.id = t.lead_id
JOIN lead_contact_status lcs ON lcs.contact_id = t.lead_id
LEFT JOIN users u ON u.id = lcs.assigned_to;

-- Sales de ese mismo contacto en Rednacrem, con su seller.
SELECT
  s.id AS sale_id,
  s.fecha,
  s.organization_id,
  s.medio_pago,
  s.seller_id,
  su.nombre || ' ' || su.apellido AS seller_nombre
FROM tmp_paso1b_lead t
JOIN datos_para_trabajar dpt ON dpt.id = t.lead_id
JOIN sales s ON s.contact_id = dpt.contact_id
LEFT JOIN users su ON su.id = s.seller_id
ORDER BY s.fecha;

-- Sin COMMIT a proposito -- revisar todo lo de arriba y confirmar a mano
-- con COMMIT; (o ROLLBACK; si algo no cierra).
