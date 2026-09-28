-- Diagnóstico de solo lectura — correr esto ANTES de aplicar
-- 067_recupero_prioritario_a_comun.sql. No modifica nada.
--
-- Contexto: Recupero pasa a ser un único acumulado de bajas (sin
-- segmentación Prioritario/Resto), así que el lote fijo del sistema
-- "Prioritario — 0 a 3 meses" deja de aprovisionarse. En producción ese
-- lote ya tiene candidatos y vendedores asignados, así que no se puede
-- borrar ni vaciar — la migración 067 lo pasa a lote común
-- (is_system_dataset = false), conservando todo su historial, para que
-- quede disponible en el flujo normal de "Finalizar" cuando el supervisor
-- decida cerrarlo.
--
-- Esta consulta muestra, por organización, cuántos candidatos tiene hoy ese
-- lote (agrupados por si tienen o no un vendedor asignado) y cuántos
-- vendedores distintos aparecen — tanto por recupero_candidatos.seller_id
-- (candidatos con gestión activa) como por el roster persistente
-- recupero_dataset_sellers (vendedores agregados al lote aunque no tengan
-- ningún candidato, ver migración 064) — para confirmar el impacto real
-- antes de tocar el flag.
SELECT
  rij.id AS dataset_id,
  rij.organization_id,
  o.nombre AS organization_nombre,
  rij.dataset_status,
  rij.is_system_dataset,
  COUNT(rc.id) AS candidatos_total,
  COUNT(rc.id) FILTER (WHERE rc.seller_id IS NOT NULL) AS candidatos_con_vendedor,
  COUNT(rc.id) FILTER (WHERE rc.seller_id IS NULL) AS candidatos_sin_vendedor,
  COUNT(DISTINCT rc.seller_id) AS vendedores_distintos_con_candidatos,
  (
    SELECT COUNT(DISTINCT rds.seller_id)
    FROM recupero_dataset_sellers rds
    WHERE rds.dataset_id = rij.id
  ) AS vendedores_en_roster
FROM recupero_import_jobs rij
JOIN organizations o ON o.id = rij.organization_id
LEFT JOIN recupero_candidatos rc ON rc.dataset_id = rij.id
WHERE rij.dataset_name = 'Prioritario — 0 a 3 meses'
  AND rij.is_system_dataset = true
GROUP BY rij.id, rij.organization_id, o.nombre, rij.dataset_status, rij.is_system_dataset
ORDER BY o.nombre;
