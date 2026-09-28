-- Recupero pasa a ser un único acumulado de bajas (sin segmentación
-- Prioritario/Resto, ver módulo "Retención" que ahora cubre ese caso de uso
-- para contratos todavía de alta). El lote fijo del sistema
-- "Prioritario — 0 a 3 meses" deja de aprovisionarse (ensureRecuperoSystemDatasets
-- en index.mjs ya solo crea "General de recupero" para organizaciones
-- nuevas).
--
-- En producción ese lote ya tiene candidatos y vendedores asignados (correr
-- 067_recupero_prioritario_a_comun_diagnostico.sql antes de esto para ver el
-- impacto exacto por organización) — no se puede borrar ni vaciar. En vez
-- de eso, se lo pasa a lote común (is_system_dataset = false): conserva
-- datos, vendedores e historial intactos, y a partir de ahí sigue el ciclo
-- de vida normal de un lote común, incluido el flujo de "Finalizar" ya
-- existente (mueve los candidatos no terminales a "General de recupero")
-- para cuando el supervisor decida cerrarlo.
--
-- Seguro contra el índice recupero_import_jobs_system_dataset_unique_idx
-- (migración 061): es un índice único PARCIAL (WHERE is_system_dataset =
-- true) sobre (organization_id, dataset_name) — al pasar la fila a false
-- deja de participar en ese índice, no hay conflicto posible.
--
-- Idempotente: si ya se corrió (o si el lote no existe en una organización
-- dada), el UPDATE no encuentra filas y no hace nada.
UPDATE public.recupero_import_jobs
SET is_system_dataset = false,
    updated_at = NOW()
WHERE dataset_name = 'Prioritario — 0 a 3 meses'
  AND is_system_dataset = true;
