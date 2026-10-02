-- Carga de médicos facturadores de SU Emergencia (2026-10): su_personal
-- necesita un tercer tipo_personal, 'facturador' (factura por cuenta
-- propia, no tiene empresa_contratista_id como 'externo' ni es personal
-- directo de planta como 'interno').
--
-- Confirmado contra RDS producción (consulta corrida por Damián) --
-- existen DOS constraints que hoy solo contemplan interno/externo:
--   su_personal_tipo_personal_check: CHECK (tipo_personal = ANY (ARRAY['interno','externo']))
--   chk_personal_tipo_empresa: CHECK (
--     (tipo_personal = 'interno' AND empresa_contratista_id IS NULL)
--     OR (tipo_personal = 'externo' AND empresa_contratista_id IS NOT NULL)
--   )
-- Se reemplazan las DOS -- la segunda suma la rama
-- (tipo_personal = 'facturador' AND empresa_contratista_id IS NULL), mismo
-- comportamiento que 'interno' respecto a empresa_contratista_id.
--
-- Validado en local con BEGIN/ROLLBACK contra una réplica exacta de estas
-- dos constraints de prod (no existían en el schema local, que diverge de
-- prod en este punto): aplica limpio, las filas interno/externo existentes
-- siguen siendo válidas, un alta facturador sin empresa_contratista_id
-- pasa, un alta facturador CON empresa_contratista_id lo rechaza (mismo
-- chequeo cruzado que ya existe en index.mjs para interno/externo, ver
-- validatePersonalRegimenFijoFields / los handlers POST y PATCH
-- /operaciones/personal, actualizados en este mismo cambio).
--
-- DROP + ADD de ambas constraints: idempotente si ya se corrió.

ALTER TABLE su_personal DROP CONSTRAINT IF EXISTS su_personal_tipo_personal_check;
ALTER TABLE su_personal ADD CONSTRAINT su_personal_tipo_personal_check
  CHECK (tipo_personal = ANY (ARRAY['interno', 'externo', 'facturador']));

ALTER TABLE su_personal DROP CONSTRAINT IF EXISTS chk_personal_tipo_empresa;
ALTER TABLE su_personal ADD CONSTRAINT chk_personal_tipo_empresa CHECK (
  (tipo_personal = 'interno' AND empresa_contratista_id IS NULL)
  OR (tipo_personal = 'externo' AND empresa_contratista_id IS NOT NULL)
  OR (tipo_personal = 'facturador' AND empresa_contratista_id IS NULL)
);
