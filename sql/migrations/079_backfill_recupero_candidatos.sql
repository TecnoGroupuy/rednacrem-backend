-- BACKFILL, no migracion de esquema. NO aplicar en produccion de forma
-- automatica -- Damian la corre a mano en RDS: BEGIN; correr este archivo;
-- revisar las dos salidas de verificacion; COMMIT o ROLLBACK a mano segun
-- lo que vea. Validada en local con BEGIN/ROLLBACK antes de esto.
--
-- Cubre el bug de closeManualTicket (commit 6f07e8a): contact_products que
-- quedaron con estado='baja' sin que nunca se haya creado su fila en
-- recupero_candidatos. Diagnostico ya corrido por Damian contra RDS: 25
-- filas en ese estado (2 Global Assist por Retencion en 2026-09, 16 Global
-- Assist en 2026-05, 3 Global Assist en 2026-06, 4 Rednacrem sueltas en
-- 2026-04/08/09).
--
-- Replica EXACTAMENTE la logica de recupero_candidatos que ya tiene
-- aplicarBajaContactProduct en index.mjs (mismo dedup por
-- organization_id + (contact_id O documento+nombre+apellido normalizados)
-- con estado != 'recuperado', mismos valores, mismo
-- estado/estado_administrativo/resultado_gestion). A proposito NO toca
-- recupero_alerts (son avisos de bajas recientes, esto es historico) ni
-- contact_product_baja_audit (la funcion ya los hizo en su momento para
-- estas filas -- lo que faltaba era solo el alta en Recupero).
--
-- importado_por = contact_products.baja_gestionada_por (quien gestiono la
-- baja en su momento); NULL si esa columna quedo sin setear (bajas de
-- closeManualTicket antes de este fix, que no pasaba baja_gestionada_por).

BEGIN;

CREATE TEMP TABLE _bajas_candidatas AS
SELECT
  cp.id AS contact_product_id,
  cp.contact_id,
  cp.organization_id,
  cp.nombre_producto,
  cp.precio,
  cp.fecha_alta,
  -- contact_products no tiene columna medio_pago (ni en local ni en prod --
  -- ver docs/prod-schema/prod_columns.csv; aplicarBajaContactProduct ya la
  -- trata como NULL via deteccion dinamica de columnas). Se deja NULL igual
  -- que la funcion real.
  NULL::text AS medio_pago,
  cp.seller_name_snapshot,
  cp.fecha_baja,
  cp.motivo_baja,
  cp.motivo_baja_detalle,
  cp.baja_gestionada_por,
  c.nombre AS contacto_nombre,
  c.apellido AS contacto_apellido,
  c.documento AS contacto_documento,
  c.telefono AS contacto_telefono,
  c.celular AS contacto_celular,
  c.fecha_nacimiento AS contacto_fecha_nacimiento,
  c.departamento AS contacto_departamento,
  c.direccion AS contacto_direccion,
  regexp_replace(coalesce(c.documento, ''), '\D', '', 'g') AS documento_norm,
  lower(trim(coalesce(c.nombre, ''))) AS nombre_norm,
  lower(trim(coalesce(c.apellido, ''))) AS apellido_norm,
  EXISTS (
    SELECT 1 FROM manual_tickets mt
    WHERE mt.producto_contrato_id = cp.id
      AND mt.tipo_solicitud = 'solicitud_baja'
  ) AS via_retencion
FROM contact_products cp
JOIN contacts c ON c.id = cp.contact_id
WHERE cp.estado = 'baja'
  -- Guarda defensiva: recupero_candidatos.organization_id es NOT NULL. El
  -- diagnostico que corrio Damian contra RDS ya mostro las 25 filas
  -- agrupadas limpiamente por organizacion (Global Assist/Rednacrem, sin
  -- categoria "sin organizacion"), asi que esto no deberia excluir ninguna
  -- de las 25 reales -- es solo para no romper contra datos viejos con
  -- organization_id NULL (existen en local, de pruebas previas).
  AND cp.organization_id IS NOT NULL;

-- Candidato NO-recuperado mas reciente que matchea (misma regla que
-- aplicarBajaContactProduct: contact_id O documento+nombre+apellido
-- normalizados, misma organizacion, estado != 'recuperado').
CREATE TEMP TABLE _match_no_recuperado AS
SELECT DISTINCT ON (b.contact_product_id)
  b.contact_product_id,
  rc.id AS recupero_id
FROM _bajas_candidatas b
LEFT JOIN recupero_candidatos rc
  ON rc.organization_id = b.organization_id
 AND rc.estado != 'recuperado'
 AND (
   rc.contact_id = b.contact_id
   OR (
     b.documento_norm <> ''
     AND regexp_replace(coalesce(rc.documento, ''), '\D', '', 'g') = b.documento_norm
     AND lower(trim(coalesce(rc.nombre, ''))) = b.nombre_norm
     AND lower(trim(coalesce(rc.apellido, ''))) = b.apellido_norm
   )
 )
ORDER BY b.contact_product_id, rc.created_at DESC NULLS LAST;

-- Si NO matchea con uno no-recuperado, el candidato 'recuperado' mas
-- reciente que matchea igual (para el punto 4: churn repetido -- el unico
-- match es un candidato ya recuperado, que la regla real excluye del
-- dedup, asi que segun esa regla DEBERIA haber generado uno nuevo).
CREATE TEMP TABLE _match_recuperado AS
SELECT DISTINCT ON (b.contact_product_id)
  b.contact_product_id,
  rc.id AS recupero_id,
  rc.updated_at AS recuperado_en
FROM _bajas_candidatas b
JOIN _match_no_recuperado mnr
  ON mnr.contact_product_id = b.contact_product_id AND mnr.recupero_id IS NULL
LEFT JOIN recupero_candidatos rc
  ON rc.organization_id = b.organization_id
 AND rc.estado = 'recuperado'
 AND (
   rc.contact_id = b.contact_id
   OR (
     b.documento_norm <> ''
     AND regexp_replace(coalesce(rc.documento, ''), '\D', '', 'g') = b.documento_norm
     AND lower(trim(coalesce(rc.nombre, ''))) = b.nombre_norm
     AND lower(trim(coalesce(rc.apellido, ''))) = b.apellido_norm
   )
 )
ORDER BY b.contact_product_id, rc.updated_at DESC NULLS LAST;

-- Alcance de esta 079: SOLO las bajas sin NINGUN match (ni recuperado ni
-- no-recuperado) -- las 25 del diagnostico. Las que matchean solo con un
-- 'recuperado' se cuentan aparte mas abajo, sin insertar.
CREATE TEMP TABLE _a_insertar AS
SELECT b.*
FROM _bajas_candidatas b
JOIN _match_no_recuperado mnr
  ON mnr.contact_product_id = b.contact_product_id AND mnr.recupero_id IS NULL
JOIN _match_recuperado mr
  ON mr.contact_product_id = b.contact_product_id AND mr.recupero_id IS NULL;

-- Por si el diagnostico se re-corre mas adelante con datos nuevos: si
-- alguna baja SI matchea con un candidato no-recuperado, se revive (mismos
-- valores que aplicarBajaContactProduct) en vez de insertar uno nuevo. Para
-- las 25 actuales esta tabla queda vacia (todas son INSERT nuevo).
CREATE TEMP TABLE _a_revivir AS
SELECT b.*, mnr.recupero_id
FROM _bajas_candidatas b
JOIN _match_no_recuperado mnr
  ON mnr.contact_product_id = b.contact_product_id AND mnr.recupero_id IS NOT NULL;

UPDATE recupero_candidatos rc
SET
  nombre = a.contacto_nombre,
  apellido = a.contacto_apellido,
  documento = a.contacto_documento,
  telefono = a.contacto_telefono,
  celular = a.contacto_celular,
  fecha_nacimiento = a.contacto_fecha_nacimiento,
  departamento = a.contacto_departamento,
  direccion = a.contacto_direccion,
  producto_anterior = a.nombre_producto,
  precio_anterior = a.precio,
  fecha_venta = a.fecha_alta,
  medio_pago = a.medio_pago,
  vendedor_origen = a.seller_name_snapshot,
  fecha_baja = a.fecha_baja,
  motivo_baja = a.motivo_baja,
  motivo_baja_detalle = a.motivo_baja_detalle,
  contact_id = a.contact_id,
  requiere_revision = false,
  estado = 'disponible',
  estado_administrativo = 'activo',
  resultado_gestion = 'nuevo',
  seller_id = NULL,
  fecha_asignacion = NULL,
  updated_at = now()
FROM _a_revivir a
WHERE rc.id = a.recupero_id;

-- INSERT de las 25 (o las que correspondan si el diagnostico cambio).
WITH nuevos AS (
  INSERT INTO recupero_candidatos (
    organization_id, nombre, apellido, documento, telefono, celular,
    fecha_nacimiento, departamento, direccion, producto_anterior,
    precio_anterior, fecha_venta, medio_pago, vendedor_origen, fecha_baja,
    motivo_baja, motivo_baja_detalle, contact_id, requiere_revision,
    estado, estado_administrativo, resultado_gestion, importado_por,
    importado_at
  )
  SELECT
    organization_id, contacto_nombre, contacto_apellido, contacto_documento,
    contacto_telefono, contacto_celular, contacto_fecha_nacimiento,
    contacto_departamento, contacto_direccion, nombre_producto, precio,
    fecha_alta, medio_pago, seller_name_snapshot, fecha_baja, motivo_baja,
    motivo_baja_detalle, contact_id, false,
    'disponible', 'activo', 'nuevo', baja_gestionada_por, now()
  FROM _a_insertar
  RETURNING id, contact_id, organization_id, fecha_baja
)
-- ===== VERIFICACION 1: filas insertadas o revividas =====
SELECT
  'insertado' AS accion,
  o.nombre AS organizacion,
  b.contacto_nombre AS nombre,
  b.contacto_apellido AS apellido,
  b.contacto_documento AS documento,
  b.motivo_baja,
  b.fecha_baja,
  b.via_retencion AS cerrado_por_retencion,
  b.seller_name_snapshot AS vendedor_origen
FROM nuevos n
JOIN _a_insertar b ON b.contact_id = n.contact_id AND b.organization_id = n.organization_id AND b.fecha_baja IS NOT DISTINCT FROM n.fecha_baja
LEFT JOIN organizations o ON o.id = n.organization_id
UNION ALL
SELECT
  'revivido' AS accion,
  o.nombre,
  a.contacto_nombre,
  a.contacto_apellido,
  a.contacto_documento,
  a.motivo_baja,
  a.fecha_baja,
  a.via_retencion,
  a.seller_name_snapshot
FROM _a_revivir a
LEFT JOIN organizations o ON o.id = a.organization_id
ORDER BY organizacion, fecha_baja;

-- ===== VERIFICACION 2 (punto 4 del pedido): bajas cuyo UNICO match es un
-- candidato ya 'recuperado', con fecha_baja posterior a cuando se
-- recupero -- churn repetido que, segun la regla real (excluye
-- 'recuperado' del dedup), deberia haber generado un candidato nuevo y no
-- lo hizo. Se cuentan, NO se insertan -- decision de Damian. =====
SELECT
  count(*) AS bajas_con_unico_match_recuperado_y_fecha_baja_posterior
FROM _bajas_candidatas b
JOIN _match_no_recuperado mnr
  ON mnr.contact_product_id = b.contact_product_id AND mnr.recupero_id IS NULL
JOIN _match_recuperado mr
  ON mr.contact_product_id = b.contact_product_id AND mr.recupero_id IS NOT NULL
WHERE b.fecha_baja > mr.recuperado_en::date;

-- SIN COMMIT -- Damian revisa las dos verificaciones de arriba y decide.
