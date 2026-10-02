-- ============================================================
-- YA APLICADO EN PRODUCCIÓN (2026-10, COMMIT confirmado por Damián) --
-- los 26 médicos ya están cargados en su_personal/su_personal_roles,
-- con un INSERT equivalente al de este archivo (corrido a mano, no este
-- script literal). NO VOLVER A CORRER: reinsertaría los 26 duplicados,
-- la query de duplicados de la auditoría original ya no aplica (ahora SÍ
-- existen en su_personal). Se deja el archivo como referencia histórica
-- de qué se cargó y cómo se validó (dígito verificador, formato de
-- documento, la excepción de Ramón Ávila).
-- ============================================================
--
-- Carga de 26 médicos facturadores de SU Emergencia (2026-10).
--
-- Solo nombre, apellido, documento, tipo_personal='facturador' (requiere
-- la migración 087 ya aplicada -- CHECK su_personal_tipo_personal_check /
-- chk_personal_tipo_empresa) y estado='activo'. El resto de los campos de
-- su_personal queda vacío: cada médico lo completa desde el link de
-- autocompletado (fix del fecha_nacimiento NULL incluido en este mismo
-- deploy, ver index.mjs). Rol 'Medico' como rol principal en
-- su_personal_roles.
--
-- DOCUMENTO: 8 dígitos (BASE + dígito verificador), sin guion -- es el
-- formato confirmado contra RDS producción y el que exige el link público
-- (CompletarFichaScreen.jsx manda el documento con onlyDigits(), los 8
-- dígitos tal cual, sin separador).
--
-- DUPLICADOS: verificado contra RDS producción antes de este script (0
-- coincidencias en su_personal de SU Emergencia, con y sin guion, con y
-- sin dígito verificador) -- los 26 son altas nuevas.
--
-- DÍGITO VERIFICADOR: validado contra el algoritmo uruguayo (pesos
-- 2,9,8,7,6,3,4 sobre la base de 7 dígitos) ANTES de insertar nada -- el
-- DO $$ de abajo corta todo con RAISE EXCEPTION si encuentra una cédula
-- inválida que no sea la excepción documentada.
--
-- EXCEPCIÓN DOCUMENTADA: Ramón Ávila, 66116189 -- el dígito verificador
-- correcto para la base 6611618 sería 8 (66116188), pero la planilla
-- original trae 9. Se carga TAL CUAL figura en la planilla (decisión de
-- Damián) -- queda marcado aparte en la verificación del final para que
-- quede visible que es un caso conocido, no un error de carga.
--
-- Corrida: BEGIN sin COMMIT -- revisar el SELECT de verificación del final
-- y commitear a mano (o ROLLBACK).
--
-- Orden de deploy acordado: esta carga corre DESPUÉS de la migración 087 y
-- del push del backend/frontend (el código nuevo ya tiene que estar en
-- producción para que el link de autocompletado funcione con
-- fecha_nacimiento NULL).

BEGIN;

DO $$
DECLARE
  r RECORD;
  v_sum int;
  v_expected int;
  v_errores text := '';
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('Alejandra','Schettini','2021164','3'),
      ('Alexis','Olivo Izquiel','6401440','9'),
      ('Ana Isabel','Nuñez','6562328','5'),
      ('Arasay','Garcia','6350369','9'),
      ('Edwin','Cañon','6308168','9'),
      ('Elbis','Azaharez Rodríguez','6579371','1'),
      ('Enmanuel','Samon','6611616','6'),
      ('Florencia','Abelenda','4951161','6'),
      ('Gisela','Garcia','6621344','5'),
      ('Johanna','Pintos','5792903','5'),
      ('Laura','Atria','6546352','8'),
      ('Lisset','Batista','6586579','0'),
      ('Liset','Pereda','6581900','8'),
      ('Luis Alberto','Cintra','6437194','0'),
      ('Marek','Viamonte Guerra','6559243','4'),
      ('Maydel','López','6450219','1'),
      ('Ramon','Avila','6611618','9'),
      ('Reynier','Teleña','6586569','3'),
      ('Virginia','Bermolen','4666602','4'),
      ('Yaima','Cordova','6579369','2'),
      ('Yonney','Llorente','6368607','3'),
      ('Yuniel','Mas','6621102','7'),
      ('Yoansy','Bello','6600496','9'),
      ('Yariel','Del Valle','6595064','2'),
      ('Lisandra','Gonzalez','6708550','4'),
      ('Jeiler','Sanchez','6577332','3')
    ) AS t(nombre, apellido, base, dv)
  LOOP
    v_sum :=
        substring(r.base from 1 for 1)::int * 2
      + substring(r.base from 2 for 1)::int * 9
      + substring(r.base from 3 for 1)::int * 8
      + substring(r.base from 4 for 1)::int * 7
      + substring(r.base from 5 for 1)::int * 6
      + substring(r.base from 6 for 1)::int * 3
      + substring(r.base from 7 for 1)::int * 4;
    v_expected := CASE WHEN v_sum % 10 = 0 THEN 0 ELSE 10 - (v_sum % 10) END;

    IF v_expected <> r.dv::int THEN
      IF r.nombre = 'Ramon' AND r.apellido = 'Avila' AND r.base = '6611618' AND r.dv = '9' THEN
        RAISE NOTICE 'Excepción documentada: Ramón Ávila, cédula %-% (correcto sería %-%), se carga tal cual figura en la planilla.', r.base, r.dv, r.base, v_expected;
      ELSE
        v_errores := v_errores || format('%s %s: cédula %s-%s inválida (dígito correcto: %s). ', r.nombre, r.apellido, r.base, r.dv, v_expected);
      END IF;
    END IF;
  END LOOP;

  IF v_errores <> '' THEN
    RAISE EXCEPTION 'Cédulas con dígito verificador inválido, carga cancelada sin tocar nada: %', v_errores;
  END IF;
END $$;

WITH nuevos AS (
  INSERT INTO su_personal (organization_id, nombre, apellido, documento, tipo_personal, estado)
  VALUES
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Alejandra', 'Schettini', '20211643', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Alexis', 'Olivo Izquiel', '64014409', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Ana Isabel', 'Nuñez', '65623285', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Arasay', 'Garcia', '63503699', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Edwin', 'Cañon', '63081689', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Elbis', 'Azaharez Rodríguez', '65793711', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Enmanuel', 'Samon', '66116166', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Florencia', 'Abelenda', '49511616', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Gisela', 'Garcia', '66213445', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Johanna', 'Pintos', '57929035', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Laura', 'Atria', '65463528', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Lisset', 'Batista', '65865790', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Liset', 'Pereda', '65819008', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Luis Alberto', 'Cintra', '64371940', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Marek', 'Viamonte Guerra', '65592434', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Maydel', 'López', '64502191', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Ramon', 'Avila', '66116189', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Reynier', 'Teleña', '65865693', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Virginia', 'Bermolen', '46666024', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Yaima', 'Cordova', '65793692', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Yonney', 'Llorente', '63686073', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Yuniel', 'Mas', '66211027', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Yoansy', 'Bello', '66004969', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Yariel', 'Del Valle', '65950642', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Lisandra', 'Gonzalez', '67085504', 'facturador', 'activo'),
    ('ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', 'Jeiler', 'Sanchez', '65773323', 'facturador', 'activo')
  RETURNING id, documento
)
INSERT INTO su_personal_roles (organization_id, personal_id, rol, rol_principal)
SELECT 'ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd', id, 'Medico', true
FROM nuevos;

-- Verificación: los 26, con su rol. Confirmar nombre/apellido/documento
-- contra la planilla y que son 26 filas antes de decidir COMMIT.
SELECT
  sp.nombre, sp.apellido, sp.documento, sp.tipo_personal, sp.estado,
  spr.rol, spr.rol_principal
FROM su_personal sp
JOIN su_personal_roles spr ON spr.personal_id = sp.id
WHERE sp.organization_id = 'ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd'
  AND sp.documento IN (
    '20211643','64014409','65623285','63503699','63081689','65793711',
    '66116166','49511616','66213445','57929035','65463528','65865790',
    '65819008','64371940','65592434','64502191','66116189','65865693',
    '46666024','65793692','63686073','66211027','66004969','65950642',
    '67085504','65773323'
  )
ORDER BY sp.apellido, sp.nombre;

SELECT count(*) AS total_cargados
FROM su_personal
WHERE organization_id = 'ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd'
  AND documento IN (
    '20211643','64014409','65623285','63503699','63081689','65793711',
    '66116166','49511616','66213445','57929035','65463528','65865790',
    '65819008','64371940','65592434','64502191','66116189','65865693',
    '46666024','65793692','63686073','66211027','66004969','65950642',
    '67085504','65773323'
  );
-- Esperado: 26.

-- Caso aparte: Ramón Ávila, dígito verificador inválido en la planilla
-- original (ver comentario del DO $$ más arriba) -- carga intencional,
-- no es un error de este script.
SELECT nombre, apellido, documento,
       'Dígito verificador inválido en la planilla original (correcto: 66116188) -- cargado tal cual, excepción documentada.' AS nota
FROM su_personal
WHERE organization_id = 'ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd' AND documento = '66116189';

-- Sin COMMIT: revisar las 3 consultas de arriba y decidir COMMIT o ROLLBACK.
