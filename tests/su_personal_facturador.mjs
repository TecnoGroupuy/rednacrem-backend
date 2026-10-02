#!/usr/bin/env node
// Prueba de punta a punta, REPETIBLE, de los dos fixes de la carga de
// médicos facturadores de SU Emergencia (2026-10):
//
//   1) tipo_personal='facturador': migración 087 (su_personal_tipo_personal_check
//      + chk_personal_tipo_empresa) + validación de index.mjs
//      (POST/PATCH /operaciones/personal) -- se crea sin
//      empresa_contratista_id (200/201), y se rechaza con empresa_contratista_id
//      seteado (400), igual que 'interno'.
//   2) Link de autocompletado con fecha_nacimiento NULL: antes,
//      `fecha_nacimiento = $3::date` contra una columna NULL nunca es TRUE
//      en SQL, así que una ficha cargada sin fecha de nacimiento quedaba
//      inaccesible para siempre. Ahora el primer ingreso exitoso graba la
//      fecha ingresada como dato de control (con auditoría), y un segundo
//      intento con una fecha DISTINTA ya no entra.
//
// Cada corrida genera su propio documento (RUN_ID), no depende de datos
// fijos. Al terminar borra todo lo que creó -- se puede correr las veces
// que haga falta.
//
// Requisitos:
// - Postgres local con las migraciones aplicadas, incluida 087
//   (su_personal tipo_personal admite 'facturador').
// - local-server.mjs corriendo en :3001.
//
// Uso: node tests/su_personal_facturador.mjs

import fs from "node:fs";
import path from "node:path";
import pg from "pg";

const ROOT = path.resolve(new URL(".", import.meta.url).pathname, "..");

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  const text = fs.readFileSync(filePath, "utf8");
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    let value = trimmed.slice(idx + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}
loadEnvFile(path.join(ROOT, ".env"));
loadEnvFile(path.join(ROOT, ".env.local"));

const BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3001";
const ORG_SU_EMERGENCIA = "ec63de4e-8ac3-4054-a4c7-8ceae5c76ddd";

const RUN_ID = String(Date.now()).slice(-6);

function headersFor(role, email, sub) {
  return {
    "Content-Type": "application/json",
    "x-dev-auth": "true",
    "x-dev-user-email": email,
    "x-dev-user-role": role,
    "x-dev-user-sub": sub
  };
}
const operacionesHeaders = headersFor("operaciones", "operaciones.su@local.test", "dev-operaciones-su-emergencia");

async function call(method, pathname, body, headers = operacionesHeaders) {
  const res = await fetch(`${BASE_URL}${pathname}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  let json = null;
  try { json = await res.json(); } catch { /* respuesta no-JSON */ }
  return { status: res.status, json };
}
const post = (p, b, h) => call("POST", p, b, h);
const patch = (p, b, h) => call("PATCH", p, b, h);

const results = { pass: 0, fail: 0 };
function expect(label, condition, detail) {
  if (condition) {
    results.pass += 1;
    console.log(`  OK  - ${label}`);
  } else {
    results.fail += 1;
    console.log(`  FAIL- ${label} ${detail ? `(${detail})` : ""}`);
  }
}

async function run() {
  const client = new pg.Client();
  await client.connect();

  const createdPersonalIds = [];

  try {
    console.log(`\n=== RUN_ID ${RUN_ID} ===\n`);

    // ---------------------------------------------------------------
    // 1) tipo_personal='facturador'
    // ---------------------------------------------------------------
    console.log("--- tipo_personal='facturador' ---");

    const doc1 = `9${RUN_ID}1`;
    const crear1 = await post("/operaciones/personal", {
      nombre: "Facturador",
      apellido: `Test${RUN_ID}`,
      documento: doc1,
      tipo_personal: "facturador",
      estado: "activo",
      roles: ["Medico"]
    });
    console.log(`  [${crear1.status}] crear facturador sin empresa`);
    expect("1a) crear facturador sin empresa_contratista_id: 201", crear1.status === 201, `status=${crear1.status} body=${JSON.stringify(crear1.json)}`);
    const personalId1 = crear1.json?.item?.id;
    if (personalId1) createdPersonalIds.push(personalId1);
    expect("1b) queda con rol Medico", crear1.json?.item?.roles?.[0]?.rol === "Medico", JSON.stringify(crear1.json?.item?.roles));
    expect("1c) empresa_contratista_id queda NULL", crear1.json?.item?.empresa_contratista_id === null, crear1.json?.item?.empresa_contratista_id);

    const doc2 = `9${RUN_ID}2`;
    const crear2 = await post("/operaciones/personal", {
      nombre: "Facturador",
      apellido: "ConEmpresaInvalida",
      documento: doc2,
      tipo_personal: "facturador",
      empresa_contratista_id: "11111111-1111-1111-1111-111111111111",
      estado: "activo"
    });
    console.log(`  [${crear2.status}] crear facturador CON empresa (debe fallar)`);
    expect("1d) crear facturador con empresa_contratista_id: 400", crear2.status === 400, `status=${crear2.status}`);
    // Si por algún motivo el 400 no frenó la escritura, hay que limpiarlo igual.
    if (crear2.json?.item?.id) createdPersonalIds.push(crear2.json.item.id);

    // PATCH: pasar un 'interno' existente a 'facturador' con empresa seteada -> 400.
    const docPatch = `9${RUN_ID}3`;
    const crearParaPatch = await post("/operaciones/personal", {
      nombre: "ParaPatch",
      apellido: "Test",
      documento: docPatch,
      tipo_personal: "interno",
      estado: "activo"
    });
    const personalIdPatch = crearParaPatch.json?.item?.id;
    if (personalIdPatch) createdPersonalIds.push(personalIdPatch);
    expect("1e) setup PATCH: crear interno: 201", crearParaPatch.status === 201, JSON.stringify(crearParaPatch.json));

    const patchMalo = await patch(`/operaciones/personal/${personalIdPatch}`, {
      tipo_personal: "facturador",
      empresa_contratista_id: "11111111-1111-1111-1111-111111111111"
    });
    expect("1f) PATCH a facturador CON empresa: 400", patchMalo.status === 400, `status=${patchMalo.status}`);

    const patchBueno = await patch(`/operaciones/personal/${personalIdPatch}`, { tipo_personal: "facturador" });
    expect("1g) PATCH a facturador sin empresa: 200", patchBueno.status === 200, `status=${patchBueno.status} body=${JSON.stringify(patchBueno.json)}`);

    // ---------------------------------------------------------------
    // 2) Link de autocompletado con fecha_nacimiento NULL
    // ---------------------------------------------------------------
    console.log("\n--- Link de autocompletado: fecha_nacimiento NULL ---");

    const codigo = `TST${RUN_ID}`;
    await client.query(
      `INSERT INTO ficha_links (organization_id, codigo, expires_at) VALUES ($1, $2, now() + interval '1 day')`,
      [ORG_SU_EMERGENCIA, codigo]
    );

    const docFicha = `9${RUN_ID}4`;
    const crearFicha = await post("/operaciones/personal", {
      nombre: "SinFecha",
      apellido: "Test",
      documento: docFicha,
      tipo_personal: "facturador",
      estado: "activo"
    });
    const personalIdFicha = crearFicha.json?.item?.id;
    if (personalIdFicha) createdPersonalIds.push(personalIdFicha);
    expect("2a) setup: crear ficha sin fecha_nacimiento: 201", crearFicha.status === 201, JSON.stringify(crearFicha.json));

    const verificar1 = await post("/publico/ficha-personal/verificar", { codigo, documento: docFicha, fecha_nacimiento: "1985-03-15" }, { "Content-Type": "application/json" });
    expect("2b) primer ingreso (fecha_nacimiento NULL, cualquier fecha): 200", verificar1.status === 200, `status=${verificar1.status} body=${JSON.stringify(verificar1.json)}`);
    expect("2c) devuelve la fecha recién grabada", verificar1.json?.persona?.fecha_nacimiento === "1985-03-15", verificar1.json?.persona?.fecha_nacimiento);

    const fechaEnDb = await client.query(`SELECT fecha_nacimiento::text AS fecha_nacimiento FROM su_personal WHERE id = $1`, [personalIdFicha]);
    expect("2d) fecha_nacimiento quedó grabada en la base", fechaEnDb.rows[0]?.fecha_nacimiento === "1985-03-15", fechaEnDb.rows[0]?.fecha_nacimiento);

    const auditoria = await client.query(
      `SELECT campo, valor_anterior, valor_nuevo FROM su_personal_cambios_publicos WHERE personal_id = $1 AND campo = 'fecha_nacimiento'`,
      [personalIdFicha]
    );
    expect("2e) queda auditado (valor_anterior NULL -> valor_nuevo la fecha)", auditoria.rows.length === 1 && auditoria.rows[0].valor_anterior === null, JSON.stringify(auditoria.rows));

    const verificar2 = await post("/publico/ficha-personal/verificar", { codigo, documento: docFicha, fecha_nacimiento: "1985-03-15" }, { "Content-Type": "application/json" });
    expect("2f) segundo ingreso con la MISMA fecha (ya fijada): 200", verificar2.status === 200, `status=${verificar2.status}`);

    const verificar3 = await post("/publico/ficha-personal/verificar", { codigo, documento: docFicha, fecha_nacimiento: "2000-01-01" }, { "Content-Type": "application/json" });
    expect("2g) tercer ingreso con fecha DISTINTA: 404 (ya no matchea NULL)", verificar3.status === 404, `status=${verificar3.status}`);

    console.log(`\n=== Resultado: ${results.pass} OK / ${results.fail} FAIL ===`);
  } finally {
    console.log("\n--- Limpieza ---");
    if (createdPersonalIds.length) {
      const delCambios = await client.query(`DELETE FROM su_personal_cambios_publicos WHERE personal_id = ANY($1) RETURNING id`, [createdPersonalIds]);
      console.log(`  su_personal_cambios_publicos borrados: ${delCambios.rowCount}`);
      const delRoles = await client.query(`DELETE FROM su_personal_roles WHERE personal_id = ANY($1) RETURNING id`, [createdPersonalIds]);
      console.log(`  su_personal_roles borrados: ${delRoles.rowCount}`);
      const del = await client.query(`DELETE FROM su_personal WHERE id = ANY($1) RETURNING id`, [createdPersonalIds]);
      console.log(`  su_personal borrados: ${del.rowCount}`);
    }
    await client.query(`DELETE FROM ficha_links WHERE codigo = $1`, [`TST${RUN_ID}`]);
    await client.end();
  }

  process.exit(results.fail > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("ERROR", err);
  process.exit(1);
});
