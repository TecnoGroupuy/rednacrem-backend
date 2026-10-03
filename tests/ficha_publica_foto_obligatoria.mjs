#!/usr/bin/env node
// Prueba de punta a punta, REPETIBLE, de la foto de perfil obligatoria en
// el link de autocompletado de ficha (2026-10):
//
//   1) Una persona SIN foto_url puede verificarse igual (documento+fecha) --
//      la foto no es parte de la verificación de identidad.
//   2) GET /publico/ficha-personal/documentos NO está bloqueado por falta
//      de foto -- el frontend lo pide apenas hay sessionToken, ANTES de
//      llegar al paso "foto" (para la barra de progreso); bloquearlo
//      rompería la pantalla inicial para cualquiera sin foto todavía.
//   3) POST /publico/ficha-personal/turno/aviso tampoco está bloqueado --
//      es el canal para avisarle a RRHH que algo no coincide, tiene que
//      funcionar siempre.
//   4) POST /publico/ficha-personal/documentos (subir un documento o
//      curso) SÍ está bloqueado con 409 mientras falte la foto.
//   5) Con foto_url ya cargada, el mismo POST ya no da 409 (pasa el gate;
//      si falla después es por la subida real a S3, no por este chequeo --
//      ver nota en el test).
//   6) Una persona que YA tenía foto desde el alta nunca ve el 409, en
//      ningún momento del flujo.
//
// NOTA sobre el punto 5: este entorno local no tiene credenciales de AWS,
// así que la subida real a S3 (POST /publico/ficha-personal/foto) no se
// puede probar de punta a punta acá -- se simula "ya tiene foto" con un
// UPDATE directo de foto_url, que es exactamente lo único que el gate
// chequea (le da igual cómo se llegó a tener un valor ahí).
//
// Cada corrida genera su propio documento (RUN_ID), no depende de datos
// fijos. Al terminar borra todo lo que creó -- se puede correr las veces
// que haga falta.
//
// Requisitos:
// - Postgres local con las migraciones aplicadas.
// - local-server.mjs corriendo en :3001.
//
// Uso: node tests/ficha_publica_foto_obligatoria.mjs

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

function opsHeaders() {
  return {
    "Content-Type": "application/json",
    "x-dev-auth": "true",
    "x-dev-user-email": "operaciones.su@local.test",
    "x-dev-user-role": "operaciones",
    "x-dev-user-sub": "dev-operaciones-su-emergencia"
  };
}

async function call(method, pathname, body, headers) {
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
const get = (p, h) => call("GET", p, undefined, h);

async function postRaw(pathname, buffer, headers) {
  const res = await fetch(`${BASE_URL}${pathname}`, { method: "POST", headers, body: buffer });
  let json = null;
  try { json = await res.json(); } catch { /* respuesta no-JSON */ }
  return { status: res.status, json };
}

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

const FAKE_JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x74, 0x65, 0x73, 0x74]);

async function verificar(codigo, documento, fecha) {
  const resp = await post("/publico/ficha-personal/verificar", { codigo, documento, fecha_nacimiento: fecha }, { "Content-Type": "application/json" });
  return resp;
}

async function subirDocumento(sessionToken) {
  return postRaw("/publico/ficha-personal/documentos", FAKE_JPEG, {
    "X-Ficha-Session": sessionToken,
    "X-Doc-Categoria": "ci_frente",
    "X-Doc-Nombre-Archivo": "test.jpg",
    "Content-Type": "image/jpeg"
  });
}

async function run() {
  const client = new pg.Client();
  await client.connect();

  const createdPersonalIds = [];
  const createdCodigos = [];

  try {
    console.log(`\n=== RUN_ID ${RUN_ID} ===\n`);

    // ---------------------------------------------------------------
    // Caso 1: persona SIN foto -- verificación, GET documentos y
    // turno/aviso funcionan; POST documentos da 409.
    // ---------------------------------------------------------------
    console.log("--- Caso 1: persona sin foto_url ---");
    const doc1 = `8${RUN_ID}1`;
    const crear1 = await post("/operaciones/personal", {
      nombre: "SinFoto", apellido: `Test${RUN_ID}`, documento: doc1, tipo_personal: "facturador", estado: "activo"
    }, opsHeaders());
    const personalId1 = crear1.json?.item?.id;
    if (personalId1) createdPersonalIds.push(personalId1);
    expect("1a) setup: crear persona sin foto: 201", crear1.status === 201, JSON.stringify(crear1.json));

    const codigo1 = `FT${RUN_ID}1`;
    createdCodigos.push(codigo1);
    await client.query(`INSERT INTO ficha_links (organization_id, codigo, expires_at) VALUES ($1, $2, now() + interval '1 day')`, [ORG_SU_EMERGENCIA, codigo1]);

    const verif1 = await verificar(codigo1, doc1, "1990-01-01");
    expect("1b) verificación sin foto: 200 (la foto no es parte de la identidad)", verif1.status === 200, `status=${verif1.status} body=${JSON.stringify(verif1.json)}`);
    const session1 = verif1.json?.session_token;

    const getDocs1 = await get("/publico/ficha-personal/documentos", { "X-Ficha-Session": session1 });
    expect("1c) GET documentos sin foto: 200 (NO bloqueado -- lo pide el frontend antes del paso foto)", getDocs1.status === 200, `status=${getDocs1.status} body=${JSON.stringify(getDocs1.json)}`);

    const aviso1 = await post("/publico/ficha-personal/turno/aviso", { comentario: "no coincide" }, { "X-Ficha-Session": session1, "Content-Type": "application/json" });
    expect("1d) POST turno/aviso sin foto: 200 (NO bloqueado -- canal de aviso a RRHH)", aviso1.status === 200, `status=${aviso1.status} body=${JSON.stringify(aviso1.json)}`);

    const subirDoc1 = await subirDocumento(session1);
    expect("1e) POST documentos sin foto: 409", subirDoc1.status === 409, `status=${subirDoc1.status} body=${JSON.stringify(subirDoc1.json)}`);
    expect("1f) mensaje claro de 409", subirDoc1.json?.message === "Subí tu foto de perfil antes de continuar.", subirDoc1.json?.message);

    // ---------------------------------------------------------------
    // Caso 2: la misma persona, ahora CON foto -- POST documentos ya no
    // da 409 (pasa el gate; si falla después es la subida real a S3, no
    // este chequeo -- ver nota del encabezado).
    // ---------------------------------------------------------------
    console.log("\n--- Caso 2: misma persona, ahora con foto_url ---");
    await client.query(`UPDATE su_personal SET foto_url = 'https://example.com/fake-foto.jpg' WHERE id = $1`, [personalId1]);

    const verif2 = await verificar(codigo1, doc1, "1990-01-01");
    const session2 = verif2.json?.session_token;
    const subirDoc2 = await subirDocumento(session2);
    expect("2a) POST documentos con foto: ya NO da 409", subirDoc2.status !== 409, `status=${subirDoc2.status} body=${JSON.stringify(subirDoc2.json)}`);

    // ---------------------------------------------------------------
    // Caso 3: persona que YA tenía foto desde el alta -- nunca ve el 409.
    // ---------------------------------------------------------------
    console.log("\n--- Caso 3: persona que ya tenía foto desde el alta ---");
    const doc3 = `8${RUN_ID}3`;
    const crear3 = await post("/operaciones/personal", {
      nombre: "ConFoto", apellido: `Test${RUN_ID}`, documento: doc3, tipo_personal: "facturador", estado: "activo"
    }, opsHeaders());
    const personalId3 = crear3.json?.item?.id;
    if (personalId3) createdPersonalIds.push(personalId3);
    await client.query(`UPDATE su_personal SET foto_url = 'https://example.com/foto-previa.jpg' WHERE id = $1`, [personalId3]);

    const codigo3 = `FT${RUN_ID}3`;
    createdCodigos.push(codigo3);
    await client.query(`INSERT INTO ficha_links (organization_id, codigo, expires_at) VALUES ($1, $2, now() + interval '1 day')`, [ORG_SU_EMERGENCIA, codigo3]);

    const verif3 = await verificar(codigo3, doc3, "1990-01-01");
    const session3 = verif3.json?.session_token;
    expect("3a) verificación: devuelve la foto ya cargada", Boolean(verif3.json?.persona?.foto_url), verif3.json?.persona?.foto_url);

    const subirDoc3 = await subirDocumento(session3);
    expect("3b) POST documentos: nunca vio el 409 (ya tenía foto)", subirDoc3.status !== 409, `status=${subirDoc3.status}`);

    console.log(`\n=== Resultado: ${results.pass} OK / ${results.fail} FAIL ===`);
  } finally {
    console.log("\n--- Limpieza ---");
    if (createdPersonalIds.length) {
      await client.query(`DELETE FROM su_personal_cambios_publicos WHERE personal_id = ANY($1)`, [createdPersonalIds]);
      await client.query(`DELETE FROM su_personal_roles WHERE personal_id = ANY($1)`, [createdPersonalIds]);
      const del = await client.query(`DELETE FROM su_personal WHERE id = ANY($1) RETURNING id`, [createdPersonalIds]);
      console.log(`  su_personal borrados: ${del.rowCount}`);
    }
    if (createdCodigos.length) {
      const delLinks = await client.query(`DELETE FROM ficha_links WHERE codigo = ANY($1) RETURNING id`, [createdCodigos]);
      console.log(`  ficha_links borrados: ${delLinks.rowCount}`);
    }
    await client.end();
  }

  process.exit(results.fail > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("ERROR", err);
  process.exit(1);
});
