#!/usr/bin/env node
// Prueba de punta a punta, REPETIBLE, del fix de closeManualTicket (commit
// 6f07e8a): un ticket de Retencion (manual_tickets, tipo_solicitud=
// 'solicitud_baja') cerrado con outcome='baja_confirmada' tiene que generar
// un candidato en recupero_candidatos, exactamente igual que la baja
// individual (POST /contacts/:contactId/products/:productId/baja).
//
// Cubre:
//   1) Cierre de ticket de Retencion -> aparece en recupero_candidatos.
//   2) La baja individual normal sigue funcionando igual que antes.
//
// Cada corrida genera su propio documento/celular (RUN_ID), no depende de
// datos fijos. Al terminar borra todo lo que creo (los contactos, en
// cascada, se llevan puestos contact_products/recupero_candidatos/
// manual_tickets vinculados) -- se puede correr las veces que haga falta.
//
// Requisitos:
// - Postgres local con las migraciones 071-080 aplicadas (rednacrem db).
// - local-server.mjs corriendo en :3001.
//
// Uso: node tests/retencion_baja_recupero.mjs

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
const ORG_REDNACREM = "9223d62d-f558-4f4c-b9bd-9dcea9888a0e";
const SUPERVISOR_EMAIL = "supervisor@renacrem.com";
const SUPERVISOR_ID = "ec6350f5-8438-49cb-80ba-5022dccc54df";

const RUN_ID = String(Date.now()).slice(-6);

function devHeaders() {
  return {
    "Content-Type": "application/json",
    "x-dev-auth": "true",
    "x-dev-user-email": SUPERVISOR_EMAIL,
    "x-dev-user-role": "supervisor",
    "x-dev-user-sub": "local-dev-supervisor"
  };
}

async function post(pathname, body) {
  const res = await fetch(`${BASE_URL}${pathname}`, {
    method: "POST",
    headers: devHeaders(),
    body: JSON.stringify(body)
  });
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

async function run() {
  const client = new pg.Client();
  await client.connect();

  const createdContactIds = [];

  try {
    console.log(`\n=== RUN_ID ${RUN_ID} ===\n`);

    // ---------------------------------------------------------------
    // Caso 1: ticket de Retencion cerrado con "Baja confirmada"
    // ---------------------------------------------------------------
    console.log("--- Caso 1: cierre de ticket de Retencion (solicitud_baja -> baja_confirmada) ---");

    const doc1 = `51${RUN_ID}1`;
    const contactRes1 = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Retencion', 'TestUno', $1, $2, $3, 'activo') RETURNING id`,
      [doc1, `099${RUN_ID}1`, ORG_REDNACREM]
    );
    const contactId1 = contactRes1.rows[0].id;
    createdContactIds.push(contactId1);

    const cpRes1 = await client.query(
      `INSERT INTO contact_products (contact_id, nombre_producto, precio, fecha_alta, estado, seller_name_snapshot, organization_id)
       VALUES ($1, 'Plan Retencion Test', 150, '2026-01-01', 'alta', 'Vendedor Retencion', $2) RETURNING id`,
      [contactId1, ORG_REDNACREM]
    );
    const productId1 = cpRes1.rows[0].id;

    const ticketRes1 = await client.query(
      `INSERT INTO manual_tickets (cliente_id, tipo_solicitud, resumen, prioridad, estado, producto_contrato_id, organization_id)
       VALUES ($1, 'solicitud_baja', 'sin_liquidez', 'media', 'en_proceso', $2, $3) RETURNING id`,
      [contactId1, productId1, ORG_REDNACREM]
    );
    const ticketId1 = ticketRes1.rows[0].id;

    const closeResp = await post(`/manual-tickets/${ticketId1}/close`, {
      outcome: "baja_confirmada",
      note: "Baja confirmada"
    });
    console.log(`  [${closeResp.status}] close ticket:`, JSON.stringify(closeResp.json));
    expect("cierre de ticket: 200", closeResp.status === 200, `status=${closeResp.status}`);

    const cpAfter1 = await client.query(`SELECT estado, motivo_baja, baja_gestionada_por FROM contact_products WHERE id = $1`, [productId1]);
    expect("contact_product queda en baja", cpAfter1.rows[0]?.estado === "baja", JSON.stringify(cpAfter1.rows[0]));
    expect("motivo_baja mapeado desde el resumen ('sin_liquidez')", cpAfter1.rows[0]?.motivo_baja === "sin_liquidez", cpAfter1.rows[0]?.motivo_baja);
    expect("baja_gestionada_por es el actor del cierre", cpAfter1.rows[0]?.baja_gestionada_por === SUPERVISOR_ID, cpAfter1.rows[0]?.baja_gestionada_por);

    const recuperoAfter1 = await client.query(
      `SELECT estado, estado_administrativo, resultado_gestion, motivo_baja, vendedor_origen, importado_por, contact_id
       FROM recupero_candidatos WHERE contact_id = $1`,
      [contactId1]
    );
    expect("aparece en recupero_candidatos", recuperoAfter1.rows.length === 1, `rows=${recuperoAfter1.rows.length}`);
    const rc1 = recuperoAfter1.rows[0] || {};
    expect("recupero: estado='disponible'", rc1.estado === "disponible", rc1.estado);
    expect("recupero: resultado_gestion='nuevo'", rc1.resultado_gestion === "nuevo", rc1.resultado_gestion);
    expect("recupero: vendedor_origen = seller_name_snapshot", rc1.vendedor_origen === "Vendedor Retencion", rc1.vendedor_origen);
    expect("recupero: importado_por = actor del cierre", rc1.importado_por === SUPERVISOR_ID, rc1.importado_por);

    const auditAfter1 = await client.query(`SELECT count(*)::int AS n FROM contact_product_baja_audit WHERE contact_id = $1`, [contactId1]);
    expect("queda auditoria en contact_product_baja_audit", auditAfter1.rows[0]?.n === 1, auditAfter1.rows[0]?.n);

    // ---------------------------------------------------------------
    // Caso 2: baja individual normal (POST /contacts/:id/products/:id/baja)
    // sigue funcionando igual que antes.
    // ---------------------------------------------------------------
    console.log("\n--- Caso 2: baja individual normal (sin pasar por Retencion) ---");

    const doc2 = `51${RUN_ID}2`;
    const contactRes2 = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Baja', 'TestDos', $1, $2, $3, 'activo') RETURNING id`,
      [doc2, `099${RUN_ID}2`, ORG_REDNACREM]
    );
    const contactId2 = contactRes2.rows[0].id;
    createdContactIds.push(contactId2);

    const cpRes2 = await client.query(
      `INSERT INTO contact_products (contact_id, nombre_producto, precio, fecha_alta, estado, seller_name_snapshot, organization_id)
       VALUES ($1, 'Plan Baja Individual Test', 200, '2026-01-01', 'alta', 'Vendedor Individual', $2) RETURNING id`,
      [contactId2, ORG_REDNACREM]
    );
    const productId2 = cpRes2.rows[0].id;

    const bajaResp = await post(`/contacts/${contactId2}/products/${productId2}/baja`, {
      motivo_baja: "falta_de_pago",
      observacion: "Prueba de baja individual"
    });
    console.log(`  [${bajaResp.status}] baja individual:`, JSON.stringify(bajaResp.json));
    expect("baja individual: 200", bajaResp.status === 200, `status=${bajaResp.status}`);

    const cpAfter2 = await client.query(`SELECT estado, motivo_baja FROM contact_products WHERE id = $1`, [productId2]);
    expect("contact_product queda en baja (individual)", cpAfter2.rows[0]?.estado === "baja", JSON.stringify(cpAfter2.rows[0]));
    expect("motivo_baja = el enviado", cpAfter2.rows[0]?.motivo_baja === "falta_de_pago", cpAfter2.rows[0]?.motivo_baja);

    const recuperoAfter2 = await client.query(
      `SELECT estado, vendedor_origen FROM recupero_candidatos WHERE contact_id = $1`,
      [contactId2]
    );
    expect("baja individual tambien aparece en recupero_candidatos (sin cambios de comportamiento)", recuperoAfter2.rows.length === 1, `rows=${recuperoAfter2.rows.length}`);
    expect("recupero (individual): vendedor_origen = seller_name_snapshot", recuperoAfter2.rows[0]?.vendedor_origen === "Vendedor Individual", recuperoAfter2.rows[0]?.vendedor_origen);

    console.log(`\n=== Resultado: ${results.pass} OK / ${results.fail} FAIL ===`);
  } finally {
    console.log("\n--- Limpieza ---");
    if (createdContactIds.length) {
      // recupero_candidatos.contact_id no tiene FK a contacts (agregada por
      // la migracion 078 como columna simple, sin constraint) -- hay que
      // borrarla a mano, no cascadea con el DELETE de contacts.
      const delRecupero = await client.query(`DELETE FROM recupero_candidatos WHERE contact_id = ANY($1) RETURNING id`, [createdContactIds]);
      console.log(`  recupero_candidatos borrados a mano (sin FK a contacts): ${delRecupero.rowCount}`);
      const del = await client.query(`DELETE FROM contacts WHERE id = ANY($1) RETURNING id`, [createdContactIds]);
      console.log(`  Contactos borrados (cascada a contact_products/manual_tickets/contact_product_baja_audit): ${del.rowCount}`);
    }
    await client.end();
  }

  process.exit(results.fail > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("ERROR", err);
  process.exit(1);
});
