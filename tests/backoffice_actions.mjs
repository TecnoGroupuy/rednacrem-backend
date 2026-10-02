#!/usr/bin/env node
// Prueba de punta a punta, REPETIBLE, de las ACCIONES (no solo acceso de
// lectura) del rol "backoffice" (auditoría 2026-10, ver src/lib/permissions.js
// y los commits "feat: rol backoffice (PASO 2/PASO 3)"). Cubre los 6 puntos
// pedidos antes del push:
//
//   a) Cerrar un ticket común (no solicitud_baja) -> 200.
//   b) Cerrar solicitud_baja: sin asignar -> 200; asignada al propio
//      backoffice -> 200; asignada a OTRO usuario -> 403.
//   c) Baja directa de un producto -> 200, y el contacto aparece en
//      recupero_candidatos igual que una baja hecha por supervisor (ver
//      tests/retencion_baja_recupero.mjs, que ya prueba esto para
//      supervisor -- acá se repite para backoffice y se compara).
//   d) Gestionar (POST .../gestionar) un candidato de recupero propio ->
//      200; uno asignado a otro vendedor -> 403.
//   e) /api/seller/ventas-historicas y /agenda con seller_id ajeno por
//      query param -> el backend ignora el query param y devuelve solo lo
//      propio de backoffice (comercial.cuenta_como_vendedor /
//      recupero.gestionar_propios).
//   f) /api/supervisor/agents, pedido como supervisor -> el usuario
//      backoffice aparece en la lista de agentes asignables
//      (comercial.asignable).
//
// Cada corrida genera su propio documento/celular (RUN_ID), no depende de
// datos fijos. Al terminar borra todo lo que creó -- se puede correr las
// veces que haga falta.
//
// Requisitos:
// - Postgres local con las migraciones aplicadas (rednacrem db).
// - local-server.mjs corriendo en :3001.
// - El usuario backoffice de prueba local tiene que existir en `users`
//   (email backoffice@rednacrem.com, cognito_sub dev-backoffice-rednacrem --
//   lo crea automáticamente el bypass de dev-auth si no existe) y tener fila
//   en organization_users para Rednacrem, activo=true (si no, todo da 403
//   "Usuario no asociado a una organización activa" -- no es un bug del
//   rol, es un dato de prueba faltante, ver CLAUDE.md del frontend/sesión
//   2026-10). Este script la crea si falta, idempotente.
// - Requiere además un segundo usuario real (vendedor@rednacrem.com) para
//   los casos "asignado a OTRO usuario".
//
// Uso: node tests/backoffice_actions.mjs

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

const BACKOFFICE_EMAIL = "backoffice@rednacrem.com";
const BACKOFFICE_SUB = "dev-backoffice-rednacrem";
const VENDEDOR_EMAIL = "vendedor@rednacrem.com";

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
const backofficeHeaders = headersFor("backoffice", BACKOFFICE_EMAIL, BACKOFFICE_SUB);
const supervisorHeaders = headersFor("supervisor", "supervisor@renacrem.com", "local-dev-supervisor");

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
const post = (p, b, h = backofficeHeaders) => call("POST", p, b, h);
const get = (p, h = backofficeHeaders) => call("GET", p, undefined, h);

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
  const createdCandidatoIds = [];
  let backofficeId = null;
  let vendedorId = null;

  try {
    console.log(`\n=== RUN_ID ${RUN_ID} ===\n`);

    // ---------------------------------------------------------------
    // Setup: resolver (o crear) el usuario backoffice de prueba vía el
    // propio bypass de dev-auth del backend (igual que hace la UI), y
    // asegurar su membresía en organization_users -- sin esto, cualquier
    // endpoint que resuelva organización da 403 "no asociado", algo que no
    // tiene que ver con el gateo por rol/capacidad que estamos probando.
    // ---------------------------------------------------------------
    console.log("--- Setup: usuario backoffice de prueba + membresía de organización ---");
    const meResp = await get("/api/me");
    backofficeId = meResp.json?.user?.id || null;
    expect("GET /api/me resuelve (o crea) el usuario backoffice", Boolean(backofficeId), JSON.stringify(meResp.json));

    const vendedorRes = await client.query(`SELECT id FROM users WHERE email = $1 LIMIT 1`, [VENDEDOR_EMAIL]);
    vendedorId = vendedorRes.rows[0]?.id || null;
    expect(`existe el usuario ${VENDEDOR_EMAIL} (fixture usado como "otro usuario")`, Boolean(vendedorId), "corré la app local al menos una vez con el preset Vendedor para crearlo");

    // organization_users no tiene constraint UNIQUE (organization_id,
    // user_id) en este schema local -- ON CONFLICT no serviría de guarda
    // acá (insertaría duplicados en cada corrida). Se verifica existencia
    // antes de insertar.
    const existingMembership = await client.query(
      `SELECT 1 FROM organization_users WHERE organization_id = $1 AND user_id = $2 LIMIT 1`,
      [ORG_REDNACREM, backofficeId]
    );
    if (!existingMembership.rows.length) {
      await client.query(
        `INSERT INTO organization_users (organization_id, user_id, activo, role_in_org) VALUES ($1, $2, true, 'backoffice')`,
        [ORG_REDNACREM, backofficeId]
      );
    }
    const membership = await client.query(
      `SELECT activo FROM organization_users WHERE organization_id = $1 AND user_id = $2`,
      [ORG_REDNACREM, backofficeId]
    );
    expect("backoffice tiene membresía activa en organization_users (Rednacrem)", membership.rows[0]?.activo === true, JSON.stringify(membership.rows[0]));

    if (!backofficeId || !vendedorId) {
      throw new Error("Setup incompleto -- no se puede continuar con los casos a-f");
    }

    // ---------------------------------------------------------------
    // a) Cerrar un ticket común (no solicitud_baja) -> 200
    // ---------------------------------------------------------------
    console.log("\n--- a) Cerrar ticket común (tipo_solicitud='consulta') ---");
    const docA = `52${RUN_ID}0`;
    const contactA = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Backoffice', 'CasoA', $1, $2, $3, 'activo') RETURNING id`,
      [docA, `099${RUN_ID}0`, ORG_REDNACREM]
    );
    createdContactIds.push(contactA.rows[0].id);
    const ticketA = await client.query(
      `INSERT INTO manual_tickets (cliente_id, tipo_solicitud, resumen, prioridad, estado, organization_id)
       VALUES ($1, 'consulta', 'Consulta general de prueba', 'media', 'en_proceso', $2) RETURNING id`,
      [contactA.rows[0].id, ORG_REDNACREM]
    );
    const closeA = await post(`/manual-tickets/${ticketA.rows[0].id}/close`, { outcome: "resuelto", note: "Cerrado por backoffice" });
    console.log(`  [${closeA.status}]`, JSON.stringify(closeA.json));
    expect("a) cerrar ticket común: 200", closeA.status === 200, `status=${closeA.status}`);

    // ---------------------------------------------------------------
    // b) solicitud_baja: sin asignar / asignada a mí / asignada a otro
    // ---------------------------------------------------------------
    console.log("\n--- b) Cerrar solicitud_baja (sin asignar / asignada a mí / asignada a otro) ---");

    const docB1 = `52${RUN_ID}1`;
    const contactB1 = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Backoffice', 'CasoB1', $1, $2, $3, 'activo') RETURNING id`,
      [docB1, `099${RUN_ID}1`, ORG_REDNACREM]
    );
    createdContactIds.push(contactB1.rows[0].id);
    const ticketB1 = await client.query(
      `INSERT INTO manual_tickets (cliente_id, tipo_solicitud, resumen, prioridad, estado, organization_id)
       VALUES ($1, 'solicitud_baja', 'voluntaria', 'media', 'en_proceso', $2) RETURNING id`,
      [contactB1.rows[0].id, ORG_REDNACREM]
    );
    const closeB1 = await post(`/manual-tickets/${ticketB1.rows[0].id}/close`, { outcome: "retenido", note: "Sin asignar" });
    console.log(`  [${closeB1.status}] sin asignar:`, JSON.stringify(closeB1.json));
    expect("b1) solicitud_baja SIN asignar: 200", closeB1.status === 200, `status=${closeB1.status}`);

    const docB2 = `52${RUN_ID}2`;
    const contactB2 = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Backoffice', 'CasoB2', $1, $2, $3, 'activo') RETURNING id`,
      [docB2, `099${RUN_ID}2`, ORG_REDNACREM]
    );
    createdContactIds.push(contactB2.rows[0].id);
    const ticketB2 = await client.query(
      `INSERT INTO manual_tickets (cliente_id, tipo_solicitud, resumen, prioridad, estado, organization_id, assigned_to)
       VALUES ($1, 'solicitud_baja', 'voluntaria', 'media', 'en_proceso', $2, $3) RETURNING id`,
      [contactB2.rows[0].id, ORG_REDNACREM, backofficeId]
    );
    const closeB2 = await post(`/manual-tickets/${ticketB2.rows[0].id}/close`, { outcome: "retenido", note: "Asignada a mí" });
    console.log(`  [${closeB2.status}] asignada a mí:`, JSON.stringify(closeB2.json));
    expect("b2) solicitud_baja asignada al propio backoffice: 200", closeB2.status === 200, `status=${closeB2.status}`);

    const docB3 = `52${RUN_ID}3`;
    const contactB3 = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Backoffice', 'CasoB3', $1, $2, $3, 'activo') RETURNING id`,
      [docB3, `099${RUN_ID}3`, ORG_REDNACREM]
    );
    createdContactIds.push(contactB3.rows[0].id);
    const ticketB3 = await client.query(
      `INSERT INTO manual_tickets (cliente_id, tipo_solicitud, resumen, prioridad, estado, organization_id, assigned_to)
       VALUES ($1, 'solicitud_baja', 'voluntaria', 'media', 'en_proceso', $2, $3) RETURNING id`,
      [contactB3.rows[0].id, ORG_REDNACREM, vendedorId]
    );
    const closeB3 = await post(`/manual-tickets/${ticketB3.rows[0].id}/close`, { outcome: "retenido", note: "Asignada a otro" });
    console.log(`  [${closeB3.status}] asignada a otro vendedor:`, JSON.stringify(closeB3.json));
    expect("b3) solicitud_baja asignada a OTRO usuario: 403", closeB3.status === 403, `status=${closeB3.status}`);

    // ---------------------------------------------------------------
    // c) Baja directa de un producto -> 200, aparece en recupero_candidatos
    // (mismo resultado que una baja de supervisor, ver
    // tests/retencion_baja_recupero.mjs caso 2).
    // ---------------------------------------------------------------
    console.log("\n--- c) Baja directa de un producto ---");
    const docC = `52${RUN_ID}4`;
    const contactC = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Backoffice', 'CasoC', $1, $2, $3, 'activo') RETURNING id`,
      [docC, `099${RUN_ID}4`, ORG_REDNACREM]
    );
    createdContactIds.push(contactC.rows[0].id);
    const cpC = await client.query(
      `INSERT INTO contact_products (contact_id, nombre_producto, precio, fecha_alta, estado, seller_name_snapshot, organization_id)
       VALUES ($1, 'Plan Backoffice Test', 180, '2026-01-01', 'alta', 'Vendedor Original', $2) RETURNING id`,
      [contactC.rows[0].id, ORG_REDNACREM]
    );
    const bajaC = await post(`/contacts/${contactC.rows[0].id}/products/${cpC.rows[0].id}/baja`, {
      motivo_baja: "voluntaria",
      observacion: "Baja directa por backoffice"
    });
    console.log(`  [${bajaC.status}]`, JSON.stringify(bajaC.json));
    expect("c) baja directa: 200", bajaC.status === 200, `status=${bajaC.status}`);

    const cpAfterC = await client.query(`SELECT estado, motivo_baja, baja_gestionada_por FROM contact_products WHERE id = $1`, [cpC.rows[0].id]);
    expect("c) contact_product queda en baja", cpAfterC.rows[0]?.estado === "baja", JSON.stringify(cpAfterC.rows[0]));
    expect("c) baja_gestionada_por = backoffice (el actor)", cpAfterC.rows[0]?.baja_gestionada_por === backofficeId, cpAfterC.rows[0]?.baja_gestionada_por);

    const recuperoAfterC = await client.query(
      `SELECT estado, resultado_gestion, vendedor_origen, importado_por FROM recupero_candidatos WHERE contact_id = $1`,
      [contactC.rows[0].id]
    );
    expect(
      "c) aparece en recupero_candidatos, igual que una baja de supervisor (mismo flujo compartido, aplicarBajaContactProduct)",
      recuperoAfterC.rows.length === 1 && recuperoAfterC.rows[0]?.estado === "disponible" && recuperoAfterC.rows[0]?.resultado_gestion === "nuevo",
      JSON.stringify(recuperoAfterC.rows[0])
    );
    expect("c) recupero: importado_por = backoffice (el actor de la baja)", recuperoAfterC.rows[0]?.importado_por === backofficeId, recuperoAfterC.rows[0]?.importado_por);

    // ---------------------------------------------------------------
    // d) Gestionar un candidato de recupero: propio -> 200; de otro -> 403
    // ---------------------------------------------------------------
    console.log("\n--- d) Gestionar candidato de recupero (propio / de otro vendedor) ---");

    const docD1 = `52${RUN_ID}5`;
    const candD1 = await client.query(
      `INSERT INTO recupero_candidatos (organization_id, nombre, apellido, documento, celular, seller_id, estado, estado_administrativo, resultado_gestion)
       VALUES ($1, 'Candidato', 'Propio', $2, $3, $4, 'en_gestion', 'activo', 'nuevo') RETURNING id`,
      [ORG_REDNACREM, docD1, `099${RUN_ID}5`, backofficeId]
    );
    createdCandidatoIds.push(candD1.rows[0].id);
    const gestionD1 = await post(`/api/recupero/candidatos/${candD1.rows[0].id}/gestionar`, { status: "no_contesta", note: "Primer intento" });
    console.log(`  [${gestionD1.status}] candidato propio:`, JSON.stringify(gestionD1.json));
    expect("d1) gestionar candidato propio: 200", gestionD1.status === 200, `status=${gestionD1.status}`);

    const docD2 = `52${RUN_ID}6`;
    const candD2 = await client.query(
      `INSERT INTO recupero_candidatos (organization_id, nombre, apellido, documento, celular, seller_id, estado, estado_administrativo, resultado_gestion)
       VALUES ($1, 'Candidato', 'DeOtro', $2, $3, $4, 'en_gestion', 'activo', 'nuevo') RETURNING id`,
      [ORG_REDNACREM, docD2, `099${RUN_ID}6`, vendedorId]
    );
    createdCandidatoIds.push(candD2.rows[0].id);
    const gestionD2 = await post(`/api/recupero/candidatos/${candD2.rows[0].id}/gestionar`, { status: "no_contesta", note: "No debería poder" });
    console.log(`  [${gestionD2.status}] candidato de otro vendedor:`, JSON.stringify(gestionD2.json));
    expect("d2) gestionar candidato asignado a OTRO vendedor: 403", gestionD2.status === 403, `status=${gestionD2.status}`);

    // ---------------------------------------------------------------
    // e) ventas-historicas y /agenda: seller_id ajeno por query param se
    // ignora, el backend fuerza siempre el propio.
    // ---------------------------------------------------------------
    console.log("\n--- e) /api/seller/ventas-historicas y /agenda ignoran seller_id ajeno ---");

    const ventasHist = await get(`/api/seller/ventas-historicas?type=ventas&seller_id=${vendedorId}`);
    console.log(`  [${ventasHist.status}] ventas-historicas:`, JSON.stringify(ventasHist.json));
    expect("e1) ventas-historicas: 200", ventasHist.status === 200, `status=${ventasHist.status}`);
    expect(
      "e1) ventas-historicas ignora seller_id ajeno del query -- devuelve el propio (comercial.cuenta_como_vendedor)",
      ventasHist.json?.seller_id === backofficeId,
      `seller_id devuelto=${ventasHist.json?.seller_id}, esperado=${backofficeId}`
    );

    const docE1 = `52${RUN_ID}7`;
    const candE1 = await client.query(
      `INSERT INTO recupero_candidatos (organization_id, nombre, apellido, documento, celular, seller_id, estado, estado_administrativo, resultado_gestion)
       VALUES ($1, 'Agenda', 'Propia', $2, $3, $4, 'en_gestion', 'activo', 'nuevo') RETURNING id`,
      [ORG_REDNACREM, docE1, `099${RUN_ID}7`, backofficeId]
    );
    createdCandidatoIds.push(candE1.rows[0].id);
    await client.query(
      `INSERT INTO recupero_agenda (candidato_id, seller_id, fecha_agenda, nota, cumplida) VALUES ($1, $2, NOW() + interval '1 day', 'Agenda propia de backoffice', false)`,
      [candE1.rows[0].id, backofficeId]
    );

    const docE2 = `52${RUN_ID}8`;
    const candE2 = await client.query(
      `INSERT INTO recupero_candidatos (organization_id, nombre, apellido, documento, celular, seller_id, estado, estado_administrativo, resultado_gestion)
       VALUES ($1, 'Agenda', 'Ajena', $2, $3, $4, 'en_gestion', 'activo', 'nuevo') RETURNING id`,
      [ORG_REDNACREM, docE2, `099${RUN_ID}8`, vendedorId]
    );
    createdCandidatoIds.push(candE2.rows[0].id);
    await client.query(
      `INSERT INTO recupero_agenda (candidato_id, seller_id, fecha_agenda, nota, cumplida) VALUES ($1, $2, NOW() + interval '1 day', 'Agenda del otro vendedor', false)`,
      [candE2.rows[0].id, vendedorId]
    );

    const agendaResp = await get(`/api/agenda?seller_id=${vendedorId}&incluir_cumplidas=true`);
    console.log(`  [${agendaResp.status}] agenda:`, JSON.stringify(agendaResp.json));
    expect("e2) /agenda: 200", agendaResp.status === 200, `status=${agendaResp.status}`);
    const agendaItems = agendaResp.json?.data?.items || [];
    const seesOwn = agendaItems.some((it) => it.contact_id === candE1.rows[0].id);
    const seesForeign = agendaItems.some((it) => it.contact_id === candE2.rows[0].id);
    expect("e2) /agenda con seller_id ajeno en el query: ve lo propio (recupero.gestionar_propios fuerza dbUser.id)", seesOwn, `items=${JSON.stringify(agendaItems.map((i) => i.contact_id))}`);
    expect("e2) /agenda con seller_id ajeno en el query: NO ve lo del otro vendedor", !seesForeign, `items=${JSON.stringify(agendaItems.map((i) => i.contact_id))}`);

    // ---------------------------------------------------------------
    // f) /api/supervisor/agents, pedido como supervisor -> aparece
    // backoffice (comercial.asignable)
    // ---------------------------------------------------------------
    console.log("\n--- f) /api/supervisor/agents (pedido como supervisor) ---");
    const agentsResp = await get(`/api/supervisor/agents?search=backoffice`, supervisorHeaders);
    console.log(`  [${agentsResp.status}]`, JSON.stringify(agentsResp.json));
    expect("f) GET /api/supervisor/agents: 200", agentsResp.status === 200, `status=${agentsResp.status}`);
    const agentEmails = (agentsResp.json?.agents || []).map((a) => a.email);
    expect(`f) backoffice (${BACKOFFICE_EMAIL}) aparece en la lista de agentes asignables`, agentEmails.includes(BACKOFFICE_EMAIL), JSON.stringify(agentEmails));

    console.log(`\n=== Resultado: ${results.pass} OK / ${results.fail} FAIL ===`);
  } finally {
    console.log("\n--- Limpieza ---");
    if (createdCandidatoIds.length) {
      const delAgenda = await client.query(`DELETE FROM recupero_agenda WHERE candidato_id = ANY($1) RETURNING id`, [createdCandidatoIds]);
      console.log(`  recupero_agenda borrados: ${delAgenda.rowCount}`);
      const delCand = await client.query(`DELETE FROM recupero_candidatos WHERE id = ANY($1) RETURNING id`, [createdCandidatoIds]);
      console.log(`  recupero_candidatos (d/e) borrados: ${delCand.rowCount}`);
    }
    if (createdContactIds.length) {
      // recupero_candidatos.contact_id no tiene FK a contacts -- hay que
      // borrarla a mano, no cascadea con el DELETE de contacts (igual que
      // en tests/retencion_baja_recupero.mjs).
      const delRecupero = await client.query(`DELETE FROM recupero_candidatos WHERE contact_id = ANY($1) RETURNING id`, [createdContactIds]);
      console.log(`  recupero_candidatos (por contact_id, caso c) borrados: ${delRecupero.rowCount}`);
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
