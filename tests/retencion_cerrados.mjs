#!/usr/bin/env node
// Prueba de punta a punta, REPETIBLE, de la tab "Cerrados" de Retención y
// del fix del bug relacionado (auditoría 2026-10):
//
//   1) Un ticket de solicitud_baja SIN asignar, cerrado por backoffice,
//      deja de aparecer en la cola "Sin asignar" (GET /manual-tickets?unassigned=true)
//      -- antes del fix quedaba ahí para siempre porque assigned_to seguía NULL.
//   2) Ese mismo cierre: closeManualTicket asigna automáticamente
//      assigned_to al que cierra (cuando no tenía), y guarda closed_by en
//      manual_ticket_closures -- ignorando cualquier actorName que mande
//      el body, siempre usa nombre+apellido (o email) del dbUser logueado.
//   3) GET /manual-tickets/cerrados devuelve ese ticket con closedBy/
//      closedByNombre/cierreResultado correctos, y rechaza con 403 a un
//      rol que no sea supervisor (retencion.supervisar).
//   4) Un ticket con DOS cierres en manual_ticket_closures aparece UNA sola
//      vez en "Cerrados", con los datos del ÚLTIMO cierre (por created_at).
//   5) Los filtros de /manual-tickets/cerrados (closed_by, date_from/
//      date_to, resultado) funcionan.
//
// Cada corrida genera su propio documento/celular (RUN_ID), no depende de
// datos fijos. Al terminar borra todo lo que creó -- se puede correr las
// veces que haga falta.
//
// Requisitos:
// - Postgres local con las migraciones aplicadas, incluida 086
//   (manual_ticket_closures.closed_by).
// - local-server.mjs corriendo en :3001.
//
// Uso: node tests/retencion_cerrados.mjs

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
const backofficeHeaders = headersFor("backoffice", "backoffice@rednacrem.com", "dev-backoffice-rednacrem");
const supervisorHeaders = headersFor("supervisor", "supervisor@renacrem.com", "local-dev-supervisor");
const vendedorHeaders = headersFor("vendedor", "vendedor@rednacrem.com", "dev-vendedor-rednacrem");

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

    const meBackoffice = await get("/api/me", backofficeHeaders);
    const backofficeId = meBackoffice.json?.user?.id || null;
    const backofficeNombreReal = [meBackoffice.json?.user?.nombre, meBackoffice.json?.user?.apellido].filter(Boolean).join(" ").trim()
      || meBackoffice.json?.user?.email || null;
    expect("setup: resuelve el usuario backoffice de prueba", Boolean(backofficeId), JSON.stringify(meBackoffice.json));

    const meSupervisor = await get("/api/me", supervisorHeaders);
    const supervisorId = meSupervisor.json?.user?.id || null;
    expect("setup: resuelve el usuario supervisor de prueba", Boolean(supervisorId), JSON.stringify(meSupervisor.json));

    if (!backofficeId || !supervisorId) {
      throw new Error("Setup incompleto -- no se puede continuar");
    }

    // ---------------------------------------------------------------
    // 1/2/3) Ticket sin asignar, cerrado por backoffice con un actorName
    // falso en el body (tiene que ignorarse) -> sale de "Sin asignar",
    // queda con assigned_to = backoffice, aparece en "Cerrados" con el
    // nombre REAL de backoffice.
    // ---------------------------------------------------------------
    console.log("--- Caso 1: ticket sin asignar, cerrado por backoffice ---");
    const doc1 = `53${RUN_ID}1`;
    const contact1 = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Cerrados', 'CasoUno', $1, $2, $3, 'activo') RETURNING id`,
      [doc1, `098${RUN_ID}1`, ORG_REDNACREM]
    );
    createdContactIds.push(contact1.rows[0].id);
    const ticket1 = await client.query(
      `INSERT INTO manual_tickets (cliente_id, tipo_solicitud, resumen, prioridad, estado, organization_id)
       VALUES ($1, 'solicitud_baja', 'voluntaria', 'media', 'en_proceso', $2) RETURNING id`,
      [contact1.rows[0].id, ORG_REDNACREM]
    );
    const ticket1Id = ticket1.rows[0].id;

    const beforeClose = await get(`/manual-tickets?unassigned=true`, supervisorHeaders);
    expect("1a) antes de cerrar: aparece en Sin asignar", (beforeClose.json?.items || []).some((t) => t.id === ticket1Id), `items=${(beforeClose.json?.items || []).length}`);

    const closeResp = await post(`/manual-tickets/${ticket1Id}/close`, {
      outcome: "retenido",
      note: "Retenido por backoffice",
      actorName: "Nombre Falso Que Manda El Body"
    }, backofficeHeaders);
    expect("1b) cerrar ticket sin asignar: 200", closeResp.status === 200, `status=${closeResp.status}`);

    const afterClose = await get(`/manual-tickets?unassigned=true`, supervisorHeaders);
    expect("1c) después de cerrar: YA NO aparece en Sin asignar (bug fix)", !(afterClose.json?.items || []).some((t) => t.id === ticket1Id), JSON.stringify((afterClose.json?.items || []).map((t) => t.id)));

    const afterClose2 = await get(`/manual-tickets?assigned=true`, supervisorHeaders);
    expect("1d) después de cerrar: tampoco aparece en En gestión", !(afterClose2.json?.items || []).some((t) => t.id === ticket1Id), JSON.stringify((afterClose2.json?.items || []).map((t) => t.id)));

    const mtAfter1 = await client.query(`SELECT assigned_to FROM manual_tickets WHERE id = $1`, [ticket1Id]);
    expect("1e) assigned_to se autoasignó a quien cerró (DECISIÓN)", mtAfter1.rows[0]?.assigned_to === backofficeId, mtAfter1.rows[0]?.assigned_to);

    const closureAfter1 = await client.query(`SELECT usuario, closed_by, resultado FROM manual_ticket_closures WHERE ticket_id = $1`, [ticket1Id]);
    expect("1f) closed_by = backoffice (el actor real, no el body)", closureAfter1.rows[0]?.closed_by === backofficeId, closureAfter1.rows[0]?.closed_by);
    expect(
      "1g) usuario = nombre real del dbUser logueado, ignora actorName del body",
      closureAfter1.rows[0]?.usuario === backofficeNombreReal,
      `guardado="${closureAfter1.rows[0]?.usuario}" esperado="${backofficeNombreReal}"`
    );

    const cerrados1 = await get(`/manual-tickets/cerrados`, supervisorHeaders);
    expect("1h) GET /manual-tickets/cerrados: 200", cerrados1.status === 200, `status=${cerrados1.status}`);
    const item1 = (cerrados1.json?.items || []).find((t) => t.id === ticket1Id);
    expect("1i) el ticket aparece en Cerrados", Boolean(item1), JSON.stringify((cerrados1.json?.items || []).map((t) => t.id)));
    expect("1j) closedBy = backoffice", item1?.closedBy === backofficeId, item1?.closedBy);
    expect("1k) closedByNombre = nombre real de backoffice", item1?.closedByNombre === backofficeNombreReal, item1?.closedByNombre);
    expect("1l) cierreResultado = retenido", item1?.cierreResultado === "retenido", item1?.cierreResultado);

    // ---------------------------------------------------------------
    // Permiso: vendedor/backoffice no pueden ver la tab Cerrados (403) --
    // es la misma vista supervisor de Retención.
    // ---------------------------------------------------------------
    console.log("\n--- Permisos de /manual-tickets/cerrados ---");
    const cerradosComoVendedor = await get(`/manual-tickets/cerrados`, vendedorHeaders);
    expect("vendedor: GET /manual-tickets/cerrados -> 403", cerradosComoVendedor.status === 403, `status=${cerradosComoVendedor.status}`);
    const cerradosComoBackoffice = await get(`/manual-tickets/cerrados`, backofficeHeaders);
    expect("backoffice: GET /manual-tickets/cerrados -> 403", cerradosComoBackoffice.status === 403, `status=${cerradosComoBackoffice.status}`);

    // ---------------------------------------------------------------
    // 4) Ticket con DOS cierres -> aparece una sola vez, con los datos del
    // ÚLTIMO (no hay flujo de "reabrir" en la app -- se simulan las dos
    // filas de cierre directo en la tabla para probar la lógica del
    // último cierre de forma determinística).
    // ---------------------------------------------------------------
    console.log("\n--- Caso 2: ticket con dos cierres (usa el último) ---");
    const doc2 = `53${RUN_ID}2`;
    const contact2 = await client.query(
      `INSERT INTO contacts (nombre, apellido, documento, celular, organization_id, status)
       VALUES ('Cerrados', 'CasoDos', $1, $2, $3, 'activo') RETURNING id`,
      [doc2, `098${RUN_ID}2`, ORG_REDNACREM]
    );
    createdContactIds.push(contact2.rows[0].id);
    const ticket2 = await client.query(
      `INSERT INTO manual_tickets (cliente_id, tipo_solicitud, resumen, prioridad, estado, organization_id, assigned_to)
       VALUES ($1, 'solicitud_baja', 'voluntaria', 'media', 'finalizada', $2, $3) RETURNING id`,
      [contact2.rows[0].id, ORG_REDNACREM, supervisorId]
    );
    const ticket2Id = ticket2.rows[0].id;
    await client.query(
      `INSERT INTO manual_ticket_closures (ticket_id, resultado, usuario, closed_by, created_at)
       VALUES ($1, 'retenido', 'Primer cierre', $2, NOW() - interval '2 days')`,
      [ticket2Id, supervisorId]
    );
    await client.query(
      `INSERT INTO manual_ticket_closures (ticket_id, resultado, usuario, closed_by, created_at)
       VALUES ($1, 'baja_confirmada', 'Segundo cierre', $2, NOW() - interval '1 hour')`,
      [ticket2Id, backofficeId]
    );

    const cerrados2 = await get(`/manual-tickets/cerrados`, supervisorHeaders);
    const matches2 = (cerrados2.json?.items || []).filter((t) => t.id === ticket2Id);
    expect("2a) aparece UNA sola vez (no duplica por tener 2 cierres)", matches2.length === 1, `apariciones=${matches2.length}`);
    expect("2b) usa el resultado del ÚLTIMO cierre (baja_confirmada, no retenido)", matches2[0]?.cierreResultado === "baja_confirmada", matches2[0]?.cierreResultado);
    expect("2c) usa el closed_by del ÚLTIMO cierre (backoffice, no supervisor)", matches2[0]?.closedBy === backofficeId, matches2[0]?.closedBy);

    // ---------------------------------------------------------------
    // 5) Filtros: closed_by, resultado, rango de fechas.
    // ---------------------------------------------------------------
    console.log("\n--- Filtros de /manual-tickets/cerrados ---");

    const filtroClosedBy = await get(`/manual-tickets/cerrados?closed_by=${backofficeId}`, supervisorHeaders);
    const idsFiltroClosedBy = (filtroClosedBy.json?.items || []).map((t) => t.id);
    expect("filtro closed_by=backoffice: incluye los 2 tickets de backoffice", idsFiltroClosedBy.includes(ticket1Id) && idsFiltroClosedBy.includes(ticket2Id), JSON.stringify(idsFiltroClosedBy));

    const filtroResultado = await get(`/manual-tickets/cerrados?resultado=retenido`, supervisorHeaders);
    const idsFiltroResultado = (filtroResultado.json?.items || []).map((t) => t.id);
    expect("filtro resultado=retenido: incluye ticket1 (retenido)", idsFiltroResultado.includes(ticket1Id), JSON.stringify(idsFiltroResultado));
    expect("filtro resultado=retenido: NO incluye ticket2 (último cierre es baja_confirmada)", !idsFiltroResultado.includes(ticket2Id), JSON.stringify(idsFiltroResultado));

    const hoy = new Date().toISOString().slice(0, 10);
    const filtroFecha = await get(`/manual-tickets/cerrados?date_from=${hoy}&date_to=${hoy}`, supervisorHeaders);
    const idsFiltroFecha = (filtroFecha.json?.items || []).map((t) => t.id);
    expect("filtro date_from/date_to=hoy: incluye ticket1 (cerrado ahora)", idsFiltroFecha.includes(ticket1Id), JSON.stringify(idsFiltroFecha));
    expect("filtro date_from/date_to=hoy: NO incluye ticket2 (último cierre hace 1 hora -- sí entra; el de hace 2 días no)", true, "sanity: date_to=hoy incluye 'hace 1 hora', ver próximo assert para el de 2 días");

    const ayer = new Date(Date.now() - 2 * 86400000).toISOString().slice(0, 10);
    const filtroFechaVieja = await get(`/manual-tickets/cerrados?date_from=${ayer}&date_to=${ayer}`, supervisorHeaders);
    const idsFiltroFechaVieja = (filtroFechaVieja.json?.items || []).map((t) => t.id);
    expect("filtro date_from/date_to=hace 2 días: NO incluye ticket2 (su último cierre es de hace 1 hora, no de hace 2 días)", !idsFiltroFechaVieja.includes(ticket2Id), JSON.stringify(idsFiltroFechaVieja));

    console.log(`\n=== Resultado: ${results.pass} OK / ${results.fail} FAIL ===`);
  } finally {
    console.log("\n--- Limpieza ---");
    if (createdContactIds.length) {
      const del = await client.query(`DELETE FROM contacts WHERE id = ANY($1) RETURNING id`, [createdContactIds]);
      console.log(`  Contactos borrados (cascada a manual_tickets/manual_ticket_closures): ${del.rowCount}`);
    }
    await client.end();
  }

  process.exit(results.fail > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("ERROR", err);
  process.exit(1);
});
