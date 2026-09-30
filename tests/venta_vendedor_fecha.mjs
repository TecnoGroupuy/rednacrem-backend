#!/usr/bin/env node
// Prueba de punta a punta, REPETIBLE, de los 3 modos de vendedor
// (seller_mode: logueado/asignado/externo) y de la validacion de fecha de
// venta no futura -- agregados para que un supervisor pueda cargar una
// venta que vino de un vendedor externo o de otro vendedor interno sin que
// quede atribuida al usuario logueado (ver resolveSaleSeller en index.mjs y
// CLAUDE.md).
//
// Cubre los dos caminos que un supervisor puede disparar desde el wizard de
// alta manual real:
//   - POST /contacts            (contacto nuevo, wizard "Nuevo cliente")
//   - POST /leads/:id/management (contacto/lead ya existente)
// Cada corrida genera su propio documento/celular (RUN_ID), asi que no
// depende de datos fijos y no colisiona con corridas anteriores. Al
// terminar borra todo lo que creo (los contactos, en cascada, se llevan
// puestos sales/contact_products) y restaura el lead_contact_status de los
// leads que uso en /leads/:id/management -- se puede correr las veces que
// haga falta.
//
// Requisitos:
// - Postgres local con las migraciones 071-078 aplicadas (rednacrem db) y
//   el seed sql/seeds/003_payment_methods_local.sql corrido.
// - local-server.mjs corriendo en :3001 (`node local-server.mjs`, desde
//   rednacrem-backend/, con .env.local).
//
// Uso: node tests/venta_vendedor_fecha.mjs

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
const VENDEDOR_INTERNO_ID = "4162e68c-a0b6-4a8a-9791-a9283f16053b"; // Matias Decker, vendedor Rednacrem
const VENDEDOR_OTRA_ORG_ID = "f948e949-d5e6-4cd6-965e-16129105e07e"; // admin@local.test, SU Emergencia
const PRODUCT_ID = "4c80dfda-0611-49ef-9750-127daf573329"; // "Plan Prueba", ya existente en local
const PAYMENT_METHOD_ID = "40644517-0df3-43bd-99e8-ac508fcabc98"; // Visa, Rednacrem (seed 003)

const RUN_ID = String(Date.now()).slice(-8);
const todayStr = () => new Date().toLocaleDateString("en-CA", { timeZone: "America/Montevideo" });
const daysAgo = (n) => {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toLocaleDateString("en-CA", { timeZone: "America/Montevideo" });
};
const daysAhead = (n) => {
  const d = new Date();
  d.setDate(d.getDate() + n);
  return d.toLocaleDateString("en-CA", { timeZone: "America/Montevideo" });
};

const TODAY = todayStr();
const HACE_5_DIAS = daysAgo(5);
const FUTURA = daysAhead(5);

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

function logResult(label, { status, json }) {
  console.log(`  [${status}] ${label}:`, JSON.stringify(json));
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

  const createdContactDocumentos = [];
  const touchedLeads = []; // { id, original: {...} }
  const TEST_PRODUCT_NAME = `Plan Prueba TEST ${RUN_ID}`;

  try {
    console.log(`\n=== RUN_ID ${RUN_ID} (${TODAY}) ===\n`);

    // ---------------------------------------------------------------
    // Bloque A: POST /contacts (wizard "Nuevo cliente" real -- ClientsView)
    // ---------------------------------------------------------------
    console.log("--- Bloque A: POST /contacts ---");

    const docExterno = `9${RUN_ID}1`;
    const docAsignado = `9${RUN_ID}2`;
    const docLogueado = `9${RUN_ID}3`;
    const docFutura = `9${RUN_ID}4`;
    const docCrossOrg = `9${RUN_ID}5`;

    // products.nombre tiene un indice unico GLOBAL en local (no por
    // organizacion -- ver CLAUDE.md), asi que un nombre fijo como "Plan
    // Prueba" choca con productos de organization_id NULL ya existentes en
    // cuanto createProductAndSale intenta crear su propia fila con
    // organization_id seteado. Se usa un nombre unico por corrida para
    // esquivarlo sin tocar ese indice (fuera de alcance de este feature) y
    // se borra al limpiar (TEST_PRODUCT_NAME, declarado arriba).
    const contactsProduct = (fechaAlta) => ({
      nombreProducto: TEST_PRODUCT_NAME,
      nombre_producto: TEST_PRODUCT_NAME,
      plan: "Plan estándar",
      precio: 100,
      payment_method_id: PAYMENT_METHOD_ID,
      medio_pago: "Visa",
      fechaAlta,
      estado: "alta"
    });

    const celular = (scenarioDigit) => `09${RUN_ID.slice(-6)}${scenarioDigit}`;

    console.log("1) Vendedor externo 'Matías Decker', fecha de venta hace 5 días");
    const r1 = await post("/contacts", {
      contact: { nombre: "Test", apellido: "Externo", documento: docExterno, celular: celular(1) },
      seller_mode: "externo",
      vendedor_nombre: "Matías Decker",
      fecha_venta: HACE_5_DIAS,
      products: [contactsProduct(HACE_5_DIAS)]
    });
    logResult("POST /contacts externo", r1);
    expect("externo: 200/201", [200, 201].includes(r1.status), `status=${r1.status}`);
    if ([200, 201].includes(r1.status)) createdContactDocumentos.push(docExterno);

    console.log("2) Vendedor asignado (otro vendedor de Rednacrem)");
    const r2 = await post("/contacts", {
      contact: { nombre: "Test", apellido: "Asignado", documento: docAsignado, celular: celular(2) },
      seller_mode: "asignado",
      vendedor_id: VENDEDOR_INTERNO_ID,
      fecha_venta: TODAY,
      products: [contactsProduct(TODAY)]
    });
    logResult("POST /contacts asignado", r2);
    expect("asignado: 200/201", [200, 201].includes(r2.status), `status=${r2.status}`);
    if ([200, 201].includes(r2.status)) createdContactDocumentos.push(docAsignado);

    console.log("3) Usuario logueado, fecha de hoy");
    const r3 = await post("/contacts", {
      contact: { nombre: "Test", apellido: "Logueado", documento: docLogueado, celular: celular(3) },
      seller_mode: "logueado",
      fecha_venta: TODAY,
      products: [contactsProduct(TODAY)]
    });
    logResult("POST /contacts logueado", r3);
    expect("logueado: 200/201", [200, 201].includes(r3.status), `status=${r3.status}`);
    if ([200, 201].includes(r3.status)) createdContactDocumentos.push(docLogueado);

    console.log("4) Fecha futura -- se espera 400");
    const r4 = await post("/contacts", {
      contact: { nombre: "Test", apellido: "Futura", documento: docFutura, celular: celular(4) },
      seller_mode: "logueado",
      fecha_venta: FUTURA,
      products: [contactsProduct(FUTURA)]
    });
    logResult("POST /contacts fecha futura", r4);
    expect("fecha futura: 400", r4.status === 400, `status=${r4.status}`);

    console.log("5) Vendedor asignado de OTRA organización -- se espera 400");
    const r5 = await post("/contacts", {
      contact: { nombre: "Test", apellido: "CrossOrg", documento: docCrossOrg, celular: celular(5) },
      seller_mode: "asignado",
      vendedor_id: VENDEDOR_OTRA_ORG_ID,
      fecha_venta: TODAY,
      products: [contactsProduct(TODAY)]
    });
    logResult("POST /contacts vendedor cross-org", r5);
    expect("vendedor cross-org: 400", r5.status === 400, `status=${r5.status}`);

    if (createdContactDocumentos.length) {
      const { rows } = await client.query(
        `
        SELECT c.documento, s.seller_user_id, u.nombre AS seller_nombre, u.apellido AS seller_apellido,
               s.seller_name_snapshot, s.seller_origin, s.fecha_venta, s.registrada_por_user_id,
               ru.nombre AS registrada_por_nombre, ru.apellido AS registrada_por_apellido
        FROM sales s
        JOIN contacts c ON c.id = s.contact_id
        LEFT JOIN users u ON u.id = s.seller_user_id
        LEFT JOIN users ru ON ru.id = s.registrada_por_user_id
        WHERE c.documento = ANY($1)
        ORDER BY s.created_at
        `,
        [createdContactDocumentos]
      );
      console.log("\n  Filas en sales (POST /contacts):");
      console.table(rows);

      const { rows: cpRows } = await client.query(
        `
        SELECT c.documento, cp.seller_user_id, cp.seller_name_snapshot, cp.seller_origin, cp.fecha_alta
        FROM contact_products cp
        JOIN contacts c ON c.id = cp.contact_id
        WHERE c.documento = ANY($1)
        ORDER BY cp.created_at
        `,
        [createdContactDocumentos]
      );
      console.log("  Filas en contact_products (POST /contacts):");
      console.table(cpRows);
    }

    // ---------------------------------------------------------------
    // Bloque B: POST /leads/:id/management (contacto/lead ya existente)
    // ---------------------------------------------------------------
    console.log("\n--- Bloque B: POST /leads/:id/management ---");

    const { rows: freshLeads } = await client.query(
      `
      SELECT lcs.contact_id
      FROM lead_contact_status lcs
      JOIN datos_para_trabajar d ON d.id = lcs.contact_id
      WHERE lcs.organization_id = $1
        AND lcs.estado_venta <> 'venta'
        AND d.telefono IN (
          SELECT telefono FROM datos_para_trabajar
          WHERE organization_id = $1
          GROUP BY telefono
          HAVING COUNT(*) = 1
        )
      ORDER BY random()
      LIMIT 5
      `,
      [ORG_REDNACREM]
    );
    if (freshLeads.length < 5) {
      console.log(`  No hay suficientes leads libres (encontrados ${freshLeads.length}/5) -- se salta el Bloque B.`);
    } else {
      for (const row of freshLeads) {
        const { rows: statusRows } = await client.query(
          `SELECT estado_venta, intentos, proxima_accion, batch_id, assigned_to, ola_actual
           FROM lead_contact_status WHERE contact_id = $1 AND organization_id = $2`,
          [row.contact_id, ORG_REDNACREM]
        );
        touchedLeads.push({ id: row.contact_id, original: statusRows[0] || null });
      }

      const [leadExterno, leadAsignado, leadLogueado, leadFutura, leadCrossOrg] = touchedLeads.map((t) => t.id);
      const mgmtDocExterno = `8${RUN_ID}1`;
      const mgmtDocAsignado = `8${RUN_ID}2`;
      const mgmtDocLogueado = `8${RUN_ID}3`;
      const mgmtDocFutura = `8${RUN_ID}4`;
      const mgmtDocCrossOrg = `8${RUN_ID}5`;

      const mgmtProduct = (fechaAlta) => ({ id: PRODUCT_ID, nombre: "Plan Prueba", precio: 100, fecha_alta: fechaAlta });

      console.log("1) [management] Vendedor externo 'Matías Decker', fecha hace 5 días");
      const m1 = await post(`/leads/${leadExterno}/management`, {
        status: "venta",
        contact: { documento: mgmtDocExterno, nombre: "Mgmt", apellido: "Externo" },
        seller_mode: "externo",
        vendedor_nombre: "Matías Decker",
        product: mgmtProduct(HACE_5_DIAS),
        medio_pago: "efectivo"
      });
      logResult("management externo", m1);
      expect("management externo: ok", m1.json?.ok === true, JSON.stringify(m1.json));
      if (m1.json?.ok) createdContactDocumentos.push(mgmtDocExterno);

      console.log("2) [management] Vendedor asignado explícito");
      const m2 = await post(`/leads/${leadAsignado}/management`, {
        status: "venta",
        contact: { documento: mgmtDocAsignado, nombre: "Mgmt", apellido: "Asignado" },
        seller_mode: "asignado",
        vendedor_id: VENDEDOR_INTERNO_ID,
        product: mgmtProduct(TODAY),
        medio_pago: "efectivo"
      });
      logResult("management asignado", m2);
      expect("management asignado: ok", m2.json?.ok === true, JSON.stringify(m2.json));
      if (m2.json?.ok) createdContactDocumentos.push(mgmtDocAsignado);

      console.log("3) [management] Usuario logueado, fecha de hoy");
      const m3 = await post(`/leads/${leadLogueado}/management`, {
        status: "venta",
        contact: { documento: mgmtDocLogueado, nombre: "Mgmt", apellido: "Logueado" },
        seller_mode: "logueado",
        product: mgmtProduct(TODAY),
        medio_pago: "efectivo"
      });
      logResult("management logueado", m3);
      expect("management logueado: ok", m3.json?.ok === true, JSON.stringify(m3.json));
      if (m3.json?.ok) createdContactDocumentos.push(mgmtDocLogueado);

      console.log("4) [management] Fecha futura -- se espera 400");
      const m4 = await post(`/leads/${leadFutura}/management`, {
        status: "venta",
        contact: { documento: mgmtDocFutura, nombre: "Mgmt", apellido: "Futura" },
        seller_mode: "logueado",
        product: mgmtProduct(FUTURA),
        medio_pago: "efectivo"
      });
      logResult("management fecha futura", m4);
      expect("management fecha futura: 400", m4.status === 400, `status=${m4.status}`);

      console.log("5) [management] Vendedor asignado de OTRA organización -- se espera 400");
      const m5 = await post(`/leads/${leadCrossOrg}/management`, {
        status: "venta",
        contact: { documento: mgmtDocCrossOrg, nombre: "Mgmt", apellido: "CrossOrg" },
        seller_mode: "asignado",
        vendedor_id: VENDEDOR_OTRA_ORG_ID,
        product: mgmtProduct(TODAY),
        medio_pago: "efectivo"
      });
      logResult("management vendedor cross-org", m5);
      expect("management vendedor cross-org: 400", m5.status === 400, `status=${m5.status}`);

      const { rows: mgmtSalesRows } = await client.query(
        `
        SELECT c.documento, s.seller_user_id, u.nombre AS seller_nombre, u.apellido AS seller_apellido,
               s.seller_name_snapshot, s.seller_origin, s.fecha_venta, s.registrada_por_user_id
        FROM sales s
        JOIN contacts c ON c.id = s.contact_id
        LEFT JOIN users u ON u.id = s.seller_user_id
        WHERE c.documento = ANY($1)
        ORDER BY s.created_at
        `,
        [[mgmtDocExterno, mgmtDocAsignado, mgmtDocLogueado]]
      );
      console.log("\n  Filas en sales (/leads/:id/management):");
      console.table(mgmtSalesRows);
    }

    console.log(`\n=== Resultado: ${results.pass} OK / ${results.fail} FAIL ===`);
  } finally {
    // -----------------------------------------------------------------
    // Cleanup: borra todo lo creado por esta corrida (los contactos se
    // llevan puestos sales/contact_products por ON DELETE CASCADE) y
    // restaura lead_contact_status de los leads usados en el Bloque B.
    // -----------------------------------------------------------------
    console.log("\n--- Limpieza ---");
    if (createdContactDocumentos.length) {
      const del = await client.query(
        `DELETE FROM contacts WHERE documento = ANY($1) RETURNING id`,
        [createdContactDocumentos]
      );
      console.log(`  Contactos borrados (cascada a sales/contact_products): ${del.rowCount}`);
    }
    const delProduct = await client.query(
      `DELETE FROM products WHERE lower(nombre) = lower($1) RETURNING id`,
      [TEST_PRODUCT_NAME]
    );
    if (delProduct.rowCount) {
      console.log(`  Producto de prueba "${TEST_PRODUCT_NAME}" borrado.`);
    }
    for (const lead of touchedLeads) {
      if (!lead.original) continue;
      await client.query(
        `
        UPDATE lead_contact_status
        SET estado_venta = $2, intentos = $3, proxima_accion = $4, batch_id = $5, assigned_to = $6, ola_actual = $7
        WHERE contact_id = $1
        `,
        [
          lead.id,
          lead.original.estado_venta,
          lead.original.intentos,
          lead.original.proxima_accion,
          lead.original.batch_id,
          lead.original.assigned_to,
          lead.original.ola_actual
        ]
      );
    }
    if (touchedLeads.length) {
      console.log(`  lead_contact_status restaurado para ${touchedLeads.length} lead(s).`);
    }
    await client.end();
  }

  process.exit(results.fail > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("ERROR", err);
  process.exit(1);
});
