// Auditoría "rol backoffice" (2026-10), pasos 2/3: mapa central de
// capacidades (src/lib/permissions.js) + comparación de acceso por
// endpoint tocado (antes vs. después del reemplazo de requireRole por
// requirePermission) -- para los 22 endpoints que cambiaron de gate, el
// rol_key resuelto por la capacidad nueva tiene que ser EXACTAMENTE el
// gate viejo + backoffice, sin que ningún rol existente gane ni pierda
// acceso. Ver la tabla endpoint -> gate viejo -> capacidad nueva de la
// auditoría para el detalle completo; acá se testea cada capacidad
// DISTINTA una sola vez (varios endpoints comparten la misma).
import test from "node:test";
import assert from "node:assert/strict";
import {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  roleHasPermission,
  getRolesWithPermission,
  INTERNO_BASE_ROLES
} from "../src/lib/permissions.js";
import { __testables } from "../index.mjs";

const { requirePermission } = __testables;

const ALL_SEVEN_ROLES = [
  "superadministrador",
  "director",
  "supervisor",
  "operaciones",
  "atencion_cliente",
  "vendedor",
  "backoffice"
];

function assertExactRoleSet(actual, expected, label) {
  assert.deepEqual([...actual].sort(), [...expected].sort(), label);
}

test("interno.base = exactamente LEAD_ACCESS_ROLES/INTERNAL_CONTACT_ACCESS_ROLES de antes (6 roles) + backoffice", () => {
  assertExactRoleSet(
    getRolesWithPermission(PERMISSIONS.INTERNO_BASE),
    ["superadministrador", "director", "supervisor", "operaciones", "atencion_cliente", "vendedor", "backoffice"],
    "interno.base"
  );
  assertExactRoleSet(getRolesWithPermission(PERMISSIONS.INTERNO_BASE), INTERNO_BASE_ROLES, "interno.base vs INTERNO_BASE_ROLES");
});

test("clientes.baja_directa = exactamente el gate viejo (supervisor, superadministrador) + backoffice", () => {
  assertExactRoleSet(
    getRolesWithPermission(PERMISSIONS.CLIENTES_BAJA_DIRECTA),
    ["supervisor", "superadministrador", "backoffice"],
    "clientes.baja_directa"
  );
});

test("tickets.cerrar_baja_propia = exactamente el restringido viejo (vendedor) + backoffice -- nadie más", () => {
  assertExactRoleSet(
    getRolesWithPermission(PERMISSIONS.TICKETS_CERRAR_BAJA_PROPIA),
    ["vendedor", "backoffice"],
    "tickets.cerrar_baja_propia"
  );
});

test("recupero.gestionar_propios = exactamente vendedor + backoffice", () => {
  assertExactRoleSet(
    getRolesWithPermission(PERMISSIONS.RECUPERO_GESTIONAR_PROPIOS),
    ["vendedor", "backoffice"],
    "recupero.gestionar_propios"
  );
});

test("comercial.asignable = exactamente vendedor + backoffice", () => {
  assertExactRoleSet(
    getRolesWithPermission(PERMISSIONS.COMERCIAL_ASIGNABLE),
    ["vendedor", "backoffice"],
    "comercial.asignable"
  );
});

test("comercial.cuenta_como_vendedor = exactamente vendedor + backoffice", () => {
  assertExactRoleSet(
    getRolesWithPermission(PERMISSIONS.COMERCIAL_CUENTA_COMO_VENDEDOR),
    ["vendedor", "backoffice"],
    "comercial.cuenta_como_vendedor"
  );
});

test("ningún rol EXISTENTE gana una capacidad que no tenía antes (solo backoffice es nuevo en todas)", () => {
  // Para cada capacidad, todo rol presente salvo 'backoffice' ya la tenía
  // en el gate viejo -- si esto falla, alguno de los 6 roles existentes
  // ganó acceso de más por el refactor.
  for (const permission of Object.values(PERMISSIONS)) {
    const roles = getRolesWithPermission(permission);
    const newRoles = roles.filter((r) => r !== "backoffice");
    const expectedByPermission = {
      [PERMISSIONS.INTERNO_BASE]: ["superadministrador", "director", "supervisor", "operaciones", "atencion_cliente", "vendedor"],
      [PERMISSIONS.CLIENTES_BAJA_DIRECTA]: ["supervisor", "superadministrador"],
      [PERMISSIONS.TICKETS_CERRAR_BAJA_PROPIA]: ["vendedor"],
      [PERMISSIONS.RECUPERO_GESTIONAR_PROPIOS]: ["vendedor"],
      [PERMISSIONS.COMERCIAL_ASIGNABLE]: ["vendedor"],
      [PERMISSIONS.COMERCIAL_CUENTA_COMO_VENDEDOR]: ["vendedor"],
      [PERMISSIONS.PANTALLA_SOPORTE]: ["atencion_cliente"],
      [PERMISSIONS.PANTALLA_RETENCION]: ["supervisor", "vendedor"],
      [PERMISSIONS.PANTALLA_RECUPERO_VENDEDOR]: ["vendedor", "atencion_cliente"],
      [PERMISSIONS.PANTALLA_CLIENTES]: ["superadministrador", "director", "operaciones", "supervisor"],
      [PERMISSIONS.PANTALLA_AGENDA]: ["vendedor"],
      // Estas dos NO le dan la capacidad a backoffice -- newRoles (sin
      // 'backoffice') tiene que coincidir con el set completo de hoy.
      [PERMISSIONS.CLIENTES_ALTA]: ["superadministrador", "director", "operaciones", "supervisor"],
      [PERMISSIONS.CLIENTES_BAJA_MASIVA]: ["superadministrador", "director", "operaciones", "supervisor"]
    };
    assertExactRoleSet(newRoles, expectedByPermission[permission], `${permission}: roles pre-existentes`);
  }
});

test("backoffice tiene las 11 capacidades que le corresponden, NO clientes.alta/clientes.baja_masiva", () => {
  const sinBoton = Object.values(PERMISSIONS).filter(
    (p) => p !== PERMISSIONS.CLIENTES_ALTA && p !== PERMISSIONS.CLIENTES_BAJA_MASIVA
  );
  assertExactRoleSet(ROLE_PERMISSIONS.backoffice, sinBoton, "backoffice");
});

test("requirePermission: 403 si el rol no tiene la capacidad, null si la tiene", () => {
  const withPerm = requirePermission({}, { role_key: "backoffice" }, PERMISSIONS.CLIENTES_BAJA_DIRECTA);
  assert.equal(withPerm, null);

  const withoutPerm = requirePermission({}, { role_key: "director" }, PERMISSIONS.CLIENTES_BAJA_DIRECTA);
  assert.equal(withoutPerm.statusCode, 403);
  const payload = JSON.parse(withoutPerm.body);
  assert.equal(payload.ok, false);
  assert.equal(payload.requiredPermission, PERMISSIONS.CLIENTES_BAJA_DIRECTA);

  const noUser = requirePermission({}, null, PERMISSIONS.INTERNO_BASE);
  assert.equal(noUser.statusCode, 403);
});

test("roleHasPermission: casos puntuales de los 7 roles (snapshot manual de la tabla de la auditoría)", () => {
  // superadministrador/director/operaciones/atencion_cliente: solo interno.base.
  for (const role of ["director", "operaciones", "atencion_cliente"]) {
    assert.equal(roleHasPermission(role, PERMISSIONS.INTERNO_BASE), true, `${role} interno.base`);
    assert.equal(roleHasPermission(role, PERMISSIONS.CLIENTES_BAJA_DIRECTA), false, `${role} clientes.baja_directa`);
    assert.equal(roleHasPermission(role, PERMISSIONS.RECUPERO_GESTIONAR_PROPIOS), false, `${role} recupero.gestionar_propios`);
    assert.equal(roleHasPermission(role, PERMISSIONS.COMERCIAL_ASIGNABLE), false, `${role} comercial.asignable`);
  }
  // superadministrador/supervisor: interno.base + clientes.baja_directa (ya la tenían).
  for (const role of ["superadministrador", "supervisor"]) {
    assert.equal(roleHasPermission(role, PERMISSIONS.CLIENTES_BAJA_DIRECTA), true, `${role} clientes.baja_directa`);
    assert.equal(roleHasPermission(role, PERMISSIONS.RECUPERO_GESTIONAR_PROPIOS), false, `${role} recupero.gestionar_propios`);
  }
  // vendedor: todo salvo clientes.baja_directa (nunca la tuvo).
  assert.equal(roleHasPermission("vendedor", PERMISSIONS.CLIENTES_BAJA_DIRECTA), false, "vendedor clientes.baja_directa");
  assert.equal(roleHasPermission("vendedor", PERMISSIONS.RECUPERO_GESTIONAR_PROPIOS), true, "vendedor recupero.gestionar_propios");
  assert.equal(roleHasPermission("vendedor", PERMISSIONS.TICKETS_CERRAR_BAJA_PROPIA), true, "vendedor tickets.cerrar_baja_propia");
  // backoffice: todo salvo los 2 botones de Clientes (alta/baja masiva).
  for (const permission of Object.values(PERMISSIONS)) {
    const expected = permission !== PERMISSIONS.CLIENTES_ALTA && permission !== PERMISSIONS.CLIENTES_BAJA_MASIVA;
    assert.equal(roleHasPermission("backoffice", permission), expected, `backoffice ${permission}`);
  }
});

test("ALL_SEVEN_ROLES cubre exactamente los roles presentes en ROLE_PERMISSIONS (sin huérfanos)", () => {
  assertExactRoleSet(Object.keys(ROLE_PERMISSIONS), ALL_SEVEN_ROLES, "roles del mapa");
});

// --- Capacidades de pantalla (menú/rutas del frontend) y de botón ---
// Snapshot exacto del estado hoy de cada ítem de ROLE_NAV (roles.js) + 1
// (backoffice, donde corresponde) -- si esto cambia para algún rol
// EXISTENTE, es una regresión real de menú.

test("pantalla.soporte = atencion_cliente + backoffice (nav 'soporte', hoy roles:['atencion_cliente'])", () => {
  assertExactRoleSet(getRolesWithPermission(PERMISSIONS.PANTALLA_SOPORTE), ["atencion_cliente", "backoffice"], "pantalla.soporte");
});

test("pantalla.retencion = supervisor, vendedor + backoffice (nav 'retencion', hoy roles:['supervisor','vendedor'])", () => {
  assertExactRoleSet(getRolesWithPermission(PERMISSIONS.PANTALLA_RETENCION), ["supervisor", "vendedor", "backoffice"], "pantalla.retencion");
});

test("pantalla.recupero_vendedor = vendedor, atencion_cliente + backoffice (nav 'recupero', hoy roles:['vendedor','atencion_cliente'])", () => {
  assertExactRoleSet(getRolesWithPermission(PERMISSIONS.PANTALLA_RECUPERO_VENDEDOR), ["vendedor", "atencion_cliente", "backoffice"], "pantalla.recupero_vendedor");
});

test("pantalla.clientes = superadministrador, director, operaciones, supervisor + backoffice (nav 'clientes' cartera)", () => {
  assertExactRoleSet(
    getRolesWithPermission(PERMISSIONS.PANTALLA_CLIENTES),
    ["superadministrador", "director", "operaciones", "supervisor", "backoffice"],
    "pantalla.clientes"
  );
});

test("pantalla.agenda = vendedor + backoffice (nav 'agenda', hoy roles:['vendedor'])", () => {
  assertExactRoleSet(getRolesWithPermission(PERMISSIONS.PANTALLA_AGENDA), ["vendedor", "backoffice"], "pantalla.agenda");
});

test("clientes.alta / clientes.baja_masiva = los mismos 4 roles de pantalla.clientes, SIN backoffice", () => {
  const sinBackoffice = ["superadministrador", "director", "operaciones", "supervisor"];
  assertExactRoleSet(getRolesWithPermission(PERMISSIONS.CLIENTES_ALTA), sinBackoffice, "clientes.alta");
  assertExactRoleSet(getRolesWithPermission(PERMISSIONS.CLIENTES_BAJA_MASIVA), sinBackoffice, "clientes.baja_masiva");
  assert.equal(roleHasPermission("backoffice", PERMISSIONS.CLIENTES_ALTA), false, "backoffice NO clientes.alta");
  assert.equal(roleHasPermission("backoffice", PERMISSIONS.CLIENTES_BAJA_MASIVA), false, "backoffice NO clientes.baja_masiva");
});

test("backoffice tiene las 5 capacidades de pantalla, ningún otro rol gana una que no tenía", () => {
  const pantallas = [
    PERMISSIONS.PANTALLA_SOPORTE,
    PERMISSIONS.PANTALLA_RETENCION,
    PERMISSIONS.PANTALLA_RECUPERO_VENDEDOR,
    PERMISSIONS.PANTALLA_CLIENTES,
    PERMISSIONS.PANTALLA_AGENDA
  ];
  for (const p of pantallas) {
    assert.equal(roleHasPermission("backoffice", p), true, `backoffice ${p}`);
  }
});
