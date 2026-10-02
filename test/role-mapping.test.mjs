// Auditoría "rol backoffice" (2026-10), PASO 1(d): cubre el mapeo de
// grupos de Cognito -> un único role_key, en los dos lugares que lo hacen
// (pickRoleFromGroups, el que corre de verdad en producción vía
// ensureUserRole; y getPrimaryRole, el fallback de desarrollo local) --
// ambos ahora comparten la misma precedencia (ROLE_KEYS, ver
// src/lib/constants.js), así que un mismo set de casos sirve para los dos.
//
// El caso "grupo desconocido" es el que motivó este test: antes
// pickRoleFromGroups devolvía "vendedor" como default silencioso si ningún
// grupo matcheaba un rol conocido, y ensureUserRole persistía eso en
// users.role_key en cada login -- un typo en el nombre del grupo de
// Cognito, o un rol nuevo (como 'backoffice' antes de este cambio)
// terminaba reescribiendo el rol real del usuario sin ningún error visible.
// Ahora debe devolver null ("sin cambio").
import test from "node:test";
import assert from "node:assert/strict";
import { pickRoleFromGroups, ensureUserRole } from "../src/services/userService.js";
import { __testables } from "../index.mjs";

const { getPrimaryRole } = __testables;

test("pickRoleFromGroups: un solo grupo reconocido devuelve ese rol", () => {
  assert.equal(pickRoleFromGroups(["vendedor"]), "vendedor");
  assert.equal(pickRoleFromGroups(["atencion_cliente"]), "atencion_cliente");
  assert.equal(pickRoleFromGroups(["backoffice"]), "backoffice");
});

test("pickRoleFromGroups: varios grupos a la vez respetan la precedencia (ROLE_KEYS)", () => {
  assert.equal(pickRoleFromGroups(["vendedor", "supervisor"]), "supervisor");
  assert.equal(pickRoleFromGroups(["atencion_cliente", "backoffice"]), "backoffice");
  assert.equal(pickRoleFromGroups(["vendedor", "backoffice"]), "backoffice");
  assert.equal(pickRoleFromGroups(["superadministrador", "backoffice", "vendedor"]), "superadministrador");
});

test("pickRoleFromGroups: ningún grupo reconocido devuelve null (no pisa el rol existente)", () => {
  assert.equal(pickRoleFromGroups([]), null);
  assert.equal(pickRoleFromGroups(["grupo-inexistente"]), null);
  // pickRoleFromGroups espera los grupos ya normalizados (en minúsculas) --
  // eso lo hace normalizeGroups, en el llamador real (findCurrentUserFromClaims).
  // Un grupo con mayúsculas acá no matchea nada, mismo resultado: null.
  assert.equal(pickRoleFromGroups(["Vendedor"]), null);
});

test("getPrimaryRole (fallback de dev local) usa la misma precedencia que pickRoleFromGroups", () => {
  assert.equal(getPrimaryRole(["vendedor"]), "vendedor");
  assert.equal(getPrimaryRole(["vendedor", "backoffice"]), "backoffice");
  assert.equal(getPrimaryRole(["backoffice", "atencion_cliente"]), "backoffice");
  assert.equal(getPrimaryRole([]), null);
  assert.equal(getPrimaryRole(["grupo-inexistente"]), null);
});

test("ensureUserRole: usuario EXISTENTE sin grupo reconocido conserva su role_key (no lo pisa con 'vendedor')", async () => {
  const supervisor = { id: "u1", email: "sup@test.com", role_key: "supervisor" };
  const result = await ensureUserRole(supervisor, pickRoleFromGroups(["grupo-inexistente"]));
  assert.equal(result.role_key, "supervisor");
  assert.equal(result, supervisor); // mismo objeto: no se hizo ningún UPDATE

  const atencion = { id: "u2", email: "at@test.com", role_key: "atencion_cliente" };
  assert.equal((await ensureUserRole(atencion, pickRoleFromGroups([]))).role_key, "atencion_cliente");
});

// Alta de usuario NUEVO desde Cognito (auto_create_from_cognito): existió
// (migró 'vendedor' como default cuando ningún grupo matcheaba, igual que
// pickRoleFromGroups antes de este cambio) pero se eliminó por completo en
// el commit 2957fc9 "Disable auto-create users on Cognito login"
// (2026-05-13) -- findCurrentUserFromClaims devuelve null si no encuentra
// el usuario, sin crear nada. La única alta hoy es createManualUser, que
// exige `role` explícito y nunca pasa por pickRoleFromGroups. No hay caso
// de "usuario nuevo sin grupo reconocido" que probar porque no hay código
// que lo ejecute -- si ese camino se reintroduce alguna vez, este test
// debería agregarse recién ahí.

test("ROLE_KEYS ordena 'backoffice' entre 'operaciones' y 'vendedor'", async () => {
  const { ROLE_KEYS } = await import("../src/lib/constants.js");
  const idx = (role) => ROLE_KEYS.indexOf(role);
  assert.ok(idx("backoffice") > idx("operaciones"), "backoffice debe tener menos precedencia que operaciones");
  assert.ok(idx("backoffice") < idx("vendedor"), "backoffice debe tener más precedencia que vendedor");
  assert.ok(idx("backoffice") < idx("atencion_cliente"), "backoffice debe tener más precedencia que atencion_cliente");
});
