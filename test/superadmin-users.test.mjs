import test from "node:test";
import assert from "node:assert/strict";
import { __testables } from "../index.mjs";

test("validateSuperadminUserPayload accepts valid payload", () => {
  const result = __testables.validateSuperadminUserPayload({
    nombre: "Supervisor Test",
    apellido: "Backend",
    email: "supervisor@test.com",
    telefono: "099123123",
    rol: "supervisor",
    status: "approved",
    activo: true
  });

  assert.equal(result.valid, true);
  assert.equal(result.data.email, "supervisor@test.com");
  assert.equal(result.data.rol, "supervisor");
  assert.equal(result.data.status, "approved");
});

test("validateSuperadminUserPayload rejects invalid payload", () => {
  const result = __testables.validateSuperadminUserPayload({
    nombre: "",
    email: "no-valido",
    rol: "fantasia"
  });

  assert.equal(result.valid, false);
  assert.equal(result.errors.nombre, "El nombre es obligatorio");
  assert.equal(result.errors.email, "El email no es válido");
  assert.equal(result.errors.rol, "El rol no es válido");
});

test("mapUserRowToApi returns frontend-compatible shape", () => {
  const mapped = __testables.mapUserRowToApi({
    id: "uuid-1",
    nombre: "Damian",
    apellido: "Olivera",
    email: "admin@test.com",
    telefono: "099123123",
    role_key: "superadministrador",
    status: "approved",
    last_login_at: "2026-03-15T15:00:00Z",
    created_at: "2026-03-01T10:00:00Z"
  });

  assert.deepEqual(mapped, {
    id: "uuid-1",
    nombre: "Damian Olivera",
    email: "admin@test.com",
    telefono: "099123123",
    rol: "superadministrador",
    role: "superadministrador",
    activo: true,
    status: "approved",
    ultimoAcceso: "2026-03-15T15:00:00Z",
    last_login_at: "2026-03-15T15:00:00Z",
    createdAt: "2026-03-01T10:00:00Z",
    created_at: "2026-03-01T10:00:00Z"
  });
});

test("requireRole returns 403 payload for non-superadmin", () => {
  const response = __testables.requireRole({}, { role_key: "supervisor" }, ["superadministrador"]);
  const payload = JSON.parse(response.body);

  assert.equal(response.statusCode, 403);
  assert.equal(payload.ok, false);
  assert.equal(payload.message, "Insufficient role permissions");
});

test("status/activo helpers stay aligned", () => {
  assert.equal(__testables.statusFromActivo(true), "approved");
  assert.equal(__testables.statusFromActivo(false), "inactive");
  assert.equal(__testables.isActiveFromStatus("approved"), true);
  assert.equal(__testables.isActiveFromStatus("inactive"), false);
  assert.equal(__testables.isActiveFromStatus("blocked"), false);
});
