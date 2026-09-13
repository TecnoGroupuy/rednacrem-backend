import test from "node:test";
import assert from "node:assert/strict";
import { __testables } from "../index.mjs";

test("validateProductPayload accepts a valid create payload", () => {
  const result = __testables.validateProductPayload({
    nombre: "Servicio Oro",
    categoria: "Planes",
    precio: "1500",
    descripcion: "Cobertura premium",
    observaciones: "Demo local",
    activo: true
  });

  assert.equal(result.valid, true);
  assert.equal(result.data.nombre, "Servicio Oro");
  assert.equal(result.data.categoria, "Planes");
  assert.equal(result.data.precio, 1500);
  assert.equal(result.data.activo, true);
});

test("validateProductPayload rejects invalid values", () => {
  const result = __testables.validateProductPayload({
    nombre: "",
    precio: "-10"
  });

  assert.equal(result.valid, false);
  assert.equal(result.errors.nombre, "El nombre es obligatorio");
  assert.equal(result.errors.precio, "El precio no puede ser negativo");
});

test("mapProductRowToApi returns frontend-compatible fields", () => {
  const mapped = __testables.mapProductRowToApi({
    id: "prd-1",
    nombre: "Servicio Oro",
    categoria: "Planes",
    descripcion: "Cobertura premium",
    observaciones: "Demo local",
    precio: "1500.00",
    activo: true,
    created_at: "2026-03-17T10:00:00Z",
    updated_at: "2026-03-17T11:00:00Z"
  });

  assert.deepEqual(mapped, {
    id: "prd-1",
    nombre: "Servicio Oro",
    categoria: "Planes",
    descripcion: "Cobertura premium",
    observaciones: "Demo local",
    precio: 1500,
    activo: true,
    createdAt: "2026-03-17T10:00:00Z",
    updatedAt: "2026-03-17T11:00:00Z",
    created_at: "2026-03-17T10:00:00Z",
    updated_at: "2026-03-17T11:00:00Z"
  });
});
