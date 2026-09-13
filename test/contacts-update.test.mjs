import test from "node:test";
import assert from "node:assert/strict";
import { __testables } from "../index.mjs";

test("validateContactUpdatePayload accepts telefono and celular separately", () => {
  const result = __testables.validateContactUpdatePayload({
    contact: {
      nombre: "Marcos",
      apellido: "Olivera",
      documento: "476936289",
      telefono: "2900900",
      celular: "092900900",
      email: "marcos@marcos.com",
      direccion: "Montevideo",
      departamento: "Montevideo",
      pais: "Uruguay",
      status: "activo"
    }
  });

  assert.equal(result.valid, true);
  assert.equal(result.data.contact.telefono, "2900900");
  assert.equal(result.data.contact.celular, "092900900");
});

test("validateContactUpdatePayload rejects invalid email", () => {
  const result = __testables.validateContactUpdatePayload({
    contact: {
      nombre: "Marcos",
      documento: "476936289",
      email: "no-valido"
    }
  });

  assert.equal(result.valid, false);
  assert.equal(result.errors.email, "El email no es valido");
});
