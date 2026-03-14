import { parseJsonBody, success } from "../../lib/http.js";
import { requireRole } from "../../lib/auth.js";
import { normalizePhone, optionalString, requiredEmail, requiredString } from "../../lib/validation.js";
import { createManualUser } from "../../services/userService.js";

export async function createUserHandler(event) {
  const { user } = await requireRole(event, ["superadministrador"]);
  const payload = parseJsonBody(event);

  const createdUser = await createManualUser(
    {
      nombre: requiredString(payload.nombre, "nombre", 120),
      apellido: requiredString(payload.apellido, "apellido", 120),
      email: requiredEmail(payload.email),
      telefono: normalizePhone(requiredString(payload.telefono, "telefono", 40)),
      role: requiredString(payload.role, "role", 60),
      status: requiredString(payload.status, "status", 60),
      reason: optionalString(payload.reason, 500),
    },
    user,
  );

  return success(201, createdUser);
}