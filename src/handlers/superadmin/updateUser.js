import { parseJsonBody, success } from "../../lib/http.js";
import { requireRole } from "../../lib/auth.js";
import { normalizePhone, optionalString, optionalString as maybeString } from "../../lib/validation.js";
import { updateUser } from "../../services/userService.js";

export async function updateUserHandler(event, { params }) {
  const { user } = await requireRole(event, ["superadministrador"]);
  const payload = parseJsonBody(event);

  const updatedUser = await updateUser(
    {
      userId: params.id,
      nombre: maybeString(payload.nombre, 120),
      apellido: maybeString(payload.apellido, 120),
      telefono: payload.telefono !== undefined ? normalizePhone(payload.telefono) : undefined,
      role: optionalString(payload.role, 60),
      status: optionalString(payload.status, 60),
      reason: optionalString(payload.reason, 500),
    },
    user,
  );

  return success(200, updatedUser);
}