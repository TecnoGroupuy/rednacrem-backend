import { parseJsonBody, success } from "../../lib/http.js";
import { requireRole } from "../../lib/auth.js";
import { approveRegistrationRequest } from "../../services/registrationService.js";

export async function approveRegistrationRequestHandler(event, { params }) {
  const { user } = await requireRole(event, ["supervisor", "superadministrador"]);
  const payload = parseJsonBody(event);
  const result = await approveRegistrationRequest(params.id, user, payload.reviewNotes);
  return success(200, result);
}