import { parseJsonBody, success } from "../../lib/http.js";
import { requireRole } from "../../lib/auth.js";
import { rejectRegistrationRequest } from "../../services/registrationService.js";

export async function rejectRegistrationRequestHandler(event, { params }) {
  const { user } = await requireRole(event, ["supervisor", "superadministrador"]);
  const payload = parseJsonBody(event);
  const request = await rejectRegistrationRequest(params.id, user, payload.reviewNotes);
  return success(200, request);
}