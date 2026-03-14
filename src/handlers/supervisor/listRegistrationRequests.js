import { getQueryParams, success } from "../../lib/http.js";
import { requireRole } from "../../lib/auth.js";
import { listRegistrationRequests } from "../../services/registrationService.js";

export async function listRegistrationRequestsHandler(event) {
  await requireRole(event, ["supervisor", "superadministrador"]);
  const filters = getQueryParams(event);
  const requests = await listRegistrationRequests({ status: filters.status || "pending" });
  return success(200, requests);
}