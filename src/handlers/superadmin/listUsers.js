import { getQueryParams, success } from "../../lib/http.js";
import { requireRole } from "../../lib/auth.js";
import { listUsers } from "../../services/userService.js";

export async function listUsersHandler(event) {
  await requireRole(event, ["superadministrador"]);
  const filters = getQueryParams(event);
  const users = await listUsers({
    role: filters.role,
    status: filters.status,
    search: filters.search,
  });
  return success(200, users);
}