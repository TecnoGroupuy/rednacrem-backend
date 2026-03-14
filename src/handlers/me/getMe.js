import { success } from "../../lib/http.js";
import { loadCurrentUser } from "../../lib/auth.js";
import { getBusinessSession } from "../../services/userService.js";

export async function getMeHandler(event) {
  const { claims, user } = await loadCurrentUser(event);
  const session = await getBusinessSession({ claims, user });
  return success(200, session);
}