import { parseJsonBody, success } from "../../lib/http.js";
import { createVendorRegistrationRequest } from "../../services/registrationService.js";

export async function createVendorRegistrationRequestHandler(event) {
  const payload = parseJsonBody(event);
  const request = await createVendorRegistrationRequest(payload);
  return success(201, request);
}