import { createRouter } from "./lib/router.js";
import { getMeHandler } from "./handlers/me/getMe.js";
import { createVendorRegistrationRequestHandler } from "./handlers/auth/createVendorRegistrationRequest.js";
import { listRegistrationRequestsHandler } from "./handlers/supervisor/listRegistrationRequests.js";
import { approveRegistrationRequestHandler } from "./handlers/supervisor/approveRegistrationRequest.js";
import { rejectRegistrationRequestHandler } from "./handlers/supervisor/rejectRegistrationRequest.js";
import { listUsersHandler } from "./handlers/superadmin/listUsers.js";
import { createUserHandler } from "./handlers/superadmin/createUser.js";
import { updateUserHandler } from "./handlers/superadmin/updateUser.js";

export const handler = createRouter([
  { method: "GET", path: "/me", handler: getMeHandler },
  { method: "POST", path: "/auth/vendor-registration-request", handler: createVendorRegistrationRequestHandler },
  { method: "GET", path: "/supervisor/registration-requests", handler: listRegistrationRequestsHandler },
  { method: "POST", path: "/supervisor/registration-requests/:id/approve", handler: approveRegistrationRequestHandler },
  { method: "POST", path: "/supervisor/registration-requests/:id/reject", handler: rejectRegistrationRequestHandler },
  { method: "GET", path: "/superadmin/users", handler: listUsersHandler },
  { method: "POST", path: "/superadmin/users", handler: createUserHandler },
  { method: "PUT", path: "/superadmin/users/:id", handler: updateUserHandler },
]);