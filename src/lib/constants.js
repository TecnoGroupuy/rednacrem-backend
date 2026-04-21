export const ROLE_KEYS = [
  "superadministrador",
  "director",
  "supervisor",
  "operaciones",
  "vendedor",
  "atencion_cliente",
];

export const ROLE_PRIORITY = {
  superadministrador: 100,
  director: 90,
  supervisor: 80,
  operaciones: 70,
  vendedor: 60,
  atencion_cliente: 50,
};

export const USER_STATUSES = ["pending", "approved", "rejected", "blocked", "inactive", "pausado"];
export const REGISTRATION_STATUSES = ["pending", "approved", "rejected"];

export function isValidRole(role) {
  return ROLE_KEYS.includes(role);
}

export function isValidUserStatus(status) {
  return USER_STATUSES.includes(status);
}

export function isValidRegistrationStatus(status) {
  return REGISTRATION_STATUSES.includes(status);
}
