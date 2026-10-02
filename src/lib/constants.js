// Fuente única del vocabulario de roles del backend (auditoría "rol
// backoffice", 2026-10): antes había 4 listas separadas y desincronizadas
// --- VALID_ROLES y la precedence list de getPrimaryRole en index.mjs, la
// priority list de pickRoleFromGroups en userService.js, y esta misma
// ROLE_KEYS --- las 3 primeras ahora importan de acá. El orden de este
// array ES la precedencia de mapeo de grupos de Cognito a un único rol
// (un usuario puede estar en varios grupos a la vez; gana el primero que
// aparezca acá, ver pickRoleFromGroups/getPrimaryRole).
//
// 'backoffice' entre 'operaciones' y 'vendedor': sus capacidades (ficha de
// negocio 2026-10) combinan alcance completo de atencion_cliente + una
// porción de Recupero equivalente a vendedor + una capacidad puntual (baja
// manual de producto) hoy reservada a supervisor/superadministrador. Para
// desempate de grupos Cognito se lo trata como "más que vendedor/
// atencion_cliente solos", por eso precede a ambos.
export const ROLE_KEYS = [
  "superadministrador",
  "director",
  "supervisor",
  "operaciones",
  "backoffice",
  "vendedor",
  "atencion_cliente",
];

// OJO: esta escala (50-100, pasos de 10) es independiente de la columna
// roles.priority en Postgres (enteros 1-6, sin relación numérica con esta
// escala) -- ninguna de las dos la lee código alguno hoy (confirmado por
// grep en index.mjs y src/**), son puramente descriptivas. No es la fuente
// de la precedencia real (eso lo define el ORDEN de ROLE_KEYS arriba).
export const ROLE_PRIORITY = {
  superadministrador: 100,
  director: 90,
  supervisor: 80,
  operaciones: 70,
  backoffice: 65,
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
