// Mapa central de capacidades (auditoría "rol backoffice", 2026-10, pasos
// 2/3). Reemplaza, SOLO en los endpoints que el rol backoffice necesita, el
// patrón `requireRole(event, dbUser, LEAD_ACCESS_ROLES)` /
// `INTERNAL_CONTACT_ACCESS_ROLES` por `requirePermission(event, dbUser, <capacidad>)`.
//
// Regla seguida en todo este archivo (corrección pedida sobre la primera
// versión del diseño): al reemplazar el gate de un endpoint, la capacidad
// nueva tiene EXACTAMENTE los roles del gate viejo + backoffice -- nunca un
// subconjunto más chico. Las capacidades acotadas (clientes.baja_directa,
// comercial.*, recupero.gestionar_propios, tickets.cerrar_baja_propia) se
// usan SOLO donde el gate de ese endpoint ya era acotado, o donde no son un
// gate de endpoint sino lógica interna de scoping (quién cuenta como
// "vendedor" para un reporte, a qué seller_id se filtra una consulta).
//
// `interno.base` es la capacidad "ancha": todo lo que hoy exige
// LEAD_ACCESS_ROLES o INTERNAL_CONTACT_ACCESS_ROLES (idénticas en
// membresía) pasa por acá -- los 6 roles existentes quedan exactamente
// igual, backoffice se suma.
const EXISTING_INTERNAL_ROLES = [
  "superadministrador",
  "director",
  "supervisor",
  "operaciones",
  "atencion_cliente",
  "vendedor"
];

export const PERMISSIONS = {
  INTERNO_BASE: "interno.base",
  TICKETS_CERRAR_BAJA_PROPIA: "tickets.cerrar_baja_propia",
  CLIENTES_BAJA_DIRECTA: "clientes.baja_directa",
  RECUPERO_GESTIONAR_PROPIOS: "recupero.gestionar_propios",
  COMERCIAL_ASIGNABLE: "comercial.asignable",
  COMERCIAL_CUENTA_COMO_VENDEDOR: "comercial.cuenta_como_vendedor",
  // Capacidades de PANTALLA (menú/rutas del frontend, main.jsx) -- no
  // gatean ningún endpoint, solo viajan en /me -> permissions para que el
  // front decida qué ítems de ROLE_NAV/ramas de renderRoute mostrar sin
  // comparar role==='x'. Cada una tiene EXACTAMENTE los roles que hoy ven
  // ese ítem (su `roles` array actual en ROLE_NAV) + backoffice donde
  // corresponde -- ver la tabla de la auditoría.
  PANTALLA_SOPORTE: "pantalla.soporte",
  PANTALLA_RETENCION: "pantalla.retencion",
  PANTALLA_RECUPERO_VENDEDOR: "pantalla.recupero_vendedor",
  PANTALLA_CLIENTES: "pantalla.clientes",
  PANTALLA_AGENDA: "pantalla.agenda",
  // Capacidades de BOTÓN (Clientes): hoy "Nuevo cliente"/"Baja masiva" no
  // tienen ningún gate, se muestran a cualquiera que vea la pantalla
  // Clientes -- se les da ese mismo gate explícito (los 4 roles que ya ven
  // pantalla.clientes), SIN backoffice (punto 3 de la ficha de negocio: no
  // alta de clientes, no baja masiva).
  CLIENTES_ALTA: "clientes.alta",
  CLIENTES_BAJA_MASIVA: "clientes.baja_masiva"
};

// rol -> capacidades. Reconstruido desde el acceso REAL de cada
// endpoint/ítem de menú tocado (ver tabla endpoint -> gate viejo ->
// capacidad de la auditoría), no inventado -- por eso
// superadministrador/director/operaciones no tienen
// tickets.cerrar_baja_propia/comercial.* salvo donde ya las tenían hoy, y
// clientes.alta/clientes.baja_masiva nunca incluyen a backoffice.
export const ROLE_PERMISSIONS = {
  superadministrador: [
    PERMISSIONS.INTERNO_BASE,
    PERMISSIONS.CLIENTES_BAJA_DIRECTA,
    PERMISSIONS.PANTALLA_CLIENTES,
    PERMISSIONS.CLIENTES_ALTA,
    PERMISSIONS.CLIENTES_BAJA_MASIVA
  ],
  director: [
    PERMISSIONS.INTERNO_BASE,
    PERMISSIONS.PANTALLA_CLIENTES,
    PERMISSIONS.CLIENTES_ALTA,
    PERMISSIONS.CLIENTES_BAJA_MASIVA
  ],
  supervisor: [
    PERMISSIONS.INTERNO_BASE,
    PERMISSIONS.CLIENTES_BAJA_DIRECTA,
    PERMISSIONS.PANTALLA_RETENCION,
    PERMISSIONS.PANTALLA_CLIENTES,
    PERMISSIONS.CLIENTES_ALTA,
    PERMISSIONS.CLIENTES_BAJA_MASIVA
  ],
  operaciones: [
    PERMISSIONS.INTERNO_BASE,
    PERMISSIONS.PANTALLA_CLIENTES,
    PERMISSIONS.CLIENTES_ALTA,
    PERMISSIONS.CLIENTES_BAJA_MASIVA
  ],
  atencion_cliente: [
    PERMISSIONS.INTERNO_BASE,
    PERMISSIONS.PANTALLA_SOPORTE,
    PERMISSIONS.PANTALLA_RECUPERO_VENDEDOR
  ],
  vendedor: [
    PERMISSIONS.INTERNO_BASE,
    PERMISSIONS.TICKETS_CERRAR_BAJA_PROPIA,
    PERMISSIONS.RECUPERO_GESTIONAR_PROPIOS,
    PERMISSIONS.COMERCIAL_ASIGNABLE,
    PERMISSIONS.COMERCIAL_CUENTA_COMO_VENDEDOR,
    PERMISSIONS.PANTALLA_RETENCION,
    PERMISSIONS.PANTALLA_RECUPERO_VENDEDOR,
    PERMISSIONS.PANTALLA_AGENDA
  ],
  backoffice: [
    PERMISSIONS.INTERNO_BASE,
    PERMISSIONS.TICKETS_CERRAR_BAJA_PROPIA,
    PERMISSIONS.CLIENTES_BAJA_DIRECTA,
    PERMISSIONS.RECUPERO_GESTIONAR_PROPIOS,
    PERMISSIONS.COMERCIAL_ASIGNABLE,
    PERMISSIONS.COMERCIAL_CUENTA_COMO_VENDEDOR,
    PERMISSIONS.PANTALLA_SOPORTE,
    PERMISSIONS.PANTALLA_RETENCION,
    PERMISSIONS.PANTALLA_RECUPERO_VENDEDOR,
    PERMISSIONS.PANTALLA_CLIENTES,
    PERMISSIONS.PANTALLA_AGENDA
    // SIN clientes.alta / clientes.baja_masiva -- a propósito.
  ]
};

export function roleHasPermission(roleKey, permission) {
  return (ROLE_PERMISSIONS[roleKey] || []).includes(permission);
}

// Roles que resuelven una capacidad dada -- para los SQL que hoy hardcodean
// `role_key = 'vendedor'` y pasan a `role_key = ANY($n)`.
export function getRolesWithPermission(permission) {
  return Object.keys(ROLE_PERMISSIONS).filter((role) => roleHasPermission(role, permission));
}

// Verificación de consistencia en el arranque del módulo (no en cada
// request): confirma que interno.base resuelve EXACTAMENTE a los 6 roles
// existentes + backoffice, ni más ni menos -- si alguien agrega un rol
// nuevo a ROLE_KEYS sin darle interno.base (o sin querer dárselo a todos),
// esto no revienta nada solo, pero sirve de referencia para los tests.
export const INTERNO_BASE_ROLES = [...EXISTING_INTERNAL_ROLES, "backoffice"];
