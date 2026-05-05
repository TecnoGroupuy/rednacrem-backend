import fs from "node:fs";
import crypto from "node:crypto";
import { Client } from "pg";
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminAddUserToGroupCommand,
  ListUsersCommand
} from "@aws-sdk/client-cognito-identity-provider";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { AppError } from "./src/lib/errors.js";
import { handleOptions, getMethod as getMethodFromHttp, CORS_HEADERS } from "./src/lib/http.js";
import { normalizePhone as normalizePhoneValidation } from "./src/lib/validation.js";
import { createManualUser, updateUser, listUsers as listUsersService } from "./src/services/userService.js";
import { emitRealtime } from "./src/monitoring/realtimeBus.js";
import { findCurrentUserFromClaims } from "./src/services/userService.js";
import { generateCertificatePdf, buildClientDocumentFilename } from "./src/lib/certificatePdf.js";

const sqs = new SQSClient({ region: process.env.AWS_REGION || "us-east-2" });
const s3Client = new S3Client({ region: "us-east-1" });
const S3_BUCKET = "rednacrem-assets";
const S3_BASE_URL = `https://${S3_BUCKET}.s3.amazonaws.com`;

function getRequestId(event) {
  const headerId =
    event?.headers?.["x-request-id"] ||
    event?.headers?.["X-Request-Id"] ||
    event?.headers?.["x-amzn-trace-id"] ||
    event?.headers?.["X-Amzn-Trace-Id"];
  return headerId || event?.requestContext?.requestId || crypto.randomUUID();
}

function safeResponse({ data, emptyCondition, warnings, meta, message }) {
  const warningsList = Array.isArray(warnings) ? warnings : [];
  const isEmpty = Boolean(emptyCondition);
  const status = isEmpty ? "empty" : warningsList.length ? "partial" : "success";
  const response = {
    ok: true,
    success: true,
    status,
    message: message || (isEmpty ? "Sin datos" : "OK"),
    data: data ?? null,
    meta: meta || null,
    warnings: warningsList
  };
  if (data && typeof data === "object") {
    if (Object.prototype.hasOwnProperty.call(data, "items")) response.items = data.items;
    if (Object.prototype.hasOwnProperty.call(data, "total")) response.total = data.total;
    if (Object.prototype.hasOwnProperty.call(data, "metrics")) response.metrics = data.metrics;
    if (Object.prototype.hasOwnProperty.call(data, "page")) response.page = data.page;
    if (Object.prototype.hasOwnProperty.call(data, "limit")) response.limit = data.limit;
  }
  return json(200, response);
}

function loadEnvFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      return;
    }

    const text = fs.readFileSync(filePath, "utf8");
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const separatorIndex = trimmed.indexOf("=");
      if (separatorIndex === -1) continue;

      const key = trimmed.slice(0, separatorIndex).trim();
      let value = trimmed.slice(separatorIndex + 1).trim();

      if (
        (value.startsWith("\"") && value.endsWith("\"")) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      if (!(key in process.env)) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    console.warn("ENV_LOAD_WARNING", error.message);
  }
}

loadEnvFile(".env");
loadEnvFile(".env.local");

async function enqueueNoCallJob(jobId, startAt) {
  const queueUrl = process.env.NO_CALL_IMPORT_QUEUE_URL;
  if (!queueUrl) {
    throw new Error("NO_CALL_IMPORT_QUEUE_URL not set");
  }
  const payload = startAt ? { jobId, startAt } : { jobId };
  await sqs.send(
    new SendMessageCommand({
      QueueUrl: queueUrl,
      MessageBody: JSON.stringify(payload),
    })
  );
}

function getDatosTrabajarQueueUrl() {
  return process.env.DATOS_TRABAJAR_IMPORT_QUEUE_URL || process.env.NO_CALL_IMPORT_QUEUE_URL || "";
}

async function enqueueDatosTrabajarJob(jobId, startAt) {
  const queueUrl = getDatosTrabajarQueueUrl();
  if (!queueUrl) {
    throw new Error("DATOS_TRABAJAR_IMPORT_QUEUE_URL not set");
  }
  const payload = startAt
    ? { jobId, startAt, type: "datos_para_trabajar" }
    : { jobId, type: "datos_para_trabajar" };
  await sqs.send(
    new SendMessageCommand({
      QueueUrl: queueUrl,
      MessageBody: JSON.stringify(payload),
    })
  );
}

function getContactImportQueueUrl() {
  return process.env.CONTACT_IMPORT_QUEUE_URL || "";
}

async function enqueueContactImportJob(batchId, options = {}) {
  const queueUrl = getContactImportQueueUrl();
  if (!queueUrl) {
    throw new Error("CONTACT_IMPORT_QUEUE_URL not set");
  }
  const payload = {
    type: "contact_import",
    batchId,
    createProducts: options.createProducts !== false,
    organizationId: options.organizationId || null
  };
  await sqs.send(
    new SendMessageCommand({
      QueueUrl: queueUrl,
      MessageBody: JSON.stringify(payload),
    })
  );
}

function getRecuperoImportQueueUrl() {
  return process.env.RECUPERO_IMPORT_QUEUE_URL || process.env.CONTACT_IMPORT_QUEUE_URL || "";
}

async function enqueueRecuperoImportJob(jobId) {
  const queueUrl = getRecuperoImportQueueUrl();
  if (!queueUrl) {
    throw new Error("RECUPERO_IMPORT_QUEUE_URL not set");
  }
  const payload = { type: "recupero_import", jobId };
  await sqs.send(
    new SendMessageCommand({
      QueueUrl: queueUrl,
      MessageBody: JSON.stringify(payload),
    })
  );
}

const VALID_USER_STATUSES = [
  "pending",
  "approved",
  "rejected",
  "blocked",
  "inactive",
  "pausado"
];

const VALID_VENDOR_REQUEST_STATUSES = [
  "pending",
  "approved",
  "rejected"
];

const VALID_ROLES = [
  "superadministrador",
  "director",
  "supervisor",
  "operaciones",
  "atencion_cliente",
  "vendedor"
];

const INTERNAL_CONTACT_ACCESS_ROLES = [
  "superadministrador",
  "director",
  "supervisor",
  "operaciones",
  "atencion_cliente",
  "vendedor"
];

const INACTIVITY_MINUTES = 15;

const LEAD_ACCESS_ROLES = [
  ...INTERNAL_CONTACT_ACCESS_ROLES,
  "vendedor"
];

const cognitoClient = new CognitoIdentityProviderClient({
  region: process.env.AWS_REGION
});

function json(statusCode, payload) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...CORS_HEADERS
    },
    body: JSON.stringify(payload)
  };
}

function getPath(event) {
  return (
    event.rawPath ||
    event.path ||
    event.requestContext?.http?.path ||
    ""
  );
}

function getMethod(event) {
  return (
    event.requestContext?.http?.method ||
    event.httpMethod ||
    ""
  );
}

function getQueryParam(event, key) {
  // Primero intentar como objeto
  if (event?.queryStringParameters && typeof event.queryStringParameters === "object") {
    const val = event.queryStringParameters[key];
    if (val !== undefined && val !== null) return String(val);
  }
  // Luego intentar rawQueryString como string
  let raw = event?.rawQueryString || event?.queryString || "";
  if (!raw) return null;
  // Si es URL completa, extraer solo el querystring
  if (raw.includes("?")) {
    raw = raw.split("?").slice(1).join("?");
  }
  const params = new URLSearchParams(raw);
  return params.get(key);
}

function getPathSegments(path) {
  return path.split("/").filter(Boolean);
}

function matchVendorRequestActionPath(path, action) {
  const escapedAction = String(action || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = String(path || "").match(
    new RegExp(`/supervisor/vendor-requests/([^/]+)/${escapedAction}$`)
  );

  if (!match) return null;

  return {
    requestId: match[1]
  };
}

function normalizeGroups(groups) {
  if (!groups) return [];
  if (Array.isArray(groups)) return groups;
  if (typeof groups === "string") {
    return groups
      .replace(/[\[\]"]/g, " ")
      .split(/[\s,]+/)
      .map((g) => g.trim())
      .filter(Boolean);
  }
  return [];
}

function getPrimaryRole(groups) {
  const normalized = normalizeGroups(groups);

  const precedence = [
    "superadministrador",
    "director",
    "supervisor",
    "operaciones",
    "vendedor",
    "atencion_cliente"
  ];

  for (const role of precedence) {
    if (normalized.includes(role)) return role;
  }

  return null;
}

function getAuthUser(event) {
  const claims =
    event.requestContext?.authorizer?.jwt?.claims ||
    event.requestContext?.authorizer?.claims;

  if (claims) {
    const groups = normalizeGroups(claims["cognito:groups"]);

    return {
      authenticated: true,
      sub: claims.sub || null,
      email: claims.email || null,
      name: claims.name || null,
      given_name: claims.given_name || null,
      family_name: claims.family_name || null,
      groups,
      fallbackRole: getPrimaryRole(groups),
      claims
    };
  }

  const headers = event.headers || {};
  const devAuth =
    headers["x-dev-auth"] ||
    headers["X-Dev-Auth"] ||
    headers["x-dev-authenticated"] ||
    headers["X-Dev-Authenticated"];
  if (String(devAuth || "").toLowerCase() === "true") {
    const devEmail =
      headers["x-dev-user-email"] ||
      headers["X-Dev-User-Email"] ||
      "admin@local.test";
    const devRole =
      headers["x-dev-user-role"] ||
      headers["X-Dev-User-Role"] ||
      "superadministrador";
    const devSub =
      headers["x-dev-user-sub"] ||
      headers["X-Dev-User-Sub"] ||
      "dev-user";

    return {
      authenticated: true,
      sub: devSub,
      email: devEmail,
      name: devEmail,
      given_name: "",
      family_name: "",
      groups: [devRole],
      fallbackRole: devRole,
      localDev: true,
      claims: {
        sub: devSub,
        email: devEmail,
        name: devEmail,
        "cognito:groups": [devRole]
      }
    };
  }

  const localDevAuth = process.env.LOCAL_DEV_AUTH;
  if (String(localDevAuth || "").toLowerCase() === "true") {
    const devEmail = process.env.LOCAL_DEV_USER_EMAIL || "admin@local.test";
    const devRole = process.env.LOCAL_DEV_USER_ROLE || "superadministrador";
    const devSub = process.env.LOCAL_DEV_USER_SUB || "local-dev-user";
    const devName = process.env.LOCAL_DEV_USER_NAME || devEmail;

    return {
      authenticated: true,
      sub: devSub,
      email: devEmail,
      name: devName,
      given_name: "",
      family_name: "",
      groups: [devRole],
      fallbackRole: devRole,
      localDev: true,
      claims: {
        sub: devSub,
        email: devEmail,
        name: devName,
        "cognito:groups": [devRole]
      }
    };
  }

  const authHeader =
    event.headers?.authorization ||
    event.headers?.Authorization;

  if (!authHeader) {
    return null;
  }

  return {
    authenticated: true,
    scheme: authHeader.split(" ")[0] || "unknown",
    tokenPreview: authHeader.slice(0, 20),
    fallbackRole: null,
    groups: [],
    claims: null,
    sub: null,
    email: null,
    name: null,
    given_name: null,
    family_name: null
  };
}

function createDbClient() {
  const pgsslRaw = (process.env.PGSSL || process.env.DATABASE_SSL || "").toLowerCase();
  const urlSsl =
    process.env.DATABASE_URL &&
    /sslmode=(require|verify-full|verify-ca)/i.test(process.env.DATABASE_URL);
  const useSsl =
    ["true", "1", "require", "verify-full", "verify-ca"].includes(pgsslRaw) || urlSsl;

  return new Client({
    connectionString: process.env.DATABASE_URL || undefined,
    host: process.env.PGHOST || process.env.DATABASE_HOST,
    port: process.env.PGPORT
      ? Number(process.env.PGPORT)
      : process.env.DATABASE_PORT
      ? Number(process.env.DATABASE_PORT)
      : 5432,
    user: process.env.PGUSER || process.env.DATABASE_USER,
    password: process.env.PGPASSWORD || process.env.DATABASE_PASSWORD,
    database: process.env.PGDATABASE || process.env.DATABASE_NAME,
    ssl: useSsl ? { rejectUnauthorized: false } : undefined
  });
}

async function checkDatabaseConnection() {
  const client = createDbClient();

  await client.connect();
  const result = await client.query("SELECT NOW() AS server_time");
  await client.end();

  return result.rows[0];
}

function safeParseBody(event) {
  if (!event.body) return {};
  try {
    return typeof event.body === "string" ? JSON.parse(event.body) : event.body;
  } catch {
    return null;
  }
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeText(value) {
  return String(value || "").trim();
}

function isValidUuid(value) {
  const v = String(value || "").trim();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
}

function sanitizeUuidValue(value) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (trimmed === "") return null;
  if (isValidUuid(trimmed)) return trimmed;
  return value;
}

function sanitizeUuidFields(input) {
  if (Array.isArray(input)) {
    return input
      .map(sanitizeUuidFields)
      .filter((value) => value !== undefined);
  }
  if (!input || typeof input !== "object") return input;

  const out = {};
  for (const [key, value] of Object.entries(input)) {
    const cleaned = sanitizeUuidFields(value);
    const isUuidKey =
      key === "id" ||
      key.endsWith("_id") ||
      key.endsWith("Id") ||
      key.endsWith("_ids") ||
      key.endsWith("Ids");

    if (isUuidKey) {
      if (Array.isArray(cleaned)) {
        out[key] = cleaned
          .map((v) => sanitizeUuidValue(v))
          .filter((v) => v !== null && v !== "");
      } else {
        out[key] = sanitizeUuidValue(cleaned);
      }
      continue;
    }

    out[key] = cleaned;
  }
  return out;
}

function normalizeEmptyStringsToNull(input) {
  if (Array.isArray(input)) {
    return input.map(normalizeEmptyStringsToNull);
  }
  if (!input || typeof input !== "object") {
    if (typeof input === "string" && input.trim() === "") return null;
    return input;
  }
  const out = {};
  for (const [key, value] of Object.entries(input)) {
    out[key] = normalizeEmptyStringsToNull(value);
  }
  return out;
}

function splitFullName(value) {
  const text = normalizeText(value);
  if (!text) return { nombre: "", apellido: "" };
  const parts = text.split(/\s+/);
  if (parts.length === 1) return { nombre: parts[0], apellido: "" };
  return { nombre: parts.slice(0, -1).join(" "), apellido: parts.slice(-1).join(" ") };
}

// --- HELPERS CAMPANA ---------------------------------------------------------
const normalizePhone = (value) => {
  if (!value) return null;
  return String(value)
    .replace(/^p:/i, "")
    .replace(/\s+/g, "")
    .replace(/[^\d+]/g, "")
    .trim() || null;
};

const parseDateMDY = (value) => {
  if (!value) return null;
  const parts = String(value).split("/");
  if (parts.length !== 3) return null;
  const [month, day, year] = parts;
  if (!month || !day || !year) return null;
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
};

let userProfileColumnsReady = false;
async function ensureUserProfileColumns(client) {
  if (userProfileColumnsReady) return;
  await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS extension TEXT");
  await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS department TEXT");
  userProfileColumnsReady = true;
}

let leadContactColumnsCache = null;
async function getLeadContactColumns(client) {
  if (leadContactColumnsCache) return leadContactColumnsCache;
  const res = await client.query(
    `
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name IN ('datos_para_trabajar', 'contacts')
    `
  );
  const map = {
    datos_para_trabajar: new Set(),
    contacts: new Set()
  };
  for (const row of res.rows) {
    if (map[row.table_name]) {
      map[row.table_name].add(row.column_name);
    }
  }
  leadContactColumnsCache = {
    d: map.datos_para_trabajar,
    c: map.contacts
  };
  return leadContactColumnsCache;
}

function normalizePhoneDigits(value) {
  const digits = String(value || "").replace(/\D/g, "");
  return digits || "";
}

function classifyPhone(value) {
  const digits = normalizePhoneDigits(value);
  if (!digits) return { tipo: null, valor: null };

  if (digits.startsWith("0")) {
    return { tipo: "celular", valor: digits };
  }

  if (digits.startsWith("2") || digits.startsWith("4")) {
    return { tipo: "telefono", valor: digits };
  }

  if (digits.length === 8) {
    if (digits.startsWith("9")) {
      return { tipo: "celular", valor: `0${digits}` };
    }
    return { tipo: "telefono", valor: digits };
  }

  return { tipo: "telefono", valor: digits };
}

function normalizeContactPhones(telefonoRaw, celularRaw) {
  const candidates = [telefonoRaw, celularRaw].filter((value) => value !== null && value !== undefined && String(value).trim() !== "");
  let telefono = null;
  let celular = null;

  for (const candidate of candidates) {
    const { tipo, valor } = classifyPhone(candidate);
    if (!tipo || !valor) continue;
    if (tipo === "celular" && !celular) celular = valor;
    if (tipo === "telefono" && !telefono) telefono = valor;
  }

  return { telefono, celular };
}

function sanitizePhone(value) {
  if (!value) return null;
  const digits = String(value).replace(/\D/g, "");
  if (!digits) return null;
  if (digits.length < 7) return null;
  if (/^(.)\1+$/.test(digits)) return null;
  return digits;
}

function unaccentSimple(value) {
  if (!value) return "";
  return String(value)
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}

function normalizeUyNumber(value) {
  let digits = normalizePhoneDigits(value);
  if (!digits) return "";
  if (digits.startsWith("598")) {
    digits = digits.slice(3);
  }
  if (digits.length === 8 && digits.startsWith("9")) {
    digits = `0${digits}`;
  }
  return digits;
}

function buildNormalizedPhoneSql(columnRef) {
  const digits = `regexp_replace(${columnRef}, '\\\\D', '', 'g')`;
  const withoutCountry = `CASE WHEN ${digits} LIKE '598%' THEN substr(${digits}, 4) ELSE ${digits} END`;
  return `
  CASE
    WHEN ${columnRef} IS NULL OR BTRIM(${columnRef}) = '' THEN NULL
    WHEN length(${withoutCountry}) = 8 AND ${withoutCountry} LIKE '9%' THEN '0' || ${withoutCountry}
    ELSE ${withoutCountry}
  END
  `;
}

const recuperoSearchCache = new Map();
const recuperoSearchInflight = new Map();

function hashPayload(payload) {
  try {
    return crypto.createHash("sha1").update(JSON.stringify(payload || {})).digest("hex");
  } catch {
    return crypto.randomUUID();
  }
}

function countFilterRules(node) {
  if (!node || typeof node !== "object") return 0;
  if (!isAdvancedFilterPayload(node)) return 0;
  if (Array.isArray(node.rules)) {
    return node.rules.reduce((acc, rule) => acc + countFilterRules(rule), 0);
  }
  if (node.type === "rule" || node.field) return 1;
  return 0;
}

function isAdvancedFilterPayload(filters) {
  if (!filters || typeof filters !== "object") return false;
  return Array.isArray(filters.rules) || Boolean(filters.combinator) || filters.type === "group";
}

function hasSimpleFilters(filters) {
  if (!filters || typeof filters !== "object") return false;
  if (isAdvancedFilterPayload(filters)) return false;
  const entries = Object.entries(filters);
  return entries.some(([key, value]) => {
    if (value === null || value === undefined) return false;
    if (Array.isArray(value)) return value.filter((v) => String(v).trim() !== "").length > 0;
    if (typeof value === "number") return !Number.isNaN(value);
    if (typeof value === "string") return value.trim() !== "";
    if (typeof value === "object") return Object.values(value).some((v) => String(v || "").trim() !== "");
    return false;
  });
}

function isEmptySearchPayload(payload) {
  if (!payload || typeof payload !== "object") return true;
  const search = String(payload.search || "").trim();
  const tab = String(payload.tab || "").trim();
  const producto = String(payload.producto || "").trim();
  const departamento = String(payload.departamento || "").trim();
  const motivoBaja = String(payload.motivo_baja || "").trim();
  const rulesCount = countFilterRules(payload.filters);
  const simpleFilters = hasSimpleFilters(payload.filters);
  return !search && !tab && !producto && !departamento && !motivoBaja && rulesCount === 0 && !simpleFilters;
}

const RECUPERO_FILTER_FIELD_TYPES = {
  contacto: "text",
  documento: "text",
  edad: "number",
  telefono: "text",
  departamento: "text",
  producto: "text",
  precio: "number",
  fecha_baja: "date",
  motivo_baja: "text",
  lote: "text",
  vendedor_asignado: "text",
  ultimo_estado: "text",
  ultima_gestion: "date"
};

const RECUPERO_FILTER_OPERATORS = {
  text: ["contains", "not_contains", "eq", "ne", "starts", "ends", "empty", "not_empty", "in", "not_in"],
  number: ["eq", "ne", "gt", "gte", "lt", "lte", "between", "empty", "not_empty"],
  date: ["before", "after", "between", "today", "last_days", "this_month", "empty", "not_empty"],
  enum: ["in", "not_in", "empty", "not_empty"],
  boolean: ["is_true", "is_false"]
};

function validateFilterTree(node) {
  if (!node) return { valid: true };
  if (!isAdvancedFilterPayload(node)) {
    return { valid: true };
  }
  if (Array.isArray(node.rules)) {
    for (const child of node.rules) {
      const result = validateFilterTree(child);
      if (!result.valid) return result;
    }
    return { valid: true };
  }
  if (node.type === "group") {
    return { valid: false, message: "Filtros invalidos" };
  }
  const fieldKey = String(node.field || "").trim();
  const operator = String(node.operator || "").trim();
  if (!fieldKey || !operator) return { valid: false, message: "Filtros invalidos" };
  const type = RECUPERO_FILTER_FIELD_TYPES[fieldKey];
  if (!type) return { valid: false, message: "Campo de filtro invalido" };
  const allowed = RECUPERO_FILTER_OPERATORS[type] || [];
  if (!allowed.includes(operator)) return { valid: false, message: "Operador de filtro invalido" };
  return { valid: true };
}

function normalizeTextValue(value) {
  return String(value || "").trim();
}

function normalizeLowerValue(value) {
  return normalizeTextValue(value).toLowerCase();
}

function normalizeArrayValue(value, mapper = normalizeTextValue) {
  const list = Array.isArray(value) ? value : [value];
  return list.map((v) => mapper(v)).filter((v) => v !== "");
}

function normalizeEstadoValue(value) {
  const raw = normalizeLowerValue(value);
  if (!raw) return "";
  if (raw.includes("no contesta")) return "no_contesta";
  if (raw.includes("rechazo")) return "rechazo";
  if (raw.includes("rellamar")) return "rellamar";
  if (raw.includes("seguimiento")) return "seguimiento";
  if (raw.includes("venta")) return "venta";
  if (raw.includes("dato")) return "dato_erroneo";
  if (raw.includes("alta")) return "alta";
  return raw.replace(/\s+/g, "_");
}

const RECUPERO_SIMPLE_FILTER_FIELDS = new Set([
  "contacto",
  "documento",
  "telefono",
  "edad_min",
  "edad_max",
  "fecha_baja_desde",
  "fecha_baja_hasta",
  "motivo_baja",
  "ultimo_estado",
  "producto",
  "departamento",
  "vendedor_asignado",
  "precio_min",
  "precio_max",
  "lote"
]);

function validateSimpleFilters(filters) {
  if (!filters || typeof filters !== "object") return { valid: true };
  if (isAdvancedFilterPayload(filters)) return { valid: true };

  const unknown = Object.keys(filters).filter((key) => !RECUPERO_SIMPLE_FILTER_FIELDS.has(key));
  if (unknown.length) {
    return { valid: false, message: "Campo de filtro no soportado" };
  }

  const edadMin = filters.edad_min !== undefined && filters.edad_min !== null ? Number(filters.edad_min) : null;
  const edadMax = filters.edad_max !== undefined && filters.edad_max !== null ? Number(filters.edad_max) : null;
  if ((edadMin !== null && Number.isNaN(edadMin)) || (edadMax !== null && Number.isNaN(edadMax))) {
    return { valid: false, message: "Rango de edad invalido" };
  }
  if (edadMin !== null && edadMax !== null && edadMin > edadMax) {
    return { valid: false, message: "Rango de edad invalido" };
  }

  const precioMin = filters.precio_min !== undefined && filters.precio_min !== null ? Number(filters.precio_min) : null;
  const precioMax = filters.precio_max !== undefined && filters.precio_max !== null ? Number(filters.precio_max) : null;
  if ((precioMin !== null && Number.isNaN(precioMin)) || (precioMax !== null && Number.isNaN(precioMax))) {
    return { valid: false, message: "Rango de precio invalido" };
  }
  if (precioMin !== null && precioMax !== null && precioMin > precioMax) {
    return { valid: false, message: "Rango de precio invalido" };
  }

  const fechaDesde = normalizeTextValue(filters.fecha_baja_desde);
  const fechaHasta = normalizeTextValue(filters.fecha_baja_hasta);
  const desdeTs = fechaDesde ? Date.parse(fechaDesde) : null;
  const hastaTs = fechaHasta ? Date.parse(fechaHasta) : null;
  if ((fechaDesde && Number.isNaN(desdeTs)) || (fechaHasta && Number.isNaN(hastaTs))) {
    return { valid: false, message: "Rango de fecha invalido" };
  }
  if (desdeTs !== null && hastaTs !== null && desdeTs > hastaTs) {
    return { valid: false, message: "Rango de fecha invalido" };
  }

  return { valid: true };
}

async function fetchRecuperoContactos({
  client,
  producto,
  departamento,
  search,
  motivoBaja,
  tab,
  sortField,
  sortDir,
  page,
  limit,
  filters,
  organizationId
}) {
  const sortableColumns = {
    edad: "DATE_PART('year', AGE(c.fecha_nacimiento))",
    telefono: "c.telefono",
    departamento: "c.departamento",
    nombre_producto: "cp.nombre_producto",
    precio: "cp.precio",
    fecha_baja: "cp.fecha_baja"
  };

  const offset = (page - 1) * limit;
  const conditions = [
    "cp.estado = 'baja'",
    "(COALESCE(NULLIF(c.telefono, ''), NULLIF(c.celular, '')) IS NOT NULL)",
    `COALESCE(NULLIF(c.telefono, ''), NULLIF(c.celular, '')) NOT IN (
      SELECT COALESCE(NULLIF(c2.telefono, ''), NULLIF(c2.celular, ''))
      FROM contacts c2
      JOIN contact_products cp2 ON cp2.contact_id = c2.id
      WHERE cp2.estado = 'alta'
        AND COALESCE(NULLIF(c2.telefono, ''), NULLIF(c2.celular, '')) IS NOT NULL
    )`,
    "cp.fecha_baja BETWEEN '2000-01-01' AND '2030-12-31'"
  ];

  const values = [];
  let idx = 1;

  conditions.push(`($${idx}::uuid IS NULL OR c.organization_id = $${idx}::uuid)`);
  values.push(organizationId ?? null);
  idx += 1;

  console.log("[recupero] organizationId type:", typeof organizationId, "value:", organizationId);
  console.log("[recupero] values array:", values);
  console.log("[recupero] idx at query time:", idx);

  if (producto) {
    conditions.push(`cp.nombre_producto = $${idx}`);
    values.push(producto);
    idx += 1;
  }
  if (departamento) {
    conditions.push(`c.departamento = $${idx}`);
    values.push(departamento);
    idx += 1;
  }
  if (search) {
    conditions.push(`
      (
        c.nombre ILIKE $${idx}
        OR c.apellido ILIKE $${idx}
        OR c.telefono ILIKE $${idx}
        OR c.celular ILIKE $${idx}
        OR c.documento ILIKE $${idx}
        OR c.departamento ILIKE $${idx}
        OR cp.nombre_producto ILIKE $${idx}
      )
    `);
    values.push(`%${search}%`);
    idx += 1;
  }
    if (motivoBaja) {
      const normalizedMotivo = motivoBaja.toLowerCase();
      if (normalizedMotivo === "sin motivo" || normalizedMotivo === "sin_motivo" || normalizedMotivo === "sin-motivo") {
      conditions.push(`(COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, '')) IS NULL)`);
      } else {
      conditions.push(`COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, '')) = $${idx}`);
        values.push(motivoBaja);
        idx += 1;
      }
    }

  const simpleFilters = !isAdvancedFilterPayload(filters) ? filters : null;
  if (simpleFilters) {
    const contactoVal = normalizeTextValue(simpleFilters.contacto);
    if (contactoVal) {
      conditions.push(`COALESCE(NULLIF(TRIM(CONCAT(c.nombre, ' ', c.apellido)), ''), c.nombre) ILIKE $${idx}`);
      values.push(`%${contactoVal}%`);
      idx += 1;
    }

    const documentoVal = normalizeTextValue(simpleFilters.documento);
    if (documentoVal) {
      conditions.push(`c.documento ILIKE $${idx}`);
      values.push(`%${documentoVal}%`);
      idx += 1;
    }

    const telefonoVal = normalizeTextValue(simpleFilters.telefono);
    if (telefonoVal) {
      const telefonoDigits = normalizePhoneDigits(telefonoVal);
      if (telefonoDigits) {
        const telefonoExpr = buildNormalizedPhoneSql("c.telefono");
        const celularExpr = buildNormalizedPhoneSql("c.celular");
        conditions.push(`(${telefonoExpr} ILIKE $${idx} OR ${celularExpr} ILIKE $${idx})`);
        values.push(`%${telefonoDigits}%`);
      } else {
        conditions.push(`(c.telefono ILIKE $${idx} OR c.celular ILIKE $${idx})`);
        values.push(`%${telefonoVal}%`);
      }
      idx += 1;
    }

    const edadExpr = "DATE_PART('year', AGE(c.fecha_nacimiento))";
    const edadMin = simpleFilters.edad_min !== undefined && simpleFilters.edad_min !== null
      ? Number(simpleFilters.edad_min)
      : null;
    const edadMax = simpleFilters.edad_max !== undefined && simpleFilters.edad_max !== null
      ? Number(simpleFilters.edad_max)
      : null;
    if (edadMin !== null && !Number.isNaN(edadMin)) {
      conditions.push(`${edadExpr} >= $${idx}`);
      values.push(edadMin);
      idx += 1;
    }
    if (edadMax !== null && !Number.isNaN(edadMax)) {
      conditions.push(`${edadExpr} <= $${idx}`);
      values.push(edadMax);
      idx += 1;
    }

    const fechaDesde = normalizeTextValue(simpleFilters.fecha_baja_desde);
    const fechaHasta = normalizeTextValue(simpleFilters.fecha_baja_hasta);
    if (fechaDesde && fechaHasta) {
      conditions.push(`cp.fecha_baja BETWEEN $${idx}::date AND $${idx + 1}::date`);
      values.push(fechaDesde, fechaHasta);
      idx += 2;
    } else if (fechaDesde) {
      conditions.push(`cp.fecha_baja >= $${idx}::date`);
      values.push(fechaDesde);
      idx += 1;
    } else if (fechaHasta) {
      conditions.push(`cp.fecha_baja <= $${idx}::date`);
      values.push(fechaHasta);
      idx += 1;
    }

    const precioMin = simpleFilters.precio_min !== undefined && simpleFilters.precio_min !== null
      ? Number(simpleFilters.precio_min)
      : null;
    const precioMax = simpleFilters.precio_max !== undefined && simpleFilters.precio_max !== null
      ? Number(simpleFilters.precio_max)
      : null;
    if (precioMin !== null && !Number.isNaN(precioMin)) {
      conditions.push(`cp.precio >= $${idx}`);
      values.push(precioMin);
      idx += 1;
    }
    if (precioMax !== null && !Number.isNaN(precioMax)) {
      conditions.push(`cp.precio <= $${idx}`);
      values.push(precioMax);
      idx += 1;
    }

    const motivosRaw = normalizeArrayValue(simpleFilters.motivo_baja, normalizeLowerValue);
    if (motivosRaw.length) {
      const sinMotivo = motivosRaw.some((v) => ["sin motivo", "sin_motivo", "sin-motivo"].includes(v));
      const motivos = motivosRaw.filter((v) => !["sin motivo", "sin_motivo", "sin-motivo"].includes(v));
      if (sinMotivo && motivos.length) {
        conditions.push(`(COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, '')) IS NULL OR LOWER(COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, ''))) = ANY($${idx}::text[]))`);
        values.push(motivos);
        idx += 1;
      } else if (sinMotivo) {
        conditions.push(`COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, '')) IS NULL`);
      } else if (motivos.length) {
        conditions.push(`LOWER(COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, ''))) = ANY($${idx}::text[])`);
        values.push(motivos);
        idx += 1;
      }
    }

    const estadosRaw = normalizeArrayValue(simpleFilters.ultimo_estado, normalizeEstadoValue);
    if (estadosRaw.length) {
      const sinEstado = estadosRaw.some((v) => ["sin estado", "sin_estado", "sin-estado"].includes(v));
      const estados = estadosRaw.filter((v) => !["sin estado", "sin_estado", "sin-estado"].includes(v));
      if (sinEstado && estados.length) {
        conditions.push(`(COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado) IS NULL OR LOWER(COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado)) = ANY($${idx}::text[]))`);
        values.push(estados);
        idx += 1;
      } else if (sinEstado) {
        conditions.push(`COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado) IS NULL`);
      } else if (estados.length) {
        conditions.push(`LOWER(COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado)) = ANY($${idx}::text[])`);
        values.push(estados);
        idx += 1;
      }
    }

    const productos = normalizeArrayValue(simpleFilters.producto, normalizeLowerValue);
    if (productos.length) {
      conditions.push(`LOWER(cp.nombre_producto) = ANY($${idx}::text[])`);
      values.push(productos);
      idx += 1;
    }

    const departamentos = normalizeArrayValue(simpleFilters.departamento, normalizeLowerValue);
    if (departamentos.length) {
      conditions.push(`LOWER(c.departamento) = ANY($${idx}::text[])`);
      values.push(departamentos);
      idx += 1;
    }

    const vendedores = normalizeArrayValue(simpleFilters.vendedor_asignado, normalizeLowerValue);
    if (vendedores.length) {
      conditions.push(`LOWER(lote.vendedor_asignado_nombre) = ANY($${idx}::text[])`);
      values.push(vendedores);
      idx += 1;
    }

    const lotes = normalizeArrayValue(simpleFilters.lote, normalizeLowerValue);
    if (lotes.length) {
      conditions.push(`LOWER(lote.nombre_lote) = ANY($${idx}::text[])`);
      values.push(lotes);
      idx += 1;
    }
  }

  const filterFields = {
    contacto: { expr: "COALESCE(NULLIF(TRIM(CONCAT(c.nombre, ' ', c.apellido)), ''), c.nombre)", type: "text" },
    documento: { expr: "c.documento", type: "text" },
    edad: { expr: "DATE_PART('year', AGE(c.fecha_nacimiento))", type: "number" },
    telefono: { expr: "COALESCE(NULLIF(c.telefono, ''), NULLIF(c.celular, ''))", type: "text" },
    departamento: { expr: "c.departamento", type: "text" },
    producto: { expr: "cp.nombre_producto", type: "text" },
    precio: { expr: "cp.precio", type: "number" },
    fecha_baja: { expr: "cp.fecha_baja", type: "date" },
    motivo_baja: { expr: "COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, ''))", type: "text" },
    lote: { expr: "lote.nombre_lote", type: "text" },
    vendedor_asignado: { expr: "lote.vendedor_asignado_nombre", type: "text" },
    ultimo_estado: { expr: "COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado)", type: "text" },
    ultima_gestion: { expr: "COALESCE(gestion.fecha_ultima_gestion, gestion.fecha_ultima_gestion_ts)", type: "date" }
  };

  const buildRuleClause = (rule) => {
    if (!rule || typeof rule !== "object") return null;
    const fieldKey = String(rule.field || "").trim();
    const operator = String(rule.operator || "").trim();
    const field = filterFields[fieldKey];
    if (!field || !operator) return null;
    const expr = field.expr;
    const type = field.type;
    const value = rule.value;

    const pushValue = (val) => {
      values.push(val);
      const placeholder = `$${idx}`;
      idx += 1;
      return placeholder;
    };

    if (operator === "empty") {
      return type === "text"
        ? `(${expr} IS NULL OR ${expr} = '')`
        : `${expr} IS NULL`;
    }
    if (operator === "not_empty") {
      return type === "text"
        ? `(${expr} IS NOT NULL AND ${expr} <> '')`
        : `${expr} IS NOT NULL`;
    }

    if (type === "text") {
      const textVal = value === null || value === undefined ? "" : String(value);
      if (operator === "contains") return `${expr} ILIKE ${pushValue(`%${textVal}%`)}`;
      if (operator === "not_contains") return `${expr} NOT ILIKE ${pushValue(`%${textVal}%`)}`;
      if (operator === "eq") return `${expr} ILIKE ${pushValue(textVal)}`;
      if (operator === "ne") return `${expr} NOT ILIKE ${pushValue(textVal)}`;
      if (operator === "starts") return `${expr} ILIKE ${pushValue(`${textVal}%`)}`;
      if (operator === "ends") return `${expr} ILIKE ${pushValue(`%${textVal}`)}`;
      if (operator === "in") {
        const list = Array.isArray(value) ? value : [value];
        const cleaned = list.map((v) => String(v)).filter(Boolean);
        if (!cleaned.length) return null;
        return `${expr} = ANY(${pushValue(cleaned)}::text[])`;
      }
      if (operator === "not_in") {
        const list = Array.isArray(value) ? value : [value];
        const cleaned = list.map((v) => String(v)).filter(Boolean);
        if (!cleaned.length) return null;
        return `${expr} <> ALL(${pushValue(cleaned)}::text[])`;
      }
    }

    if (type === "number") {
      const numVal = value === null || value === undefined || value === "" ? null : Number(value);
      if (operator === "between" && Array.isArray(value) && value.length === 2) {
        const minVal = Number(value[0]);
        const maxVal = Number(value[1]);
        const p1 = pushValue(minVal);
        const p2 = pushValue(maxVal);
        return `${expr} BETWEEN ${p1} AND ${p2}`;
      }
      if (numVal === null || Number.isNaN(numVal)) return null;
      if (operator === "eq") return `${expr} = ${pushValue(numVal)}`;
      if (operator === "ne") return `${expr} <> ${pushValue(numVal)}`;
      if (operator === "gt") return `${expr} > ${pushValue(numVal)}`;
      if (operator === "gte") return `${expr} >= ${pushValue(numVal)}`;
      if (operator === "lt") return `${expr} < ${pushValue(numVal)}`;
      if (operator === "lte") return `${expr} <= ${pushValue(numVal)}`;
    }

    if (type === "date") {
      if (operator === "today") return `${expr} = CURRENT_DATE`;
      if (operator === "this_month") {
        return `${expr} >= date_trunc('month', CURRENT_DATE)::date AND ${expr} < (date_trunc('month', CURRENT_DATE) + interval '1 month')::date`;
      }
      if (operator === "last_days") {
        const daysVal = value === null || value === undefined || value === "" ? null : Number(value);
        if (daysVal === null || Number.isNaN(daysVal)) return null;
        return `${expr} >= (CURRENT_DATE - ${pushValue(daysVal)}::int)`;
      }
      if (operator === "between" && Array.isArray(value) && value.length === 2) {
        const p1 = pushValue(value[0]);
        const p2 = pushValue(value[1]);
        return `${expr} BETWEEN ${p1}::date AND ${p2}::date`;
      }
      if (operator === "before" && value) return `${expr} < ${pushValue(value)}::date`;
      if (operator === "after" && value) return `${expr} > ${pushValue(value)}::date`;
    }

    if (type === "boolean") {
      if (operator === "is_true") return `${expr} = TRUE`;
      if (operator === "is_false") return `${expr} = FALSE`;
    }

    return null;
  };

  const buildFilterClause = (node) => {
    if (!node || typeof node !== "object") return null;
    if (Array.isArray(node.rules)) {
      const combinator = String(node.combinator || "AND").toUpperCase() === "OR" ? "OR" : "AND";
      const parts = [];
      for (const rule of node.rules) {
        const clause = rule?.rules ? buildFilterClause(rule) : buildRuleClause(rule);
        if (clause) parts.push(clause);
      }
      if (!parts.length) return null;
      return `(${parts.join(` ${combinator} `)})`;
    }
    return buildRuleClause(node);
  };

  const advancedFilters = isAdvancedFilterPayload(filters) ? filters : null;
  const advancedClause = buildFilterClause(advancedFilters);
  if (advancedClause) conditions.push(advancedClause);

  const baseConditions = [...conditions];

  if (tab) {
    if (tab === "disponibles") {
      conditions.push(`
        NOT EXISTS (
          SELECT 1
          FROM lead_batch_contacts lbc
          JOIN lead_batches lb ON lb.id = lbc.batch_id
          WHERE lbc.client_contact_id = c.id
            AND lb.tipo = 'recupero'
            AND lb.estado IN ('activo', 'asignado')
        )
      `);
    } else if (tab === "en_lote") {
      conditions.push(`
        EXISTS (
          SELECT 1
          FROM lead_batch_contacts lbc
          JOIN lead_batches lb ON lb.id = lbc.batch_id
          WHERE lbc.client_contact_id = c.id
            AND lb.tipo = 'recupero'
        )
      `);
    } else if (tab === "asignados") {
      conditions.push(`
        EXISTS (
          SELECT 1
          FROM datos_para_trabajar d2
          JOIN lead_contact_status lcs ON lcs.contact_id = d2.id
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE d2.contact_id = c.id
            AND lb.tipo = 'recupero'
            AND lcs.assigned_to IS NOT NULL
        )
      `);
    } else if (tab === "gestionados") {
      conditions.push(`
        (
          EXISTS (
            SELECT 1
            FROM datos_para_trabajar d2
            JOIN lead_contact_status lcs ON lcs.contact_id = d2.id
            JOIN lead_batches lb ON lb.id = lcs.batch_id
            WHERE d2.contact_id = c.id
              AND lb.tipo = 'recupero'
              AND lcs.intentos > 0
          )
          OR COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado) IS NOT NULL
        )
      `);
    } else if (tab === "recuperados") {
      conditions.push(
        `COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado) IN ('venta', 'alta')`
      );
    } else if (tab === "rechazados") {
      conditions.push(
        `COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado) = 'rechazo'`
      );
    }
  }

  const where = conditions.join(" AND ");
  const baseWhere = baseConditions.join(" AND ");
  const orderBy = sortField && sortableColumns[sortField]
    ? `${sortableColumns[sortField]} ${sortDir}`
    : "cp.fecha_baja DESC";

  console.log("[recupero] organizationId:", organizationId);
  console.log("[recupero] params:", { producto, tab, page });

  let itemsRes;
  try {
    console.log("[recupero] starting itemsRes query");
    itemsRes = await client.query(
      `
      SELECT DISTINCT ON (c.telefono)
        c.id,
        c.nombre,
        c.apellido,
        c.telefono,
        c.celular,
        c.documento,
        CASE WHEN c.fecha_nacimiento IS NULL THEN NULL ELSE DATE_PART('year', AGE(c.fecha_nacimiento))::int END AS edad,
        c.departamento,
        cp.nombre_producto,
        cp.precio,
        cp.fecha_baja,
        COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, '')) AS motivo_baja,
        COALESCE(NULLIF(cp.motivo_baja_detalle, ''), NULLIF(ems.motivo_baja, ''), NULLIF(cp.motivo_baja, '')) AS motivo_baja_detalle,
        lote.batch_id,
        lote.nombre_lote,
        lote.vendedor_asignado_id,
        lote.vendedor_asignado_nombre,
        lote.vendedor_asignado_nombre AS vendedor_asignado,
        COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado) AS ultimo_estado_gestion,
        gestion.fecha_ultima_gestion,
        COALESCE(gestion.fecha_ultima_gestion, gestion.fecha_ultima_gestion_ts) AS ultima_gestion
      FROM contacts c
      JOIN contact_products cp ON cp.contact_id = c.id
      LEFT JOIN external_management_status ems
        ON ems.documento = c.documento
      LEFT JOIN datos_para_trabajar d
        ON d.contact_id = c.id
      LEFT JOIN LATERAL (
        SELECT
          lbc.batch_id,
          lb.nombre AS nombre_lote,
          lcs.assigned_to AS vendedor_asignado_id,
          COALESCE(NULLIF(TRIM(CONCAT(u.nombre, ' ', u.apellido)), ''), u.nombre) AS vendedor_asignado_nombre
        FROM lead_batch_contacts lbc
        JOIN lead_batches lb ON lb.id = lbc.batch_id
        LEFT JOIN lead_contact_status lcs
          ON lcs.contact_id = d.id
         AND lcs.batch_id = lbc.batch_id
        LEFT JOIN users u ON u.id = lcs.assigned_to
        WHERE lbc.client_contact_id = c.id
          AND lb.tipo = 'recupero'
          AND lb.estado IN ('activo', 'asignado')
        ORDER BY lb.created_at DESC
        LIMIT 1
      ) lote ON true
      LEFT JOIN LATERAL (
        SELECT
          lmh.resultado AS ultimo_estado_gestion,
          (lmh.fecha_gestion AT TIME ZONE 'America/Montevideo')::date AS fecha_ultima_gestion,
          lmh.created_at AS fecha_ultima_gestion_ts
        FROM lead_management_history lmh
        JOIN lead_batches lb ON lb.id = lmh.batch_id
        WHERE lmh.contact_id = d.id
          AND lb.tipo = 'recupero'
        ORDER BY lmh.fecha_gestion DESC
        LIMIT 1
      ) gestion ON true
      WHERE ${where}
      ORDER BY c.telefono, ${orderBy}
      LIMIT $${idx} OFFSET $${idx + 1}
      `,
      [...values, limit, offset]
    );
    console.log("[recupero] itemsRes done, rows:", itemsRes.rows.length);
  } catch (err) {
    console.error("[recupero] SQL error:", err.message);
    console.error("[recupero] SQL detail:", err.detail);
    throw err;
  }

  let countRes;
  try {
    console.log("[recupero] starting countRes query");
    countRes = await client.query(
      `
      SELECT COUNT(DISTINCT c.telefono) AS total
      FROM contacts c
      JOIN contact_products cp ON cp.contact_id = c.id
      LEFT JOIN external_management_status ems
        ON ems.documento = c.documento
      LEFT JOIN datos_para_trabajar d
        ON d.contact_id = c.id
      LEFT JOIN LATERAL (
        SELECT
          lbc.batch_id,
          lb.nombre AS nombre_lote,
          lcs.assigned_to AS vendedor_asignado_id,
          COALESCE(NULLIF(TRIM(CONCAT(u.nombre, ' ', u.apellido)), ''), u.nombre) AS vendedor_asignado_nombre
        FROM lead_batch_contacts lbc
        JOIN lead_batches lb ON lb.id = lbc.batch_id
        LEFT JOIN lead_contact_status lcs
          ON lcs.contact_id = d.id
         AND lcs.batch_id = lbc.batch_id
        LEFT JOIN users u ON u.id = lcs.assigned_to
        WHERE lbc.client_contact_id = c.id
          AND lb.tipo = 'recupero'
          AND lb.estado IN ('activo', 'asignado')
        ORDER BY lb.created_at DESC
        LIMIT 1
      ) lote ON true
      LEFT JOIN LATERAL (
        SELECT
          lmh.resultado AS ultimo_estado_gestion,
          (lmh.fecha_gestion AT TIME ZONE 'America/Montevideo')::date AS fecha_ultima_gestion,
          lmh.created_at AS fecha_ultima_gestion_ts
        FROM lead_management_history lmh
        JOIN lead_batches lb ON lb.id = lmh.batch_id
        WHERE lmh.contact_id = d.id
          AND lb.tipo = 'recupero'
        ORDER BY lmh.fecha_gestion DESC
        LIMIT 1
      ) gestion ON true
      WHERE ${where}
      `,
      values
    );
    console.log("[recupero] countRes done:", countRes.rows[0]);
  } catch (err) {
    console.error("[recupero] SQL error:", err.message);
    console.error("[recupero] SQL detail:", err.detail);
    throw err;
  }

  const total = Number(countRes.rows[0]?.total || 0);
  const metricsRow = {
    disponibles: total,
    en_lote: 0,
    asignados: 0,
    gestionados: 0,
    recuperados: 0,
    rechazados: 0
  };
  const data = {
    items: itemsRes.rows,
    total,
    page,
    limit,
    metrics: {
      total,
      disponibles: Number(metricsRow.disponibles || 0),
      enLote: Number(metricsRow.en_lote || 0),
      asignados: Number(metricsRow.asignados || 0),
      gestionados: Number(metricsRow.gestionados || 0),
      recuperados: Number(metricsRow.recuperados || 0),
      rechazados: Number(metricsRow.rechazados || 0)
    }
  };

  return { data, emptyCondition: total === 0 };
}

function getFuenteFromNumber(numero) {
  if (!numero) return null;
  if (numero.length === 9 && numero.startsWith("09")) return "celular";
  if (numero.length === 8 && (numero.startsWith("2") || numero.startsWith("4"))) return "tel_fijo";
  if (numero.length === 9 && numero.startsWith("0")) return "celular";
  return numero.startsWith("9") ? "celular" : "tel_fijo";
}

function getDepartamentoFromFixed(numero) {
  if (!numero) return null;
  const n = numero;
  if (n.startsWith("2")) return "Montevideo";
  if (n.startsWith("42")) return "Maldonado";
  if (n.startsWith("433") || n.startsWith("437")) return "Canelones";
  if (n.startsWith("452")) return "Colonia";
  if (n.startsWith("45")) return "Colonia";
  if (n.startsWith("435")) return "Florida";
  if (n.startsWith("4364")) return "Flores";
  if (n.startsWith("436")) return "Durazno";
  if (n.startsWith("444")) return "Lavalleja";
  if (n.startsWith("477")) return "Artigas";
  if (n.startsWith("473")) return "Salto";
  if (n.startsWith("472")) return "Paysandï¿½";
  if (n.startsWith("456")) return "Rï¿½o Negro";
  if (n.startsWith("453")) return "Soriano";
  if (n.startsWith("434")) return "San Josï¿½";
  if (n.startsWith("447")) return "Rocha";
  if (n.startsWith("445")) return "Treinta y Tres";
  if (n.startsWith("464")) return "Cerro Largo";
  if (n.startsWith("462")) return "Rivera";
  if (n.startsWith("463")) return "Tacuarembï¿½";
  return null;
}

function normalizeLeadResultado(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return "nuevo";
  if (normalized.includes("no_contesta") || normalized.includes("no contesta")) return "no_contesta";
  if (normalized.includes("seguimiento") || normalized.includes("segumineto")) return "seguimiento";
  if (normalized.includes("rellamar")) return "rellamar";
  if (normalized.includes("rechazo")) return "rechazo";
  if (normalized.includes("dato_erroneo") || normalized.includes("dato err") || normalized.includes("error")) return "dato_erroneo";
  if (normalized.includes("venta")) return "venta";
  if (normalized.includes("alta")) return "venta";
  if (normalized.includes("interesado")) return "seguimiento";
  if (normalized.includes("volver_a_llamar") || normalized.includes("volver a llamar")) return "rellamar";
  return normalized;
}

async function getLeadStatusCatalogEntry(client, nombre) {
  if (!nombre) return null;
  const res = await client.query(
    `
    SELECT nombre, es_final, libera_al_cerrar
    FROM lead_status_catalog
    WHERE nombre = $1
    LIMIT 1
    `,
    [nombre]
  );
  return res.rows[0] || null;
}

function normalizeNextAction(value) {
  if (!value) return null;
  let normalized = value;
  if (typeof value === "string") {
    const trimmed = value.trim();
    const hasTz = /([zZ]|[+-]\d{2}:?\d{2})$/.test(trimmed);
    const looksLikeDateTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(trimmed);
    if (looksLikeDateTime && !hasTz) {
      normalized = `${trimmed}${trimmed.length === 16 ? ":00" : ""}-03:00`;
    }
  }
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

const NO_CALL_LOCALIDAD_BY_PREFIX = {
  "2000": "Barros Blancos",
  "2203": "Aguada",
  "2322": "Melilla",
  "2314": "Cerro",
  "2601": "Carrasco",
  "2916": "Ciudad Vieja",
  "2320": "Colï¿½n",
  "2222": "Piedras Blancas",
  "2401": "Cordï¿½n",
  "2487": "Hosp. Clï¿½nicas",
  "2292": "Pando",
  "2294": "Sauce",
  "2295": "Empalme Olmos",
  "2296": "Toledo",
  "2902": "Plaza Centro",
  "2712": "Punta Carretas",
  "2312": "Paso de la Arena",
  "2355": "Sayago",
  "2409": "Tres Cruces",
  "2506": "Uniï¿½n",
  "2347": "Autï¿½dromo",
  "2362": "La Paz",
  "2364": "Las Piedras",
  "2369": "Progreso",
  "2372": "Atlï¿½ntida",
  "2682": "Lagomar",
  "2696": "Solymar",
  "4332": "Canelones",
  "4530": "Caï¿½ada Nieto",
  "4222": "Maldonado",
  "4223": "Maldonado",
  "4224": "Maldonado",
  "4225": "Maldonado",
  "4244": "Punta del Este (Penï¿½nsula)",
  "4248": "Punta del Este Parada 5",
  "4249": "Punta del Este Parada 5",
  "4255": "Laguna del Sauce",
  "4257": "Portezuelo",
  "4266": "San Carlos",
  "4277": "La Barra",
  "4311": "Casupï¿½",
  "4312": "San Ramï¿½n",
  "4313": "San Antonio",
  "4315": "Tala",
  "4317": "Miguez",
  "4318": "Cerro Colorado",
  "4319": "Chamizo",
  "4334": "Santa Lucï¿½a",
  "4335": "Juanicï¿½",
  "4336": "Los Cerrillos",
  "4338": "Colonia Etchepare",
  "4339": "Cardal",
  "4342": "San Josï¿½",
  "4345": "Kiyï¿½",
  "4346": "Rafael Peraza",
  "4348": "Villa Rodriguez",
  "4349": "Colonia Agra.Delta",
  "4352": "Florida",
  "4354": "Sarandï¿½ Grande",
  "4360": "Blanquillo",
  "4362": "Durazno",
  "4364": "Trinidad",
  "4365": "Carmen",
  "4367": "Sarandï¿½ del Yi",
  "4368": "Carlos Reyles",
  "4369": "La Paloma",
  "4373": "La Floresta",
  "4374": "Soca",
  "4375": "Parque del Plata",
  "4376": "Salinas",
  "4377": "Piedras de Afilar",
  "4378": "Cuchilla Alta",
  "4399": "San Jacinto",
  "4430": "Gregorio Aznarez",
  "4432": "Piriï¿½polis",
  "4434": "Pan de Azï¿½car",
  "4438": "Balneario Solï¿½s",
  "4442": "Minas",
  "4446": "Aiguï¿½",
  "4447": "Solï¿½s de Mataojo",
  "4448": "Pirarajï¿½",
  "4449": "Mariscala",
  "4452": "Treinta y Tres",
  "4455": "Josï¿½ P. Varela",
  "4456": "Lascano",
  "4457": "Velï¿½zquez",
  "4458": "Vergara",
  "4459": "Cebollatï¿½",
  "4463": "Zapicï¿½n",
  "4464": "Santa Clara de Olimar",
  "4466": "Cerro Chato",
  "4469": "Batlle y Ordoï¿½ez",
  "4472": "Rocha",
  "4474": "Barra del Chuy",
  "4475": "Aguas Dulces",
  "4476": "La Coronilla",
  "4477": "Santa Teresa",
  "4479": "La Paloma (Rocha)",
  "4486": "Faro Josï¿½ Ignacio",
  "4522": "Colonia",
  "4534": "Dolores",
  "4536": "Cardona",
  "4537": "Palmitas",
  "4538": "Josï¿½ E. Rodï¿½",
  "4539": "Ismael Cortinas",
  "4542": "Balneario Zagarazï¿½",
  "4544": "Nueva Palmira",
  "4552": "Rosario",
  "4554": "Nueva Helvecia",
  "4558": "Colonia Valdense",
  "4562": "Fray Bentos",
  "4567": "Young",
  "4568": "Nuevo Berlï¿½n",
  "4569": "San Javier",
  "4574": "Semillero",
  "4575": "Colonia Miguelete",
  "4576": "Ombï¿½es de Lavalle",
  "4577": "Conchillas",
  "4586": "Juan Lacaze",
  "4587": "Playa Fomento",
  "4588": "Santa Ana",
  "4622": "Rivera",
  "4632": "Tacuarembï¿½",
  "4640": "Aceguï¿½",
  "4642": "Melo",
  "4654": "Vichadero",
  "4656": "Tranqueras",
  "4658": "Minas de Corrales",
  "4664": "Paso de los Toros",
  "4675": "Rï¿½o Branco",
  "4679": "Lago Merï¿½n",
  "4722": "Paysandï¿½",
  "4730": "Defensa (Salto)",
  "4732": "Pueblo Lavalleja",
  "4733": "Cuchilla de Salto",
  "4742": "Guichï¿½n",
  "4747": "Piedras Coloradas",
  "4754": "Quebracho",
  "4764": "Constituciï¿½n",
  "4766": "Belï¿½n",
  "4772": "Artigas",
  "4776": "Baltasar Brum",
  "4777": "Tomï¿½s Gomensoro",
  "4778": "Mones Quintela",
  "4779": "Bella Uniï¿½n",
  "4888": "Fraile Muerto",
  "5432": "Mercedes"
};

function getLocalidadFromFixed(numero) {
  if (!numero || numero.length < 4) return null;
  const prefix = numero.slice(0, 4);
  return NO_CALL_LOCALIDAD_BY_PREFIX[prefix] || null;
}

const NO_CALL_JOB_CHUNK_SIZE = 5000;
const CONTACT_IMPORT_BATCH_SIZE = 500;

function parseMultipartFormData(event, options = {}) {
  const contentType = event?.headers?.["content-type"] || event?.headers?.["Content-Type"] || "";
  if (!contentType.toLowerCase().includes("multipart/form-data")) return null;
  const boundaryMatch = contentType.match(/boundary=([^;]+)/i);
  if (!boundaryMatch) return null;
  const boundary = boundaryMatch[1].trim().replace(/^["']|["']$/g, "");
  const encoding = options?.encoding || "utf8";
  const rawBody = event?.body || "";
  const buffer = event?.isBase64Encoded
    ? Buffer.from(rawBody, "base64")
    : Buffer.from(typeof rawBody === "string" ? rawBody : JSON.stringify(rawBody));
  const text = buffer.toString(encoding);
  const parts = text.split("--" + boundary);
  console.log("parseMultipart: boundary del header:", JSON.stringify(boundary));
  console.log("parseMultipart: parts count:", parts.length);
  console.log(
    "parseMultipart: primera part (100 chars):",
    parts[1]?.substring(0, 100)
  );
  const fields = {};
  const files = {};
  for (const part of parts) {
    if (!part || part === "--" || part === "--\r\n") continue;
    const trimmed = part.startsWith("\r\n") ? part.slice(2) : part;
    const [rawHeaders, ...rest] = trimmed.split("\r\n\r\n");
    if (!rest.length) continue;
    const body = rest.join("\r\n\r\n");
    const headers = rawHeaders.split("\r\n");
    const disposition = headers.find((h) =>
      h.toLowerCase().startsWith("content-disposition")
    );
    if (!disposition) continue;
    const nameMatch = disposition.match(/name=\"([^\"]+)\"/i);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    const filenameMatch = disposition.match(/filename=\"([^\"]*)\"/i);
    const value = body.replace(/\r\n$/, "");
    if (filenameMatch) {
      files[name] = { filename: filenameMatch[1], content: value };
    } else {
      fields[name] = value;
    }
  }
  return { fields, files };
}

function extractClientsImportCsv(event) {
  const contentType = event?.headers?.["content-type"] || event?.headers?.["Content-Type"] || "";
  let csvText = "";
  let multipartFileName = null;
  let parsedMultipart = null;
  if (contentType.toLowerCase().includes("multipart/form-data")) {
    parsedMultipart = parseMultipartFormData(event, { encoding: "latin1" });
    const fileEntry =
      parsedMultipart?.files?.file ||
      parsedMultipart?.files?.archivo ||
      Object.values(parsedMultipart?.files || {})[0];
    csvText = fileEntry?.content || "";
    multipartFileName = fileEntry?.filename || null;
  } else {
    const rawBody = event?.body || "";
    const bodyText = event?.isBase64Encoded
      ? Buffer.from(rawBody, "base64").toString("latin1")
      : typeof rawBody === "string"
      ? rawBody
      : JSON.stringify(rawBody);

    csvText = bodyText;
    if (contentType.includes("application/json")) {
      const parsed = safeParseBody(event);
      csvText = parsed?.csv || "";
    }
  }

  return { csvText, fileName: multipartFileName, parsedMultipart };
}

function getClientsCsvParseContext(csvText) {
  const lineIterator = iterateCsvLines(csvText.replace(/^\uFEFF/, ""));
  const headerLineResult = lineIterator.next();
  const headerLine = headerLineResult.done ? "" : headerLineResult.value || "";
  if (!headerLine.trim()) {
    return { error: "CSV vacio" };
  }
  const separator = detectSeparator(headerLine);
  let headerCells = parseCsvLine(headerLine, separator);
  if (headerCells.length === 1 && headerLine.includes(";")) {
    headerCells = headerLine.split(";");
  } else if (headerCells.length === 1 && headerLine.includes("\t")) {
    headerCells = headerLine.split("\t");
  }
  const headerKeys = headerCells.map(
    (header) => CSV_HEADER_MAP[normalizeCsvHeader(header)] || null
  );

  return { lineIterator, headerLine, separator, headerKeys };
}

function normalizeImportValue(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[._-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeDocumento(value) {
  return String(value || "").replace(/[^0-9]/g, "");
}

function normalizeRecuperoEstado(value) {
  const normalized = normalizeImportValue(value);
  if (!normalized) return null;
  if (normalized.includes("no contesta")) return "no_contesta";
  if (normalized.includes("rechazo")) return "rechazo";
  if (normalized.includes("rellamar") || normalized.includes("volver a llamar"))
    return "rellamar";
  if (normalized.includes("seguimiento")) return "seguimiento";
  if (normalized.includes("venta") || normalized.includes("alta")) return "venta";
  if (normalized.includes("dato error") || normalized.includes("dato erroneo"))
    return "dato_erroneo";
  if (normalized.includes("abitab")) return "abitab_pendiente";
  return null;
}

function buildRecuperoErrorCsv(errors = []) {
  const lines = [
    ["Documento", "Motivo de la baja", "Ultimo estado", "Error"].join(";")
  ];
  for (const err of errors) {
    lines.push(
      [
        err.documento || "",
        err.motivo_baja || "",
        err.ultimo_estado || "",
        err.message || err.code || ""
      ].join(";")
    );
  }
  return lines.join("\n");
}

function normalizeMotivoBaja(value) {
  const normalized = normalizeImportValue(value);
  if (!normalized) return null;
  if (normalized.includes("fallec")) return "fallecido";
  if (
    normalized.includes("medio pago") ||
    normalized.includes("tarjeta") ||
    normalized.includes("cobro") ||
    normalized.includes("debito") ||
    normalized.includes("dÃ©bito")
  )
    return "error_medio_pago";
  if (normalized.includes("auditor")) return "no_pasa_auditoria";
  return "otro";
}

function detectCsvDelimiter(headerLine) {
  if (!headerLine) return ",";
  const commaCount = (headerLine.match(/,/g) || []).length;
  const semicolonCount = (headerLine.match(/;/g) || []).length;
  return semicolonCount > commaCount ? ";" : ",";
}

function countCsvRows(csvText) {
  if (!csvText) return 0;
  let count = 0;
  for (let i = 0; i < csvText.length; i += 1) {
    if (csvText[i] === "\n") count += 1;
  }
  if (csvText.length > 0 && csvText[csvText.length - 1] !== "\n") count += 1;
  return count;
}

function* iterateCsvLines(input) {
  const text = String(input || "");
  if (!text.length) return;
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (char === "\n") {
      let line = text.slice(start, i);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      yield line;
      start = i + 1;
    }
  }
  if (start <= text.length) {
    let line = text.slice(start);
    if (line.endsWith("\r")) line = line.slice(0, -1);
    if (line.length || text.length) yield line;
  }
}

function* iterateNoCallValues(csvText) {
  const text = String(csvText || "").replace(/^\uFEFF/, "");
  const iterator = iterateCsvLines(text);
  const headerResult = iterator.next();
  const header = headerResult.done ? "" : headerResult.value || "";
  const delimiter = detectCsvDelimiter(header);
  for (const line of iterator) {
    if (!line) continue;
    const cells = parseCsvLine(line, delimiter);
    const first = cells[0] || "";
    if (first && first.trim()) {
      yield first.trim();
    } else {
      yield "";
    }
  }
}

export async function processNoCallJob(jobId, options = {}) {
  const client = createDbClient();
  await client.connect();

  try {
    const jobRes = await client.query(
      `
      SELECT id, csv_text, processed_rows, inserted_rows, skipped_rows
      FROM no_call_import_jobs
      WHERE id = $1
      LIMIT 1
      `,
      [jobId]
    );

    if (!jobRes.rows.length) return;

    const csvText = jobRes.rows[0].csv_text || "";
    const totalRows = Math.max(0, countCsvRows(csvText) - 1);
    const valuesIter = iterateNoCallValues(csvText);

    let index = options.startAt ?? jobRes.rows[0].processed_rows ?? 0;
    let inserted = jobRes.rows[0].inserted_rows ?? 0;
    let skipped = jobRes.rows[0].skipped_rows ?? 0;

    await client.query(
      `
      UPDATE no_call_import_jobs
      SET status = 'processing',
          total_rows = $1,
          processed_rows = $2,
          inserted_rows = $3,
          skipped_rows = $4,
          error_message = NULL,
          started_at = now(),
          updated_at = now()
      WHERE id = $5
      `,
      [totalRows, index, inserted, skipped, jobId]
    );
    const maxMillis = options.maxMillis ?? null;
    const startedAt = Date.now();

    const buffer = [];
    let currentIndex = 0;
    for (const value of valuesIter) {
      if (currentIndex < index) {
        currentIndex += 1;
        continue;
      }
      buffer.push(value);
      currentIndex += 1;
      if (buffer.length < NO_CALL_JOB_CHUNK_SIZE) continue;

      const chunk = buffer.splice(0, buffer.length);

      try {
        await client.query("BEGIN");
        const numeros = [];
        const fuentes = [];
        const departamentos = [];
        const localidades = [];

        for (const rawValue of chunk) {
          const numero = normalizeUyNumber(rawValue);
          if (!numero) {
            skipped += 1;
            continue;
          }
          const fuente = getFuenteFromNumber(numero);
          const departamento = fuente === "tel_fijo" ? getDepartamentoFromFixed(numero) : null;
          const localidad = fuente === "tel_fijo" ? getLocalidadFromFixed(numero) : null;
          numeros.push(numero);
          fuentes.push(fuente);
          departamentos.push(departamento);
          localidades.push(localidad);
        }

        if (numeros.length > 0) {
          const result = await client.query(
            `
            INSERT INTO no_call_entries (numero, fuente, departamento, localidad)
            SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[])
            ON CONFLICT (numero) DO NOTHING
            `,
            [numeros, fuentes, departamentos, localidades]
          );
          inserted += result.rowCount;
          skipped += numeros.length - result.rowCount;
        }

        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        await client.query(
          `
          UPDATE no_call_import_jobs
          SET status = 'failed',
              error_message = $1,
              completed_at = now(),
              updated_at = now()
          WHERE id = $2
          `,
          [error.message, jobId]
        );
        await client.end();
        return;
      }

      index += chunk.length;
      await client.query(
        `
        UPDATE no_call_import_jobs
        SET processed_rows = $1,
            inserted_rows = $2,
            skipped_rows = $3,
            total_rows = $4,
            updated_at = now()
        WHERE id = $5
        `,
        [index, inserted, skipped, totalRows, jobId]
      );

      if (maxMillis && Date.now() - startedAt > maxMillis) {
        if (typeof options.requeue === "function") {
          await options.requeue(index);
        }
        await client.end();
        return;
      }
    }

    if (buffer.length > 0) {
      try {
        await client.query("BEGIN");
        const numeros = [];
        const fuentes = [];
        const departamentos = [];
        const localidades = [];

        for (const rawValue of buffer) {
          const numero = normalizeUyNumber(rawValue);
          if (!numero) {
            skipped += 1;
            continue;
          }
          const fuente = getFuenteFromNumber(numero);
          const departamento = fuente === "tel_fijo" ? getDepartamentoFromFixed(numero) : null;
          const localidad = fuente === "tel_fijo" ? getLocalidadFromFixed(numero) : null;
          numeros.push(numero);
          fuentes.push(fuente);
          departamentos.push(departamento);
          localidades.push(localidad);
        }

        if (numeros.length > 0) {
          const result = await client.query(
            `
            INSERT INTO no_call_entries (numero, fuente, departamento, localidad)
            SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[])
            ON CONFLICT (numero) DO NOTHING
            `,
            [numeros, fuentes, departamentos, localidades]
          );
          inserted += result.rowCount;
          skipped += numeros.length - result.rowCount;
        }

        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        await client.query(
          `
          UPDATE no_call_import_jobs
          SET status = 'failed',
              error_message = $1,
              completed_at = now(),
              updated_at = now()
          WHERE id = $2
          `,
          [error.message, jobId]
        );
        await client.end();
        return;
      }

      index += buffer.length;
      await client.query(
        `
        UPDATE no_call_import_jobs
        SET processed_rows = $1,
            inserted_rows = $2,
            skipped_rows = $3,
            total_rows = $4,
            updated_at = now()
        WHERE id = $5
        `,
        [index, inserted, skipped, totalRows, jobId]
      );
    }

    const finalStatus =
      totalRows > 0 && inserted === 0 && skipped > 0
        ? "failed"
        : "completed";

    await client.query(
      `
      UPDATE no_call_import_jobs
      SET status = $1,
          processed_rows = $2,
          inserted_rows = $3,
          skipped_rows = $4,
          total_rows = $5,
          completed_at = now(),
          updated_at = now()
      WHERE id = $6
      `,
      [finalStatus, index, inserted, skipped, totalRows, jobId]
    );
    await client.end();
  } catch (error) {
    await client.query(
      `
      UPDATE no_call_import_jobs
      SET status = 'failed',
          error_message = $1,
          completed_at = now(),
          updated_at = now()
      WHERE id = $2
      `,
      [error.message, jobId]
    );
    await client.end();
  }
}

function formatProductPriceSuffix(value) {
  const parsed = Number(value);
  if (Number.isNaN(parsed)) return "";
  if (Number.isInteger(parsed)) return String(parsed);
  return String(parsed);
}

function buildProductDisplayName(nombre, precio) {
  const base = normalizeText(nombre);
  if (!base) return "";
  const suffix = formatProductPriceSuffix(precio);
  return suffix ? `${base} ${suffix}` : base;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email));
}

function isActiveFromStatus(status) {
  return !["inactive", "blocked", "rejected", "pausado"].includes(status);
}

function statusFromActivo(activo) {
  return activo ? "approved" : "inactive";
}

function splitDisplayName(nombreCompleto) {
  const normalized = normalizeText(nombreCompleto);
  return {
    nombre: normalized,
    apellido: ""
  };
}

function formatUyuAmount(value) {
  const amount = Number(value || 0);
  return `$ ${amount.toLocaleString("es-UY", {
    minimumFractionDigits: 0,
    maximumFractionDigits: 0
  })}`;
}

function formatEsUyDateTime(value) {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toLocaleString("es-AR", {
    timeZone: LOCAL_TZ,
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
}

function humanizePersonType(tipoPersona) {
  switch (tipoPersona) {
    case "cliente_actual":
      return "Cliente actual";
    case "cliente_historico":
      return "Cliente historico";
    case "contacto":
    default:
      return "Contacto";
  }
}

function humanizeContactStatus(status) {
  return status === "bloqueado" ? "Bloqueado" : "Activo";
}

function getClientUiStatus(row) {
  if (row.producto_estado !== "alta") return "En baja";
  return Number(row.cuotas_pagas || 0) >= Number(row.carencia_cuotas || 0)
    ? "Al dia"
    : "Control";
}

function buildContactSummarySelect(whereClause = "") {
  return `
    SELECT
      c.id,
      c.nombre,
      c.apellido,
      c.email,
      c.telefono,
      c.celular,
      c.documento,
      c.organization_id,
            CASE\n              WHEN c.fecha_nacimiento IS NULL THEN NULL\n              ELSE DATE_PART('year', AGE(c.fecha_nacimiento))::int\n            END AS edad,
      c.status AS contacto_estado,
      COUNT(cp.id)::int AS productos_total,
      COUNT(*) FILTER (WHERE cp.estado = 'alta')::int AS productos_activos,
      CASE
        WHEN COUNT(cp.id) = 0 THEN 'contacto'
        WHEN COUNT(*) FILTER (WHERE cp.estado = 'alta') > 0 THEN 'cliente_actual'
        ELSE 'cliente_historico'
      END AS tipo_persona,
      c.created_at,
      c.updated_at
    FROM contacts c
    LEFT JOIN contact_products cp
      ON cp.contact_id = c.id
    ${whereClause}
    GROUP BY
      c.id,
      c.nombre,
      c.apellido,
      c.email,
      c.telefono,
      c.celular,
      c.documento,
      c.organization_id,
      c.status,
      c.created_at,
      c.updated_at
  `;
}

function mapContactRowToApi(row) {
  return {
    id: row.id,
    name: [row.nombre, row.apellido].filter(Boolean).join(" ").trim() || row.nombre || "",
    phone: row.telefono || "",
    city: "",
    status: humanizeContactStatus(row.contacto_estado),
    last: humanizePersonType(row.tipo_persona),
    email: row.email || "",
    documento: row.documento || "",
    tipoPersona: row.tipo_persona,
    contactoEstado: row.contacto_estado,
    productosTotal: Number(row.productos_total || 0),
    productosActivos: Number(row.productos_activos || 0),
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null
  };
}

function mapClientRowToApi(row) {
  const name = [row.nombre, row.apellido].filter(Boolean).join(" ").trim() || row.nombre || "";

  return {
    id: row.id,
    name,
    product: row.nombre_producto || "Sin producto",
    plan: row.producto_estado === "alta" ? "Activo" : "Inactivo",
    fee: formatUyuAmount(row.precio),
    status: getClientUiStatus(row),
    email: row.email || "",
    phone: row.telefono || "",
    celular: row.celular || "",
    documento: row.documento || "",
    tipoPersona: row.tipo_persona,
    contactoEstado: row.contacto_estado,
    productoEstado: row.producto_estado,
    cuotasPagas: Number(row.cuotas_pagas || 0),
    carenciaCuotas: Number(row.carencia_cuotas || 0),
    fecha_alta: row.fecha_alta || null,
    fechaAlta: row.fecha_alta || null,
    createdAt: row.fecha_alta || row.created_at || null,
    updatedAt: row.updated_at || null
  };
}

function mapUserRowToApi(row) {
  const nombreCompleto = [row.nombre, row.apellido].filter(Boolean).join(" ").trim();
  const activo = row.activo !== undefined && row.activo !== null
    ? Boolean(row.activo)
    : isActiveFromStatus(row.status);

  return {
    id: row.id,
    nombre: nombreCompleto || row.nombre || "",
    email: row.email,
    telefono: row.telefono || "",
    rol: row.role_key,
    role: row.role_key,
    activo,
    status: row.status,
    ultimoAcceso: row.last_login_at || null,
    last_login_at: row.last_login_at || null,
    createdAt: row.created_at,
    created_at: row.created_at
  };
}

function mapProductRowToApi(row) {
  return {
    id: row.id,
    nombre: row.nombre,
    categoria: row.categoria,
    descripcion: row.descripcion || "",
    observaciones: row.observaciones || "",
    precio: Number(row.precio || 0),
    activo: row.activo !== false,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

const IMPORT_TYPE_LABEL = {
  clientes: "CSV de clientes",
  no_llamar: "CSV Base No llamar",
  resultados: "CSV de resultados telefï¿½nicos",
  datos_para_trabajar: "CSV Datos para trabajar"
};

function csvEscape(value) {
  if (value === null || value === undefined) return "";
  const text = String(value);
  if (/[",\r\n]/.test(text)) {


    return `"${text.replace(/"/g, "\"\"")}"`;
  }
  return text;
}

function countSeparatorOutsideQuotes(line, separator) {
  let inQuotes = false;
  let count = 0;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (char === "\"") {
      if (inQuotes && line[i + 1] === "\"") {
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (!inQuotes && char === separator) count += 1;
  }
  return count;
}

function detectSeparator(headerLine) {
  const candidates = [",", ";", "\t"];
  const best = candidates
    .map((separator) => ({
      separator,
      count: countSeparatorOutsideQuotes(headerLine, separator)
    }))
    .sort((a, b) => b.count - a.count)[0];
  return best?.count > 0 ? best.separator : ",";
}

function parseCsv(input) {
  const text = String(input || "");
  const rows = [];
  const firstLine = text.split(/\r?\n/)[0] || "";
  const separator = detectSeparator(firstLine);
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];

    if (inQuotes) {
      if (char === "\"") {
        const nextChar = text[i + 1];
        if (nextChar === "\"") {
          field += "\"";
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === "\"") {
      inQuotes = true;
      continue;
    }

    if (char === separator) {
      row.push(field);
      field = "";
      continue;
    }

    if (char === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      continue;
    }

    if (char === "\r") {
      continue;
    }

    field += char;
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows;
}

function normalizeCsvHeader(header) {
  if (!header) return "";
  return String(header)
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ");
}

const CSV_HEADER_MAP = {
  "nombre": "nombre",
  "apellido": "apellido",
  "nombres": "nombre",
  "apellidos": "apellido",
  "documento": "documento",
  "cedula de identidad del beneficiario": "documento",
  "documento de cobranza": "documento_cobranza",
  "fecha de nacimiento": "fecha_nacimiento",
  "telefono": "telefono",
  "telefono de venta": "telefono_venta",
  "telefono venta": "telefono_venta",
  "telefono fijo": "telefono_fijo",
  "celular": "telefono_celular",
  "telefono celular": "telefono_celular",
  "correo electronico": "email",
  "direccion": "direccion",
  "telefono de contacto alternativo": "telefono_alternativo",
  "departamento": "departamento_residencia",
  "departamento de residencia": "departamento_residencia",
  "pais": "pais",
  "nombre del familiar": "nombre_familiar",
  "apellido del familiar": "apellido_familiar",
  "telefono del familiar": "telefono_familiar",
  "telefono de contacto": "telefono_familiar",
  "vinculo": "parentesco",
  "parentesco": "parentesco",
  "vendedor": "nombre_asesor",
  "nombre del asesor": "nombre_asesor",
  "nombre asesor": "nombre_asesor",
  "nombre_asesor": "nombre_asesor",
  "7_consulta vendedor": "nombre_asesor",
  "fecha y hora de la venta": "fecha_venta",
  "fecha de venta": "fecha_venta",
  "marca temporal": "fecha_venta",
  "2_fecha de venta (simplificada)": "fecha_venta_simple",
  "producto": "producto_nombre",
  "precio": "precio",
  "precio de venta (mensual)": "precio",
  "medio de pago": "medio_pago",
  "estado": "producto_estado",
  "30_estado": "producto_estado",
  "fecha de baja": "fecha_baja",
  "31_fecha de baja": "fecha_baja",
  "32_motivo de baja": "motivo_baja",
  "motivo": "motivo_baja_detalle",
  "motivo de baja": "motivo_baja_detalle",
  "obs": "observaciones",
  "cedula de identidad de cobranza": "documento_cobranza",
  "5_consulta de estado": "consulta_estado",
  "6_evaluacion": "evaluacion",
  "19_ok auditoria": "auditoria_ok",
  "plan contratado": "plan"
};

function parseDate(str) {
  if (!str?.trim()) return null;
  if (str.includes(";")) return null;
  const datePart = str.trim().split(" ")[0];
  const parts = datePart.split("/");
  if (parts.length !== 3) return null;
  let [day, month, year] = parts;
  if (!day || !month || !year) return null;
  if (year.length === 2) {
    const yearNum = parseInt(year, 10);
    if (!Number.isNaN(yearNum)) {
      year = yearNum <= 30
        ? `20${String(yearNum).padStart(2, "0")}`
        : `19${String(yearNum).padStart(2, "0")}`;
    }
  }
  const d = parseInt(day, 10);
  const m = parseInt(month, 10);
  const y = parseInt(year, 10);
  if (!Number.isFinite(d) || !Number.isFinite(m) || !Number.isFinite(y)) return null;
  if (d < 1 || d > 31) return null;
  if (m < 1 || m > 12) return null;
  if (y < 1900 || y > 2100) return null;
  return `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
}

const LOCAL_TZ = process.env.APP_TIMEZONE || process.env.TIMEZONE || "America/Argentina/Buenos_Aires";
function makeLocalDateAtNoon(ymd) {
  const parts = String(ymd || "").split("-").map((v) => Number(v));
  if (parts.length !== 3 || parts.some((v) => !Number.isFinite(v))) return new Date();
  return new Date(Date.UTC(parts[0], parts[1] - 1, parts[2], 12, 0, 0));
}

function addDaysYmd(ymd, deltaDays) {
  const date = makeLocalDateAtNoon(ymd);
  date.setUTCDate(date.getUTCDate() + deltaDays);
  return formatDateYmd(date);
}

function getLocalWeekdayIndex(ymd) {
  const date = makeLocalDateAtNoon(ymd);
  const weekday = new Intl.DateTimeFormat("en-US", {
    timeZone: LOCAL_TZ,
    weekday: "short"
  }).format(date);
  const map = {
    Mon: 1,
    Tue: 2,
    Wed: 3,
    Thu: 4,
    Fri: 5,
    Sat: 6,
    Sun: 7
  };
  return map[weekday] || 1;
}

function formatDateYmd(date, tz = LOCAL_TZ) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(date);
}

function formatTimeHm(date, tz = LOCAL_TZ) {
  return new Intl.DateTimeFormat("en-GB", {
    timeZone: tz,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  }).format(date);
}

function formatDurationLabel(seconds) {
  if (seconds === null || seconds === undefined) return null;
  const total = Math.max(0, Math.round(Number(seconds) || 0));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return `${hours}h ${String(minutes).padStart(2, "0")}m`;
}

function normalizeEstadoTipo(rawTipo) {
  const text = String(rawTipo || "").trim().toUpperCase();
  if (!text) return "";
  if (text === "BANO" || text === "BANIO" || text === "BA?O") return "BANO";
  return text;
}

function isPausaTipo(tipo) {
  return tipo === "DESCANSO" || tipo === "SUPERVISOR" || tipo === "BANO" || tipo === "BA?O";
}

function addMinutes(date, minutes) {
  const d = new Date(date);
  d.setMinutes(d.getMinutes() + minutes);
  return d;
}

function parseFechaParam(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text || text === "hoy") {
    return formatDateYmd(new Date());
  }
  return text;
}

function minutesBetween(start, end) {
  if (!start || !end) return 0;
  const diff = end.getTime() - start.getTime();
  return Math.max(0, Math.round(diff / 60000));
}

function timeToMinutes(value) {
  if (!value) return 0;
  const [h, m] = String(value).split(":").map((v) => Number(v));
  return (Number.isFinite(h) ? h : 0) * 60 + (Number.isFinite(m) ? m : 0);
}

function computeConversion(ventas, llamadas) {
  if (!llamadas) return 0;
  return Math.round((ventas / llamadas) * 1000) / 10;
}

function getInitialsFromUser(nombre, apellido) {
  const n = String(nombre || "").trim();
  const a = String(apellido || "").trim();
  const first = n ? n[0] : "";
  const second = a ? a[0] : (n.split(/\s+/)[1]?.[0] || "");
  return `${first}${second}`.toUpperCase() || "NA";
}

async function getConfigMap(client) {
  const result = await client.query("SELECT clave, valor FROM configuracion");
  const map = {};
  for (const row of result.rows) {
    const num = Number(row.valor);
    map[row.clave] = Number.isNaN(num) ? row.valor : num;
  }
  return {
    limite_bano_minutos: Number(map.limite_bano_minutos ?? 10),
    limite_descanso_minutos: Number(map.limite_descanso_minutos ?? 15),
    conversion_minima_porcentaje: Number(map.conversion_minima_porcentaje ?? 10),
    conversion_excelente_porcentaje: Number(map.conversion_excelente_porcentaje ?? 16),
    meta_llamadas_dia: Number(map.meta_llamadas_dia ?? 40),
    meta_ventas_dia: Number(map.meta_ventas_dia ?? 6),
    realtimeUrl: map.realtimeUrl || map.realtime_url || null
  };
}

async function getEstadoAgenteActual(client, agenteId, timezone = LOCAL_TZ) {
  const result = await client.query(
    `
    SELECT tipo, inicio, session_id, updated_at, last_seen_at
    FROM estado_agente_actual
    WHERE agente_id = $1
    LIMIT 1
    `,
    [agenteId]
  );
  const row = result.rows[0] || null;
  if (!row) return null;
  const inicioUtc = row.inicio ? new Date(row.inicio) : null;
  return {
    tipo: row.tipo,
    inicio: row.inicio,
    inicio_local: inicioUtc ? formatDateYmd(inicioUtc, timezone) + " " + formatTimeHm(inicioUtc, timezone) : null,
    session_id: row.session_id || null,
    updated_at: row.updated_at || null,
    last_seen_at: row.last_seen_at || null,
    requiere_bloqueo: isPausaTipo(row.tipo)
  };
}

async function upsertEstadoAgenteActual(client, agenteId, tipo, inicio, sessionId = null, lastSeenAt = null) {
  await client.query(
    `
    INSERT INTO estado_agente_actual (agente_id, tipo, inicio, session_id, last_seen_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, now())
    ON CONFLICT (agente_id)
    DO UPDATE SET
      tipo = EXCLUDED.tipo,
      inicio = EXCLUDED.inicio,
      session_id = EXCLUDED.session_id,
      last_seen_at = COALESCE(EXCLUDED.last_seen_at, estado_agente_actual.last_seen_at),
      updated_at = now()
    `,
    [agenteId, tipo, inicio, sessionId, lastSeenAt]
  );
}

async function closeActiveTurnEvent(client, eventRow, now, config) {
  if (!eventRow) return null;
  const fin = now;
  let excedido = false;
  let exceso = 0;
  if (isPausaTipo(eventRow.tipo)) {
    const limite = eventRow.tipo === "BANO" || eventRow.tipo === "BA?O"
      ? config.limite_bano_minutos
      : config.limite_descanso_minutos;
    const dur = minutesBetween(new Date(eventRow.inicio), fin);
    excedido = dur > limite;
    exceso = Math.max(0, dur - limite);
  }
  const result = await client.query(
    `
    UPDATE eventos_turno
    SET fin = $1,
        excedido = $2,
        exceso_minutos = $3
    WHERE id = $4
    RETURNING *
    `,
    [fin, excedido, exceso, eventRow.id]
  );
  return result.rows[0] || null;
}

async function applyInactividadSiCorresponde(client, agenteId, now) {
  const stateRes = await client.query(
    `
    SELECT tipo, inicio, session_id, last_seen_at
    FROM estado_agente_actual
    WHERE agente_id = $1
    LIMIT 1
    `,
    [agenteId]
  );
  const state = stateRes.rows[0] || null;
  if (!state) return { changed: false, state: null };
  if (state.tipo !== "TRABAJO") return { changed: false, state };
  if (!state.last_seen_at) return { changed: false, state };

  const lastSeen = new Date(state.last_seen_at);
  const inactiveAt = addMinutes(lastSeen, INACTIVITY_MINUTES);
  if (now <= inactiveAt) return { changed: false, state };

  await client.query(
    `
    INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
    VALUES ($1, 'INACTIVO', $2, NULL, $3)
    `,
    [agenteId, inactiveAt, formatDateYmd(inactiveAt)]
  );

  await upsertEstadoAgenteActual(client, agenteId, "INACTIVO", inactiveAt, state.session_id || null, state.last_seen_at);
  return {
    changed: true,
    state: {
      ...state,
      tipo: "INACTIVO",
      inicio: inactiveAt,
      last_seen_at: state.last_seen_at
    },
    inactiveAt
  };
}

async function getTeamSummary(client, fecha, now = new Date()) {
  const config = await getConfigMap(client);
  const sellersRes = await client.query(
    `
    SELECT id, nombre, apellido
    FROM users
    WHERE role_key = 'vendedor'
      AND status = 'approved'
      AND (is_test IS NULL OR is_test = false)
    ORDER BY nombre
    `
  );
  const sellers = sellersRes.rows;
  const sellerIds = sellers.map((u) => u.id);

  const callsRes = sellerIds.length
    ? await client.query(
      `
      SELECT
        user_id,
        COUNT(*)::int AS total_llamadas,
        COUNT(*) FILTER (WHERE resultado = 'venta')::int AS total_ventas
      FROM (
        SELECT DISTINCT ON (contact_id, user_id)
          user_id,
          contact_id,
          resultado
        FROM lead_management_history
        WHERE (fecha_gestion AT TIME ZONE $3)::date = $1::date
          AND user_id = ANY($2::uuid[])
        ORDER BY contact_id, user_id, fecha_gestion DESC
      ) last_gestiones
      GROUP BY user_id
      `,
      [fecha, sellerIds, LOCAL_TZ]
    )
    : { rows: [] };

  const callsMap = new Map();
  for (const row of callsRes.rows) {
    callsMap.set(row.user_id, {
      total_llamadas: Number(row.total_llamadas || 0),
      total_ventas: Number(row.total_ventas || 0)
    });
  }

  const pauseTypes = ["DESCANSO", "SUPERVISOR", "BA?O", "BANO"];
  const eventsRes = sellerIds.length
    ? await client.query(
      `
      SELECT
        agente_id,
        MIN(CASE WHEN tipo = 'LOGIN' THEN inicio END) AS login_time,
        MAX(CASE WHEN tipo = 'LOGOUT' THEN fin END) AS logout_time,
        SUM(CASE WHEN tipo = ANY($3::text[]) AND fin IS NOT NULL THEN EXTRACT(EPOCH FROM (fin - inicio))/60 ELSE 0 END)::int AS pause_minutes,
        COUNT(*) FILTER (WHERE tipo = ANY($3::text[]))::int AS pause_count
      FROM eventos_turno
      WHERE fecha = $1
        AND agente_id = ANY($2::uuid[])
      GROUP BY agente_id
      `,
      [fecha, sellerIds, pauseTypes]
    )
    : { rows: [] };

  const eventsMap = new Map();
  for (const row of eventsRes.rows) {
    eventsMap.set(row.agente_id, {
      login_time: row.login_time ? new Date(row.login_time) : null,
      logout_time: row.logout_time ? new Date(row.logout_time) : null,
      pause_minutes: Number(row.pause_minutes || 0),
      pause_count: Number(row.pause_count || 0)
    });
  }

  let totalLlamadas = 0;
  let totalVentas = 0;
  let totalPauseMinutes = 0;
  let agentesActivos = 0;
  const agentesOutput = [];

  for (const seller of sellers) {
    const callStats = callsMap.get(seller.id) || { total_llamadas: 0, total_ventas: 0 };
    totalLlamadas += callStats.total_llamadas;
    totalVentas += callStats.total_ventas;

    const eventStats = eventsMap.get(seller.id) || {
      login_time: null,
      logout_time: null,
      pause_minutes: 0,
      pause_count: 0
    };

    const conversion = computeConversion(callStats.total_ventas, callStats.total_llamadas);

    let tiempoConectadoMinutos = null;
    if (eventStats.login_time) {
      const end = eventStats.logout_time || now;
      tiempoConectadoMinutos = minutesBetween(eventStats.login_time, end);
    }

    if (eventStats.login_time && !eventStats.logout_time) {
      agentesActivos += 1;
    }

    totalPauseMinutes += eventStats.pause_minutes;

    agentesOutput.push({
      id: seller.id,
      nombre: seller.nombre,
      iniciales: getInitialsFromUser(seller.nombre, seller.apellido),
      turno_inicio: null,
      turno_fin: null,
      login_time: eventStats.login_time ? formatTimeHm(eventStats.login_time) : null,
      logout_time: eventStats.logout_time ? formatTimeHm(eventStats.logout_time) : null,
      tiempo_conectado_minutos: tiempoConectadoMinutos,
      total_llamadas: callStats.total_llamadas,
      total_ventas: callStats.total_ventas,
      conversion,
      estado: "Activo",
      alerta: false,
      cantidad_pausas: eventStats.pause_count,
      tiempo_total_pausas_minutos: eventStats.pause_minutes
    });
  }

  const avgPauseMinutes = sellers.length
    ? Math.round(totalPauseMinutes / sellers.length)
    : 0;

  for (const agent of agentesOutput) {
    let estado = "Activo";
    if (agent.conversion < config.conversion_minima_porcentaje) estado = "Atencion";
    if (agent.conversion >= config.conversion_excelente_porcentaje) estado = "Excelente";
    if (avgPauseMinutes && agent.tiempo_total_pausas_minutos > avgPauseMinutes + 20) {
      estado = "Atencion";
    }
    agent.estado = estado;
    agent.alerta = estado === "Atencion";
  }

  let agentesAtencion = agentesOutput.filter((a) => a.estado === "Atencion").length;

  const alertasRes = await client.query(
    `
    SELECT a.*, u.nombre AS agente_nombre
    FROM alertas a
    LEFT JOIN users u ON u.id = a.agente_id
    WHERE a.fecha = $1
      AND a.resuelta = false
    ORDER BY a.created_at DESC
    `,
    [fecha]
  );

  const resumen_equipo = {
    agentes_activos: agentesActivos,
    agentes_total: sellers.length,
    agentes_atencion: agentesAtencion,
    total_llamadas: totalLlamadas,
    meta_llamadas: config.meta_llamadas_dia * sellers.length,
    total_ventas: totalVentas,
    meta_ventas: config.meta_ventas_dia * sellers.length,
    conversion_promedio: computeConversion(totalVentas, totalLlamadas)
  };

  const alertas_activas = alertasRes.rows.map((row) => ({
    agente_nombre: row.agente_nombre,
    descripcion: row.descripcion || row.tipo
  }));

  const summary = {
    agentsActive: `${resumen_equipo.agentes_activos} / ${resumen_equipo.agentes_total}`,
    attentionCount: resumen_equipo.agentes_atencion,
    calls: resumen_equipo.total_llamadas,
    callsGoal: resumen_equipo.meta_llamadas,
    sales: resumen_equipo.total_ventas,
    salesGoal: resumen_equipo.meta_ventas,
    avgConversion: resumen_equipo.conversion_promedio,
    avgConversionNote: null,
    avgPauseMinutes,
    attentionNote: alertas_activas[0]
      ? `${alertas_activas[0].agente_nombre} requiere atenci?n ? ${alertas_activas[0].descripcion}`
      : null
  };

  const agents = agentesOutput.map((agent) => ({
    id: agent.id,
    name: agent.nombre,
    apellido: null,
    calls: agent.total_llamadas,
    sales: agent.total_ventas,
    conversion: agent.conversion,
    status: agent.estado,
    pausesMinutes: agent.tiempo_total_pausas_minutos || 0,
    pausesCount: agent.cantidad_pausas || 0,
    login: agent.login_time,
    workTime: agent.tiempo_conectado_minutos
      ? `${Math.floor(agent.tiempo_conectado_minutos / 60)}h ${agent.tiempo_conectado_minutos % 60}m`
      : null
  }));

  return {
    fecha,
    resumen_equipo,
    alertas_activas,
    agentes: agentesOutput,
    summary,
    agents
  };
}

async function getDailyWorkReport(client, fecha, timezone = LOCAL_TZ, now = new Date(), filterUserId = null) {
  const result = await client.query(
    `
    WITH base AS (
      SELECT
        e.agente_id,
        e.tipo,
        e.inicio,
        e.fin
      FROM eventos_turno e
      WHERE (e.inicio AT TIME ZONE $2)::date = $1::date
    ),
    base_ranked AS (
      SELECT
        b.*,
        CASE b.tipo
          WHEN 'TRABAJO' THEN 1
          WHEN 'INACTIVO' THEN 2
          WHEN 'DESCANSO' THEN 3
          WHEN 'BANO' THEN 4
          WHEN 'BA?O' THEN 4
          WHEN 'SUPERVISOR' THEN 5
          WHEN 'LOGOUT' THEN 6
          WHEN 'LOGIN' THEN 7
          ELSE 99
        END AS prioridad_tipo
      FROM base b
    ),
    base_dedup AS (
      SELECT *
      FROM (
        SELECT
          br.*,
          ROW_NUMBER() OVER (
            PARTITION BY br.agente_id, br.inicio
            ORDER BY br.prioridad_tipo ASC
          ) AS rn
        FROM base_ranked br
      ) x
      WHERE x.rn = 1
    ),
    intervalos AS (
      SELECT
        agente_id,
        tipo,
        inicio,
        LEAD(inicio) OVER (PARTITION BY agente_id ORDER BY inicio) AS siguiente_inicio
      FROM base_dedup
    ),
    last_state AS (
      SELECT DISTINCT ON (agente_id)
        agente_id,
        tipo AS estado_actual
      FROM base_dedup
      ORDER BY agente_id, inicio DESC, prioridad_tipo ASC
    ),
    logins AS (
      SELECT agente_id, MIN(inicio) AS login_utc
      FROM base
      WHERE tipo = 'LOGIN'
      GROUP BY agente_id
    ),
    logouts AS (
      SELECT agente_id, MAX(COALESCE(fin, inicio)) AS logout_utc
      FROM base
      WHERE tipo = 'LOGOUT'
      GROUP BY agente_id
    ),
    session_count AS (
      SELECT
        agente_id,
        COUNT(*)::int AS session_count
      FROM base
      WHERE tipo = 'LOGIN'
      GROUP BY agente_id
    ),
    durations AS (
      SELECT
        agente_id,
        SUM(CASE WHEN tipo = 'DESCANSO'
          THEN EXTRACT(EPOCH FROM (COALESCE(siguiente_inicio, $3) - inicio)) ELSE 0 END)::bigint AS descanso_seg,
        SUM(CASE WHEN tipo IN ('BANO', 'BA?O')
          THEN EXTRACT(EPOCH FROM (COALESCE(siguiente_inicio, $3) - inicio)) ELSE 0 END)::bigint AS bano_seg,
        SUM(CASE WHEN tipo = 'SUPERVISOR'
          THEN EXTRACT(EPOCH FROM (COALESCE(siguiente_inicio, $3) - inicio)) ELSE 0 END)::bigint AS supervisor_seg,
        SUM(CASE WHEN tipo = 'INACTIVO'
          THEN EXTRACT(EPOCH FROM (COALESCE(siguiente_inicio, $3) - inicio)) ELSE 0 END)::bigint AS inactivo_seg
      FROM intervalos
      GROUP BY agente_id
    ),
    jornada_span AS (
      SELECT
        l.agente_id,
        l.login_utc,
        o.logout_utc,
        COALESCE(o.logout_utc, $3) AS jornada_fin,
        CASE
          WHEN l.login_utc IS NULL THEN 0
          ELSE EXTRACT(EPOCH FROM (COALESCE(o.logout_utc, $3) - l.login_utc))
        END::bigint AS total_jornada_seg
      FROM logins l
      LEFT JOIN logouts o ON o.agente_id = l.agente_id
    )
    SELECT
      u.id,
      u.nombre,
      u.apellido,
      l.login_utc,
      o.logout_utc,
      (l.login_utc AT TIME ZONE $2) AS login_local,
      (o.logout_utc AT TIME ZONE $2) AS logout_local,
      ls.estado_actual,
      COALESCE(sc.session_count, 0) AS session_count,
      GREATEST(
        COALESCE(js.total_jornada_seg, 0)
        - COALESCE(d.descanso_seg, 0)
        - COALESCE(d.bano_seg, 0)
        - COALESCE(d.supervisor_seg, 0)
        - COALESCE(d.inactivo_seg, 0),
        0
      ) AS trabajo_seg,
      COALESCE(d.descanso_seg, 0) AS descanso_seg,
      COALESCE(d.bano_seg, 0) AS bano_seg,
      COALESCE(d.supervisor_seg, 0) AS supervisor_seg,
      js.total_jornada_seg
    FROM users u
    LEFT JOIN logins l ON l.agente_id = u.id
    LEFT JOIN logouts o ON o.agente_id = u.id
    LEFT JOIN last_state ls ON ls.agente_id = u.id
    LEFT JOIN durations d ON d.agente_id = u.id
    LEFT JOIN jornada_span js ON js.agente_id = u.id
    LEFT JOIN session_count sc ON sc.agente_id = u.id
    WHERE u.role_key = 'vendedor'
      AND u.status = 'approved'
      AND (u.is_test IS NULL OR u.is_test = false)
      AND ($4::uuid IS NULL OR u.id = $4::uuid)
    ORDER BY u.nombre
    `,
    [fecha, timezone, now, filterUserId]
  );

  return result.rows.map((row) => {
    const loginUtc = row.login_utc ? new Date(row.login_utc) : null;
    const logoutUtc = row.logout_utc ? new Date(row.logout_utc) : null;
    const trabajoSeg = Number(row.trabajo_seg || 0);
    const descansoSeg = Number(row.descanso_seg || 0);
    const banoSeg = Number(row.bano_seg || 0);
    const supervisorSeg = Number(row.supervisor_seg || 0);
    const totalJornadaSeg = row.total_jornada_seg !== null ? Number(row.total_jornada_seg) : null;

    return {
      id: row.id,
      nombre: row.nombre,
      apellido: row.apellido,
      estado_actual: row.estado_actual || null,
      sessionCount: Number(row.session_count || 0),
      login_local: row.login_local || null,
      logout_local: row.logout_local || null,
      login_time: loginUtc ? formatTimeHm(loginUtc, timezone) : null,
      logout_time: logoutUtc ? formatTimeHm(logoutUtc, timezone) : null,
      tiempoProductivoSeg: trabajoSeg,
      descansosSeg: descansoSeg,
      banosSeg: banoSeg,
      supervisorSeg: supervisorSeg,
      disponibleSeg: trabajoSeg,
      totalJornadaSeg,
      tiempoProductivoLabel: formatDurationLabel(trabajoSeg),
      descansosLabel: formatDurationLabel(descansoSeg),
      banosLabel: formatDurationLabel(banoSeg),
      supervisorLabel: formatDurationLabel(supervisorSeg),
      totalJornadaLabel: totalJornadaSeg !== null ? formatDurationLabel(totalJornadaSeg) : null
    };
  });
}

async function getAgentDetail(client, agenteId, fecha, now = new Date()) {
  const config = await getConfigMap(client);
  const sellerRes = await client.query(
    `SELECT id, nombre, apellido FROM users WHERE id = $1 LIMIT 1`,
    [agenteId]
  );
  const seller = sellerRes.rows[0];
  if (!seller) return null;

  const callsRes = await client.query(
    `
    SELECT lmh.id,
           lmh.resultado,
           lmh.nota,
           lmh.fecha_gestion,
           d.nombre AS cliente_nombre,
           d.apellido AS cliente_apellido
    FROM lead_management_history lmh
    LEFT JOIN datos_para_trabajar d ON d.id = lmh.contact_id
    WHERE lmh.user_id = $1
      AND (lmh.fecha_gestion AT TIME ZONE 'America/Montevideo')::date = $2::date
    ORDER BY lmh.fecha_gestion ASC
    `,
    [agenteId, fecha]
  );
  const calls = callsRes.rows;
  const eventosRes = await client.query(
    `
    SELECT id, tipo, inicio, fin, excedido, exceso_minutos
    FROM eventos_turno
    WHERE agente_id = $1
      AND (inicio AT TIME ZONE $3)::date = $2::date
    ORDER BY inicio ASC
    `,
    [agenteId, fecha, LOCAL_TZ]
  );
  const eventosRows = eventosRes.rows || [];

  const pauseTypes = new Set(["DESCANSO", "SUPERVISOR", "BA?O", "BANO"]);
  let totalPausas = 0;
  let totalTrabajo = 0;
  let pausaCount = 0;
  let firstLogin = null;
  let lastLogout = null;

  const eventos = eventosRows.map((row) => {
    const inicioDate = row.inicio ? new Date(row.inicio) : null;
    const finDate = row.fin ? new Date(row.fin) : null;
    const effectiveEnd = finDate || (inicioDate ? now : null);
    const duracion = inicioDate && effectiveEnd ? minutesBetween(inicioDate, effectiveEnd) : null;

    if (row.tipo === "LOGIN" && inicioDate) {
      if (!firstLogin || inicioDate < firstLogin) firstLogin = inicioDate;
    }
    if (row.tipo === "LOGOUT" && (finDate || inicioDate)) {
      const logoutAt = finDate || inicioDate;
      if (!lastLogout || logoutAt > lastLogout) lastLogout = logoutAt;
    }

    if (pauseTypes.has(row.tipo)) {
      pausaCount += 1;
      if (duracion !== null) totalPausas += duracion;
    }
    if (row.tipo === "TRABAJO" && duracion !== null) {
      totalTrabajo += duracion;
    }

    return {
      id: row.id,
      tipo: row.tipo,
      inicio: inicioDate ? formatTimeHm(inicioDate) : null,
      fin: finDate ? formatTimeHm(finDate) : null,
      duracion_minutos: duracion,
      excedido: row.excedido ?? false,
      exceso_minutos: Number(row.exceso_minutos || 0)
    };
  });

  const tiempoConectadoMin = totalTrabajo + totalPausas;
  const porcentajeProductivo = tiempoConectadoMin
    ? Number(((totalTrabajo / tiempoConectadoMin) * 100).toFixed(1))
    : null;

  const eventosConPorcentaje = tiempoConectadoMin
    ? eventos.map((evento) => ({
        ...evento,
        porcentaje_ancho: evento.duracion_minutos !== null
          ? Number(((evento.duracion_minutos / tiempoConectadoMin) * 100).toFixed(1))
          : 0
      }))
    : eventos;

  const totalCalls = calls.length;
  const totalVentas = calls.filter((c) => c.resultado === "venta").length;
  const conversion = computeConversion(totalVentas, totalCalls);

  const teamSummary = await getTeamSummary(client, fecha, now);
  const conversionPromedioEquipo = teamSummary.resumen_equipo.conversion_promedio;

  const alertas = [];
  if (conversion < config.conversion_minima_porcentaje) {
    alertas.push({
      tipo: "conversion_baja",
      descripcion: `${conversion}% actual vs mï¿½nimo ${config.conversion_minima_porcentaje}%`,
      severidad: "alta"
    });
  }

  const llamadas = calls.map((call) => ({
    id: call.id,
    hora: formatTimeHm(new Date(call.fecha_gestion)),
    duracion_segundos: null,
    cliente_nombre: [call.cliente_nombre, call.cliente_apellido].filter(Boolean).join(" ").trim() || null,
    resultado: call.resultado,
    corta: false
  }));

  const estado = conversion < config.conversion_minima_porcentaje
    ? "Atencion"
    : conversion >= config.conversion_excelente_porcentaje
    ? "Excelente"
    : "Activo";

  return {
    agente: {
      id: seller.id,
      nombre: seller.nombre,
      iniciales: getInitialsFromUser(seller.nombre, seller.apellido),
      turno_inicio: null,
      turno_fin: null,
      estado
    },
    metricas: {
      total_llamadas: totalCalls,
      meta_llamadas: config.meta_llamadas_dia,
      total_ventas: totalVentas,
      meta_ventas: config.meta_ventas_dia,
      conversion,
      conversion_promedio_equipo: conversionPromedioEquipo,
      tiempo_conectado_minutos: tiempoConectadoMin || null,
      tiempo_productivo_minutos: totalTrabajo || null,
      porcentaje_productivo: porcentajeProductivo,
      tiempo_total_pausas_minutos: totalPausas || 0,
      cantidad_pausas: pausaCount || 0
    },
    alertas,
    eventos: eventosConPorcentaje,
    llamadas
  };
}

async function getAgentWeek(client, agenteId, todayDate) {
  const config = await getConfigMap(client);
  const todayYmd = parseFechaParam(todayDate);
  const weekday = getLocalWeekdayIndex(todayYmd);
  const mondayYmd = addDaysYmd(todayYmd, -(weekday - 1));

  const dates = [];
  for (let offset = 0; offset <= 6; offset += 1) {
    const d = addDaysYmd(mondayYmd, offset);
    if (d <= todayYmd) dates.push(d);
  }

  const callsRes = await client.query(
    `
    SELECT (fecha_gestion AT TIME ZONE $3)::date AS fecha,
           COUNT(*)::int AS llamadas,
           COUNT(*) FILTER (WHERE resultado = 'venta')::int AS ventas
    FROM lead_management_history
    WHERE user_id = $1
      AND (fecha_gestion AT TIME ZONE $3)::date = ANY($2::date[])
    GROUP BY (fecha_gestion AT TIME ZONE $3)::date
    `,
    [agenteId, dates, LOCAL_TZ]
  );
  const callsMap = new Map(callsRes.rows.map((row) => [row.fecha, row]));

  let totalVentasSemana = 0;
  let totalLlamadasSemana = 0;

  const dias = dates.map((fecha) => {
    const row = callsMap.get(fecha) || { llamadas: 0, ventas: 0 };
    const llamadas = Number(row.llamadas || 0);
    const ventas = Number(row.ventas || 0);
    const conversion = computeConversion(ventas, llamadas);
    totalVentasSemana += ventas;
    totalLlamadasSemana += llamadas;
    const diaNombre = new Intl.DateTimeFormat("es-ES", { weekday: "long", timeZone: LOCAL_TZ }).format(makeLocalDateAtNoon(fecha));
    return {
      fecha,
      dia_nombre: diaNombre.charAt(0).toUpperCase() + diaNombre.slice(1),
      llamadas,
      ventas,
      conversion,
      cantidad_alertas: 0,
      bajo_minimo: conversion < config.conversion_minima_porcentaje
    };
  });

  return {
    resumen: {
      conversion_promedio_semana: computeConversion(totalVentasSemana, totalLlamadasSemana),
      total_alertas_semana: 0,
      total_ventas_semana: totalVentasSemana,
      total_llamadas_semana: totalLlamadasSemana
    },
    dias
  };
}

async function createAlert(client, payload) {
  const result = await client.query(
    `
    INSERT INTO alertas (
      agente_id,
      tipo,
      subtipo,
      descripcion,
      hora_evento,
      duracion_minutos,
      limite_minutos,
      exceso_minutos,
      veces_en_semana,
      fecha,
      resuelta
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false)
    RETURNING *
    `,
    [
      payload.agente_id,
      payload.tipo,
      payload.subtipo || null,
      payload.descripcion || null,
      payload.hora_evento || null,
      payload.duracion_minutos || null,
      payload.limite_minutos || null,
      payload.exceso_minutos || null,
      payload.veces_en_semana || 0,
      payload.fecha
    ]
  );
  return result.rows[0];
}

function parseNumber(value) {
  if (value === null || value === undefined) return null;
  const normalized = String(value).replace(/[^0-9,.-]/g, "").replace(",", ".");
  if (!normalized) return null;
  const parsed = Number(normalized);
  return Number.isNaN(parsed) ? null : parsed;
}

function normalizeCsvValue(value) {
  const text = String(value ?? "").trim();
  return text === "" ? null : text;
}

function detectCsvSeparator(headerLine) {
  const firstLine = String(headerLine || "").split("\n")[0];
  const semicolons = (firstLine.match(/;/g) || []).length;
  const commas = (firstLine.match(/,/g) || []).length;
  const tabs = (firstLine.match(/\t/g) || []).length;
  if (semicolons >= commas && semicolons >= tabs) return ";";
  if (tabs >= commas) return "\t";
  return ",";
}

function parseCsvLine(line, separator) {
  const cells = [];
  let value = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (char === "\"") {
      if (inQuotes && line[i + 1] === "\"") {
        value += "\"";
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (!inQuotes && char === separator) {
      cells.push(value.trim());
      value = "";
      continue;
    }
    value += char;
  }

  cells.push(value.trim());
  return cells;
}

function parseCsvWithHeaders(csvText) {
  const lines = String(csvText || "")
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (!lines.length) return { headers: [], rows: [] };

  const separator = detectCsvSeparator(lines[0]);
  const headers = parseCsvLine(lines[0], separator).map((h) => h.trim());
  const rows = lines.slice(1).map((line) => parseCsvLine(line, separator));
  return { headers, rows };
}

const DATOS_TRABAJAR_HEADER_MAP = {
  "nombre": "nombre",
  "apellido": "apellido",
  "documento": "documento",
  "fecha de nacimiento": "fecha_nacimiento",
  "fecha nacimiento": "fecha_nacimiento",
  "fecha_nacimiento": "fecha_nacimiento",
  "telefono": "telefono",
  "celular": "celular",
  "correo electronico": "correo_electronico",
  "correo electrï¿½nico": "correo_electronico",
  "email": "correo_electronico",
  "direccion": "direccion",
  "direcciï¿½n": "direccion",
  "departamento": "departamento",
  "localidad": "localidad",
  "pais": "pais",
  "nombre completo": "nombre_completo",
  "nombre_completo": "nombre_completo",
  "origen del dato": "origen_dato",
  "origen_dato": "origen_dato",
  "origen": "origen_dato"
};

function classifyUyPhone(rawValue) {
  const numero = normalizeUyNumber(rawValue);
  if (!numero) return { tipo: null, valor: null };
  if (numero.startsWith("0") && numero.length === 9) {
    return { tipo: "celular", valor: numero };
  }
  if (numero.length === 8 && (numero.startsWith("2") || numero.startsWith("4"))) {
    return { tipo: "telefono", valor: numero };
  }
  if (numero.length === 8 && numero.startsWith("9")) {
    return { tipo: "celular", valor: `0${numero}` };
  }
  if (numero.startsWith("9")) {
    return { tipo: "celular", valor: numero.startsWith("0") ? numero : `0${numero}` };
  }
  return { tipo: "telefono", valor: numero };
}

function splitNombreCompleto(nombreCompleto) {
  const normalized = normalizeText(nombreCompleto);
  if (!normalized) return { nombre: null, apellido: null };
  const parts = normalized.split(/\s+/).filter(Boolean);
  if (parts.length === 1) {
    return { nombre: parts[0], apellido: null };
  }
  if (parts.length === 2) {
    return { nombre: parts[1], apellido: parts[0] };
  }
  const apellido = parts.slice(0, 2).join(" ");
  const nombre = parts.slice(2).join(" ");
  return { nombre, apellido };
}

function mapDatosParaTrabajarCsv(csvText) {
  const { headers, rows } = parseCsvWithHeaders(csvText);
  if (!headers.length) return { rows: [], ignoredEmptyRows: 0 };
  const headerKeys = headers.map((header) => DATOS_TRABAJAR_HEADER_MAP[normalizeCsvHeader(header)] || null);
  const mapped = [];
  let ignoredEmptyRows = 0;

  for (const row of rows) {
    const item = {};
    for (let i = 0; i < headerKeys.length; i += 1) {
      const key = headerKeys[i];
      if (!key) continue;
      const rawValue = normalizeCsvValue(row[i]);
      if (key === "fecha_nacimiento") {
        item[key] = rawValue ? parseDate(rawValue) : null;
      } else {
        item[key] = rawValue;
      }
    }

    if ((!item.nombre || !item.apellido) && item.nombre_completo) {
      const parsed = splitNombreCompleto(item.nombre_completo);
      if (!item.nombre && parsed.nombre) item.nombre = parsed.nombre;
      if (!item.apellido && parsed.apellido) item.apellido = parsed.apellido;
    }

    const telefonoRaw = item.telefono;
    const celularRaw = item.celular;
    let telefono = null;
    let celular = null;

    for (const candidate of [telefonoRaw, celularRaw]) {
      if (!candidate) continue;
      const { tipo, valor } = classifyUyPhone(candidate);
      if (tipo === "celular" && !celular) celular = valor;
      if (tipo === "telefono" && !telefono) telefono = valor;
    }

    item.telefono = telefono;
    item.celular = celular;

    if (!item.departamento && telefono) {
      item.departamento = getDepartamentoFromFixed(telefono);
    }
    if (!item.localidad && telefono) {
      item.localidad = getLocalidadFromFixed(telefono);
    }
    const hasValues = Object.values(item).some(
      (value) => value !== null && value !== undefined && String(value).trim() !== ""
    );
    if (!hasValues) {
      ignoredEmptyRows += 1;
      continue;
    }
    mapped.push(item);
  }

  return { rows: mapped, ignoredEmptyRows };
}

function mapCsvRowsToImport(rows) {
  if (!rows.length) return { rows: [], ignoredEmptyRows: 0 };
  const headerRow = rows[0];
  const headerKeys = headerRow.map((header) => CSV_HEADER_MAP[normalizeCsvHeader(header)] || null);
  const mapped = [];
  let ignoredEmptyRows = 0;

  for (let i = 1; i < rows.length; i += 1) {
    const row = rows[i];
    const item = {};
    for (let j = 0; j < headerKeys.length; j += 1) {
      const key = headerKeys[j];
      if (!key) continue;
      item[key] = normalizeCsvValue(row[j]);
    }
    const hasValues = Object.values(item).some(
      (value) => value !== null && String(value).trim() !== ""
    );
    if (!hasValues) {
      ignoredEmptyRows += 1;
      continue;
    }
    mapped.push(item);
  }

  return { rows: mapped, ignoredEmptyRows };
}

const CONTACT_IMPORT_COLUMNS = [
  "batch_id",
  "row_number",
  "nombre",
  "apellido",
  "email",
  "telefono",
  "documento",
  "contacto_estado",
  "producto_nombre",
  "plan",
  "precio",
  "medio_pago",
  "fecha_alta",
  "cuotas_pagas",
  "carencia_cuotas",
  "producto_estado",
  "motivo_baja",
  "motivo_baja_detalle",
  "fecha_baja",
  "vendedor_nombre",
  "vendedor_email",
  "fecha_venta",
  "documento_beneficiario",
  "documento_cobranza",
  "telefono_venta",
  "telefono_fijo",
  "telefono_celular",
  "telefono_alternativo",
  "consulta_estado",
  "evaluacion",
  "auditoria_ok",
  "auditoria_comentario",
  "nombre_asesor",
  "fecha_nacimiento",
  "departamento_residencia",
  "nombre_familiar",
  "apellido_familiar",
  "telefono_familiar",
  "parentesco",
  "import_status",
  "error_detail",
  "raw_payload"
];

function buildContactImportRowValues(batchId, rowNumber, item, importStatus, errorDetail) {
  return [
    batchId,
    rowNumber,
    item.nombre,
    item.apellido,
    item.email,
    item.telefono,
    item.documento,
    "activo",
    item.producto_nombre,
    item.plan || null,
    parseNumber(item.precio),
    item.medio_pago,
    parseDate(item.fecha_venta),
    null,
    null,
    item.producto_estado,
    null,
    null,
    parseDate(item.fecha_baja),
    item.nombre_asesor,
    item.vendedor_email,
    parseDate(item.fecha_venta),
    item.documento_beneficiario,
    item.documento_cobranza,
    item.telefono_venta,
    item.telefono_fijo,
    item.telefono_celular,
    item.telefono_alternativo,
    item.consulta_estado,
    item.evaluacion,
    item.auditoria_ok,
    item.auditoria_comentario,
    item.nombre_asesor,
    parseDate(item.fecha_nacimiento),
    item.departamento_residencia,
    item.nombre_familiar,
    item.apellido_familiar,
    item.telefono_familiar,
    item.parentesco,
    importStatus,
    errorDetail,
    item
  ];
}

function buildContactImportInsertBatch(batchRows) {
  const values = [];
  const placeholders = batchRows.map((row, index) => {
    const base = index * CONTACT_IMPORT_COLUMNS.length;
    const params = CONTACT_IMPORT_COLUMNS.map((_, colIndex) => `$${base + colIndex + 1}`);
    values.push(...row);
    return `(${params.join(", ")})`;
  });
  return {
    sql: `
      INSERT INTO contact_import_rows (${CONTACT_IMPORT_COLUMNS.join(", ")})
      VALUES ${placeholders.join(", ")}
    `,
    values
  };
}

function validateImportRow(item) {
  const errors = [];
  if (!item.nombre && !item.apellido) {
    errors.push("nombre o apellido requerido");
  }
  return errors;
}

async function ensureDatosTrabajarJobTable(client) {
  await client.query(
    `
    CREATE TABLE IF NOT EXISTS datos_para_trabajar_import_jobs (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      batch_id uuid,
      file_name text,
      status text,
      total_rows int,
      processed_rows int,
      inserted_rows int,
      blocked_rows int,
      skipped_rows int,
      csv_text text,
      created_by uuid,
      error_message text,
      started_at timestamptz,
      completed_at timestamptz,
      created_at timestamptz DEFAULT now(),
      updated_at timestamptz DEFAULT now()
    )
    `
  );
}

function buildDatosTrabajarInsertBatch(batchRows, organizationId = null, importJobId = null) {
  const columns = [
    "nombre",
    "apellido",
    "documento",
    "fecha_nacimiento",
    "telefono",
    "celular",
    "email",
    "direccion",
    "departamento",
    "localidad",
    "origen_dato",
    "estado",
    "organization_id",
    "import_job_id"
  ];
  const values = [];
  const placeholders = batchRows.map((row, index) => {
    values.push(...row, organizationId, importJobId);
    const base = index * columns.length;
    const params = columns.map((_, colIndex) => `$${base + colIndex + 1}`);
    return `(${params.join(", ")})`;
  });
  return {
    sql: `
      INSERT INTO datos_para_trabajar (${columns.join(", ")})
      VALUES ${placeholders.join(", ")}
    `,
    values
  };
}

export async function processRecuperoImportJob(jobId) {
  const client = createDbClient();
  await client.connect();

  try {
    const jobRes = await client.query(
      `
      SELECT id, csv_text, status, total_rows, processed_rows, updated_rows, error_rows, delimiter, created_by
      FROM recupero_import_jobs
      WHERE id = $1
      LIMIT 1
      `,
      [jobId]
    );

    if (!jobRes.rows.length) return;
    const job = jobRes.rows[0];
    const createdBy = job.created_by || null;
    const csvText = job.csv_text || "";
    const totalRows = Math.max(0, countCsvRows(csvText) - 1);

    await client.query(
      `
      UPDATE recupero_import_jobs
      SET status = 'processing',
          total_rows = $1,
          processed_rows = $2,
          updated_rows = $3,
          error_rows = $4,
          error_message = NULL,
          started_at = now(),
          updated_at = now()
      WHERE id = $5
      `,
      [
        totalRows,
        job.processed_rows || 0,
        job.updated_rows || 0,
        job.error_rows || 0,
        jobId
      ]
    );

    if (!csvText.trim()) {
      await client.query(
        `
        UPDATE recupero_import_jobs
        SET status = 'failed',
            error_message = 'CSV vacio',
            finished_at = now(),
            updated_at = now()
        WHERE id = $1
        `,
        [jobId]
      );
      return;
    }

    const iterator = iterateCsvLines(csvText.replace(/^\uFEFF/, ""));
    const headerResult = iterator.next();
    const headerLine = headerResult.done ? "" : headerResult.value || "";
    const delimiter = job.delimiter || detectCsvDelimiter(headerLine);
    const headers = parseCsvLine(headerLine, delimiter).map((h) => normalizeImportValue(h));

    const idxDocumento = headers.findIndex((h) => h === "documento");
    const idxMotivo = headers.findIndex(
      (h) => h === "motivo de la baja" || h === "motivo de baja"
    );
    const idxEstado = headers.findIndex(
      (h) => h === "ultimo estado" || h === "Ãºltimo estado"
    );

    if (idxDocumento === -1 || idxMotivo === -1 || idxEstado === -1) {
      await client.query(
        `
        UPDATE recupero_import_jobs
        SET status = 'failed',
            error_message = 'Headers invalidos',
            finished_at = now(),
            updated_at = now()
        WHERE id = $1
        `,
        [jobId]
      );
      return;
    }

    const entriesByDocumento = new Map();
    const errors = [];
    let duplicateRows = 0;
    let invalidRows = 0;
    let notFoundRows = 0;
    let rowNumber = 1;

    for (const line of iterator) {
      rowNumber += 1;
      if (!line) continue;
      const cells = parseCsvLine(line, delimiter);
      const rawDocumento = cells[idxDocumento] || "";
      const documento = normalizeDocumento(rawDocumento);
      const motivoBajaRaw = String(cells[idxMotivo] || "").trim();
      const motivoBajaNorm = normalizeMotivoBaja(motivoBajaRaw);
      const ultimoEstadoRaw = String(cells[idxEstado] || "").trim();

      if (!documento) {
        invalidRows += 1;
        errors.push({
          row: rowNumber,
          documento: rawDocumento,
          motivo_baja: motivoBajaRaw,
          ultimo_estado: ultimoEstadoRaw,
          code: "MISSING_FIELD",
          message: "Documento requerido"
        });
        continue;
      }

      if (!motivoBajaRaw && !ultimoEstadoRaw) {
        invalidRows += 1;
        errors.push({
          row: rowNumber,
          documento,
          motivo_baja: motivoBajaRaw,
          ultimo_estado: ultimoEstadoRaw,
          code: "MISSING_FIELD",
          message: "Motivo o ultimo estado requerido"
        });
        continue;
      }

      let ultimoEstadoNorm = null;
      if (ultimoEstadoRaw) {
        ultimoEstadoNorm = normalizeRecuperoEstado(ultimoEstadoRaw);
        if (!ultimoEstadoNorm) {
          invalidRows += 1;
          errors.push({
            row: rowNumber,
            documento,
            motivo_baja: motivoBajaRaw,
            ultimo_estado: ultimoEstadoRaw,
            code: "INVALID_VALUE",
            message: "Ultimo estado invalido"
          });
          continue;
        }
      }

      if (entriesByDocumento.has(documento)) {
        duplicateRows += 1;
      }
      entriesByDocumento.set(documento, {
        documento,
        motivo_baja: motivoBajaNorm,
        motivo_baja_raw: motivoBajaRaw || null,
        ultimo_estado_raw: ultimoEstadoRaw || null,
        ultimo_estado_norm: ultimoEstadoNorm,
        row: rowNumber
      });
    }

    const documentos = Array.from(entriesByDocumento.keys());
    if (!documentos.length) {
      await client.query(
        `
        UPDATE recupero_import_jobs
        SET status = 'done',
            total_rows = $1,
            processed_rows = $2,
            updated_rows = 0,
            error_rows = $3,
            duplicate_rows = $4,
            invalid_rows = $5,
            not_found_rows = $6,
          error_rows_detail = $7,
          error_report_csv = $8,
          finished_at = now(),
          updated_at = now()
        WHERE id = $9
        `,
        [
          totalRows,
          totalRows,
          errors.length,
          duplicateRows,
          invalidRows,
          notFoundRows,
          errors.length ? JSON.stringify(errors.slice(0, 200)) : null,
          errors.length ? buildRecuperoErrorCsv(errors) : null,
          jobId
        ]
      );
      return;
    }

    const contactsRes = await client.query(
      `
      SELECT id, documento
      FROM contacts
      WHERE documento = ANY($1)
      `,
      [documentos]
    );
    const contactMap = new Map();
    for (const row of contactsRes.rows) {
      contactMap.set(row.documento, row.id);
    }

    const validRows = [];
    for (const entry of entriesByDocumento.values()) {
      const contactId = contactMap.get(entry.documento);
      if (!contactId) {
        notFoundRows += 1;
        errors.push({
          row: entry.row,
          documento: entry.documento,
          motivo_baja: entry.motivo_baja_raw,
          ultimo_estado: entry.ultimo_estado_raw,
          code: "NOT_FOUND",
          message: "Documento no encontrado"
        });
        continue;
      }
      validRows.push({
        contact_id: contactId,
        documento: entry.documento,
        motivo_baja: entry.motivo_baja,
        motivo_baja_raw: entry.motivo_baja_raw,
        ultimo_estado_raw: entry.ultimo_estado_raw,
        ultimo_estado_norm: entry.ultimo_estado_norm
      });
    }

    const chunkSize = 500;
    for (let i = 0; i < validRows.length; i += chunkSize) {
      const chunk = validRows.slice(i, i + chunkSize);
      const contactIds = chunk.map((row) => row.contact_id);
      const documentosChunk = chunk.map((row) => row.documento);
      const motivos = chunk.map((row) => row.motivo_baja);
      const estadosRaw = chunk.map((row) => row.ultimo_estado_raw);
      const estadosNorm = chunk.map((row) => row.ultimo_estado_norm);

      await client.query(
        `
        WITH src AS (
          SELECT * FROM UNNEST(
            $1::uuid[],
            $2::text[],
            $3::text[],
            $4::text[],
            $5::text[],
            $6::text[]
          ) AS t(contact_id, documento, motivo_baja, motivo_baja_raw, estado_raw, estado_norm)
        )
        UPDATE contact_products cp
        SET motivo_baja = src.motivo_baja,
            updated_at = now()
        FROM src
        WHERE cp.contact_id = src.contact_id
          AND cp.estado = 'baja'
        `,
        [contactIds, documentosChunk, motivos, chunk.map((row) => row.motivo_baja_raw), estadosRaw, estadosNorm]
      );

      await client.query(
        `
        WITH src AS (
          SELECT * FROM UNNEST(
            $1::uuid[],
            $2::text[],
            $3::text[],
            $4::text[],
            $5::text[],
            $6::text[]
          ) AS t(contact_id, documento, motivo_baja, motivo_baja_raw, estado_raw, estado_norm)
        )
        INSERT INTO external_management_status (
          contact_id,
          documento,
          estado_raw,
          estado_normalizado,
          motivo_baja,
          fuente,
          updated_at
        )
        SELECT
          contact_id,
          documento,
          estado_raw,
          estado_norm,
          motivo_baja_raw,
          'csv',
          now()
        FROM src
        ON CONFLICT (documento) DO UPDATE
        SET
          contact_id = EXCLUDED.contact_id,
          estado_raw = EXCLUDED.estado_raw,
          estado_normalizado = EXCLUDED.estado_normalizado,
          motivo_baja = EXCLUDED.motivo_baja,
          fuente = 'csv',
          updated_at = now()
        `,
        [contactIds, documentosChunk, motivos, chunk.map((row) => row.motivo_baja_raw), estadosRaw, estadosNorm]
      );

      // Nota: el flujo recupero usa contacts, no datos_para_trabajar.
      // El estado importado queda en external_management_status.
    }

    await client.query(
      `
      UPDATE recupero_import_jobs
      SET status = 'done',
          total_rows = $1,
          processed_rows = $2,
          updated_rows = $3,
          error_rows = $4,
          duplicate_rows = $5,
          invalid_rows = $6,
          not_found_rows = $7,
          error_rows_detail = $8,
          error_report_csv = $9,
          finished_at = now(),
          updated_at = now()
      WHERE id = $10
      `,
      [
        totalRows,
        totalRows,
        validRows.length,
        errors.length,
        duplicateRows,
        invalidRows,
        notFoundRows,
        errors.length ? JSON.stringify(errors.slice(0, 200)) : null,
        errors.length ? buildRecuperoErrorCsv(errors) : null,
        jobId
      ]
    );
  } catch (error) {
    await client.query(
      `
      UPDATE recupero_import_jobs
      SET status = 'failed',
          error_message = $1,
          finished_at = now(),
          updated_at = now()
      WHERE id = $2
      `,
      [error.message, jobId]
    );
    throw error;
  } finally {
    await client.end();
  }
}

export async function processDatosTrabajarJob(jobId, options = {}) {
  const client = createDbClient();
  await client.connect();

  try {
    const jobRes = await client.query(
      `
      SELECT id, batch_id, csv_text, processed_rows, inserted_rows, blocked_rows, skipped_rows, organization_id
      FROM datos_para_trabajar_import_jobs
      WHERE id = $1
      LIMIT 1
      `,
      [jobId]
    );
    if (!jobRes.rows.length) return;

    const job = jobRes.rows[0];
    const orgId = job.organization_id || null;
    const importJobId = job.id || null;
    const csvText = job.csv_text || "";
    const { rows } = mapDatosParaTrabajarCsv(csvText);
    const totalRows = rows.length;

    let index = options.startAt ?? job.processed_rows ?? 0;
    let inserted = job.inserted_rows ?? 0;
    let blocked = job.blocked_rows ?? 0;
    let skipped = job.skipped_rows ?? 0;

    await client.query(
      `
      UPDATE datos_para_trabajar_import_jobs
      SET status = 'processing',
          total_rows = $1,
          processed_rows = $2,
          inserted_rows = $3,
          blocked_rows = $4,
          skipped_rows = $5,
          error_message = NULL,
          started_at = now(),
          updated_at = now()
      WHERE id = $6
      `,
      [totalRows, index, inserted, blocked, skipped, jobId]
    );

    const normalizedNumbers = new Set();
    for (const row of rows) {
      const tel = normalizeUyNumber(row.telefono);
      const cel = normalizeUyNumber(row.celular);
      if (tel) normalizedNumbers.add(tel);
      if (cel) normalizedNumbers.add(cel);
    }

    let blockedNumbers = new Set();
    if (normalizedNumbers.size) {
      const normalizedList = Array.from(normalizedNumbers);
      const res = await client.query(
        `SELECT numero FROM no_call_entries WHERE numero = ANY($1::text[])`,
        [normalizedList]
      );
      blockedNumbers = new Set(res.rows.map((r) => r.numero));

      const contactsRes = await client.query(
        `
        SELECT telefono, celular
        FROM contacts
        WHERE telefono = ANY($1::text[])
           OR celular = ANY($1::text[])
        `,
        [normalizedList]
      );
      for (const row of contactsRes.rows) {
        if (row.telefono) blockedNumbers.add(row.telefono);
        if (row.celular) blockedNumbers.add(row.celular);
      }
    }

    const maxMillis = options.maxMillis ?? null;
    const startedAt = Date.now();
    const batchSize = options.batchSize ?? 200;
    let buffer = [];

    for (let i = index; i < rows.length; i += 1) {
      const row = rows[i];
      const tel = normalizeUyNumber(row.telefono);
      const cel = normalizeUyNumber(row.celular);
      const isBlocked =
        (tel && blockedNumbers.has(tel)) || (cel && blockedNumbers.has(cel));

      buffer.push([
        row.nombre || null,
        row.apellido || null,
        row.documento || null,
        row.fecha_nacimiento || null,
        row.telefono || null,
        row.celular || null,
        row.correo_electronico || row.email || null,
        row.direccion || null,
        row.departamento || null,
        row.localidad || null,
        row.origen_dato || null,
        isBlocked ? "bloqueado" : "nuevo"
      ]);

      if (isBlocked) blocked += 1;
      inserted += 1;
      index += 1;

      if (buffer.length >= batchSize) {
        const { sql, values } = buildDatosTrabajarInsertBatch(buffer, orgId, importJobId);
        await client.query(sql, values);
        buffer = [];
      }

      if (maxMillis && Date.now() - startedAt > maxMillis) {
        if (buffer.length) {
          const { sql, values } = buildDatosTrabajarInsertBatch(buffer, orgId, importJobId);
          await client.query(sql, values);
        }
        await client.query(
          `
          UPDATE datos_para_trabajar_import_jobs
          SET processed_rows = $1,
              inserted_rows = $2,
              blocked_rows = $3,
              skipped_rows = $4,
              total_rows = $5,
              updated_at = now()
          WHERE id = $6
          `,
          [index, inserted, blocked, skipped, totalRows, jobId]
        );
        if (typeof options.requeue === "function") {
          await options.requeue(index);
        }
        await client.end();
        return;
      }
    }

    if (buffer.length) {
      const { sql, values } = buildDatosTrabajarInsertBatch(buffer, orgId, importJobId);
      await client.query(sql, values);
    }

    await client.query(
      `
      UPDATE datos_para_trabajar_import_jobs
      SET status = 'completed',
          processed_rows = $1,
          inserted_rows = $2,
          blocked_rows = $3,
          skipped_rows = $4,
          total_rows = $5,
          completed_at = now(),
          updated_at = now()
      WHERE id = $6
      `,
      [index, inserted, blocked, skipped, totalRows, jobId]
    );

    if (job.batch_id) {
      await client.query(
        `
        UPDATE contact_import_batches
        SET total_rows = $1,
            valid_rows = $2,
            error_rows = $3,
            status = 'processed',
            updated_at = now()
        WHERE id = $4
        `,
        [totalRows, inserted, 0, job.batch_id]
      );
    }
  } catch (error) {
    try {
      await client.query(
        `
        UPDATE datos_para_trabajar_import_jobs
        SET status = 'failed',
            error_message = $1,
            completed_at = now(),
            updated_at = now()
        WHERE id = $2
        `,
        [error.message, jobId]
      );
    } catch {}
  } finally {
    await client.end();
  }
}

async function processClientImportBatch(
  batchId,
  { createProducts = true, organizationId = null } = {}
) {
  const client = createDbClient();
  await client.connect();

  let imported = 0;
  let failed = 0;
  let newContacts = 0;
  let productsCreated = 0;
  const productsSeen = new Set();
  const sellersSeen = new Set();
  const paymentMethodsSeen = new Set();

  try {
    const hasResolvedSellerUserId = await columnExists(
      client,
      "contact_import_rows",
      "resolved_seller_user_id"
    );
    if (createProducts) {
      const pendingValues = [batchId];
      const pendingOrgClause = organizationId ? "AND organization_id = $2" : "";
      if (organizationId) pendingValues.push(organizationId);
      const pendingProducts = await client.query(
        `
        SELECT
          producto_nombre,
          MAX(precio)::numeric AS precio
        FROM contact_import_rows
        WHERE batch_id = $1
          ${pendingOrgClause}
          AND import_status = 'validated'
          AND producto_nombre IS NOT NULL
          AND trim(producto_nombre) <> ''
        GROUP BY producto_nombre
        `,
        pendingValues
      );
      for (const row of pendingProducts.rows) {
        const productName = buildProductDisplayName(row.producto_nombre, row.precio);
        if (!productName) continue;
        productsSeen.add(productName.toLowerCase());
        const exists = await client.query(
          `
          SELECT id
          FROM products
          WHERE lower(nombre) = lower($1)
          ${organizationId ? "AND organization_id = $2" : ""}
          LIMIT 1
          `,
          organizationId ? [productName, organizationId] : [productName]
        );
        if (exists.rowCount > 0) continue;
        await client.query(
          `
          INSERT INTO products (nombre, categoria, precio, activo, organization_id)
          VALUES ($1, 'General', $2, true, $3)
          `,
          [productName, row.precio || 0, organizationId]
        );
        productsCreated += 1;
      }
    }

    const rowsValues = [batchId];
    const rowsOrgClause = organizationId ? "AND organization_id = $2" : "";
    if (organizationId) rowsValues.push(organizationId);
    const rowsResult = await client.query(
      `
      SELECT *
      FROM contact_import_rows
      WHERE batch_id = $1
        ${rowsOrgClause}
        AND import_status = 'validated'
      ORDER BY row_number ASC
      `,
      rowsValues
    );

    for (const row of rowsResult.rows) {
      try {
        await client.query("BEGIN");

        const documentoRaw = normalizeText(row.documento);
        const documento = documentoRaw || null;
        const email = normalizeText(row.email).toLowerCase() || null;
        const vendedorNombre = normalizeText(row.nombre_asesor);
        let sellerUserId = null;
        let sellerId = null;
        let sellerNameSnapshot = vendedorNombre || null;
        if (vendedorNombre) {
          const sellerRes = await client.query(
            `
            SELECT id, user_id, nombre, apellido
            FROM sellers
            WHERE lower(unaccent_simple(nombre || ' ' || coalesce(apellido, '')))
                  = lower(unaccent_simple($1))
               OR lower(unaccent_simple(nombre)) = lower(unaccent_simple($1))
              ${organizationId ? "AND organization_id = $2" : ""}
            LIMIT 1
            `,
            organizationId ? [vendedorNombre, organizationId] : [vendedorNombre]
          );
          if (sellerRes.rowCount > 0) {
            const seller = sellerRes.rows[0];
            sellerId = seller.id;
            sellerUserId = seller.user_id || null;
            const fullName = [seller.nombre, seller.apellido].filter(Boolean).join(" ").trim();
            sellerNameSnapshot = fullName || vendedorNombre;
          } else {
            const sellerInsert = await client.query(
              `
              INSERT INTO sellers (nombre, activo, organization_id)
              VALUES ($1, true, $2)
              RETURNING id, nombre, apellido, user_id
              `,
              [vendedorNombre, organizationId]
            );
            const seller = sellerInsert.rows[0];
            sellerId = seller.id;
            sellerUserId = seller.user_id || null;
            const fullName = [seller.nombre, seller.apellido].filter(Boolean).join(" ").trim();
            sellerNameSnapshot = fullName || vendedorNombre;
          }
        }
        const medioPago = normalizeText(row.medio_pago);
        const productoNombre = buildProductDisplayName(row.producto_nombre, row.precio);
        const telefonoSan = sanitizePhone(row.telefono || row.telefono_venta);
        const celularSan = sanitizePhone(row.telefono_celular);
        const telefonoFijoSan = sanitizePhone(row.telefono_fijo);
        const telefonoAltSan = sanitizePhone(row.telefono_alternativo);
        const phones = normalizeContactPhones(telefonoSan, celularSan);

        if (vendedorNombre) sellersSeen.add(vendedorNombre.toLowerCase());
        if (medioPago) paymentMethodsSeen.add(medioPago.toLowerCase());
        if (productoNombre) productsSeen.add(productoNombre.toLowerCase());

        const contactPayload = {
          nombre: row.nombre || null,
          apellido: row.apellido || null,
          email,
          telefono: phones.telefono || telefonoSan || null,
          celular: phones.celular || celularSan || null,
          telefono_fijo: telefonoFijoSan || null,
          telefono_alternativo: telefonoAltSan || null,
          documento: documento || null,
          fecha_nacimiento: row.fecha_nacimiento || null,
          direccion: row.direccion || null,
          departamento: row.departamento_residencia || null,
          pais: row.pais || null
        };

        let contact = null;
        let contactImportStatus = "created";
        let existingContactId = null;

        const nombreNorm = unaccentSimple(contactPayload.nombre);
        const apellidoNorm = unaccentSimple(contactPayload.apellido);
        if (documento && nombreNorm && apellidoNorm) {
          const byDoc = await client.query(
            `
            SELECT id FROM contacts
            WHERE documento = $1
              AND lower(coalesce(nombre, '')) = $2
              AND lower(coalesce(apellido, '')) = $3
              ${organizationId ? "AND organization_id = $4" : ""}
            LIMIT 1
            `,
            organizationId
              ? [documento, nombreNorm, apellidoNorm, organizationId]
              : [documento, nombreNorm, apellidoNorm]
          );
          existingContactId = byDoc.rows[0]?.id ?? null;
        }

        if (!existingContactId && documento) {
          const byDocOnly = await client.query(
            `
            SELECT id FROM contacts
            WHERE documento = $1
              ${organizationId ? "AND organization_id = $2" : ""}
            `,
            organizationId ? [documento, organizationId] : [documento]
          );
          if (byDocOnly.rowCount === 1) {
            existingContactId = byDocOnly.rows[0]?.id ?? null;
          }
        }

        if (!existingContactId && telefonoSan) {
          const byTel = await client.query(
            `
            SELECT id FROM contacts
            WHERE telefono = $1 OR celular = $1
              ${organizationId ? "AND organization_id = $2" : ""}
            LIMIT 1
            `,
            organizationId ? [telefonoSan, organizationId] : [telefonoSan]
          );
          existingContactId = byTel.rows[0]?.id ?? null;
        }

        if (existingContactId) {
          await client.query(
            `
            UPDATE contacts SET
              nombre = COALESCE($2, nombre),
              apellido = COALESCE($3, apellido),
              telefono = COALESCE($4, telefono),
              celular = COALESCE($5, celular),
              email = COALESCE($6, email),
              direccion = COALESCE($7, direccion),
              departamento = COALESCE($8, departamento),
              fecha_nacimiento = COALESCE($9, fecha_nacimiento),
              documento = COALESCE($10, documento),
              updated_at = NOW()
            WHERE id = $1
              ${organizationId ? "AND organization_id = $11" : ""}
            `,
            organizationId
              ? [
                existingContactId,
                contactPayload.nombre || null,
                contactPayload.apellido || null,
                contactPayload.telefono || null,
                contactPayload.celular || null,
                contactPayload.email || null,
                contactPayload.direccion || null,
                contactPayload.departamento || null,
                contactPayload.fecha_nacimiento || null,
                contactPayload.documento || null,
                organizationId
              ]
              : [
                existingContactId,
                contactPayload.nombre || null,
                contactPayload.apellido || null,
                contactPayload.telefono || null,
                contactPayload.celular || null,
                contactPayload.email || null,
                contactPayload.direccion || null,
                contactPayload.departamento || null,
                contactPayload.fecha_nacimiento || null,
                contactPayload.documento || null
              ]
          );
          contact = { id: existingContactId };
          contactImportStatus = "updated";
        } else {
          const insertContact = await client.query(
            `
            INSERT INTO contacts (
              nombre,
              apellido,
              email,
              telefono,
              celular,
              documento,
              fecha_nacimiento,
              direccion,
              departamento,
              pais,
              status,
              organization_id
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'activo',$11)
            RETURNING *
            `,
            [
              contactPayload.nombre || "",
              contactPayload.apellido,
              contactPayload.email,
              contactPayload.telefono,
              contactPayload.celular,
              contactPayload.documento,
              contactPayload.fecha_nacimiento,
              contactPayload.direccion,
              contactPayload.departamento,
              contactPayload.pais || "Uruguay",
              organizationId
            ]
          );
          contact = insertContact.rows[0];
          newContacts += 1;
        }
        const nombreFamiliar = String(row.nombre_familiar || "").trim();
        const apellidoFamiliar = String(row.apellido_familiar || "").trim();
        const telefonoFamiliar = sanitizePhone(row.telefono_familiar);
        const parentesco = row.parentesco || null;
        if (nombreFamiliar || apellidoFamiliar || telefonoFamiliar) {
          let relatedContactId = null;
          if (telefonoFamiliar) {
            const famRes = await client.query(
              `
              SELECT id
              FROM contacts
              WHERE (telefono = $1 OR celular = $1)
                AND translate(lower(coalesce(nombre, '')),
                  'Ã¡Ã©Ã­Ã³ÃºÃ¤Ã«Ã¯Ã¶Ã¼Ã Ã¨Ã¬Ã²Ã¹Ã¢ÃªÃ®Ã´Ã»Ã±ÃÃ‰ÃÃ“ÃšÃ„Ã‹ÃÃ–ÃœÃ€ÃˆÃŒÃ’Ã™Ã‚ÃŠÃŽÃ”Ã›Ã‘',
                  'aeiouaeiouaeiouaeiounAEIOUAEIOUAEIOUAEIOUN') = $2
                AND translate(lower(coalesce(apellido, '')),
                  'Ã¡Ã©Ã­Ã³ÃºÃ¤Ã«Ã¯Ã¶Ã¼Ã Ã¨Ã¬Ã²Ã¹Ã¢ÃªÃ®Ã´Ã»Ã±ÃÃ‰ÃÃ“ÃšÃ„Ã‹ÃÃ–ÃœÃ€ÃˆÃŒÃ’Ã™Ã‚ÃŠÃŽÃ”Ã›Ã‘',
                  'aeiouaeiouaeiouaeiounAEIOUAEIOUAEIOUAEIOUN') = $3
              LIMIT 1
              `,
              [telefonoFamiliar, unaccentSimple(nombreFamiliar), unaccentSimple(apellidoFamiliar)]
            );
            relatedContactId = famRes.rows[0]?.id ?? null;
          }

          if (relatedContactId && relatedContactId !== contact.id) {
            await client.query(
              `
              INSERT INTO contact_relations (
                contact_id_a,
                contact_id_b,
                relation,
                source
              )
              VALUES ($1,$2,$3,'import')
              ON CONFLICT (contact_id_a, contact_id_b)
              DO UPDATE SET
                relation = EXCLUDED.relation,
                updated_at = NOW()
              `,
              [contact.id, relatedContactId, parentesco || "familiar"]
            );
          }
        }

        let saleId = null;
        const productName = buildProductDisplayName(row.producto_nombre, row.precio) || null;
        const precio = row.precio !== null && row.precio !== undefined ? Number(row.precio) : null;
        const fechaVenta = row.fecha_venta || row.fecha_alta || null;

        if (productName || precio || row.medio_pago || fechaVenta) {
          const productResult = productName
            ? await client.query(
              `
              SELECT id
              FROM products
              WHERE lower(nombre) = lower($1)
              ${organizationId ? "AND organization_id = $2" : ""}
              LIMIT 1
              `,
              organizationId ? [productName, organizationId] : [productName]
            )
            : { rows: [] };

          let productId = productResult.rows[0]?.id || null;

          if (!productId && productName && !createProducts) {
            throw new Error(`Producto no existe: ${productName}`);
          }

          if (!productId && productName && createProducts) {
            const productInsert = await client.query(
              `
              INSERT INTO products (nombre, categoria, precio, activo, organization_id)
              VALUES ($1, 'General', $2, true, $3)
              RETURNING id
              `,
              [productName, precio || 0, organizationId]
            );
            productId = productInsert.rows[0].id;
          }

          const saleInsert = await client.query(
            `
            INSERT INTO sales (
              contact_id,
              seller_user_id,
              medio_pago,
              seller_name_snapshot,
              seller_origin,
              fecha_venta,
              documento_cobranza,
              titular_contact_id,
              organization_id
            )
            VALUES ($1, $2, $3, $4, 'importado', $5, $6, $7, $8)
            RETURNING id
            `,
            [
              contact.id,
              sellerUserId,
              row.medio_pago || null,
              sellerNameSnapshot,
              fechaVenta,
              row.documento_cobranza || null,
              contact.id,
              organizationId
            ]
          );
          saleId = saleInsert.rows[0].id;

          if (productId) {
            await client.query(
              `
              INSERT INTO sale_items (
                sale_id,
                product_id,
                product_name_snapshot,
                price
              )
              VALUES ($1,$2,$3,$4)
              `,
              [saleId, productId, productName || "Producto", precio || 0]
            );
          }

          const estadoRaw = normalizeText(row.producto_estado || "");
          const estadoNorm = estadoRaw.toLowerCase();
          const isAlta = estadoNorm === "alta" || estadoNorm === "activo";
          const isBaja = !isAlta;
          const fechaAlta = fechaVenta || new Date().toISOString().slice(0, 10);
          const fechaBaja = isBaja ? (row.fecha_baja || fechaAlta) : null;
          const motivoBaja = isBaja ? "otro" : null;
          const motivoBajaDetalle = isBaja ? (estadoRaw || "importado") : null;

          let shouldInsertContactProduct = true;
          if (contactImportStatus === "updated") {
            const exists = await client.query(
              `
              SELECT id
              FROM contact_products
              WHERE contact_id = $1
                AND fecha_alta = $2
                AND nombre_producto = $3
                ${organizationId ? "AND organization_id = $4" : ""}
              LIMIT 1
              `,
              organizationId
                ? [contact.id, fechaAlta, productName || "Producto", organizationId]
                : [contact.id, fechaAlta, productName || "Producto"]
            );
            if (exists.rowCount > 0) {
              shouldInsertContactProduct = false;
            }
          }

          if (shouldInsertContactProduct) {
            await client.query(
              `
              INSERT INTO contact_products (
                contact_id,
                nombre_producto,
                plan,
                precio,
                fecha_alta,
                cuotas_pagas,
                carencia_cuotas,
                estado,
                motivo_baja,
                motivo_baja_detalle,
                fecha_baja,
                seller_user_id,
                seller_name_snapshot,
                seller_origin,
                sale_id,
                organization_id
              )
              VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
              `,
              [
                contact.id,
                productName || "Producto",
                row.plan || null,
                precio || 0,
                fechaAlta,
                row.cuotas_pagas || 0,
                row.carencia_cuotas || 0,
                isBaja ? "baja" : "alta",
                motivoBaja,
                motivoBajaDetalle,
                fechaBaja,
                sellerUserId,
                sellerNameSnapshot,
                "importado",
                saleId,
                organizationId
              ]
            );
          }
        }

        const updateImportSql = `
          UPDATE contact_import_rows
          SET import_status = $3,
              error_detail = NULL,
              resolved_contact_id = $1,
              updated_at = now()
              ${hasResolvedSellerUserId ? ", resolved_seller_user_id = $4" : ""}
          WHERE id = $2
          ${organizationId ? `AND organization_id = $${hasResolvedSellerUserId ? 5 : 4}` : ""}
        `;
        const updateImportValues = hasResolvedSellerUserId
          ? [contact.id, row.id, contactImportStatus, sellerId]
          : [contact.id, row.id, contactImportStatus];
        if (organizationId) updateImportValues.push(organizationId);
        await client.query(updateImportSql, updateImportValues);

        await client.query("COMMIT");
        imported += 1;
      } catch (rowError) {
        await client.query("ROLLBACK");
        failed += 1;
        const errorValues = [rowError.message, row.id];
        const errorOrgClause = organizationId ? "AND organization_id = $3" : "";
        if (organizationId) errorValues.push(organizationId);
        await client.query(
          `
          UPDATE contact_import_rows
          SET import_status = 'error',
              error_detail = $1,
              updated_at = now()
          WHERE id = $2
          ${errorOrgClause}
          `,
          errorValues
        );
      }
    }

    const summaryValues = [batchId];
    const summaryOrgClause = organizationId ? "AND organization_id = $2" : "";
    if (organizationId) summaryValues.push(organizationId);
    const summaryResult = await client.query(
      `
      SELECT
        COUNT(*)::int AS total_rows,
        COUNT(*) FILTER (WHERE import_status = 'imported')::int AS imported_rows,
        COUNT(*) FILTER (WHERE import_status = 'error')::int AS error_rows
      FROM contact_import_rows
      WHERE batch_id = $1
      ${summaryOrgClause}
      `,
      summaryValues
    );

    const summary = summaryResult.rows[0];
    await client.query(
      `
      UPDATE contact_import_batches
      SET total_rows = $1,
          valid_rows = $2,
          error_rows = $3,
          report_products_detected = $4,
          report_products_created = $5,
          report_sellers_detected = $6,
          report_payment_methods_detected = $7,
          report_new_contacts = $8,
          status = 'processed',
          updated_at = now()
      WHERE id = $9
      ${organizationId ? "AND organization_id = $10" : ""}
      `,
      organizationId
        ? [
          summary.total_rows,
          summary.imported_rows,
          summary.error_rows,
          productsSeen.size,
          productsCreated,
          sellersSeen.size,
          paymentMethodsSeen.size,
          newContacts,
          batchId,
          organizationId
        ]
        : [
          summary.total_rows,
          summary.imported_rows,
          summary.error_rows,
          productsSeen.size,
          productsCreated,
          sellersSeen.size,
          paymentMethodsSeen.size,
          newContacts,
          batchId
        ]
    );

    return {
      ok: true,
      batchId,
      imported,
      failed,
      report: {
        productosDetectados: productsSeen.size,
        productosCreados: productsCreated,
        vendedoresDetectados: sellersSeen.size,
        mediosPagoDetectados: paymentMethodsSeen.size,
        clientesNuevos: newContacts
      }
    };
  } finally {
    await client.end();
  }
}

function buildImportSampleCsv(type) {
  if (type === "datos_para_trabajar") {
    const headers = [
      "Nombre completo",
      "Nombre",
      "Apellido",
      "Documento",
      "Fecha de nacimiento",
      "Telefono",
      "Celular",
      "Correo electronico",
      "Direccion",
      "Departamento",
      "Localidad",
      "Origen del dato",
      "Pais"
    ];

    const exampleRow = {
      "Nombre completo": "BERDIA Castillo Bernardo",
      "Nombre": "Bernardo",
      "Apellido": "BERDIA Castillo",
      "Documento": "41234567",
      "Fecha de nacimiento": "1950-10-20",
      "Telefono": "22880083",
      "Celular": "+598 92 900 900",
      "Correo electronico": "maria.gonzalez@example.com",
      "Direccion": "Manzana 12 Padron 10326U Solar 5, Barros Blancos",
      "Departamento": "Canelones",
      "Localidad": "Barros Blancos",
      "Origen del dato": "Facebook",
      "Pais": "Uruguay"
    };

    const lines = [
      headers.join(","),
      headers.map((header) => csvEscape(exampleRow[header] ?? "")).join(",")
    ];

    return lines.join("\n");

  }

  const headers = [
    "Nombre",
    "Apellido",
    "Documento",
    "Fecha de nacimiento",
    "telefono",
    "Celular",
    "Correo electronico",
    "Direcciï¿½n",
    "Departamento",
    "Pais",
    "Nombre del familiar",
    "Apellido del familiar",
    "Telefono del familiar",
    "Vinculo",
    "Vendedor",
    "Fecha de venta",
    "Producto",
    "Precio",
    "Medio de pago",
    "Estado",
    "Fecha de baja"
  ];

  const exampleRow = {
    "Nombre": "Ana",
    "Apellido": "Pereira",
    "Documento": "41234567",
    "Fecha de nacimiento": "1988-05-10",
    "telefono": "099123456",
    "Celular": "099123456",
    "Correo electronico": "ana.pereira@example.com",
    "Direcciï¿½n": "18 de Julio 1234",
    "Departamento": "Montevideo",
    "Pais": "Uruguay",
    "Nombre del familiar": "Luis",
    "Apellido del familiar": "Pereira",
    "Telefono del familiar": "098111222",
    "Vinculo": "Padre",
    "Vendedor": "Juan Gomez",
    "Fecha de venta": "2026-03-01",
    "Producto": "Plan Basico",
    "Precio": "1200",
    "Medio de pago": "tarjeta",
    "Estado": "alta",
    "Fecha de baja": ""
  };

  const lines = [
    headers.join(","),
    headers.map((header) => csvEscape(exampleRow[header] ?? "")).join(",")
  ];

    return lines.join("\n");

}

function validateProductPayload(body, options = {}) {
  const isPatch = options.partial === true;
  const nombre = normalizeText(body?.nombre);
  const categoria = normalizeText(body?.categoria || "General");
  const descripcion = normalizeText(body?.descripcion);
  const observaciones = normalizeText(body?.observaciones);
  const precio = body?.precio ?? body?.price ?? 0;
  const activo = body?.activo;

  const errors = {};

  if (!isPatch && !nombre) {
    errors.nombre = ["nombre obligatorio"];
  }

  const parsedPrecio = Number(String(precio || 0).replace(/[^0-9.-]/g, ""));
  if (Number.isNaN(parsedPrecio)) {
    errors.precio = ["precio invï¿½lido"];
  }

  if (Object.keys(errors).length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      nombre,
      categoria: categoria || "General",
      descripcion: descripcion || null,
      observaciones: observaciones || null,
      precio: Number.isNaN(parsedPrecio) ? 0 : parsedPrecio,
      activo: activo === undefined ? true : Boolean(activo)
    }
  };
}

function validateManualTicketPayload(body) {
  const clienteId = normalizeText(body?.clienteId || body?.cliente_id);
  const tipoSolicitud = normalizeText(body?.tipoSolicitud || body?.tipo_solicitud);
  const tipoSolicitudManual = normalizeText(body?.tipoSolicitudManual || body?.tipo_solicitud_manual);
  const resumen = normalizeText(body?.resumen);
  let serviceRequest = body?.serviceRequest || body?.service_request || null;
  const prioridad = normalizeText(body?.prioridad || "media").toLowerCase();
  const estado = normalizeText(body?.estado || "nueva").toLowerCase();
  const productoContratoId = normalizeText(body?.productoContratoId || body?.producto_contrato_id);

  const errors = {};

  if (!clienteId) errors.clienteId = ["clienteId obligatorio"];
  if (!tipoSolicitud) errors.tipoSolicitud = ["tipoSolicitud obligatorio"];
  if (!resumen) errors.resumen = ["resumen obligatorio"];
  if (tipoSolicitud === "otro" && !tipoSolicitudManual) {
    errors.tipoSolicitudManual = ["tipoSolicitudManual obligatorio"];
  }

  if (!serviceRequest) {
    const hasServiceFields = [
      body?.solicitanteNombre,
      body?.solicitanteDocumento,
      body?.solicitanteTelefono,
      body?.solicitanteRelacion,
      body?.cuerpoUbicacion,
      body?.requiereTraslado,
      body?.trasladoOrigen,
      body?.trasladoDestino,
      body?.servicioTipo,
      body?.velatorioLugar,
      body?.servicioFechaHora,
      body?.crematorio
    ].some((value) => value !== undefined && value !== null && String(value).trim() !== "");
    if (hasServiceFields) {
      serviceRequest = {
        solicitanteNombre: body?.solicitanteNombre,
        solicitanteDocumento: body?.solicitanteDocumento,
        solicitanteTelefono: body?.solicitanteTelefono,
        solicitanteRelacion: body?.solicitanteRelacion,
        cuerpoUbicacion: body?.cuerpoUbicacion,
        requiereTraslado: body?.requiereTraslado,
        trasladoOrigen: body?.trasladoOrigen,
        trasladoDestino: body?.trasladoDestino,
        servicioTipo: body?.servicioTipo,
        velatorioLugar: body?.velatorioLugar,
        servicioFechaHora: body?.servicioFechaHora,
        crematorio: body?.crematorio
      };
    }
  }

  if (tipoSolicitud === "solicitud_servicio") {
    const sr = serviceRequest || {};
    if (!normalizeText(sr.solicitanteNombre)) errors.solicitanteNombre = ["solicitanteNombre obligatorio"];
    if (!normalizeText(sr.solicitanteDocumento)) errors.solicitanteDocumento = ["solicitanteDocumento obligatorio"];
    if (!normalizeText(sr.solicitanteTelefono)) errors.solicitanteTelefono = ["solicitanteTelefono obligatorio"];
    if (!normalizeText(sr.cuerpoUbicacion)) errors.cuerpoUbicacion = ["cuerpoUbicacion obligatorio"];
    if (!normalizeText(sr.servicioTipo)) errors.servicioTipo = ["servicioTipo obligatorio"];
    if (sr.requiereTraslado === true) {
      if (!normalizeText(sr.trasladoOrigen)) errors.trasladoOrigen = ["trasladoOrigen obligatorio"];
      if (!normalizeText(sr.trasladoDestino)) errors.trasladoDestino = ["trasladoDestino obligatorio"];
    }
  }

  const prioridadesValidas = new Set(["baja", "media", "alta"]);
  if (prioridad && !prioridadesValidas.has(prioridad)) {
    errors.prioridad = ["prioridad invalida"];
  }

  const estadosValidos = new Set(["nueva", "en_proceso", "finalizada"]);
  if (estado && !estadosValidos.has(estado)) {
    errors.estado = ["estado invalido"];
  }

  if (Object.keys(errors).length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      clienteId,
      tipoSolicitud,
      tipoSolicitudManual: tipoSolicitudManual || null,
      resumen,
      serviceRequest: serviceRequest || null,
      prioridad: prioridadesValidas.has(prioridad) ? prioridad : "media",
      estado: estadosValidos.has(estado) ? estado : "nueva",
      productoContratoId: productoContratoId || null
    }
  };
}

function normalizeManualTicketPatch(body) {
  const tipoSolicitud = normalizeText(body?.tipoSolicitud || body?.tipo_solicitud);
  const tipoSolicitudManual = normalizeText(body?.tipoSolicitudManual || body?.tipo_solicitud_manual);
  const resumen = normalizeText(body?.resumen);
  let serviceRequest = body?.serviceRequest || body?.service_request || null;
  const prioridad = normalizeText(body?.prioridad || "").toLowerCase();
  const estado = normalizeText(body?.estado || "").toLowerCase();
  const productoContratoId = normalizeText(body?.productoContratoId || body?.producto_contrato_id);

  const errors = {};
  const patch = {};

  if (tipoSolicitud) patch.tipoSolicitud = tipoSolicitud;
  if (tipoSolicitudManual) patch.tipoSolicitudManual = tipoSolicitudManual;
  if (resumen) patch.resumen = resumen;
  if (!serviceRequest) {
    const hasServiceFields = [
      body?.solicitanteNombre,
      body?.solicitanteDocumento,
      body?.solicitanteTelefono,
      body?.solicitanteRelacion,
      body?.cuerpoUbicacion,
      body?.requiereTraslado,
      body?.trasladoOrigen,
      body?.trasladoDestino,
      body?.servicioTipo,
      body?.velatorioLugar,
      body?.servicioFechaHora,
      body?.crematorio
    ].some((value) => value !== undefined && value !== null && String(value).trim() !== "");
    if (hasServiceFields) {
      serviceRequest = {
        solicitanteNombre: body?.solicitanteNombre,
        solicitanteDocumento: body?.solicitanteDocumento,
        solicitanteTelefono: body?.solicitanteTelefono,
        solicitanteRelacion: body?.solicitanteRelacion,
        cuerpoUbicacion: body?.cuerpoUbicacion,
        requiereTraslado: body?.requiereTraslado,
        trasladoOrigen: body?.trasladoOrigen,
        trasladoDestino: body?.trasladoDestino,
        servicioTipo: body?.servicioTipo,
        velatorioLugar: body?.velatorioLugar,
        servicioFechaHora: body?.servicioFechaHora,
        crematorio: body?.crematorio
      };
    }
  }

  if (serviceRequest) patch.serviceRequest = serviceRequest;

  const prioridadesValidas = new Set(["baja", "media", "alta"]);
  if (prioridad) {
    if (!prioridadesValidas.has(prioridad)) {
      errors.prioridad = ["prioridad invalida"];
    } else {
      patch.prioridad = prioridad;
    }
  }

  const estadosValidos = new Set(["nueva", "en_proceso", "finalizada"]);
  if (estado) {
    if (!estadosValidos.has(estado)) {
      errors.estado = ["estado invalido"];
    } else {
      patch.estado = estado;
    }
  }

  if (productoContratoId) patch.productoContratoId = productoContratoId;

  if (Object.keys(errors).length > 0) {
    return { valid: false, errors };
  }

  return { valid: true, data: patch };
}

function validateSuperadminUserPayload(body, options = {}) {
  const nombre = normalizeText(body?.nombre);
  const apellido = normalizeText(body?.apellido);
  const email = normalizeEmail(body?.email);
  const telefono = normalizeText(body?.telefono);
  const rol = normalizeText(body?.rol || body?.role);
  const status = normalizeText(body?.status);
  const reason = normalizeText(body?.reason);
  const hasActivo = body?.activo !== undefined;
  const activo = hasActivo ? Boolean(body.activo) : undefined;
  const errors = {};

  if (!options.partial || body?.nombre !== undefined) {
    if (!nombre) {
      errors.nombre = "El nombre es obligatorio";
    }
  }

  if (!options.partial || body?.apellido !== undefined) {
    if (!apellido) {
      errors.apellido = "El apellido es obligatorio";
    }
  }

  if (!options.partial || body?.email !== undefined) {
    if (!email) {
      errors.email = "El email es obligatorio";
    } else if (!isValidEmail(email)) {
      errors.email = "El email no es vï¿½lido";
    }
  }

  if (!options.partial || body?.telefono !== undefined) {
    if (!telefono) {
      errors.telefono = "El telï¿½fono es obligatorio";
    }
  }

  if (!options.partial || body?.rol !== undefined || body?.role !== undefined) {
    if (!rol) {
      errors.rol = "El rol es obligatorio";
    } else if (!VALID_ROLES.includes(rol)) {
      errors.rol = "El rol no es vï¿½lido";
    }
  }

  if (!options.partial || body?.status !== undefined) {
    if (!status) {
      errors.status = "El estado es obligatorio";
    } else if (!VALID_USER_STATUSES.includes(status)) {
      errors.status = "El estado no es vï¿½lido";
    }
  }

  if (reason && reason.length > 500) {
    errors.reason = "El motivo no puede superar los 500 caracteres";
  }

  if (Object.keys(errors).length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      nombre,
      apellido,
      email,
      telefono,
      rol,
      status,
      reason,
      activo
    }
  };
}

function validateVendorRegistrationPayload(body) {
  const nombre = normalizeText(body?.nombre);
  const apellido = normalizeText(body?.apellido);
  const email = normalizeEmail(body?.email);
  const telefono = normalizeText(body?.telefono);

  const errors = {};

  if (!nombre) errors.nombre = "El nombre es obligatorio";
  if (!apellido) errors.apellido = "El apellido es obligatorio";
  if (!email) errors.email = "El email es obligatorio";
  if (!telefono) errors.telefono = "El telï¿½fono es obligatorio";

  return {
    valid: Object.keys(errors).length === 0,
    errors,
    data: { nombre, apellido, email, telefono }
  };
}

async function getUserByCognitoSub(cognitoSub) {
  const client = createDbClient();

  try {
    await client.connect();
    return await getUserByCognitoSubWithClient(client, cognitoSub);
  } finally {
    await client.end();
  }
}

async function getUserByEmail(email) {
  const client = createDbClient();

  try {
    await client.connect();
    return await getUserByEmailWithClient(client, email);
  } finally {
    await client.end();
  }
}

async function getUsersTableMetadata(client) {
  const result = await client.query(
    `
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'users'
    `
  );

  const columns = new Set(result.rows.map((row) => row.column_name));

  return {
    hasUsersTable: columns.size > 0,
    hasCognitoSub: columns.has("cognito_sub"),
    columns
  };
}

const tableColumnsCache = new Map();
async function getTableColumns(client, tableName) {
  if (tableColumnsCache.has(tableName)) return tableColumnsCache.get(tableName);
  const res = await client.query(
    `
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = $1
    `,
    [tableName]
  );
  const cols = new Set(res.rows.map((row) => row.column_name));
  tableColumnsCache.set(tableName, cols);
  return cols;
}

async function columnExists(client, tableName, columnName) {
  const cols = await getTableColumns(client, tableName);
  return cols.has(columnName);
}

function buildUserSelect(metadata) {
  return `
    SELECT
      id,
      ${metadata.hasCognitoSub ? "cognito_sub" : "NULL::text AS cognito_sub"},
      email,
      nombre,
      apellido,
      telefono,
      role_key,
      status,
      created_at,
      updated_at,
      last_login_at
    FROM users
  `;
}

async function getUserByCognitoSubWithClient(client, cognitoSub) {
  if (!cognitoSub) {
    return null;
  }

  const metadata = await getUsersTableMetadata(client);
  if (!metadata.hasUsersTable || !metadata.hasCognitoSub) {
    return null;
  }

  const result = await client.query(
    `
    ${buildUserSelect(metadata)}
    WHERE cognito_sub = $1
    LIMIT 1
    `,
    [cognitoSub]
  );

  return result.rows[0] || null;
}

async function getUserByEmailWithClient(client, email) {
  if (!email) {
    return null;
  }

  const metadata = await getUsersTableMetadata(client);
  if (!metadata.hasUsersTable) {
    return null;
  }

  const result = await client.query(
    `
    ${buildUserSelect(metadata)}
    WHERE lower(email) = lower($1)
    LIMIT 1
    `,
    [email]
  );

  return result.rows[0] || null;
}

async function syncUserCognitoSub(client, userId, cognitoSub) {
  const metadata = await getUsersTableMetadata(client);

  if (!metadata.hasUsersTable || !metadata.hasCognitoSub || !cognitoSub) {
    return;
  }

  await client.query(
    `
    UPDATE users
    SET cognito_sub = $2, updated_at = now()
    WHERE id = $1
      AND (cognito_sub IS NULL OR cognito_sub = '')
    `,
    [userId, cognitoSub]
  );
}

async function getUserByAuthUser(authUser) {
  const client = createDbClient();

  try {
    await client.connect();

    let dbUser = await getUserByCognitoSubWithClient(client, authUser?.sub);

    if (!dbUser && authUser?.email) {
      dbUser = await getUserByEmailWithClient(client, authUser.email);

      if (dbUser && authUser?.sub) {
        await syncUserCognitoSub(client, dbUser.id, authUser.sub);
        dbUser = await getUserByEmailWithClient(client, authUser.email);
      }
    }

    return dbUser;
  } finally {
    await client.end();
  }
}

async function insertApprovedVendorUser(client, input) {
  const metadata = await getUsersTableMetadata(client);

  if (metadata.hasCognitoSub) {
    const result = await client.query(
      `
      INSERT INTO users (
        cognito_sub,
        email,
        nombre,
        apellido,
        telefono,
        role_key,
        status,
        approved_by,
        approved_at,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, 'vendedor', 'approved', $6, now(), now(), now())
      RETURNING id, cognito_sub, email, nombre, apellido, telefono, role_key, status
      `,
      [
        input.cognitoSub,
        input.email,
        input.nombre,
        input.apellido,
        input.telefono,
        input.reviewerUserId
      ]
    );

    return result.rows[0];
  }

  const result = await client.query(
    `
    INSERT INTO users (
      email,
      nombre,
      apellido,
      telefono,
      role_key,
      status,
      approved_by,
      approved_at,
      created_at,
      updated_at
    )
    VALUES ($1, $2, $3, $4, 'vendedor', 'approved', $5, now(), now(), now())
    RETURNING id, NULL::text AS cognito_sub, email, nombre, apellido, telefono, role_key, status
    `,
    [
      input.email,
      input.nombre,
      input.apellido,
      input.telefono,
      input.reviewerUserId
    ]
  );

  return result.rows[0];
}

async function getCurrentDbUserFromEvent(event) {
  const authUser = getAuthUser(event);

  if (!authUser || (!authUser.sub && !authUser.email)) {
    return { authUser, dbUser: null };
  }

  let dbUser = null;
  const baseClaims = authUser?.claims || {};
  const mergedClaims = {
    ...baseClaims,
    sub: authUser?.sub || baseClaims.sub || null,
    email: authUser?.email || baseClaims.email || null,
    name: authUser?.name || baseClaims.name || null,
    given_name: authUser?.given_name || baseClaims.given_name || null,
    family_name: authUser?.family_name || baseClaims.family_name || null,
    "cognito:groups": authUser?.groups || baseClaims["cognito:groups"] || baseClaims.groups || []
  };
  if (authUser?.claims || authUser?.sub || authUser?.email) {
    dbUser = await findCurrentUserFromClaims(mergedClaims);
  } else {
    dbUser = await getUserByAuthUser(authUser);
  }

  if (!dbUser && authUser?.localDev) {
    const client = createDbClient();
    try {
      await client.connect();

      const metadata = await getUsersTableMetadata(client);
      if (!metadata.hasUsersTable) {
        return { authUser, dbUser: null };
      }

      const nombre = authUser.given_name || authUser.name || "Local";
      const apellido = authUser.family_name || "Dev";
      const roleKey = authUser.fallbackRole || "superadministrador";

      if (metadata.hasCognitoSub) {
        await client.query(
          `
          INSERT INTO users (cognito_sub, email, nombre, apellido, role_key, status, approved_at)
          VALUES ($1, $2, $3, $4, $5, 'approved', NOW())
          ON CONFLICT (email) DO UPDATE
          SET cognito_sub = COALESCE(users.cognito_sub, EXCLUDED.cognito_sub),
              nombre = EXCLUDED.nombre,
              apellido = EXCLUDED.apellido,
              role_key = EXCLUDED.role_key,
              status = 'approved',
              approved_at = NOW(),
              updated_at = NOW();
          `,
          [authUser.sub || "local-dev-user", authUser.email, nombre, apellido, roleKey]
        );
      } else {
        await client.query(
          `
          INSERT INTO users (email, nombre, apellido, role_key, status, approved_at)
          VALUES ($1, $2, $3, $4, 'approved', NOW())
          ON CONFLICT (email) DO UPDATE
          SET nombre = EXCLUDED.nombre,
              apellido = EXCLUDED.apellido,
              role_key = EXCLUDED.role_key,
              status = 'approved',
              approved_at = NOW(),
              updated_at = NOW();
          `,
          [authUser.email, nombre, apellido, roleKey]
        );
      }

      dbUser = await getUserByEmailWithClient(client, authUser.email);
    } finally {
      await client.end();
    }
  }

  return { authUser, dbUser };
}

async function resolveOrganizationId(client, dbUser, event) {
  if (!dbUser) return null;
  if (dbUser.role_key === "superadministrador") {
    return getQueryParam(event, "organization_id") || null;
  }
  const orgIdParam = getQueryParam(event, "organization_id");
  if (orgIdParam) {
    const check = await client.query(
      `SELECT organization_id FROM organization_users
       WHERE user_id = $1 AND organization_id = $2 AND activo = true
       LIMIT 1`,
      [dbUser.id, orgIdParam]
    );
    if (check.rows[0]) {
      return check.rows[0].organization_id;
    }
  }
  const orgUser = await client.query(
    `
    SELECT organization_id
    FROM organization_users
    WHERE user_id = $1
      AND activo = true
    ORDER BY created_at ASC
    LIMIT 1
    `,
    [dbUser.id]
  );
  if (!orgUser.rows[0]) {
    throw { status: 403, message: "Usuario no asociado a una organizaciÃ³n activa" };
  }
  return orgUser.rows[0].organization_id;
}

async function resolveOrganizationIdForRequest(dbUser, event) {
  const client = createDbClient();
  try {
    await client.connect();
    return await resolveOrganizationId(client, dbUser, event);
  } finally {
    await client.end();
  }
}

async function listSuperadminUsers() {
  const client = createDbClient();

  try {
    await client.connect();

    const metadata = await getUsersTableMetadata(client);
    if (!metadata.hasUsersTable) {
      throw new Error("users table does not exist");
    }

    const result = await client.query(
      `
      SELECT
        u.id,
        ${metadata.hasCognitoSub ? "u.cognito_sub" : "NULL::text AS cognito_sub"},
        u.email,
        u.nombre,
        u.apellido,
        u.telefono,
        u.role_key,
        u.status,
        u.created_at,
        u.updated_at,
        COALESCE(et.ultimo_acceso, u.last_login_at) AS last_login_at
      FROM users u
      LEFT JOIN (
        SELECT agente_id, MAX(inicio) AS ultimo_acceso
        FROM eventos_turno
        GROUP BY agente_id
      ) et ON et.agente_id = u.id
      ORDER BY u.created_at DESC
      `
    );

    return result.rows.map(mapUserRowToApi);
  } finally {
    await client.end();
  }
}

async function listContacts(organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [];
    const whereClause = organizationId ? "WHERE c.organization_id = $1" : "";
    if (organizationId) values.push(organizationId);

    const result = await client.query(
      `
      ${buildContactSummarySelect(whereClause)}
      ORDER BY created_at DESC, nombre ASC, apellido ASC
      `,
      values
    );

    return result.rows.map(mapContactRowToApi);
  } finally {
    await client.end();
  }
}

async function listClientsDirectory({
  page = 1,
  limit = 50,
  search = "",
  organizationId = null
} = {}) {
  const client = createDbClient();

  try {
    await client.connect();

    const safePage = Math.max(1, Number(page) || 1);
    const safeLimit = Math.min(200, Math.max(1, Number(limit) || 50));
    const offset = (safePage - 1) * safeLimit;
    const searchText = String(search || "").trim().toLowerCase();

    const whereParts = ["s.productos_total > 0"];
    const values = [];

    if (organizationId) {
      values.push(organizationId);
      whereParts.push(`s.organization_id = $${values.length}`);
    }

    if (searchText) {
      const digits = searchText.replace(/[^\d]/g, "");
      if (digits) {
        values.push(`%${digits}%`);
        const idx = values.length;
        const phoneClause = `(REPLACE(REPLACE(REPLACE(coalesce(s.telefono, ''), ' ', ''), '-', ''), '+', '') ILIKE $${idx} OR REPLACE(REPLACE(REPLACE(coalesce(s.celular, ''), ' ', ''), '-', ''), '+', '') ILIKE $${idx})`;
        whereParts.push(
          `(lower(s.nombre) LIKE $${idx} OR lower(s.apellido) LIKE $${idx} OR lower(coalesce(s.email, '')) LIKE $${idx} OR lower(coalesce(s.documento, '')) LIKE $${idx} OR ${phoneClause})`
        );
      } else {
        values.push(`%${searchText}%`);
        const idx = values.length;
        whereParts.push(
          `(lower(s.nombre) LIKE $${idx} OR lower(s.apellido) LIKE $${idx} OR lower(coalesce(s.email, '')) LIKE $${idx} OR lower(coalesce(s.telefono, '')) LIKE $${idx} OR lower(coalesce(s.celular, '')) LIKE $${idx} OR lower(coalesce(s.documento, '')) LIKE $${idx})`
        );
      }
    }

    const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

    const countResult = await client.query(
      `
      WITH summary AS (
        ${buildContactSummarySelect()}
      ),
      ranked_products AS (
        SELECT
          cp.*,
          ROW_NUMBER() OVER (
            PARTITION BY cp.contact_id
            ORDER BY
              CASE WHEN cp.estado = 'alta' THEN 0 ELSE 1 END,
              cp.fecha_alta DESC NULLS LAST,
              cp.created_at DESC
          ) AS rn
        FROM contact_products cp
      )
      SELECT COUNT(*)::int AS total
      FROM summary s
      JOIN ranked_products rp
        ON rp.contact_id = s.id
       AND rp.rn = 1
      ${whereClause}
      `,
      values
    );

    const total = Number(countResult.rows[0]?.total || 0);

    values.push(safeLimit);
    const limitIdx = values.length;
    values.push(offset);
    const offsetIdx = values.length;

    const result = await client.query(
      `
      WITH summary AS (
        ${buildContactSummarySelect()}
      ),
      ranked_products AS (
        SELECT
          cp.*,
          ROW_NUMBER() OVER (
            PARTITION BY cp.contact_id
            ORDER BY
              CASE WHEN cp.estado = 'alta' THEN 0 ELSE 1 END,
              cp.fecha_alta DESC NULLS LAST,
              cp.created_at DESC
          ) AS rn
        FROM contact_products cp
      )
      SELECT
        s.*,
        rp.nombre_producto,
        rp.plan,
        rp.precio,
        rp.estado AS producto_estado,
        rp.fecha_alta,
        rp.cuotas_pagas,
        rp.carencia_cuotas
      FROM summary s
      JOIN ranked_products rp
        ON rp.contact_id = s.id
       AND rp.rn = 1
      ${whereClause}
      ORDER BY
        CASE WHEN rp.estado = 'alta' THEN 0 ELSE 1 END,
        s.created_at DESC,
        s.nombre ASC,
        s.apellido ASC
      LIMIT $${limitIdx} OFFSET $${offsetIdx}
      `,
      values
    );

    return {
      items: result.rows.map(mapClientRowToApi),
      total,
      page: safePage,
      limit: safeLimit
    };
  } finally {
    await client.end();
  }
}

function normalizePhoneSearchValue(value) {
  return String(value || "")
    .trim()
    .replace(/[^\d]/g, "");
}

function buildPhoneSearchClause(fieldPrefix, idx) {
  // TODO: add telefono_norm/celular_norm columns with indexes and compare directly
  return `(
    REPLACE(REPLACE(REPLACE(${fieldPrefix}.telefono, ' ', ''), '-', ''), '+', '') ILIKE $${idx}
    OR REPLACE(REPLACE(REPLACE(${fieldPrefix}.celular, ' ', ''), '-', ''), '+', '') ILIKE $${idx}
  )`;
}

async function fetchCodificaciones({
  limit = 10,
  offset = 0,
  searchPhone = "",
  sellerId = "",
  from = "",
  to = "",
  resultado = "",
  resultadoCorregido = "",
  estado = ""
} = {}) {
  const client = createDbClient();
  try {
    await client.connect();

    const whereParts = [];
    const values = [];

    if (sellerId) {
      values.push(sellerId);
      whereParts.push(`lmh.user_id = $${values.length}`);
    }
    if (from) {
      values.push(from);
      whereParts.push(`lmh.fecha_gestion >= $${values.length}::timestamptz`);
    }
    if (to) {
      values.push(to);
      whereParts.push(`lmh.fecha_gestion <= $${values.length}::timestamptz`);
    }
    const normalizedSearchPhone = normalizePhoneSearchValue(searchPhone);
    if (normalizedSearchPhone) {
      values.push(`%${normalizedSearchPhone}%`);
      whereParts.push(buildPhoneSearchClause("d", values.length));
    }
    if (resultado) {
      values.push(resultado);
      whereParts.push(`lmh.resultado = $${values.length}`);
    }
    if (resultadoCorregido) {
      values.push(resultadoCorregido);
      whereParts.push(`la.resultado_corregido = $${values.length}`);
    }
    if (estado) {
      if (estado === "corregida") {
        whereParts.push(`la.id IS NOT NULL`);
      } else if (estado === "pendiente") {
        whereParts.push(`la.id IS NULL`);
      }
    }

    const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

    const countResult = await client.query(
      `
      WITH latest_audit AS (
        SELECT
          a.*,
          ROW_NUMBER() OVER (PARTITION BY a.management_id ORDER BY a.corrected_at DESC) AS rn
        FROM lead_coding_audit a
      )
      SELECT COUNT(*)::int AS total
      FROM lead_management_history lmh
      LEFT JOIN datos_para_trabajar d ON d.id = lmh.contact_id
      LEFT JOIN latest_audit la ON la.management_id = lmh.id AND la.rn = 1
      ${whereClause}
      `,
      values
    );

    const total = Number(countResult.rows[0]?.total || 0);

    values.push(limit);
    const limitIdx = values.length;
    values.push(offset);
    const offsetIdx = values.length;

    const result = await client.query(
      `
      WITH latest_audit AS (
        SELECT
          a.*,
          ROW_NUMBER() OVER (PARTITION BY a.management_id ORDER BY a.corrected_at DESC) AS rn
        FROM lead_coding_audit a
      )
      SELECT
        lmh.id AS management_id,
        lmh.contact_id,
        lmh.batch_id,
        lmh.fecha_gestion,
        lmh.resultado AS resultado_original,
        lmh.nota,
        d.telefono,
        d.celular,
        COALESCE(NULLIF(d.telefono, ''), NULLIF(d.celular, '')) AS telefono_display,
        u.nombre AS vendedor_nombre,
        u.apellido AS vendedor_apellido,
        TRIM(CONCAT(u.nombre, ' ', u.apellido)) AS vendedor_nombre_completo,
        la.resultado_corregido,
        la.corrected_at,
        la.corrected_by,
        TRIM(CONCAT(sup.nombre, ' ', sup.apellido)) AS supervisor_nombre_completo,
        CASE WHEN la.id IS NULL THEN 'pendiente' ELSE 'corregida' END AS estado_auditoria
      FROM lead_management_history lmh
      LEFT JOIN datos_para_trabajar d ON d.id = lmh.contact_id
      LEFT JOIN users u ON u.id = lmh.user_id
      LEFT JOIN latest_audit la ON la.management_id = lmh.id AND la.rn = 1
      LEFT JOIN users sup ON sup.id = la.corrected_by
      ${whereClause}
      ORDER BY lmh.fecha_gestion DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx}
      `,
      values
    );

    return { items: result.rows, total };
  } finally {
    await client.end();
  }
}
async function getClientMetrics(organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [];
    const summaryWhere = organizationId ? "WHERE c.organization_id = $1" : "";
    const productWhere = organizationId ? "AND organization_id = $1" : "";
    if (organizationId) values.push(organizationId);

    const result = await client.query(
      `
      WITH summary AS (
        ${buildContactSummarySelect(summaryWhere)}
      ),
      active_products AS (
        SELECT precio
        FROM contact_products
        WHERE estado = 'alta'
        ${productWhere}
      )
      SELECT
        (SELECT COUNT(*)::int FROM summary WHERE tipo_persona = 'cliente_actual') AS activos,
        (SELECT COUNT(*)::int FROM summary WHERE tipo_persona = 'cliente_historico') AS en_baja,
        (SELECT COALESCE(AVG(precio), 0)::numeric(12,2) FROM active_products) AS cuota_promedio
      `,
      values
    );

    const row = result.rows[0] || {};

    return {
      activos: Number(row.activos || 0),
      enBaja: Number(row.en_baja || 0),
      cuotaPromedio: Number(row.cuota_promedio || 0),
      cuotaPromedioLabel: formatUyuAmount(row.cuota_promedio || 0)
    };
  } finally {
    await client.end();
  }
}

async function getClientDocumentData(clientId, organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const metadata = await getUsersTableMetadata(client);

    const userSelect = metadata.hasUsersTable
      ? "u.nombre AS seller_nombre, u.apellido AS seller_apellido"
      : "NULL::text AS seller_nombre, NULL::text AS seller_apellido";
    const userJoin = metadata.hasUsersTable ? "LEFT JOIN users u ON u.id = s.seller_user_id" : "";

    const values = [clientId];
    let idx = values.length;
    let orgClause = "";
    if (organizationId) {
      values.push(organizationId);
      idx = values.length;
      orgClause = `AND c.organization_id = $${idx}`;
    }

    const result = await client.query(
      `
      SELECT
        c.*,
        cp.nombre_producto,
        cp.plan,
        cp.precio,
        cp.fecha_alta,
        cp.estado AS producto_estado,
        cp.cuotas_pagas,
        cp.carencia_cuotas,
        s.id AS sale_id,
        COALESCE(s.fecha_venta, s.created_at) AS sale_fecha,
        s.medio_pago,
        s.seller_origin,
        s.seller_name_snapshot,
        s.seller_user_id AS seller_id,
        ${userSelect}
      FROM contacts c
      LEFT JOIN LATERAL (
        SELECT *
        FROM contact_products
        WHERE contact_id = c.id
          ${organizationId ? "AND organization_id = $2" : ""}
        ORDER BY fecha_alta DESC NULLS LAST, created_at DESC
        LIMIT 1
      ) cp ON true
      LEFT JOIN sales s
        ON s.id = cp.sale_id
      ${userJoin}
      WHERE c.id = $1
      ${orgClause}
      LIMIT 1
      `,
      values
    );

    const row = result.rows[0];
    if (!row) return null;

    const sellerName = row.seller_origin === "externo"
      ? row.seller_name_snapshot
      : [row.seller_nombre, row.seller_apellido].filter(Boolean).join(" ").trim() || row.seller_name_snapshot;

    return {
      client: {
        id: row.id,
        nombre: row.nombre,
        apellido: row.apellido,
        documento: row.documento,
        email: row.email,
        telefono: row.telefono,
        celular: row.celular,
        fecha_nacimiento: row.fecha_nacimiento,
        direccion: row.direccion,
        departamento: row.departamento,
        pais: row.pais,
        created_at: row.created_at
      },
      product: {
        nombre_producto: row.nombre_producto,
        plan: row.plan,
        precio: row.precio,
        fecha_alta: row.fecha_alta,
        estado: row.producto_estado,
        cuotas_pagas: row.cuotas_pagas,
        carencia_cuotas: row.carencia_cuotas
      },
      sale: {
        id: row.sale_id,
        fecha: row.sale_fecha,
        medio_pago: row.medio_pago,
        seller_origin: row.seller_origin,
        seller_name: sellerName
      }
    };
  } finally {
    await client.end();
  }
}

async function getClientDetailData(clientId, organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const metadata = await getUsersTableMetadata(client);

    const contactValues = [clientId];
    let contactOrgClause = "";
    if (organizationId) {
      contactValues.push(organizationId);
      contactOrgClause = `AND organization_id = $2`;
    }
    const contactResult = await client.query(
      `
      SELECT *
      FROM contacts
      WHERE id = $1
      ${contactOrgClause}
      LIMIT 1
      `,
      contactValues
    );

    const contact = contactResult.rows[0];
    if (!contact) return null;

    const userSelect = metadata.hasUsersTable
      ? "u.nombre AS seller_nombre, u.apellido AS seller_apellido"
      : "NULL::text AS seller_nombre, NULL::text AS seller_apellido";
    const userJoin = metadata.hasUsersTable ? "LEFT JOIN users u ON u.id = s.seller_user_id" : "";

    const productsValues = [clientId];
    let productsOrgClause = "";
    if (organizationId) {
      productsValues.push(organizationId);
      productsOrgClause = `AND cp.organization_id = $2`;
    }
    const productsResult = await client.query(
      `
      SELECT
        cp.*,
        COALESCE(s.fecha_venta, s.created_at) AS sale_fecha,
        s.medio_pago,
        s.seller_origin,
        s.seller_name_snapshot,
        s.seller_user_id AS seller_id,
        ${userSelect}
      FROM contact_products cp
      LEFT JOIN sales s
        ON s.id = cp.sale_id
      ${userJoin}
      WHERE cp.contact_id = $1
      ${productsOrgClause}
      ORDER BY cp.fecha_alta DESC NULLS LAST, cp.created_at DESC
      `,
      productsValues
    );

    const products = productsResult.rows.map((row) => {
      const sellerName = row.seller_origin === "externo"
        ? row.seller_name_snapshot
        : [row.seller_nombre, row.seller_apellido].filter(Boolean).join(" ").trim() || row.seller_name_snapshot;

      return {
        id: row.id,
        productId: row.product_id,
        nombreProducto: row.nombre_producto,
        nombre_producto: row.nombre_producto,
        plan: row.plan,
        precio: row.precio,
        estado: row.estado,
        fechaAlta: row.fecha_alta,
        fecha_alta: row.fecha_alta,
        fechaBaja: row.fecha_baja,
        fecha_baja: row.fecha_baja,
        cuotasPagas: row.cuotas_pagas,
        cuotas_pagas: row.cuotas_pagas,
        carenciaCuotas: row.carencia_cuotas,
        carencia_cuotas: row.carencia_cuotas,
        sellerName,
        seller_name: sellerName,
        medioPago: row.medio_pago,
        medio_pago: row.medio_pago,
        sellerOrigin: row.seller_origin,
        seller_origin: row.seller_origin
      };
    });

    const salesValues = [clientId];
    let salesOrgClause = "";
    if (organizationId) {
      salesValues.push(organizationId);
      salesOrgClause = `AND s.organization_id = $2`;
    }
    const salesResult = await client.query(
      `
      SELECT
        s.*,
        ${userSelect}
      FROM sales s
      ${userJoin}
      WHERE s.contact_id = $1
      ${salesOrgClause}
      ORDER BY s.created_at DESC
      `,
      salesValues
    );

    const salesHistory = salesResult.rows.map((row) => {
      const sellerName = row.seller_origin === "externo"
        ? row.seller_name_snapshot
        : [row.seller_nombre, row.seller_apellido].filter(Boolean).join(" ").trim() || row.seller_name_snapshot;
      const saleFecha = row.fecha_venta || row.created_at;

      return {
        id: row.id,
        fecha: saleFecha,
        fecha_alta: saleFecha,
        fecha_venta: row.fecha_venta,
        fechaVenta: saleFecha,
        medioPago: row.medio_pago,
        medio_pago: row.medio_pago,
        sellerName,
        seller_name: sellerName,
        sellerOrigin: row.seller_origin,
        seller_origin: row.seller_origin
      };
    });

    const relativesResult = await client.query(
      `
      SELECT
        id,
        nombre,
        apellido,
        telefono,
        parentesco,
        created_at
      FROM contact_relatives
      WHERE contact_id = $1
      ORDER BY created_at ASC
      `,
      [clientId]
    );

    const relatives = relativesResult.rows.map((row) => ({
      id: row.id,
      nombre: row.nombre,
      apellido: row.apellido,
      telefono: row.telefono,
      parentesco: row.parentesco,
      createdAt: row.created_at,
      created_at: row.created_at
    }));

    return {
      id: contact.id,
      nombre: contact.nombre,
      apellido: contact.apellido,
      email: contact.email,
      telefono: contact.telefono,
      celular: contact.celular,
      documento: contact.documento,
      fechaNacimiento: contact.fecha_nacimiento,
      fecha_nacimiento: contact.fecha_nacimiento,
      direccion: contact.direccion,
      departamento: contact.departamento,
      pais: contact.pais,
      createdAt: contact.created_at,
      updatedAt: contact.updated_at,
      products,
      salesHistory,
      relatives
    };
  } finally {
    await client.end();
  }
}

async function recordClientDocumentEvent(payload) {
  const client = createDbClient();

  try {
    await client.connect();
    const result = await client.query(
      `
      INSERT INTO client_document_events (
        client_id,
        user_id,
        event,
        origin,
        template,
        lang,
        channel,
        note
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
      `,
      [
        payload.clientId,
        payload.userId || null,
        payload.event,
        payload.origin || null,
        payload.template || null,
        payload.lang || null,
        payload.channel || null,
        payload.note || null
      ]
    );

    return result.rows[0];
  } finally {
    await client.end();
  }
}

async function listProducts(organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [];
    const whereClause = organizationId ? "WHERE organization_id = $1" : "";
    if (organizationId) values.push(organizationId);
    const result = await client.query(
      `
      SELECT
        id,
        nombre,
        categoria,
        descripcion,
        observaciones,
        precio,
        activo,
        created_at,
        updated_at
      FROM products
      ${whereClause}
      ORDER BY created_at DESC, nombre ASC
      `,
      values
    );

    return result.rows.map(mapProductRowToApi);
  } finally {
    await client.end();
  }
}

async function createProductRecord(payload, organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const result = await client.query(
      `
      INSERT INTO products (
        nombre,
        categoria,
        descripcion,
        observaciones,
        precio,
        activo,
        organization_id
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
      `,
      [
        payload.nombre,
        payload.categoria,
        payload.descripcion,
        payload.observaciones,
        payload.precio,
        payload.activo,
        organizationId
      ]
    );

    return mapProductRowToApi(result.rows[0]);
  } finally {
    await client.end();
  }
}

async function updateProductRecord(productId, payload, organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [
      productId,
      payload.nombre || null,
      payload.categoria || null,
      payload.descripcion || null,
      payload.observaciones || null,
      payload.precio ?? null,
      payload.activo === undefined ? null : payload.activo
    ];
    let orgClause = "";
    if (organizationId) {
      values.push(organizationId);
      orgClause = `AND organization_id = $${values.length}`;
    }

    const result = await client.query(
      `
      UPDATE products
      SET
        nombre = COALESCE($2, nombre),
        categoria = COALESCE($3, categoria),
        descripcion = COALESCE($4, descripcion),
        observaciones = COALESCE($5, observaciones),
        precio = COALESCE($6, precio),
        activo = COALESCE($7, activo),
        updated_at = now()
      WHERE id = $1
      ${orgClause}
      RETURNING *
      `,
      values
    );

    if (!result.rows[0]) return null;
    return mapProductRowToApi(result.rows[0]);
  } finally {
    await client.end();
  }
}

function mapManualTicketRowToApi(row) {
  return {
    id: row.id,
    numero: row.numero,
    clienteId: row.cliente_id,
    tipoSolicitud: row.tipo_solicitud,
    tipoSolicitudManual: row.tipo_solicitud_manual || "",
    resumen: row.resumen,
    serviceRequest: row.service_request || null,
    prioridad: row.prioridad,
    estado: row.estado,
    productoContratoId: row.producto_contrato_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function createManualTicket(payload, organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const result = await client.query(
      `
      INSERT INTO manual_tickets (
        cliente_id,
        tipo_solicitud,
        tipo_solicitud_manual,
        resumen,
        service_request,
        prioridad,
        estado,
        producto_contrato_id,
        organization_id
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
      `,
      [
        payload.clienteId,
        payload.tipoSolicitud,
        payload.tipoSolicitudManual,
        payload.resumen,
        payload.serviceRequest ? JSON.stringify(payload.serviceRequest) : null,
        payload.prioridad,
        payload.estado,
        payload.productoContratoId,
        organizationId
      ]
    );

    return mapManualTicketRowToApi(result.rows[0]);
  } finally {
    await client.end();
  }
}

async function listManualTickets({ clienteId, organizationId } = {}) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [];
    let where = "";
    if (clienteId) {
      values.push(clienteId);
      where = `WHERE cliente_id = $${values.length}`;
    }
    if (organizationId) {
      values.push(organizationId);
      where = where
        ? `${where} AND organization_id = $${values.length}`
        : `WHERE organization_id = $${values.length}`;
    }

    const result = await client.query(
      `
      SELECT *
      FROM manual_tickets
      ${where}
      ORDER BY created_at DESC
      `,
      values
    );

    const items = result.rows.map(mapManualTicketRowToApi);
    if (!items.length) return items;

    const ids = items.map((item) => item.id);
    const notesResult = await client.query(
      `
      SELECT
        ticket_id,
        autor,
        texto,
        created_at
      FROM manual_ticket_notes
      WHERE ticket_id = ANY($1::uuid[])
      ORDER BY created_at DESC
      `,
      [ids]
    );

    const notesByTicket = new Map();
    for (const row of notesResult.rows) {
      if (!notesByTicket.has(row.ticket_id)) notesByTicket.set(row.ticket_id, []);
      notesByTicket.get(row.ticket_id).push({
        autor: row.autor || "Usuario",
        texto: row.texto,
        createdAt: row.created_at
      });
    }

    const closuresResult = await client.query(
      `
      SELECT
        ticket_id,
        resultado,
        usuario,
        created_at
      FROM manual_ticket_closures
      WHERE ticket_id = ANY($1::uuid[])
      ORDER BY created_at DESC
      `,
      [ids]
    );
    const closuresByTicket = new Map();
    for (const row of closuresResult.rows) {
      if (!closuresByTicket.has(row.ticket_id)) closuresByTicket.set(row.ticket_id, []);
      closuresByTicket.get(row.ticket_id).push({
        at: row.created_at,
        user: row.usuario || "Usuario",
        resultado: row.resultado
      });
    }

    return items.map((item) => ({
      ...item,
      notas: notesByTicket.get(item.id) || [],
      cierreHistory: closuresByTicket.get(item.id) || []
    }));
  } finally {
    await client.end();
  }
}

async function getManualTicketById(ticketId, organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [ticketId];
    let orgClause = "";
    if (organizationId) {
      values.push(organizationId);
      orgClause = `AND organization_id = $2`;
    }
    const result = await client.query(
      `
      SELECT *
      FROM manual_tickets
      WHERE id = $1
      ${orgClause}
      LIMIT 1
      `,
      values
    );

    const row = result.rows[0];
    if (!row) return null;

    const notesResult = await client.query(
      `
      SELECT
        autor,
        texto,
        created_at
      FROM manual_ticket_notes
      WHERE ticket_id = $1
      ORDER BY created_at DESC
      `,
      [ticketId]
    );

    const closuresResult = await client.query(
      `
      SELECT
        resultado,
        usuario,
        created_at
      FROM manual_ticket_closures
      WHERE ticket_id = $1
      ORDER BY created_at DESC
      `,
      [ticketId]
    );

    const item = mapManualTicketRowToApi(row);
    return {
      ...item,
      notas: notesResult.rows.map((note) => ({
        autor: note.autor || "Usuario",
        texto: note.texto,
        createdAt: note.created_at
      })),
      cierreHistory: closuresResult.rows.map((row) => ({
        at: row.created_at,
        user: row.usuario || "Usuario",
        resultado: row.resultado
      }))
    };
  } finally {
    await client.end();
  }
}

async function updateManualTicket(ticketId, patch, organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [
      ticketId,
      patch.tipoSolicitud || null,
      patch.tipoSolicitudManual || null,
      patch.resumen || null,
      patch.serviceRequest ? JSON.stringify(patch.serviceRequest) : null,
      patch.prioridad || null,
      patch.estado || null,
      patch.productoContratoId || null
    ];
    let orgClause = "";
    if (organizationId) {
      values.push(organizationId);
      orgClause = `AND organization_id = $${values.length}`;
    }
    const result = await client.query(
      `
      UPDATE manual_tickets
      SET
        tipo_solicitud = COALESCE($2, tipo_solicitud),
        tipo_solicitud_manual = COALESCE($3, tipo_solicitud_manual),
        resumen = COALESCE($4, resumen),
        service_request = COALESCE($5, service_request),
        prioridad = COALESCE($6, prioridad),
        estado = COALESCE($7, estado),
        producto_contrato_id = COALESCE($8, producto_contrato_id),
        updated_at = now()
      WHERE id = $1
      ${orgClause}
      RETURNING *
      `,
      values
    );

    if (!result.rows[0]) return null;
    return mapManualTicketRowToApi(result.rows[0]);
  } finally {
    await client.end();
  }
}

async function addManualTicketNote(ticketId, { texto, autor }, organizationId) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [ticketId];
    let orgClause = "";
    if (organizationId) {
      values.push(organizationId);
      orgClause = `AND organization_id = $2`;
    }
    await client.query(
      `
      UPDATE manual_tickets
      SET estado = 'en_proceso',
          updated_at = now()
      WHERE id = $1
      ${orgClause}
      `,
      values
    );

    const result = await client.query(
      `
      INSERT INTO manual_ticket_notes (ticket_id, autor, texto)
      VALUES ($1, $2, $3)
      RETURNING *
      `,
      [ticketId, autor || null, texto]
    );

    return {
      autor: result.rows[0].autor || "Usuario",
      texto: result.rows[0].texto,
      createdAt: result.rows[0].created_at
    };
  } finally {
    await client.end();
  }
}

async function closeManualTicket({ ticketId, outcome, note, actorName, organizationId }) {
  const client = createDbClient();

  try {
    await client.connect();
    await client.query("BEGIN");

    const ticketValues = [ticketId];
    let ticketOrgClause = "";
    if (organizationId) {
      ticketValues.push(organizationId);
      ticketOrgClause = `AND organization_id = $2`;
    }
    const ticketResult = await client.query(
      `SELECT * FROM manual_tickets WHERE id = $1 ${ticketOrgClause} LIMIT 1`,
      ticketValues
    );
    const ticket = ticketResult.rows[0];
    if (!ticket) {
      await client.query("ROLLBACK");
      return { notFound: true };
    }

    if (ticket.tipo_solicitud === "solicitud_baja") {
      if (!["retenido", "baja_confirmada"].includes(outcome)) {
        await client.query("ROLLBACK");
        return { error: "Debes seleccionar el resultado: retenido o baja_confirmada." };
      }

      if (outcome === "baja_confirmada") {
        if (!ticket.producto_contrato_id) {
          await client.query("ROLLBACK");
          return { error: "La solicitud de baja requiere producto_contrato_id." };
        }
        await client.query(
          `
          UPDATE contact_products
          SET
            estado = 'baja',
            motivo_baja = 'otro',
            motivo_baja_detalle = $2,
            fecha_baja = now()::date,
            updated_at = now()
          WHERE id = $1
          ${organizationId ? "AND organization_id = $3" : ""}
          `,
          organizationId
            ? [ticket.producto_contrato_id, note || "Baja confirmada", organizationId]
            : [ticket.producto_contrato_id, note || "Baja confirmada"]
        );
      }
    }

    await client.query(
      `
      UPDATE manual_tickets
      SET estado = 'finalizada',
          updated_at = now()
      WHERE id = $1
      ${organizationId ? "AND organization_id = $2" : ""}
      `,
      organizationId ? [ticketId, organizationId] : [ticketId]
    );

    await client.query(
      `
      INSERT INTO manual_ticket_closures (ticket_id, resultado, usuario, note)
      VALUES ($1, $2, $3, $4)
      `,
      [ticketId, outcome || "cerrado", actorName || null, note || null]
    );

    if (note && note.trim()) {
      await client.query(
        `
        INSERT INTO manual_ticket_notes (ticket_id, autor, texto)
        VALUES ($1, $2, $3)
        `,
        [ticketId, actorName || null, note.trim()]
      );
    }

    await client.query("COMMIT");
    return { ok: true };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    throw error;
  } finally {
    await client.end();
  }
}

async function findUserByIdWithClient(client, userId) {
  const metadata = await getUsersTableMetadata(client);
  if (!metadata.hasUsersTable) {
    return null;
  }

  const result = await client.query(
    `
    ${buildUserSelect(metadata)}
    WHERE id = $1
    LIMIT 1
    `,
    [userId]
  );

  return result.rows[0] || null;
}

async function findUserByEmailForSuperadmin(client, email, excludeUserId = null) {
  const metadata = await getUsersTableMetadata(client);
  if (!metadata.hasUsersTable) {
    return null;
  }

  const values = [email];
  let where = "WHERE lower(email) = lower($1)";

  if (excludeUserId) {
    where += ` AND id <> $${values.length}`;
  }

  const result = await client.query(
    `
    ${buildUserSelect(metadata)}
    ${where}
    LIMIT 1
    `,
    values
  );

  return result.rows[0] || null;
}

async function createSuperadminUserRecord(input, actorUserId) {
  const client = createDbClient();

  try {
    await client.connect();
    await client.query("BEGIN");

    const existingUser = await findUserByEmailForSuperadmin(client, input.email);
    if (existingUser) {
      await client.query("ROLLBACK");
      return { conflict: true, message: "Ya existe un usuario con ese email" };
    }

    const nameParts = splitDisplayName(input.nombre);
    const status = statusFromActivo(input.activo ?? true);
    const metadata = await getUsersTableMetadata(client);

    const result = await client.query(
      `
      INSERT INTO users (
        ${metadata.hasCognitoSub ? "cognito_sub," : ""}
        email,
        nombre,
        apellido,
        telefono,
        role_key,
        status,
        created_by,
        approved_by,
        approved_at,
        created_at,
        updated_at
      )
      VALUES (
        ${metadata.hasCognitoSub ? "NULL," : ""}
        $1, $2, $3, $4, $5, $6, $7,
        ${status === "approved" ? "now()" : "NULL"},
        now(), now()
      )
      RETURNING *
      `,
      [
        input.email,
        nameParts.nombre,
        nameParts.apellido,
        input.telefono || null,
        input.rol,
        status,
        actorUserId
      ]
    );

    const createdUser = result.rows[0];

    await client.query(
      `
      INSERT INTO user_role_history (
        user_id,
        old_role,
        new_role,
        changed_by,
        changed_at,
        reason
      )
      VALUES ($1, $2, $3, $4, now(), $5)
      `,
      [
        createdUser.id,
        null,
        input.rol,
        actorUserId,
        "Alta manual desde superadmin/users"
      ]
    );

    await client.query(
      `
      INSERT INTO user_status_history (
        user_id,
        old_status,
        new_status,
        changed_by,
        changed_at,
        reason
      )
      VALUES ($1, $2, $3, $4, now(), $5)
      `,
      [
        createdUser.id,
        null,
        status,
        actorUserId,
        "Alta manual desde superadmin/users"
      ]
    );

    await client.query("COMMIT");

    return { user: mapUserRowToApi(createdUser) };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    throw error;
  } finally {
    await client.end();
  }
}

async function updateSuperadminUserRecord(userId, input, actorUserId) {
  const client = createDbClient();

  try {
    await client.connect();
    await client.query("BEGIN");

    const existingUser = await findUserByIdWithClient(client, userId);
    if (!existingUser) {
      await client.query("ROLLBACK");
      return { notFound: true };
    }

    if (existingUser.id === actorUserId && input.rol && input.rol !== existingUser.role_key) {
      await client.query("ROLLBACK");
      return { forbidden: true, message: "No puedes cambiar tu propio rol" };
    }

    const duplicate = await findUserByEmailForSuperadmin(client, input.email, userId);
    if (duplicate) {
      await client.query("ROLLBACK");
      return { conflict: true, message: "Ya existe un usuario con ese email" };
    }

    const nameParts = splitDisplayName(input.nombre);
    const status = statusFromActivo(input.activo ?? isActiveFromStatus(existingUser.status));

    const result = await client.query(
      `
      UPDATE users
      SET
        email = $2,
        nombre = $3,
        apellido = $4,
        telefono = $5,
        role_key = $6,
        status = $7,
        updated_at = now()
      WHERE id = $1
      RETURNING *
      `,
      [
        userId,
        input.email,
        nameParts.nombre,
        nameParts.apellido,
        input.telefono || null,
        input.rol,
        status
      ]
    );

    const updatedUser = result.rows[0];

    if (existingUser.role_key !== updatedUser.role_key) {
      await client.query(
        `
        INSERT INTO user_role_history (
          user_id,
          old_role,
          new_role,
          changed_by,
          changed_at,
          reason
        )
        VALUES ($1, $2, $3, $4, now(), $5)
        `,
        [
          updatedUser.id,
          existingUser.role_key,
          updatedUser.role_key,
          actorUserId,
          "Actualizaciï¿½n desde superadmin/users"
        ]
      );
    }

    if (existingUser.status !== updatedUser.status) {
      await client.query(
        `
        INSERT INTO user_status_history (
          user_id,
          old_status,
          new_status,
          changed_by,
          changed_at,
          reason
        )
        VALUES ($1, $2, $3, $4, now(), $5)
        `,
        [
          updatedUser.id,
          existingUser.status,
          updatedUser.status,
          actorUserId,
          "Actualizaciï¿½n desde superadmin/users"
        ]
      );
    }

    await client.query("COMMIT");

    return { user: mapUserRowToApi(updatedUser) };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    throw error;
  } finally {
    await client.end();
  }
}

function requireAuthenticated(event, authUser) {
  if (!authUser) {
    return json(401, {
      ok: false,
      message: "Authorization header is required"
    });
  }

  if (!authUser.sub) {
    return json(401, {
      ok: false,
      message: "JWT claims with sub are required"
    });
  }

  return null;
}

function requireDbUser(event, dbUser) {
  if (!dbUser) {
    return json(404, {
      ok: false,
      message: "User not found in database"
    });
  }

  return null;
}

function requireApproved(event, dbUser) {
  if (!dbUser || dbUser.status !== "approved") {
    return json(403, {
      ok: false,
      message: "User is not approved"
    });
  }

  return null;
}

function requireRole(event, dbUser, allowedRoles) {
  console.log("[role-check] roles requeridos:", allowedRoles);
  console.log("[role-check] rol del usuario:", dbUser?.role_key);
  console.log("[role-check] ï¿½tiene acceso?:", allowedRoles.includes(dbUser?.role_key));
  if (!dbUser || !allowedRoles.includes(dbUser.role_key)) {
    return json(403, {
      ok: false,
      message: "Insufficient role permissions",
      requiredRoles: allowedRoles
    });
  }

  return null;
}

async function createVendorRegistrationRequest(data) {
  const client = createDbClient();

  try {
    await client.connect();
    await client.query("BEGIN");

    const existingUser = await client.query(
      `
      SELECT id, email
      FROM users
      WHERE lower(email) = lower($1)
      LIMIT 1
      `,
      [data.email]
    );

    if (existingUser.rows.length > 0) {
      await client.query("ROLLBACK");
      return {
        conflict: true,
        message: "Ya existe un usuario con ese email"
      };
    }

    const existingPendingRequest = await client.query(
      `
      SELECT id
      FROM vendor_registration_requests
      WHERE lower(email) = lower($1)
        AND status = 'pending'
      LIMIT 1
      `,
      [data.email]
    );

    if (existingPendingRequest.rows.length > 0) {
      await client.query("ROLLBACK");
      return {
        conflict: true,
        message: "Ya existe una solicitud pendiente para ese email"
      };
    }

    const insertResult = await client.query(
      `
      INSERT INTO vendor_registration_requests (
        nombre,
        apellido,
        email,
        telefono,
        status,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, 'pending', now(), now())
      RETURNING id, nombre, apellido, email, telefono, status, created_at
      `,
      [data.nombre, data.apellido, data.email, data.telefono]
    );

    await client.query("COMMIT");
    return { request: insertResult.rows[0] };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    throw error;
  } finally {
    await client.end();
  }
}

async function listPendingVendorRequests() {
  const client = createDbClient();

  try {
    await client.connect();

    const result = await client.query(
      `
      SELECT
        id,
        nombre,
        apellido,
        email,
        telefono,
        status,
        reviewed_by,
        reviewed_at,
        review_notes,
        user_id,
        created_at,
        updated_at
      FROM vendor_registration_requests
      WHERE status = 'pending'
      ORDER BY created_at ASC
      `
    );

    return result.rows;
  } finally {
    await client.end();
  }
}

async function createCognitoVendorUser({ email, nombre, apellido }) {
  const userPoolId = process.env.COGNITO_USER_POOL_ID;

  if (!userPoolId) {
    throw new Error("COGNITO_USER_POOL_ID is required");
  }

  await cognitoClient.send(
    new AdminCreateUserCommand({
      UserPoolId: userPoolId,
      Username: email,
      DesiredDeliveryMediums: ["EMAIL"],
      UserAttributes: [
        { Name: "email", Value: email },
        { Name: "email_verified", Value: "true" },
        { Name: "given_name", Value: nombre },
        { Name: "family_name", Value: apellido },
        { Name: "name", Value: `${nombre} ${apellido}`.trim() }
      ]
    })
  );

  await cognitoClient.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: userPoolId,
      Username: email,
      GroupName: "vendedor"
    })
  );
}

async function getCognitoUserByEmail(email) {
  const userPoolId = process.env.COGNITO_USER_POOL_ID;

  if (!userPoolId) {
    throw new Error("COGNITO_USER_POOL_ID is required");
  }

  const result = await cognitoClient.send(
    new ListUsersCommand({
      UserPoolId: userPoolId,
      Filter: `email = "${email}"`,
      Limit: 1
    })
  );

  return result.Users?.[0] || null;
}

function extractSubFromCognitoUser(cognitoUser) {
  return (
    cognitoUser?.Attributes?.find((attribute) => attribute.Name === "sub")?.Value ||
    null
  );
}

async function getCognitoSubByEmail(email) {
  const client = createDbClient();

  try {
    await client.connect();

    const result = await client.query(
      `
      SELECT cognito_sub
      FROM users
      WHERE lower(email) = lower($1)
      LIMIT 1
      `,
      [email]
    );

    return result.rows[0]?.cognito_sub || null;
  } finally {
    await client.end();
  }
}

async function approveVendorRequest({ requestId, reviewerUserId }) {
  const client = createDbClient();

  try {
    await client.connect();

    const requestResult = await client.query(
      `
      SELECT
        id,
        nombre,
        apellido,
        email,
        telefono,
        status,
        user_id
      FROM vendor_registration_requests
      WHERE id = $1
      LIMIT 1
      `,
      [requestId]
    );

    const requestRow = requestResult.rows[0];

    if (!requestRow) {
      return { notFound: true };
    }

    if (requestRow.status !== "pending") {
      return {
        invalidState: true,
        message: "La solicitud ya no estï¿½ pendiente"
      };
    }

    await createCognitoVendorUser({
      email: requestRow.email,
      nombre: requestRow.nombre,
      apellido: requestRow.apellido
    });

    const cognitoUser = await getCognitoUserByEmail(requestRow.email);
    const cognitoSub = extractSubFromCognitoUser(cognitoUser);

    await client.query("BEGIN");

    const existingUserResult = await client.query(
      `
      SELECT id
      FROM users
      WHERE lower(email) = lower($1)
      LIMIT 1
      `,
      [requestRow.email]
    );

    if (existingUserResult.rows.length > 0) {
      await client.query("ROLLBACK");
      return {
        conflict: true,
        message: "Ya existe un usuario con ese email"
      };
    }

    const newUser = await insertApprovedVendorUser(client, {
      cognitoSub,
      email: requestRow.email,
      nombre: requestRow.nombre,
      apellido: requestRow.apellido,
      telefono: requestRow.telefono,
      reviewerUserId
    });

    await client.query(
      `
      UPDATE vendor_registration_requests
      SET
        status = 'approved',
        reviewed_by = $2,
        reviewed_at = now(),
        user_id = $3,
        updated_at = now()
      WHERE id = $1
      `,
      [requestId, reviewerUserId, newUser.id]
    );

    await client.query(
      `
      INSERT INTO user_role_history (
        user_id,
        old_role,
        new_role,
        changed_by,
        changed_at,
        reason
      )
      VALUES ($1, $2, $3, $4, now(), $5)
      `,
      [
        newUser.id,
        null,
        "vendedor",
        reviewerUserId,
        "Aprobaciï¿½n de solicitud de vendedor"
      ]
    );

    await client.query(
      `
      INSERT INTO user_status_history (
        user_id,
        old_status,
        new_status,
        changed_by,
        changed_at,
        reason
      )
      VALUES ($1, $2, $3, $4, now(), $5)
      `,
      [
        newUser.id,
        null,
        "approved",
        reviewerUserId,
        "Usuario aprobado desde solicitud de vendedor"
      ]
    );

    await client.query("COMMIT");

    return { user: newUser };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    throw error;
  } finally {
    await client.end();
  }
}

async function rejectVendorRequest({ requestId, reviewerUserId, reviewNotes }) {
  const client = createDbClient();

  try {
    await client.connect();
    await client.query("BEGIN");

    const requestResult = await client.query(
      `
      SELECT
        id,
        status
      FROM vendor_registration_requests
      WHERE id = $1
      LIMIT 1
      `,
      [requestId]
    );

    const requestRow = requestResult.rows[0];

    if (!requestRow) {
      await client.query("ROLLBACK");
      return { notFound: true };
    }

    if (requestRow.status !== "pending") {
      await client.query("ROLLBACK");
      return {
        invalidState: true,
        message: "La solicitud ya no estï¿½ pendiente"
      };
    }

    const result = await client.query(
      `
      UPDATE vendor_registration_requests
      SET
        status = 'rejected',
        reviewed_by = $2,
        reviewed_at = now(),
        review_notes = $3,
        updated_at = now()
      WHERE id = $1
      RETURNING id, status, reviewed_by, reviewed_at, review_notes
      `,
      [requestId, reviewerUserId, reviewNotes || null]
    );

    await client.query("COMMIT");
    return { request: result.rows[0] };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    throw error;
  } finally {
    await client.end();
  }
}

export const handler = async (event) => {
  try {
  const preflightMethod =
    event?.requestContext?.http?.method || event?.httpMethod || "";
  const hasPreflightHeader =
    Boolean(
      event?.headers?.["access-control-request-method"] ||
        event?.headers?.["Access-Control-Request-Method"]
    );
  if (preflightMethod === "OPTIONS" || hasPreflightHeader) {
    return handleOptions(event);
  }
  if (Array.isArray(event?.Records) && event.Records[0]?.eventSource === "aws:sqs") {
    for (const record of event.Records) {
      let payload = null;
      try {
        payload = JSON.parse(record.body || "{}");
      } catch {
        continue;
      }
      if (!payload) continue;
      if (payload.type === "recupero_import") {
        const jobId = payload.jobId;
        if (jobId) {
          await processRecuperoImportJob(jobId);
        }
        continue;
      }
      if (payload.type && payload.type !== "contact_import" && payload.type !== "clientes") {
        continue;
      }
      const batchId = payload.batchId || payload.jobId;
      if (!batchId) continue;
      const createProducts = payload.createProducts !== false;
      const organizationId = payload.organizationId || null;
      await processClientImportBatch(batchId, { createProducts, organizationId });
    }
    return { ok: true };
  }
  if (getMethodFromHttp(event) === "OPTIONS") {
    return handleOptions(event);
  }
  const path = getPath(event);
  const method = getMethod(event);
  const segments = getPathSegments(path);
  const clientDocumentMatch = path.match(/\/clients\/([^/]+)\/document$/);
  const clientDocumentSentMatch = path.match(/\/clients\/([^/]+)\/document\/sent$/);
  const productMatch = path.match(/\/products\/([^/]+)$/);
  const clientDetailMatch = path.match(/\/clients\/([^/]+)$/);
  const contactDetailMatch = path.match(/\/contacts\/([^/]+)$/);
  const manualTicketsPath = path.endsWith("/manual-tickets");
  const manualTicketMatch = path.match(/\/manual-tickets\/([^/]+)$/);
  const manualTicketNotesMatch = path.match(/\/manual-tickets\/([^/]+)\/notes$/);
  const manualTicketCloseMatch = path.match(/\/manual-tickets\/([^/]+)\/close$/);
  console.log("REQUEST", {
    method,
    path,
    origin: event?.headers?.origin || event?.headers?.Origin || null,
    hasAuthorization: Boolean(
      event?.headers?.authorization || event?.headers?.Authorization
    ),
    authorizerKeys: Object.keys(event?.requestContext?.authorizer || {})
  });

  if (method === "GET" && path.endsWith("/health")) {
    return json(200, {
      ok: true,
      service: "rednacrem-backend",
      timestamp: new Date().toISOString(),
      path,
      method
    });
  }

  if (method === "GET" && path.endsWith("/db-check")) {
    try {
      const result = await checkDatabaseConnection();

      return json(200, {
        ok: true,
        database: "connected",
        serverTime: result.server_time,
        path,
        method
      });
    } catch (error) {
      return json(500, {
        ok: false,
        database: "disconnected",
        error: error.message,
        path,
        method
      });
    }
  }

  // â”€â”€â”€ WEBHOOK META LEADS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // GET /webhooks/meta â€” verificaciÃ³n del webhook por Meta
  if (method === "GET" && path.endsWith("/webhooks/meta")) {
    const params = event.queryStringParameters || {};
    const mode = params["hub.mode"];
    const token = params["hub.verify_token"];
    const challenge = params["hub.challenge"];

    if (mode === "subscribe" && token === process.env.META_VERIFY_TOKEN) {
      return {
        statusCode: 200,
        headers: { "Content-Type": "text/plain" },
        body: challenge
      };
    }
    return json(403, { ok: false, message: "Forbidden" });
  }

  // POST /webhooks/meta â€” recibir leads
  if (method === "POST" && path.endsWith("/webhooks/meta")) {
    try {
      const body = safeParseBody(event);
      if (!body) return json(200, { ok: true }); // Siempre 200 a Meta

      const entries = body?.entry || [];
      const defaultOrgId = process.env.DEFAULT_ORGANIZATION_ID || "9223d62d-f558-4f4c-b9bd-9dcea9888a0e";

      for (const entry of entries) {
        const changes = entry?.changes || [];
        for (const change of changes) {
          if (change?.field !== "leadgen") continue;
          const leadgenId = change?.value?.leadgen_id;
          const pageId = change?.value?.page_id;
          if (!leadgenId || !pageId) continue;

          // Obtener datos del lead desde Meta Graph API
          const pageToken = process.env.META_PAGE_ACCESS_TOKEN;
          if (!pageToken || pageToken === "pendiente") continue;

          const leadRes = await fetch(
            `https://graph.facebook.com/v19.0/${leadgenId}?access_token=${pageToken}`
          );
          const leadData = await leadRes.json();
          if (!leadData || leadData.error) continue;

          // Parsear campos del formulario
          const fieldData = leadData.field_data || [];
          const getField = (name) => {
            const f = fieldData.find((x) =>
              String(x.name || "").toLowerCase().includes(name)
            );
            return f?.values?.[0] || null;
          };

          const nombre = normalizeText(getField("first_name") || getField("nombre") || getField("name")) || null;
          const apellido = normalizeText(getField("last_name") || getField("apellido")) || null;
          const telefono = normalizeText(getField("phone_number") || getField("telefono") || getField("phone")) || null;
          const celular = normalizeText(getField("celular") || getField("mobile")) || null;
          const email = normalizeEmail(getField("email") || getField("correo")) || null;

          if (!nombre && !telefono && !email) continue;

          const client = createDbClient();
          await client.connect();
          try {
            // Buscar el lote "Meta" activo
            const batchRes = await client.query(
              `
              SELECT id FROM lead_batches
              WHERE nombre = 'Meta'
                AND estado IN ('activo', 'asignado')
                AND organization_id = $1
              ORDER BY created_at DESC
              LIMIT 1
              `,
              [defaultOrgId]
            );

            const batchId = batchRes.rows[0]?.id || null;
            if (!batchId) continue; // Si no hay lote Meta, ignorar

            // Obtener vendedores del lote para round-robin
            const sellersRes = await client.query(
              `
              SELECT lbs.seller_id
              FROM lead_batch_sellers lbs
              JOIN users u ON u.id = lbs.seller_id
              WHERE lbs.batch_id = $1
                AND lower(coalesce(u.status, 'approved')) <> 'pausado'
              ORDER BY seller_id ASC
              `,
              [batchId]
            );

            const sellers = sellersRes.rows.map((r) => r.seller_id);

            // Insertar en datos_para_trabajar
            const insertRes = await client.query(
              `
              INSERT INTO datos_para_trabajar (
                nombre, apellido, telefono, celular,
                correo_electronico, origen_dato, estado, organization_id
              ) VALUES ($1, $2, $3, $4, $5, 'facebook', 'nuevo', $6)
              RETURNING id
              `,
              [nombre, apellido, telefono, celular, email, defaultOrgId]
            );

            const leadId = insertRes.rows[0]?.id;
            if (!leadId) continue;

            // Insertar en lead_batch_contacts
            await client.query(
              `
              INSERT INTO lead_batch_contacts (batch_id, contact_id, organization_id)
              VALUES ($1, $2, $3)
              ON CONFLICT DO NOTHING
              `,
              [batchId, leadId, defaultOrgId]
            );

            // Asignar vendedor round-robin
            let assignedTo = null;
            if (sellers.length) {
              // Contar cuÃ¡ntos leads tiene cada vendedor en este lote
              const countsRes = await client.query(
                `
                SELECT assigned_to, COUNT(*) AS total
                FROM lead_contact_status
                WHERE batch_id = $1
                GROUP BY assigned_to
                `,
                [batchId]
              );

              const counts = {};
              for (const row of countsRes.rows) {
                counts[row.assigned_to] = parseInt(row.total, 10);
              }

              // Asignar al vendedor con menos leads
              assignedTo = sellers.reduce((min, s) =>
                (counts[s] || 0) < (counts[min] || 0) ? s : min
              , sellers[0]);
            }

            // Insertar en lead_contact_status
            await client.query(
              `
              INSERT INTO lead_contact_status (
                contact_id, estado_venta, intentos,
                batch_id, assigned_to, organization_id
              ) VALUES ($1, 'nuevo', 0, $2, $3, $4)
              ON CONFLICT (contact_id) DO UPDATE SET
                batch_id = $2,
                assigned_to = $3,
                estado_venta = 'nuevo',
                updated_at = now()
              `,
              [leadId, batchId, assignedTo, defaultOrgId]
            );
          } finally {
            await client.end();
          }
        }
      }

      return json(200, { ok: true });
    } catch (error) {
      console.error("Meta webhook error:", error);
      return json(200, { ok: true }); // Siempre 200 a Meta aunque falle
    }
  }

  // POST /webhooks/meta-sheet â€” ingesta desde n8n/Google Sheets
  if (method === "POST" && path.endsWith("/webhooks/meta-sheet")) {
    try {
      const body = safeParseBody(event);
      console.log("WEBHOOK BODY:", JSON.stringify(body));
      if (!body) return json(200, { ok: true, skipped: true });

      const defaultOrgId = process.env.DEFAULT_ORGANIZATION_ID || "9223d62d-f558-4f4c-b9bd-9dcea9888a0e";

      // Parsear campos
      const rawNombre = normalizeText(body?.full_name || body?.nombre || "");
      const parts = rawNombre ? rawNombre.split(" ") : [];
      const nombre = parts[0] || null;
      const apellido = normalizeText(body?.apellido) || parts.slice(1).join(" ") || null;
      const stripUY = (n) => {
        if (!n) return n;
        n = n.replace(/^\+598/, '');
        if (n.startsWith('9')) n = '0' + n;
        return n;
      };
      const telefono = stripUY(normalizePhone(body?.phone_number || body?.telefono));
      const celular = stripUY(normalizePhone(body?.celular));
      const email = normalizeEmail(body?.email || body?.correo);
      const parseDateFlexible = (val) => {
        if (!val) return null;
        // Formato ISO 8601 con timezone: YYYY-MM-DDTHH:mm:ss-03:00
        if (/^\d{4}-\d{2}-\d{2}T/.test(val)) {
          const parsed = new Date(val);
          if (Number.isNaN(parsed.getTime())) return null;
          return parsed.toISOString();
        }
        // Formato ISO: YYYY-MM-DD
        if (/^\d{4}-\d{2}-\d{2}$/.test(val)) return val;
        // Formato MDY: MM/DD/YYYY
        if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(val)) {
          const [m, d, y] = val.split('/');
          return `${y}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`;
        }
        return null;
      };
      const fechaNacimiento = parseDateFlexible(body?.date_of_birth || body?.fecha_nacimiento);
      const nota = normalizeText(body?.nota) || null;
      const localidad = normalizeText(body?.localidad) || null;
      const departamento = normalizeText(body?.departamento) || null;
      const fechaLead = parseDateFlexible(body?.fecha_lead) || null;
      const origenDato = normalizeText(body?.origen_dato) || "facebook";
      const campana = normalizeText(body?.campaign_name || body?.campana) || null;
      const formulario = normalizeText(body?.form_name || body?.formulario) || null;

      if (!nombre && !telefono && !email) {
        return json(200, { ok: true, skipped: true, reason: "sin_datos" });
      }

      const client = createDbClient();
      let responseData = { ok: true, skipped: true };
      try {
        await client.connect();

        // Normalizar telÃ©fono para comparaciÃ³n â€” quitar +598, 598, y 0 inicial
        const normalizeForCompare = (n) => {
          if (!n) return null;
          return n.replace(/^\+598/, '').replace(/^598/, '').replace(/^0/, '');
        };

        const telefonoNorm = normalizeForCompare(telefono);
        const celularNorm = normalizeForCompare(celular);

        // 1. Detectar si ya es cliente en contacts
        let isClient = false;
        if (telefonoNorm || celularNorm || email) {
          const clientRes = await client.query(
            `SELECT id FROM contacts
             WHERE organization_id = $1
               AND (
                 ($2::text IS NOT NULL AND regexp_replace(regexp_replace(regexp_replace(telefono, '^\\+598', ''), '^598', ''), '^0', '') = $2)
                 OR ($2::text IS NOT NULL AND regexp_replace(regexp_replace(regexp_replace(celular, '^\\+598', ''), '^598', ''), '^0', '') = $2)
                 OR ($3::text IS NOT NULL AND regexp_replace(regexp_replace(regexp_replace(telefono, '^\\+598', ''), '^598', ''), '^0', '') = $3)
                 OR ($3::text IS NOT NULL AND regexp_replace(regexp_replace(regexp_replace(celular, '^\\+598', ''), '^598', ''), '^0', '') = $3)
                 OR ($4::text IS NOT NULL AND lower(email) = lower($4))
               )
             LIMIT 1`,
            [defaultOrgId, telefonoNorm, celularNorm, email]
          );
          if (clientRes.rows.length) isClient = true;
        }

        // 2. Detectar duplicado solo si no es cliente
        let isDuplicate = false;
        if (!isClient && (telefonoNorm || celularNorm || email)) {
          const dupRes = await client.query(
            `SELECT id FROM datos_para_trabajar
             WHERE organization_id = $1
               AND (
                 ($2::text IS NOT NULL AND regexp_replace(regexp_replace(regexp_replace(telefono, '^\\+598', ''), '^598', ''), '^0', '') = $2)
                 OR ($2::text IS NOT NULL AND regexp_replace(regexp_replace(regexp_replace(celular, '^\\+598', ''), '^598', ''), '^0', '') = $2)
                 OR ($3::text IS NOT NULL AND regexp_replace(regexp_replace(regexp_replace(telefono, '^\\+598', ''), '^598', ''), '^0', '') = $3)
                 OR ($3::text IS NOT NULL AND regexp_replace(regexp_replace(regexp_replace(celular, '^\\+598', ''), '^598', ''), '^0', '') = $3)
                 OR ($4::text IS NOT NULL AND lower(email) = lower($4))
               )
             LIMIT 1`,
            [defaultOrgId, telefonoNorm, celularNorm, email]
          );
          if (dupRes.rows.length) isDuplicate = true;
        }

        const estado = (isDuplicate || isClient) ? "bloqueado" : "nuevo";
        const motivoBloqueo = isClient ? "cliente_existente" : isDuplicate ? "duplicado" : null;

        const insertRes = await client.query(
          `INSERT INTO datos_para_trabajar (
            nombre, apellido, telefono, celular,
            email, fecha_nacimiento,
            origen_dato, estado, organization_id,
            nota, localidad, departamento, fecha_lead, motivo_bloqueo
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14
          )
          RETURNING id`,
          [
            nombre, apellido, telefono, celular,
            email, fechaNacimiento,
            origenDato, estado, defaultOrgId,
            nota, localidad, departamento, fechaLead, motivoBloqueo
          ]
        );
        const leadId = insertRes.rows[0]?.id;
        if (leadId && estado === "nuevo") {
          const batchName = body?.batch_name || 'Meta';
          const orgId = body?.organization_id || defaultOrgId;
          const batchRes = await client.query(
            `SELECT id FROM lead_batches
             WHERE nombre = $1
               AND estado IN ('activo', 'asignado')
               AND organization_id = $2
             ORDER BY created_at DESC LIMIT 1`,
            [batchName, orgId]
          );
          const batchId = batchRes.rows[0]?.id || null;

          if (batchId) {
            await client.query(
              `INSERT INTO lead_batch_contacts (batch_id, contact_id, organization_id)
               VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
              [batchId, leadId, orgId]
            );

            const sellersRes = await client.query(
              `SELECT lbs.seller_id
               FROM lead_batch_sellers lbs
               JOIN users u ON u.id = lbs.seller_id
               WHERE lbs.batch_id = $1
                 AND lower(coalesce(u.status, 'approved')) <> 'pausado'
               ORDER BY seller_id ASC`,
              [batchId]
            );
            const sellers = sellersRes.rows.map((r) => r.seller_id);

            let assignedTo = null;
            if (sellers.length) {
              const countsRes = await client.query(
                `SELECT assigned_to, COUNT(*) AS total
                 FROM lead_contact_status
                 WHERE batch_id = $1
                 GROUP BY assigned_to`,
                [batchId]
              );
              const counts = {};
              for (const row of countsRes.rows) counts[row.assigned_to] = parseInt(row.total, 10);
              assignedTo = sellers.reduce((min, s) =>
                (counts[s] || 0) < (counts[min] || 0) ? s : min, sellers[0]);
            }

            await client.query(
              `INSERT INTO lead_contact_status (
                 contact_id, estado_venta, intentos,
                 batch_id, assigned_to, organization_id
               ) VALUES ($1, 'nuevo', 0, $2, $3, $4)
               ON CONFLICT (contact_id) DO UPDATE SET
                 batch_id = $2, assigned_to = $3,
                 estado_venta = 'nuevo', updated_at = now()`,
              [leadId, batchId, assignedTo, orgId]
            );
          }
        }
        responseData = { ok: true, id: leadId, estado, isDuplicate, isClient };
      } catch (dbError) {
        console.error("[DB_ERROR]", dbError?.message);
        responseData = { ok: false, error: dbError?.message };
      } finally {
        try { await client.end(); } catch {}
      }
      return json(200, responseData);
    } catch (error) {
      console.error("meta-sheet webhook error:", error);
      return json(200, { ok: true, error: error.message });
    }
  }

  // POST /webhooks/discado — recibir contactos que contestaron desde discador (AMI / n8n)
  if (method === "POST" && path.endsWith("/webhooks/discado")) {
    const bodyRaw = safeParseBody(event);
    const body = normalizeEmptyStringsToNull(sanitizeUuidFields(bodyRaw));

    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }

    const organizationId = isValidUuid(body?.organization_id) ? body.organization_id : null;
    if (!organizationId) {
      return json(400, { ok: false, message: "organization_id requerido" });
    }

    const rawNombre = normalizeText(body?.nombre || "");
    const parts = rawNombre ? rawNombre.split(" ") : [];
    const nombre = normalizeText(parts[0] || "") || null;
    const apellido = normalizeText(parts.slice(1).join(" ") || "") || null;

    const telefono = sanitizePhone(normalizeUyNumber(body?.telefono || ""));
    const direccion = normalizeText(body?.direccion || "") || null;
    const departamento = normalizeText(body?.departamento || "") || null;
    const origenDato = "Discado auto";

    const parseDiscadoFecha = (val) => {
      if (!val) return null;
      const raw = String(val).trim();
      const [datePart, timePart] = raw.split(" ");
      if (!datePart || !timePart) return null;
      const dateBits = datePart.split("/").map((x) => x.trim()).filter(Boolean);
      const timeBits = timePart.split(":").map((x) => x.trim()).filter(Boolean);
      if (dateBits.length !== 3 || timeBits.length < 2) return null;
      const day = parseInt(dateBits[0], 10);
      const month = parseInt(dateBits[1], 10);
      const year = parseInt(dateBits[2], 10);
      const hours = parseInt(timeBits[0], 10);
      const minutes = parseInt(timeBits[1], 10);
      if (
        !Number.isFinite(day) ||
        !Number.isFinite(month) ||
        !Number.isFinite(year) ||
        !Number.isFinite(hours) ||
        !Number.isFinite(minutes)
      ) {
        return null;
      }
      if (month < 1 || month > 12 || day < 1 || day > 31) return null;
      const mm = String(month).padStart(2, "0");
      const dd = String(day).padStart(2, "0");
      const hh = String(hours).padStart(2, "0");
      const mi = String(minutes).padStart(2, "0");
      // Guardamos en formato ISO local (sin timezone) para timestamp sin tz.
      return `${year}-${mm}-${dd} ${hh}:${mi}:00`;
    };

    const fechaLead = parseDiscadoFecha(body?.fecha_llamada) || null;

    if (!telefono && !nombre) {
      return json(422, { ok: false, message: "telefono o nombre requerido" });
    }

    const client = createDbClient();
    await client.connect();
    try {
      const columnsInfo = await getLeadContactColumns(client);
      const dCols = columnsInfo.d;

      const columns = [];
      const placeholders = [];
      const values = [];
      let idx = 1;
      const pushCol = (col, val) => {
        if (!dCols.has(col)) return;
        columns.push(col);
        placeholders.push(`$${idx}`);
        values.push(val);
        idx += 1;
      };

      pushCol("nombre", nombre);
      pushCol("apellido", apellido);
      pushCol("telefono", telefono);
      pushCol("direccion", direccion);
      pushCol("departamento", departamento);
      pushCol("origen_dato", origenDato);
      pushCol("estado", "nuevo");
      pushCol("organization_id", organizationId);
      pushCol("fecha_lead", fechaLead);

      const conflictTarget = `ON CONFLICT (organization_id, telefono) WHERE origen_dato = 'Discado auto'`;
      const insertRes = await client.query(
        `
        INSERT INTO datos_para_trabajar (${columns.join(", ")})
        VALUES (${placeholders.join(", ")})
        ${conflictTarget}
        DO UPDATE SET
          nombre = COALESCE(EXCLUDED.nombre, datos_para_trabajar.nombre),
          apellido = COALESCE(EXCLUDED.apellido, datos_para_trabajar.apellido),
          direccion = COALESCE(EXCLUDED.direccion, datos_para_trabajar.direccion),
          departamento = COALESCE(EXCLUDED.departamento, datos_para_trabajar.departamento),
          estado = 'nuevo',
          fecha_lead = COALESCE(EXCLUDED.fecha_lead, datos_para_trabajar.fecha_lead),
          updated_at = now()
        RETURNING id
        `,
        values
      );

      const leadId = insertRes.rows[0]?.id || null;
      if (!leadId) {
        return json(500, { ok: false, message: "No se pudo crear lead" });
      }

      let assignedTo = null;
      const batchRes = await client.query(
        `SELECT id FROM lead_batches
         WHERE nombre = 'Discado auto'
           AND estado IN ('activo', 'asignado')
           AND organization_id = $1
         ORDER BY created_at DESC LIMIT 1`,
        [organizationId]
      );
      const batchId = batchRes.rows[0]?.id || null;

      if (batchId) {
        await client.query(
          `INSERT INTO lead_batch_contacts (batch_id, contact_id, organization_id)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING`,
          [batchId, leadId, organizationId]
        );

        const sellersRes = await client.query(
          `SELECT lbs.seller_id
           FROM lead_batch_sellers lbs
           JOIN users u ON u.id = lbs.seller_id
           WHERE lbs.batch_id = $1
             AND lower(coalesce(u.status, 'approved')) = 'approved'
           ORDER BY seller_id ASC`,
          [batchId]
        );
        const sellers = sellersRes.rows.map((r) => r.seller_id);

        if (sellers.length) {
          const countsRes = await client.query(
            `SELECT assigned_to, COUNT(*) AS total
             FROM lead_contact_status
             WHERE batch_id = $1
               AND assigned_to = ANY($2::uuid[])
               AND estado_venta IN ('no_contesta', 'seguimiento', 'nuevo')
             GROUP BY assigned_to`,
            [batchId, sellers]
          );
          const counts = {};
          for (const row of countsRes.rows) counts[row.assigned_to] = parseInt(row.total, 10);
          assignedTo = sellers.reduce((min, s) =>
            (counts[s] || 0) < (counts[min] || 0) ? s : min, sellers[0]);

          await client.query(
            `
            INSERT INTO lead_contact_status (
              contact_id,
              estado_venta,
              intentos,
              batch_id,
              assigned_to,
              organization_id
            )
            VALUES ($1, 'nuevo', 0, $2, $3, $4)
            ON CONFLICT (contact_id) DO UPDATE
            SET
              batch_id = EXCLUDED.batch_id,
              assigned_to = EXCLUDED.assigned_to,
              organization_id = COALESCE(EXCLUDED.organization_id, lead_contact_status.organization_id),
              estado_venta = 'nuevo',
              intentos = COALESCE(lead_contact_status.intentos, 0),
              updated_at = now()
            `,
            [leadId, batchId, assignedTo, organizationId]
          );
        }
      }

      return json(200, { ok: true, id: leadId, asignado_a: assignedTo });
    } catch (error) {
      return json(500, { ok: false, message: "Failed to process discado webhook", error: error.message });
    } finally {
      try { await client.end(); } catch {}
    }
  }

  if (method === "GET" && (path.endsWith("/auth/me") || path.endsWith("/me"))) {
    const authUser = getAuthUser(event);

    console.log("AUTH_ME", {
      hasAuthUser: Boolean(authUser),
      sub: authUser?.sub || null,
      email: authUser?.email || null,
      groups: authUser?.groups || [],
      hasClaims: Boolean(authUser?.claims)
    });

    if (!authUser) {
      return json(401, {
        ok: false,
        message: "Authorization header is required"
      });
    }

    if (!authUser.sub) {
      return json(401, {
        ok: false,
        message: "JWT claims with sub are required"
      });
    }

    try {
      const baseClaims = authUser?.claims || {};
      const mergedClaims = {
        ...baseClaims,
        sub: authUser?.sub || baseClaims.sub || null,
        email: authUser?.email || baseClaims.email || null,
        name: authUser?.name || baseClaims.name || null,
        given_name: authUser?.given_name || baseClaims.given_name || null,
        family_name: authUser?.family_name || baseClaims.family_name || null,
        "cognito:groups": authUser?.groups || baseClaims["cognito:groups"] || baseClaims.groups || []
      };
      const dbUser = await findCurrentUserFromClaims(mergedClaims);

      if (!dbUser) {
        return json(404, {
          ok: false,
          message: "User not found in database",
          cognitoSub: authUser.sub,
          email: authUser.email
        });
      }

      return json(200, {
        ok: true,
        user: {
          id: dbUser.id,
          cognito_sub: dbUser.cognito_sub,
          nombre: dbUser.nombre,
          apellido: dbUser.apellido,
          telefono: dbUser.telefono,
          extension: dbUser.extension || null,
          department: dbUser.department || null,
          email: dbUser.email,
          role: dbUser.role_key || authUser.fallbackRole,
          status: dbUser.status,
          permissions: [],
          groups: authUser.groups,
          last_login_at: dbUser.last_login_at
        },
        claims: authUser.claims
      });
    } catch (error) {
      console.error("AUTH_ME_DB_ERROR", {
        message: error.message,
        code: error.code || null,
        detail: error.detail || null,
        authSub: authUser?.sub || null,
        authEmail: authUser?.email || null
      });

      return json(500, {
        ok: false,
        message: "Failed to load user from database",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/auth/vendor-registration-request")) {
    const body = safeParseBody(event);

    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const validation = validateVendorRegistrationPayload(body);

    if (!validation.valid) {
      return json(422, {
        ok: false,
        message: "Validation failed",
        errors: validation.errors
      });
    }

    try {
      const result = await createVendorRegistrationRequest(validation.data);

      if (result.conflict) {
        return json(409, {
          ok: false,
          message: result.message
        });
      }

      return json(201, {
        ok: true,
        message: "Tu solicitud fue enviada. Un supervisor debe aprobarla.",
        request: result.request
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create vendor registration request",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/supervisor/vendor-requests")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const requests = await listPendingVendorRequests();

      return json(200, {
        ok: true,
        requests
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list vendor requests",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/contacts")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const items = await listContacts(organizationId);

      return json(200, {
        ok: true,
        items
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list contacts",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/contacts")) {
    const bodyRaw = safeParseBody(event);
    const body = normalizeEmptyStringsToNull(sanitizeUuidFields(bodyRaw));
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const gestId = body?.gestion_id ?? null;
      const contactPayload = body?.contact && typeof body.contact === "object"
        ? body.contact
        : body;
      const familySales = Array.isArray(body?.familySales) ? body.familySales : [];
      const cobranzaDocumento = normalizeText(body?.cobranza_documento || body?.documento_cobranza) || null;

      const buildContactFields = (payload) => {
        const nombre = normalizeText(payload?.nombre);
        const apellido = normalizeText(payload?.apellido);
        const documento = normalizeText(payload?.documento) || null;
        const fechaNacimiento = parseDate(payload?.fecha_nacimiento || payload?.fechaNacimiento || null);
        const telefono = normalizeText(payload?.telefono) || null;
        const celular = normalizeText(payload?.celular) || null;
        const correo = normalizeEmail(payload?.correo_electronico || payload?.email);
        const email = correo ? correo : null;
        const direccion = normalizeText(payload?.direccion) || null;
        const departamento = normalizeText(payload?.departamento) || null;
        const pais = normalizeText(payload?.pais) || "Uruguay";
        const status = normalizeText(payload?.estado || payload?.status || "activo") || "activo";
        return {
          nombre,
          apellido,
          documento,
          fechaNacimiento,
          telefono,
          celular,
          email,
          direccion,
          departamento,
          pais,
          status
        };
      };

      const client = createDbClient();
      await client.connect();
      try {
        let organizationId = null;
        try {
          organizationId = await resolveOrganizationId(client, dbUser, event);
        } catch (error) {
          if (error?.status) {
            return json(error.status, { ok: false, message: error.message });
          }
          throw error;
        }

        await client.query("BEGIN");
        const salesCols = await getTableColumns(client, "sales");
        leadContactColumnsCache = null;
        const leadCols = await getLeadContactColumns(client);
        const dCols = leadCols?.d || new Set();
        const hasContactIdCol = dCols.has("contact_id");
        const hasLeadEstadoCol = dCols.has("estado");
        const sellerUserCol = salesCols.has("seller_user_id")
          ? "seller_user_id"
          : (salesCols.has("seller_id") ? "seller_id" : null);
        const fechaVentaCol = salesCols.has("fecha_venta")
          ? "fecha_venta"
          : (salesCols.has("fecha") ? "fecha" : null);
        const hasDocumentoCobranza = salesCols.has("documento_cobranza");
        const hasSaleGroupId = salesCols.has("sale_group_id");
        const hasParentSaleId = salesCols.has("parent_sale_id");
        const hasGestionId = await columnExists(client, "sales", "gestion_id");
        const hasTitularContactId = await columnExists(client, "sales", "titular_contact_id");
        const hasRelation = await columnExists(client, "sales", "relation");
        const hasProductId = await columnExists(client, "sales", "product_id");
        const hasContactProductProductId = await columnExists(client, "contact_products", "product_id");

        const createManagementInContacts = false;

        const upsertContact = async (payload) => {
          const fields = buildContactFields(payload || {});
          if (!fields.nombre || !fields.apellido) {
            return { id: null, fields };
          }

          const isValidUuid = (value) =>
            typeof value === "string" &&
            /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(value);
          let existingId = isValidUuid(payload?.id) ? payload.id : null;
          if (!existingId && fields.documento) {
            const existingRes = await client.query(
              `
              SELECT id FROM contacts
              WHERE documento = $1
              ${organizationId ? "AND organization_id = $2" : ""}
              LIMIT 1
              `,
              organizationId ? [fields.documento, organizationId] : [fields.documento]
            );
            existingId = existingRes.rows[0]?.id || null;
          }

          if (existingId) {
            const updates = [];
            const values = [];
            let idx = 1;
            const push = (col, val) => {
              if (val === undefined || val === null) return;
              updates.push(`${col} = $${idx}`);
              values.push(val);
              idx += 1;
            };
            push("nombre", fields.nombre);
            push("apellido", fields.apellido);
            push("documento", fields.documento);
            push("fecha_nacimiento", fields.fechaNacimiento);
            push("telefono", fields.telefono);
            push("celular", fields.celular);
            push("email", fields.email);
            push("direccion", fields.direccion);
            push("departamento", fields.departamento);
            push("pais", fields.pais);
            push("status", fields.status);

            if (updates.length) {
              const updateValues = [...values, existingId];
              let orgClause = "";
              if (organizationId) {
                updateValues.push(organizationId);
                orgClause = `AND organization_id = $${updateValues.length}`;
              }
              await client.query(
                `
                UPDATE contacts
                SET ${updates.join(", ")}, updated_at = now()
                WHERE id = $${idx}
                ${orgClause}
                `,
                updateValues
              );
            }
            return { id: existingId, fields };
          }

          const insertRes = await client.query(
            `
            INSERT INTO contacts (
              nombre,
              apellido,
              documento,
              fecha_nacimiento,
              telefono,
              celular,
              email,
              direccion,
              departamento,
              pais,
              status,
              organization_id,
              created_at,
              updated_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now(), now())
            RETURNING id
            `,
            [
              fields.nombre,
              fields.apellido,
              fields.documento,
              fields.fechaNacimiento,
              fields.telefono,
              fields.celular,
              fields.email,
              fields.direccion,
              fields.departamento,
              fields.pais,
              fields.status,
              organizationId
            ]
          );
          return { id: insertRes.rows[0]?.id || null, fields };
        };

        const insertSale = async ({
          contactId,
          productId,
          sellerId,
          medioPago,
          sellerNameSnapshot,
          sellerOrigin,
          fechaVenta,
          documentoCobranza,
          saleGroupId,
          parentSaleId,
          gestionId,
          titularContactId,
          relation
        }) => {
          const safeContactId = isValidUuid(contactId) ? contactId : null;
          const safeProductId = isValidUuid(productId) ? productId : null;
          const safeSellerId = isValidUuid(sellerId) ? sellerId : null;
          const safeSaleGroupId = isValidUuid(saleGroupId) ? saleGroupId : null;
          const safeParentSaleId = isValidUuid(parentSaleId) ? parentSaleId : null;
          const safeGestionId = isValidUuid(gestionId) ? gestionId : null;
          const safeTitularContactId = isValidUuid(titularContactId) ? titularContactId : null;
          const cols = ["contact_id", "medio_pago", "seller_name_snapshot", "seller_origin"];
          const vals = [safeContactId, medioPago, sellerNameSnapshot, sellerOrigin];
          if (organizationId) {
            cols.push("organization_id");
            vals.push(organizationId);
          }
          if (sellerUserCol) {
            cols.push(sellerUserCol);
            vals.push(safeSellerId);
          }
          if (fechaVentaCol) {
            cols.push(fechaVentaCol);
            vals.push(fechaVenta);
          }
          if (hasDocumentoCobranza) {
            cols.push("documento_cobranza");
            vals.push(documentoCobranza || null);
          }
          if (hasProductId) {
            cols.push("product_id");
            vals.push(safeProductId);
          }
          if (hasSaleGroupId) {
            cols.push("sale_group_id");
            vals.push(safeSaleGroupId);
          }
          if (hasParentSaleId) {
            cols.push("parent_sale_id");
            vals.push(safeParentSaleId);
          }
          if (hasGestionId) {
            cols.push("gestion_id");
            vals.push(safeGestionId);
          }
          if (hasTitularContactId) {
            cols.push("titular_contact_id");
            vals.push(safeTitularContactId);
          }
          if (hasRelation) {
            cols.push("relation");
            vals.push(relation ?? null);
          }

          const placeholders = vals.map((_, idx) => `$${idx + 1}`);
          const saleInsert = await client.query(
            `
            INSERT INTO sales (${cols.join(", ")})
            VALUES (${placeholders.join(", ")})
            RETURNING id
            `,
            vals
          );
          return saleInsert.rows[0]?.id || null;
        };

        const products = Array.isArray(body?.products) ? body.products : [];
        const rawSellerId = normalizeText(body?.vendedor_id || "");
        const sellerId = isValidUuid(rawSellerId) ? rawSellerId : (dbUser?.id || null);
        const sellerNameSnapshot = normalizeText(
          products[0]?.sellerName ||
          products[0]?.seller_name ||
          [dbUser?.nombre, dbUser?.apellido].filter(Boolean).join(" ").trim() ||
          dbUser?.email ||
          ""
        ) || null;
        const sellerOrigin = sellerId ? "interno" : "externo";

        const saleGroupId = hasSaleGroupId ? crypto.randomUUID() : null;
        let mainSaleId = null;

        const principalContactRaw = normalizeText(
          body?.principal_contact_id ||
          body?.principalContactId ||
          body?.main_contact_id ||
          body?.mainContactId ||
          body?.parent_contact_id ||
          body?.parentContactId ||
          body?.contacto_principal_id ||
          body?.contactIdPrincipal ||
          body?.contacto_principal
        );
        let principalContactId = isValidUuid(principalContactRaw) ? principalContactRaw : null;
        let principalDocumentoFallback = null;
        let principalPhoneFallback = null;
        let principalBatchCache = null;

        const getFallbackBatch = async () => {
          const safeSellerId = isValidUuid(sellerId) ? sellerId : null;
          if (!safeSellerId) return null;

          const existingRes = await client.query(
            `
            SELECT id, tipo
            FROM lead_batches
            WHERE estado IN ('activo', 'asignado')
              AND (seller_id = $1 OR asignado_a = $1)
            ORDER BY created_at DESC
            LIMIT 1
            `,
            [safeSellerId]
          );
          if (existingRes.rows.length) {
            const row = existingRes.rows[0];
            return { batchId: row.id, batchTipo: row.tipo || "captacion" };
          }

          const fecha = new Date().toLocaleDateString("en-CA", { timeZone: "America/Montevideo" });
          const nombre = `Ventas manuales ${fecha}`;
          const createdBy = isValidUuid(dbUser?.id) ? dbUser.id : safeSellerId;
          const insertRes = await client.query(
            `
            INSERT INTO lead_batches (nombre, estado, created_by, tipo, seller_id, asignado_a)
            VALUES ($1, 'asignado', $2, 'captacion', $3, $3)
            RETURNING id, tipo
            `,
            [nombre, createdBy, safeSellerId]
          );
          return {
            batchId: insertRes.rows[0]?.id || null,
            batchTipo: insertRes.rows[0]?.tipo || "captacion"
          };
        };

        const resolvePrincipalBatch = async () => {
          if (!sellerId) return null;
          if (principalBatchCache) return principalBatchCache;

          let principalLeadId = null;
          if (!leadIdColumn) return null;
          if (principalContactId && hasContactIdCol) {
            const leadRes = await client.query(
              `SELECT ${leadIdColumn} AS lead_id FROM datos_para_trabajar WHERE contact_id = $1 LIMIT 1`,
              [principalContactId]
            );
            principalLeadId = leadRes.rows[0]?.lead_id || null;
          }

          let principalDocumento = null;
          if (!principalLeadId && principalContactId) {
            const principalContactRes = await client.query(
              `SELECT documento FROM contacts WHERE id = $1 LIMIT 1`,
              [principalContactId]
            );
            principalDocumento = principalContactRes.rows[0]?.documento || null;
            if (principalDocumento) {
              const leadRes = await client.query(
                `SELECT ${leadIdColumn} AS lead_id FROM datos_para_trabajar WHERE documento = $1 LIMIT 1`,
                [principalDocumento]
              );
              principalLeadId = leadRes.rows[0]?.lead_id || null;
            }
          }

          if (!principalLeadId && principalDocumentoFallback) {
            const leadRes = await client.query(
              `SELECT ${leadIdColumn} AS lead_id FROM datos_para_trabajar WHERE documento = $1 LIMIT 1`,
              [principalDocumentoFallback]
            );
            principalLeadId = leadRes.rows[0]?.lead_id || null;
            principalDocumento = principalDocumentoFallback;
          }

          if (!principalLeadId && principalPhoneFallback) {
            const leadRes = await client.query(
              `
              SELECT ${leadIdColumn} AS lead_id
              FROM datos_para_trabajar
              WHERE regexp_replace(telefono, '\\D', '', 'g') = $1
                 OR regexp_replace(celular, '\\D', '', 'g') = $1
              LIMIT 1
              `,
              [principalPhoneFallback]
            );
            principalLeadId = leadRes.rows[0]?.lead_id || null;
          }

          if (!principalLeadId) {
            const fallback = await getFallbackBatch();
            if (!fallback?.batchId || !isValidUuid(fallback.batchId)) return null;
            principalBatchCache = { principalLeadId: null, batchId: fallback.batchId, batchTipo: fallback.batchTipo, fallback: true };
            return principalBatchCache;
          }

          let batchId = null;
          let batchRes = null;
          const safeSellerId = isValidUuid(sellerId) ? sellerId : null;
          if (safeSellerId) {
            batchRes = await client.query(
              `
              SELECT batch_id
              FROM lead_contact_status
              WHERE contact_id = $1 AND assigned_to = $2
              ORDER BY updated_at DESC
              LIMIT 1
              `,
              [principalLeadId, safeSellerId]
            );
            batchId = batchRes.rows[0]?.batch_id || null;
          }
          if (!batchId) {
            batchRes = await client.query(
              `
              SELECT batch_id
              FROM lead_contact_status
              WHERE contact_id = $1
              ORDER BY updated_at DESC
              LIMIT 1
              `,
              [principalLeadId]
            );
            batchId = batchRes.rows[0]?.batch_id || null;
          }
          if (!batchId || !isValidUuid(batchId)) {
            const fallback = await getFallbackBatch();
            if (!fallback?.batchId || !isValidUuid(fallback.batchId)) return null;
            principalBatchCache = { principalLeadId, batchId: fallback.batchId, batchTipo: fallback.batchTipo, fallback: true };
            return principalBatchCache;
          }

          const batchInfoRes = await client.query(
            `SELECT tipo FROM lead_batches WHERE id = $1 LIMIT 1`,
            [batchId]
          );
          const batchTipo = batchInfoRes.rows[0]?.tipo || null;
          principalBatchCache = { principalLeadId, batchId, batchTipo };
          return principalBatchCache;
        };

        const managementLog = [];

        const main = await upsertContact(contactPayload);
        if (!main.id) {
          await client.query("ROLLBACK");
          return json(422, { ok: false, message: "Nombre y apellido son requeridos" });
        }
        if (!principalContactId && main?.id) {
          principalContactId = main.id;
          principalDocumentoFallback = main.fields?.documento || null;
          principalPhoneFallback = normalizePhoneDigits(main.fields?.telefono || main.fields?.celular || "");
        }

        const leadIdColumn = dCols.has("id") ? "id" : (dCols.has("contact_id") ? "contact_id" : null);

        const insertLeadFromFields = async ({ fields, contactId, batchTipo }) => {
          if (!leadIdColumn) return null;
          const columns = [];
          const values = [];
          const params = [];
          let p = 1;
          const pushCol = (name, value) => {
            if (!dCols.has(name)) return;
            columns.push(name);
            values.push(value ?? null);
            params.push(`$${p}`);
            p += 1;
          };

          const docValue = normalizeText(fields?.documento || "") || null;
          const telValue = normalizePhoneDigits(fields?.telefono || "");
          const celValue = normalizePhoneDigits(fields?.celular || "");

          // Try to reuse an existing lead row by documento/telefono/celular to avoid duplicates.
          if (docValue || telValue || celValue) {
            const existingLeadRes = await client.query(
              `
              SELECT ${leadIdColumn} AS lead_id
              FROM datos_para_trabajar
              WHERE ($1::text IS NOT NULL AND documento = $1)
                 OR ($2::text <> '' AND regexp_replace(telefono, '\\D', '', 'g') = $2)
                 OR ($3::text <> '' AND regexp_replace(celular, '\\D', '', 'g') = $3)
              ORDER BY updated_at DESC NULLS LAST, created_at DESC
              LIMIT 1
              `,
              [docValue, telValue, celValue]
            );
            const existingLeadId = existingLeadRes.rows[0]?.lead_id || null;
            if (existingLeadId) return existingLeadId;
          }

          pushCol("nombre", fields?.nombre || null);
          pushCol("apellido", fields?.apellido || null);
          pushCol("documento", docValue);
          pushCol("fecha_nacimiento", fields?.fechaNacimiento || null);
          pushCol("telefono", fields?.telefono || null);
          pushCol("celular", fields?.celular || null);
          pushCol("direccion", fields?.direccion || null);
          pushCol("departamento", fields?.departamento || null);
          if (dCols.has("localidad")) pushCol("localidad", null);
          if (dCols.has("correo_electronico")) pushCol("correo_electronico", fields?.email || null);
          if (dCols.has("origen_dato")) pushCol("origen_dato", fields?.origenDato || batchTipo || null);
          if (dCols.has("estado")) pushCol("estado", "nuevo");
          if (hasContactIdCol) pushCol("contact_id", contactId);

          if (!columns.length) return null;

          const insertRes = await client.query(
            `
            INSERT INTO datos_para_trabajar (${columns.join(", ")})
            VALUES (${params.join(", ")})
            RETURNING ${leadIdColumn} AS lead_id
            `,
            values
          );
          return insertRes.rows[0]?.lead_id || null;
        };

        const linkLeadSaleFromPrincipal = async ({ contactId, fields, sellerId }) => {
          const safeContactId = isValidUuid(contactId) ? contactId : null;
          const safeSellerId = isValidUuid(sellerId) ? sellerId : null;
          if (!safeContactId || !safeSellerId) {
            return { ok: false, reason: "missing_ids", contactId: safeContactId };
          }
          const principal = await resolvePrincipalBatch();
          if (!principal?.batchId) {
            return { ok: false, reason: "missing_batch", contactId: safeContactId };
          }

          let leadId = null;
          if (!leadIdColumn) {
            return { ok: false, reason: "missing_lead_column", contactId: safeContactId };
          }
          if (hasContactIdCol) {
            const leadRes = await client.query(
              `SELECT ${leadIdColumn} AS lead_id, contact_id FROM datos_para_trabajar WHERE contact_id = $1 LIMIT 1`,
              [safeContactId]
            );
            leadId = leadRes.rows[0]?.lead_id || null;
          }

          if (!leadId && fields?.documento) {
            const leadRes = await client.query(
              `
              SELECT ${leadIdColumn} AS lead_id, contact_id
              FROM datos_para_trabajar
              WHERE documento = $1
              ORDER BY updated_at DESC NULLS LAST, created_at DESC
              LIMIT 1
              `,
              [fields.documento]
            );
            leadId = leadRes.rows[0]?.lead_id || null;
          }

          if (!leadId) {
            leadId = await insertLeadFromFields({
              fields,
              contactId: safeContactId,
              batchTipo: principal.batchTipo
            });
          }

          if (!leadId) {
            return { ok: false, reason: "lead_not_created", contactId: safeContactId };
          }

          if (hasContactIdCol) {
            const docValue = normalizeText(fields?.documento || "") || null;
            const telValue = normalizePhoneDigits(fields?.telefono || "");
            const celValue = normalizePhoneDigits(fields?.celular || "");
            const nameValue = normalizeText(fields?.nombre || "") || null;
            const lastValue = normalizeText(fields?.apellido || "") || null;
            if (leadIdColumn === "id") {
            await client.query(
              `
              UPDATE datos_para_trabajar
              SET contact_id = $2, updated_at = now()
              WHERE id = $1
                AND contact_id IS NULL
                AND (
                  TRIM(LOWER(nombre)) = TRIM(LOWER($3))
                  OR TRIM(LOWER(apellido)) = TRIM(LOWER($4))
                  OR documento = $5
                )
              `,
              [leadId, safeContactId, nameValue, lastValue, docValue]
            );
            } else if (docValue || telValue || celValue) {
              await client.query(
                `
                UPDATE datos_para_trabajar
                SET contact_id = $2, updated_at = now()
                WHERE contact_id IS NULL
                  AND (
                    ($3::text IS NOT NULL AND documento = $3)
                    OR ($4::text <> '' AND regexp_replace(telefono, '\\D', '', 'g') = $4)
                    OR ($5::text <> '' AND regexp_replace(celular, '\\D', '', 'g') = $5)
                  )
                `,
                [leadId, safeContactId, docValue, telValue, celValue]
              );
            }
          }

          await client.query(
            `
            INSERT INTO lead_contact_status (
              contact_id,
              estado_venta,
              intentos,
              proxima_accion,
              batch_id,
              assigned_to,
              ola_actual,
              ultimo_intento_at
            )
            VALUES ($1, 'venta', 1, NULL, $2, $3, 1, now())
            ON CONFLICT (contact_id) DO UPDATE
            SET
              estado_venta = 'venta',
              intentos = COALESCE(lead_contact_status.intentos, 0) + 1,
              batch_id = EXCLUDED.batch_id,
              assigned_to = EXCLUDED.assigned_to,
              ola_actual = 1,
              ultimo_intento_at = now(),
              updated_at = now()
            `,
            [leadId, principal.batchId, safeSellerId]
          );

          if (!createManagementInContacts) {
            return {
              ok: true,
              created: false,
              reason: "management_disabled",
              contactId: safeContactId,
              leadId,
              batchId: principal.batchId
            };
          }

          if (hasLeadEstadoCol && leadIdColumn) {
            await client.query(
              `
              UPDATE datos_para_trabajar
              SET estado = 'trabajado', updated_at = now()
              WHERE ${leadIdColumn} = $1 AND estado <> 'bloqueado'
              `,
              [leadId]
            );
          }

          return { ok: true, created: false, reason: "already_today", contactId: safeContactId, leadId, batchId: principal.batchId };
        };

        const linkLeadSaleIfPossible = async ({ contactId, documento, sellerId }) => {
          const safeContactId = isValidUuid(contactId) ? contactId : null;
          const safeSellerId = isValidUuid(sellerId) ? sellerId : null;
          if (!safeContactId || !safeSellerId) {
            return { ok: false, reason: "missing_ids", contactId: safeContactId };
          }

          let leadId = null;
          if (!leadIdColumn) {
            return { ok: false, reason: "missing_lead_column", contactId: safeContactId };
          }
          if (hasContactIdCol) {
            const leadRes = await client.query(
              `SELECT ${leadIdColumn} AS lead_id, contact_id FROM datos_para_trabajar WHERE contact_id = $1 LIMIT 1`,
              [safeContactId]
            );
            leadId = leadRes.rows[0]?.lead_id || null;
          }

          if (!leadId && documento) {
            const leadRes = await client.query(
              `
              SELECT ${leadIdColumn} AS lead_id, contact_id
              FROM datos_para_trabajar
              WHERE documento = $1
              ORDER BY updated_at DESC NULLS LAST, created_at DESC
              LIMIT 1
              `,
              [documento]
            );
            leadId = leadRes.rows[0]?.lead_id || null;
          }

          if (!leadId) {
            return { ok: false, reason: "lead_not_found", contactId: safeContactId };
          }

          if (hasContactIdCol) {
            const docValue = normalizeText(documento || "") || null;
            const telValue = "";
            const celValue = "";
            if (leadIdColumn === "id") {
            await client.query(
              `
              UPDATE datos_para_trabajar
              SET contact_id = $2, updated_at = now()
              WHERE id = $1 AND contact_id IS NULL
              `,
              [leadId, safeContactId]
            );
            } else if (docValue) {
              await client.query(
                `
                UPDATE datos_para_trabajar
                SET contact_id = $2, updated_at = now()
                WHERE contact_id IS NULL
                  AND (
                    ($3::text IS NOT NULL AND documento = $3)
                  )
                `,
                [leadId, safeContactId, docValue, telValue, celValue]
              );
            }
          }

          const statusRes = await client.query(
            `
            SELECT batch_id, intentos
            FROM lead_contact_status
            WHERE contact_id = $1 AND assigned_to = $2
            ORDER BY updated_at DESC
            LIMIT 1
            `,
            [leadId, safeSellerId]
          );
          const batchId = statusRes.rows[0]?.batch_id || null;
          if (!batchId || !isValidUuid(batchId)) {
            return { ok: false, reason: "missing_batch", contactId: safeContactId, leadId };
          }

          if (!createManagementInContacts) {
            return {
              ok: true,
              created: false,
              reason: "management_disabled",
              contactId: safeContactId,
              leadId,
              batchId
            };
          }

          await client.query(
            `
            UPDATE lead_contact_status
            SET estado_venta = 'venta',
                intentos = COALESCE(intentos, 0) + 1,
                proxima_accion = NULL,
                ultimo_intento_at = now(),
                updated_at = now()
            WHERE contact_id = $1 AND batch_id = $2
            `,
            [leadId, batchId]
          );

          if (hasLeadEstadoCol && leadIdColumn) {
            await client.query(
              `
              UPDATE datos_para_trabajar
              SET estado = 'trabajado', updated_at = now()
              WHERE ${leadIdColumn} = $1 AND estado <> 'bloqueado'
              `,
              [leadId]
            );
          }
        };

        const createProductAndSale = async ({
          contactId,
          product,
          medioPagoOverride,
          parentSaleId,
          gestionId = null,
          titularContactId = null,
          relation = null
        }) => {
          const productName = normalizeText(
            product?.nombre_producto || product?.nombreProducto || product?.nombre
          ) || "Producto";
          const plan = normalizeText(product?.plan) || null;
          const precio = parseNumber(product?.precio) ?? 0;
          const fechaAlta = parseDate(product?.fecha_alta || product?.fechaAlta) || new Date().toISOString().slice(0, 10);
          const estadoRaw = normalizeText(product?.estado || product?.producto_estado || "alta");
          const estadoNorm = estadoRaw.toLowerCase();
          const isAlta = estadoNorm === "alta" || estadoNorm === "activo";
          const fechaBaja = isAlta ? null : (parseDate(product?.fecha_baja || product?.fechaBaja) || fechaAlta);
          const motivoBaja = isAlta ? null : "otro";
          const motivoBajaDetalle = isAlta ? null : (estadoRaw || "baja");
          const medioPago = normalizeText(product?.medio_pago || product?.medioPago || medioPagoOverride) || null;
          const fechaVenta = fechaAlta;

          let productId = null;
          if (productName) {
            const productRes = await client.query(
              `
              SELECT id FROM products
              WHERE lower(nombre) = lower($1)
              ${organizationId ? "AND organization_id = $2" : ""}
              LIMIT 1
              `,
              organizationId ? [productName, organizationId] : [productName]
            );
            productId = productRes.rows[0]?.id || null;
            if (!productId) {
              const productInsert = await client.query(
                `
                INSERT INTO products (nombre, categoria, precio, activo, organization_id)
                VALUES ($1, 'General', $2, true, $3)
                RETURNING id
                `,
                [productName, precio || 0, organizationId]
              );
              productId = productInsert.rows[0]?.id || null;
            }
          }

          const saleId = await insertSale({
            contactId,
            productId,
            sellerId,
            medioPago,
            sellerNameSnapshot,
            sellerOrigin,
            fechaVenta,
            documentoCobranza: cobranzaDocumento,
            saleGroupId,
            parentSaleId,
            gestionId,
            titularContactId,
            relation
          });

          if (saleId && productId) {
            await client.query(
              `
              INSERT INTO sale_items (
                sale_id,
                product_id,
                product_name_snapshot,
                price
              )
              VALUES ($1,$2,$3,$4)
              `,
              [saleId, productId, productName || "Producto", precio || 0]
            );
          }

          const safeContactId = isValidUuid(contactId) ? contactId : null;
          const safeSellerId = isValidUuid(sellerId) ? sellerId : null;
          const safeSaleId = isValidUuid(saleId) ? saleId : null;
          let resolvedProductId = null;
          if (hasContactProductProductId && productName) {
            const prodRes = await client.query(
              `
              SELECT id FROM products
              WHERE TRIM(LOWER(nombre)) = TRIM(LOWER($1))
              ${organizationId ? "AND organization_id = $2" : ""}
              LIMIT 1
              `,
              organizationId ? [productName, organizationId] : [productName]
            );
            resolvedProductId = prodRes.rows[0]?.id ?? null;
          }

          const contactProductCols = [
            "contact_id",
            "nombre_producto",
            "plan",
            "precio",
            "fecha_alta",
            "cuotas_pagas",
            "carencia_cuotas",
            "estado",
            "motivo_baja",
            "motivo_baja_detalle",
            "fecha_baja",
            "seller_user_id",
            "seller_name_snapshot",
            "seller_origin",
            "sale_id"
          ];
          const contactProductVals = [
            safeContactId,
            productName,
            plan,
            precio || 0,
            fechaAlta,
            0,
            0,
            isAlta ? "alta" : "baja",
            motivoBaja,
            motivoBajaDetalle,
            fechaBaja,
            safeSellerId,
            sellerNameSnapshot,
            sellerOrigin,
            safeSaleId
          ];
          if (organizationId) {
            contactProductCols.push("organization_id");
            contactProductVals.push(organizationId);
          }
          if (hasContactProductProductId) {
            contactProductCols.push("product_id");
            contactProductVals.push(resolvedProductId);
          }
          const contactProductPlaceholders = contactProductVals.map((_, idx) => `$${idx + 1}`);
          await client.query(
            `
            INSERT INTO contact_products (${contactProductCols.join(", ")})
            VALUES (${contactProductPlaceholders.join(", ")})
            `,
            contactProductVals
          );

          return saleId;
        };

        for (const product of products) {
          const saleId = await createProductAndSale({
            contactId: main.id,
            product,
            medioPagoOverride: body?.medioPago || null,
            parentSaleId: mainSaleId || null,
            gestionId: gestId,
            titularContactId: main.id,
            relation: "titular"
          });
          if (!mainSaleId && saleId) mainSaleId = saleId;
        }

        const hasAnyContactSignal = (contact = {}) => {
          const nombre = normalizeText(contact?.nombre);
          const apellido = normalizeText(contact?.apellido);
          const documento = normalizeText(contact?.documento);
          const telefono = normalizeText(contact?.telefono);
          const celular = normalizeText(contact?.celular);
          return Boolean(nombre || apellido || documento || telefono || celular);
        };

        for (const familySale of familySales) {
          if (!familySale?.contact || !hasAnyContactSignal(familySale.contact)) {
            continue;
          }
          const famContact = await upsertContact(familySale?.contact || {});
          if (!famContact.id) continue;
          const famProducts = Array.isArray(familySale?.products) ? familySale.products : [];
          for (const product of famProducts) {
            await createProductAndSale({
              contactId: famContact.id,
              product,
              medioPagoOverride: familySale?.medioPago || null,
              parentSaleId: mainSaleId || null,
              gestionId: gestId,
              titularContactId: famContact.id,
              relation: familySale?.relation ?? "familiar"
            });
          }
          await client.query(
            `
            INSERT INTO contact_relations (
              contact_id_a,
              contact_id_b,
              relation,
              source
            )
            VALUES ($1, $2, $3, 'venta')
            ON CONFLICT (contact_id_a, contact_id_b)
            DO UPDATE SET
              relation = EXCLUDED.relation,
              updated_at = NOW()
            `,
            [main.id, famContact.id, familySale?.relation || "familiar"]
          );
          const familyMgmt = await linkLeadSaleFromPrincipal({
            contactId: famContact.id,
            fields: famContact.fields,
            sellerId
          });
          if (familyMgmt) managementLog.push({ scope: "family", ...familyMgmt });
        }

        const linkedToPrincipal = await linkLeadSaleFromPrincipal({
          contactId: main.id,
          fields: main.fields,
          sellerId
        });
        if (linkedToPrincipal) managementLog.push({ scope: "main", ...linkedToPrincipal });
        if (!linkedToPrincipal?.ok) {
          const fallbackMgmt = await linkLeadSaleIfPossible({
            contactId: main.id,
            documento: main.fields?.documento || null,
            sellerId
          });
          if (fallbackMgmt) managementLog.push({ scope: "main_fallback", ...fallbackMgmt });
        }

        await client.query("COMMIT");

        return json(200, {
          ok: true,
          success: true,
          data: { id: main.id, management: managementLog }
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create contact",
        error: error.message
      });
    }
  }

  if (method === "PUT" && (contactDetailMatch || clientDetailMatch)) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const contactId = (contactDetailMatch || clientDetailMatch)[1];
      const contactPayload = body?.contact && typeof body.contact === "object"
        ? body.contact
        : body;

      const hasField = (key) => Object.prototype.hasOwnProperty.call(contactPayload || {}, key);
      const getField = (key, normalizeFn) => (hasField(key) ? normalizeFn(contactPayload?.[key]) : undefined);

      const nombre = getField("nombre", normalizeText);
      const apellido = getField("apellido", normalizeText);
      const documento = getField("documento", normalizeText);
      const telefono = getField("telefono", (v) => normalizeText(v) || null);
      const celular = getField("celular", (v) => normalizeText(v) || null);
      const direccion = getField("direccion", (v) => normalizeText(v) || null);
      const departamento = getField("departamento", (v) => normalizeText(v) || null);
      const pais = getField("pais", (v) => normalizeText(v) || null);
      const status = getField("estado", (v) => normalizeText(v) || null) ??
        getField("status", (v) => normalizeText(v) || null);

      let email = undefined;
      if (hasField("correo_electronico") || hasField("email")) {
        const correo = normalizeEmail(contactPayload?.correo_electronico || contactPayload?.email);
        email = correo || null;
      }

      let fechaNacimiento = undefined;
      if (hasField("fecha_nacimiento") || hasField("fechaNacimiento")) {
        fechaNacimiento = parseDate(contactPayload?.fecha_nacimiento || contactPayload?.fechaNacimiento || null);
      }

      const updates = [];
      const values = [];
      let idx = 1;
      const push = (col, val) => {
        if (val === undefined) return;
        updates.push(`${col} = $${idx}`);
        values.push(val);
        idx += 1;
      };

      push("nombre", nombre);
      push("apellido", apellido);
      push("documento", documento);
      push("fecha_nacimiento", fechaNacimiento);
      push("telefono", telefono);
      push("celular", celular);
      push("email", email);
      push("direccion", direccion);
      push("departamento", departamento);
      push("pais", pais);
      push("status", status);

      if (!updates.length) {
        return json(400, { ok: false, message: "No fields to update" });
      }

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");

        const contactRes = await client.query(
          `
          UPDATE contacts
          SET ${updates.join(", ")}, updated_at = now()
          WHERE id = $${idx}
          RETURNING *
          `,
          [...values, contactId]
        );

        const updated = contactRes.rows[0];
        if (!updated) {
          await client.query("ROLLBACK");
          return json(404, { ok: false, message: "Contact not found" });
        }

        const leadCols = await getLeadContactColumns(client);
        const dCols = leadCols?.d || new Set();
        const dUpdates = [];
        const dValues = [];
        let dIdx = 1;
        const dPush = (col, val) => {
          if (val === undefined) return;
          if (!dCols.has(col)) return;
          dUpdates.push(`${col} = $${dIdx}`);
          dValues.push(val);
          dIdx += 1;
        };

        dPush("nombre", nombre);
        dPush("apellido", apellido);
        dPush("documento", documento);
        dPush("fecha_nacimiento", fechaNacimiento);
        dPush("telefono", telefono);
        dPush("celular", celular);
        dPush("direccion", direccion);
        dPush("departamento", departamento);
        dPush("correo_electronico", email);
        dPush("estado", status);

        if (dUpdates.length) {
          let dWhere = "";
          if (dCols.has("contact_id")) {
            dWhere = `contact_id = $${dIdx}`;
            dValues.push(contactId);
            dIdx += 1;
          } else if (documento) {
            dWhere = `documento = $${dIdx}`;
            dValues.push(documento);
            dIdx += 1;
          }

          if (dWhere) {
            await client.query(
              `
              UPDATE datos_para_trabajar
              SET ${dUpdates.join(", ")}, updated_at = now()
              WHERE ${dWhere}
              `,
              dValues
            );
          }
        }

        await client.query("COMMIT");
        return json(200, { ok: true, item: updated });
      } catch (err) {
        await client.query("ROLLBACK");
        return json(500, { ok: false, message: "Failed to update contact", error: err.message });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to update contact", error: error.message });
    }
  }

  if (method === "GET" && (path.endsWith("/users/me") || path.endsWith("/profile"))) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      const client = createDbClient();
      await client.connect();
      try {
        await ensureUserProfileColumns(client);
        const result = await client.query(
          "SELECT id, nombre, apellido, email, telefono, extension, department FROM users WHERE id = $1",
          [dbUser.id]
        );
        const row = result.rows[0];
        if (!row) {
          return json(404, { ok: false, message: "User not found" });
        }
        return json(200, {
          ok: true,
          user: {
            id: row.id,
            fullName: `${row.nombre} ${row.apellido}`.trim(),
            email: row.email,
            phone: row.telefono,
            extension: row.extension || null,
            department: row.department || null
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to load profile", error: error.message });
    }
  }

  if (method === "POST" && (path.endsWith("/users/me") || path.endsWith("/profile"))) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }

    const errors = {};
    const fullName = normalizeText(body.fullName || body.name || "");
    const emailRaw = normalizeText(body.email || "");
    const email = normalizeEmail(emailRaw) || emailRaw;
    const phoneRaw = normalizeText(body.phone || body.telefono || "");
    const phoneDigits = phoneRaw ? phoneRaw.replace(/\D/g, "") : "";
    const extension = normalizeText(body.extension || "");
    const department = normalizeText(body.department || body.departamento || "");

    if (!fullName) {
      errors.fullName = "fullName requerido";
    }
    if (!emailRaw) {
      errors.email = "email requerido";
    }
    if (phoneRaw && (phoneDigits.length < 8 || phoneDigits.length > 15)) {
      errors.phone = "telefono invalido";
    }
    if (!department) {
      errors.department = "department requerido";
    }

    if (Object.keys(errors).length > 0) {
      return json(422, { ok: false, message: "Validation failed", errors });
    }

    try {
      const { authUser, dbUser: existingUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbUser = existingUser;
      if (!dbUser) {
        const baseClaims = authUser?.claims || {};
        const mergedClaims = {
          ...baseClaims,
          sub: authUser?.sub || baseClaims.sub || null,
          email: authUser?.email || baseClaims.email || null,
          name: authUser?.name || baseClaims.name || null,
          given_name: authUser?.given_name || baseClaims.given_name || null,
          family_name: authUser?.family_name || baseClaims.family_name || null,
          "cognito:groups": authUser?.groups || baseClaims["cognito:groups"] || baseClaims.groups || []
        };
        dbUser = await findCurrentUserFromClaims(mergedClaims);
      }

      if (!dbUser) {
        return json(404, { ok: false, message: "User not found" });
      }

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      const client = createDbClient();
      await client.connect();
      try {
        await ensureUserProfileColumns(client);
        const duplicate = await client.query(
          "SELECT id FROM users WHERE email = $1 AND id <> $2 LIMIT 1",
          [email, dbUser.id]
        );
        if (duplicate.rowCount > 0) {
          return json(409, { ok: false, message: "Email ya en uso" });
        }
        const nameParts = splitFullName(fullName);
        const updateRes = await client.query(
          "UPDATE users SET nombre = $1, apellido = $2, email = $3, telefono = $4, extension = $5, department = $6, updated_at = NOW() WHERE id = $7 RETURNING id, nombre, apellido, email, telefono, extension, department",
          [nameParts.nombre || "", nameParts.apellido || "", email, phoneDigits || null, extension || null, department || null, dbUser.id]
        );
        const row = updateRes.rows[0];
        if (!row) {
          return json(404, { ok: false, message: "User not found" });
        }
        return json(200, {
          ok: true,
          user: {
            id: row.id,
            fullName: `${row.nombre} ${row.apellido}`.trim(),
            email: row.email,
            phone: row.telefono,
            extension: row.extension || null,
            department: row.department || null
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to create profile", error: error.message });
    }
  }
  if (method === "PUT" && (path.endsWith("/users/me") || path.endsWith("/profile"))) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }

    const errors = {};
    const fullName = normalizeText(body.fullName || body.name || "");
    const emailRaw = normalizeText(body.email || "");
    const email = normalizeEmail(emailRaw) || emailRaw;
    const phoneRaw = normalizeText(body.phone || body.telefono || "");
    const phoneDigits = phoneRaw ? phoneRaw.replace(/\D/g, "") : "";
    const extension = normalizeText(body.extension || "");
    const department = normalizeText(body.department || body.departamento || "");

    if (!fullName) {
      errors.fullName = "fullName requerido";
    }
    if (!emailRaw) {
      errors.email = "email requerido";
    }
    if (phoneRaw && (phoneDigits.length < 8 || phoneDigits.length > 15)) {
      errors.phone = "telefono invalido";
    }
    if (!department) {
      errors.department = "department requerido";
    }

    if (Object.keys(errors).length > 0) {
      return json(422, { ok: false, message: "Validation failed", errors });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      const client = createDbClient();
      await client.connect();
      try {
        await ensureUserProfileColumns(client);
        const duplicate = await client.query(
          "SELECT id FROM users WHERE email = $1 AND id <> $2 LIMIT 1",
          [email, dbUser.id]
        );
        if (duplicate.rowCount > 0) {
          return json(409, { ok: false, message: "Email ya en uso" });
        }
        const nameParts = splitFullName(fullName);
        const updateRes = await client.query(
          "UPDATE users SET nombre = $1, apellido = $2, email = $3, telefono = $4, extension = $5, department = $6, updated_at = NOW() WHERE id = $7 RETURNING id, nombre, apellido, email, telefono, extension, department",
          [nameParts.nombre || "", nameParts.apellido || "", email, phoneDigits || null, extension || null, department || null, dbUser.id]
        );
        const row = updateRes.rows[0];
        if (!row) {
          return json(404, { ok: false, message: "User not found" });
        }
        return json(200, {
          ok: true,
          user: {
            id: row.id,
            fullName: `${row.nombre} ${row.apellido}`.trim(),
            email: row.email,
            phone: row.telefono,
            extension: row.extension || null,
            department: row.department || null
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to update profile", error: error.message });
    }
  }

  if (method === "GET" && path.endsWith("/clients")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const limit = Math.min(200, Math.max(1, Number(getQueryParam(event, "limit") || 50)));
      const search = normalizeText(getQueryParam(event, "search") || "");

      const result = await listClientsDirectory({ page, limit, search, organizationId });

      return json(200, {
        ok: true,
        ...result
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list clients",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/clients/metrics")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const metrics = await getClientMetrics(organizationId);

      return json(200, {
        ok: true,
        metrics
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load client metrics",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/sales/mine")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const sellerId = dbUser?.id || null;
      const client = createDbClient();
      await client.connect();
      try {
        const values = [sellerId];
        const orgClause = organizationId ? "AND s.organization_id = $2" : "";
        if (organizationId) values.push(organizationId);
        const salesCols = await getTableColumns(client, "sales");
        const extraSelect = [];
        if (salesCols.has("sale_group_id")) extraSelect.push("s.sale_group_id");
        if (salesCols.has("parent_sale_id")) extraSelect.push("s.parent_sale_id");
        if (salesCols.has("documento_cobranza")) extraSelect.push("s.documento_cobranza");
        const extraSelectSql = extraSelect.length ? `, ${extraSelect.join(", ")}` : "";

        const result = await client.query(
          `
          SELECT
            s.id AS sale_id,
            s.medio_pago,
            s.fecha_venta,
            s.created_at AS sale_created_at,
            s.seller_name_snapshot,
            cp.nombre_producto,
            cp.plan,
            cp.precio,
            cp.estado AS producto_estado,
            c.nombre AS contact_nombre,
            c.apellido AS contact_apellido,
            c.telefono,
            c.departamento,
            c.documento,
            c.email,
            c.direccion
            ${extraSelectSql}
          FROM sales s
          JOIN contact_products cp ON cp.sale_id = s.id
            ${organizationId ? "AND cp.organization_id = $2" : ""}
          JOIN contacts c ON c.id = s.contact_id
            ${organizationId ? "AND c.organization_id = $2" : ""}
          WHERE s.seller_user_id = $1
          ${orgClause}
          ORDER BY s.fecha_venta DESC
          `,
          values
        );

        const toItem = (row) => {
          const fechaVentaRaw = row.fecha_venta || null;
          const createdAtRaw = row.sale_created_at || null;
          let fechaVenta = fechaVentaRaw;
          // If fecha_venta is date-only (midnight), fall back to created_at to preserve time.
          if (fechaVentaRaw && createdAtRaw) {
            const fv = new Date(fechaVentaRaw);
            if (!Number.isNaN(fv.getTime())) {
              const hasTime = fv.getUTCHours() !== 0 || fv.getUTCMinutes() !== 0 || fv.getUTCSeconds() !== 0;
              if (!hasTime) fechaVenta = createdAtRaw;
            }
          }
          return ({
          id: row.sale_id,
          sale_id: row.sale_id,
          medio_pago: row.medio_pago || null,
          fecha_venta: fechaVenta,
          seller_name_snapshot: row.seller_name_snapshot || null,
          nombre_producto: row.nombre_producto || null,
          plan: row.plan || null,
          precio: row.precio !== null && row.precio !== undefined
            ? Number(row.precio)
            : null,
          producto_estado: row.producto_estado || null,
          contact_nombre: row.contact_nombre || null,
          contact_apellido: row.contact_apellido || null,
          telefono: row.telefono || null,
          ubicacion: row.departamento || row.direccion || null,
          documento: row.documento || null,
          email: row.email || null,
          direccion: row.direccion || null,
          sale_group_id: row.sale_group_id || null,
          parent_sale_id: row.parent_sale_id || null,
          documento_cobranza: row.documento_cobranza || null
          });
        };

        const rawItems = result.rows.map((row) => toItem(row));
        const hasGrouping = salesCols.has("sale_group_id") || salesCols.has("parent_sale_id");
        let items = rawItems;

        if (hasGrouping) {
          const groups = new Map();
          for (const item of rawItems) {
            const groupKey = item.sale_group_id || item.parent_sale_id || item.sale_id;
            if (!groups.has(groupKey)) groups.set(groupKey, []);
            groups.get(groupKey).push(item);
          }

          items = [];
          for (const [groupKey, groupItems] of groups.entries()) {
            let primary = groupItems.find((i) => !i.parent_sale_id) || groupItems[0];
            if (primary.sale_id !== groupKey) {
              const direct = groupItems.find((i) => i.sale_id === groupKey);
              if (direct) primary = direct;
            }
            const related = groupItems.filter((i) => i.sale_id !== primary.sale_id);
            items.push({
              ...primary,
              related_sales: related
            });
          }
        }

        return json(200, {
          ok: true,
          success: true,
          items,
          data: { items }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list sales",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/clients/my-sales")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const sellerId = dbUser?.id || null;
      const client = createDbClient();
      await client.connect();

      try {
        const values = [sellerId];
        const orgClause = organizationId ? "AND s.organization_id = $2" : "";
        if (organizationId) values.push(organizationId);
        const result = await client.query(
          `
          SELECT
            s.contact_id            AS id,
            COALESCE(c.nombre, d.nombre)            AS nombre,
            COALESCE(c.apellido, d.apellido)        AS apellido,
            COALESCE(c.telefono, d.telefono)        AS telefono,
            COALESCE(c.celular, d.celular)          AS celular,
            COALESCE(c.departamento, d.departamento) AS departamento,
            d.localidad                              AS localidad,
            d.origen_dato                            AS fuente,
            COALESCE(c.email, d.email) AS email,
            COALESCE(c.direccion, d.direccion)       AS direccion,
            s.fecha_venta,
            s.medio_pago,
            s.id                   AS sale_id,
            lb.nombre              AS nombre_lote,
            lb.id                  AS batch_id,
            cp.nombre_producto,
            cp.plan,
            cp.precio,
            cp.estado              AS producto_estado,
            lmh.nota               AS nota_venta

          FROM sales s
          LEFT JOIN contacts c           ON c.id = s.contact_id
            ${organizationId ? "AND c.organization_id = $2" : ""}
          LEFT JOIN datos_para_trabajar d ON d.id = s.contact_id
            ${organizationId ? "AND d.organization_id = $2" : ""}
          LEFT JOIN contact_products cp   ON cp.sale_id = s.id
            ${organizationId ? "AND cp.organization_id = $2" : ""}
          LEFT JOIN lead_batches lb       ON lb.id = (
            SELECT lcs2.batch_id 
            FROM lead_contact_status lcs2 
            WHERE lcs2.contact_id = s.contact_id 
              ${organizationId ? "AND lcs2.organization_id = $2" : ""}
            ORDER BY lcs2.updated_at DESC 
            LIMIT 1
          )
          LEFT JOIN lead_management_history lmh ON (
            lmh.contact_id = s.contact_id
            AND lmh.resultado = 'venta'
            AND lmh.user_id = s.seller_user_id
          )
          WHERE s.seller_user_id = $1
          ${orgClause}
          ORDER BY s.fecha_venta DESC
          `,
          values
        );

        return json(200, {
          ok: true,
          success: true,
          data: result.rows
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load my sales",
        error: error.message
      });
    }
  }

  if (method === "GET" && clientDocumentMatch) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const clientId = clientDocumentMatch[1];
      const data = await getClientDocumentData(clientId, organizationId);

      if (!data) {
        return json(404, {
          ok: false,
          message: "Client not found"
        });
      }

      const pdfBuffer = generateCertificatePdf(data);
      const filename = buildClientDocumentFilename(data.client);

      return {
        statusCode: 200,
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="${filename}"`,
          ...CORS_HEADERS
        },
        body: pdfBuffer.toString("base64"),
        isBase64Encoded: true
      };
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to generate client document",
        error: error.message
      });
    }
  }

  if (method === "POST" && clientDocumentSentMatch) {
    const body = safeParseBody(event) || {};

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const clientId = clientDocumentSentMatch[1];
      const eventRow = await recordClientDocumentEvent({
        clientId,
        userId: dbUser?.id || null,
        event: "sent_document",
        origin: event?.headers?.origin || event?.headers?.Origin || null,
        template: event?.queryStringParameters?.template || null,
        lang: event?.queryStringParameters?.lang || null,
        channel: body.channel || null,
        note: body.note || null
      });

      return json(201, { ok: true, item: eventRow });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to record client document event",
        error: error.message
      });
    }
  }

  if (method === "POST" && manualTicketsPath) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const validation = validateManualTicketPayload(body);
    if (!validation.valid) {
      return json(422, {
        ok: false,
        message: "Validation failed",
        errors: validation.errors
      });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const item = await createManualTicket(validation.data, organizationId);
      return json(201, { ok: true, item });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create manual ticket",
        error: error.message
      });
    }
  }

  if (method === "GET" && manualTicketsPath) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const clienteId = event?.queryStringParameters?.clienteId || event?.queryStringParameters?.cliente_id;
      const items = await listManualTickets({
        clienteId: normalizeText(clienteId) || null,
        organizationId
      });
      return json(200, { ok: true, items });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list manual tickets",
        error: error.message
      });
    }
  }

  if (method === "PUT" && manualTicketMatch) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const validation = normalizeManualTicketPatch(body);
    if (!validation.valid) {
      return json(422, {
        ok: false,
        message: "Validation failed",
        errors: validation.errors
      });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const item = await updateManualTicket(manualTicketMatch[1], validation.data, organizationId);
      if (!item) {
        return json(404, {
          ok: false,
          message: "Manual ticket not found"
        });
      }

      return json(200, { ok: true, item });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to update manual ticket",
        error: error.message
      });
    }
  }

  if (method === "POST" && manualTicketNotesMatch) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const texto = normalizeText(body?.texto || body?.text);
    if (!texto) {
      return json(422, {
        ok: false,
        message: "Validation failed",
        errors: { texto: ["texto obligatorio"] }
      });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const autor = [dbUser?.nombre, dbUser?.apellido].filter(Boolean).join(" ").trim() || dbUser?.email || "Usuario";
      const note = await addManualTicketNote(manualTicketNotesMatch[1], {
        texto,
        autor
      }, organizationId);

      return json(201, { ok: true, item: note });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to add ticket note",
        error: error.message
      });
    }
  }

  if (method === "POST" && manualTicketCloseMatch) {
    const body = safeParseBody(event) || {};

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const result = await closeManualTicket({
        ticketId: manualTicketCloseMatch[1],
        outcome: normalizeText(body.outcome || ""),
        note: normalizeText(body.note || ""),
        actorName: body.actorName || body.actor_name || dbUser?.nombre || "",
        organizationId
      });

      if (result?.notFound) {
        return json(404, { ok: false, message: "Manual ticket not found" });
      }

      if (result?.error) {
        return json(422, { ok: false, message: result.error });
      }

      const item = await getManualTicketById(manualTicketCloseMatch[1], organizationId);
      return json(200, { ok: true, item });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to close manual ticket",
        error: error.message
      });
    }
  }

  if (method === "GET" && manualTicketMatch) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const item = await getManualTicketById(manualTicketMatch[1], organizationId);
      if (!item) {
        return json(404, {
          ok: false,
          message: "Manual ticket not found"
        });
      }

      return json(200, { ok: true, item });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load manual ticket",
        error: error.message
      });
    }
  }

  if (method === "GET" && clientDetailMatch && !path.endsWith("/clients/metrics")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const item = await getClientDetailData(clientDetailMatch[1], organizationId);

      if (!item) {
        return json(404, {
          ok: false,
          message: "Client not found"
        });
      }

      return json(200, { ok: true, item });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load client detail",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/products")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const items = await listProducts(organizationId);
      return json(200, { ok: true, items });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list products",
        error: error.message
      });
    }
  }

  if (
    method === "GET" &&
    path.endsWith("/leads") &&
    !path.endsWith("/campanas/leads") &&
    !path.endsWith("/api/campanas/leads")
  ) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const pageSize = Math.max(1, Number(getQueryParam(event, "pageSize") || 50));
      const search = normalizeText(getQueryParam(event, "search") || "");
      const offset = (page - 1) * pageSize;

      const client = createDbClient();
      await client.connect();
      try {
        const whereParts = [];
        const values = [];
        let idx = 1;

        if (search) {
          whereParts.push(`(
            d.nombre ILIKE $${idx}
            OR d.apellido ILIKE $${idx}
            OR d.documento ILIKE $${idx}
            OR d.telefono ILIKE $${idx}
            OR d.celular ILIKE $${idx}
            OR d.departamento ILIKE $${idx}
            OR d.localidad ILIKE $${idx}
          )`);
          values.push(`%${search}%`);
          idx += 1;
        }

        if (dbUser?.role_key === "vendedor") {
          whereParts.push(`lcs.assigned_to = $${idx}`);
          values.push(dbUser?.id);
          idx += 1;
        }

        if (organizationId) {
          whereParts.push(`d.organization_id = $${idx}`);
          values.push(organizationId);
          idx += 1;
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";
        const paramMatches = whereClause.match(/\$(\d+)/g) || [];
        const maxParam = paramMatches.reduce((max, token) => Math.max(max, Number(token.slice(1))), 0);
        if (values.length < maxParam) {
          console.warn("[leads] Param mismatch", {
            whereClause,
            valuesLength: values.length,
            maxParam
          });
          while (values.length < maxParam) {
            values.push(dbUser?.id ?? null);
          }
        }

        const countResult = await client.query(
          `
          SELECT COUNT(*)::int AS total
          FROM datos_para_trabajar d
          LEFT JOIN lead_contact_status lcs ON lcs.contact_id = d.id
          ${whereClause}
          `,
          values
        );

        let total = countResult.rows[0]?.total || 0;
        let totalPages = Math.max(1, Math.ceil(total / pageSize));

        const itemsResult = await client.query(
          `
          SELECT
            d.id,
            d.nombre,
            d.apellido,
            d.documento,
            d.telefono,
            d.celular,
            d.departamento,
            d.direccion,
            d.localidad,
            d.origen_dato,
            d.estado,
            d.motivo_bloqueo,
            d.created_at,
            d.email,
            d.fecha_nacimiento,
            lcs.estado_venta,
            lcs.intentos,
            lcs.proxima_accion,
            lcs.batch_id,
            lcs.assigned_to,
            lb.nombre AS batch_nombre,
            u.nombre AS assigned_nombre,
            u.apellido AS assigned_apellido,
            last_m.fecha_gestion AS last_gestion_at,
            last_m.resultado AS last_resultado,
            last_m.nota AS last_nota,
            last_m.user_nombre AS last_user_nombre,
            last_m.user_apellido AS last_user_apellido
          FROM datos_para_trabajar d
          LEFT JOIN lead_contact_status lcs ON lcs.contact_id = d.id
          LEFT JOIN lead_batches lb ON lb.id = lcs.batch_id
          LEFT JOIN users u ON u.id = lcs.assigned_to
          LEFT JOIN LATERAL (
            SELECT
              lm.fecha_gestion,
              lm.resultado,
              lm.nota,
              u2.nombre AS user_nombre,
              u2.apellido AS user_apellido
            FROM lead_management_history lm
            LEFT JOIN users u2 ON u2.id = lm.user_id
            WHERE lm.contact_id = d.id
            ORDER BY lm.fecha_gestion DESC
            LIMIT 1
          ) last_m ON true
          ${whereClause}
          ORDER BY d.created_at DESC
          LIMIT $${idx} OFFSET $${idx + 1}
          `,
          [...values, pageSize, offset]
        );

        const items = itemsResult.rows.map((row) => {
          const assignedTo = [row.assigned_nombre, row.assigned_apellido].filter(Boolean).join(" ").trim();
          const lastBy = [row.last_user_nombre, row.last_user_apellido].filter(Boolean).join(" ").trim();
          return {
            id: row.id,
            nombre: row.nombre,
            apellido: row.apellido,
            documento: row.documento,
            telefono: row.telefono,
            celular: row.celular,
            departamento: row.departamento,
            direccion: row.direccion,
            localidad: row.localidad,
            origen_dato: row.origen_dato,
            estado: row.estado || "nuevo",
            motivo_bloqueo: row.motivo_bloqueo || null,
            created_at: row.created_at,
            email: row.email || null,
            fecha_nacimiento: row.fecha_nacimiento || null,
            estado_venta: row.estado_venta || "nuevo",
            intentos: Number(row.intentos || 0),
            proxima_accion: row.proxima_accion,
            batch_id: row.batch_id,
            batch_nombre: row.batch_nombre,
            assigned_to: row.assigned_to,
            assigned_to_name: assignedTo,
            last_gestion_at: row.last_gestion_at,
            last_resultado: row.last_resultado,
            last_nota: row.last_nota,
            last_by: lastBy
          };
        });

        return json(200, {
          ok: true,
          success: true,
          items,
          page,
          pageSize,
          total,
          totalPages,
          data: { items, page, pageSize, total, totalPages },
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list leads",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/recupero/contactos")) {
    const requestId = getRequestId(event);
    const startedAt = Date.now();
    let dbUser = null;
    try {
      const authContext = await getCurrentDbUserFromEvent(event);
      const authUser = authContext.authUser;
      dbUser = authContext.dbUser;

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const productoRaw = getQueryParam(event, "producto");
      const searchRaw = getQueryParam(event, "search");
      const sortRaw = getQueryParam(event, "sort");
      const dirRaw = getQueryParam(event, "dir");
      const departamentoRaw = getQueryParam(event, "departamento");
      const motivoBajaRaw = getQueryParam(event, "motivo_baja");
      const tabRaw = getQueryParam(event, "tab");
      const producto = productoRaw ? productoRaw.trim() : "";
      const departamento = departamentoRaw ? departamentoRaw.trim() : "";
      const search = searchRaw ? searchRaw.trim() : "";
      const sort = sortRaw ? sortRaw.trim() : "";
      const dir = dirRaw === "desc" ? "DESC" : "ASC";
      const motivoBaja = motivoBajaRaw ? motivoBajaRaw.trim() : "";
      const tab = tabRaw ? tabRaw.trim().toLowerCase() : "";

      const sortableColumns = {
        edad: "DATE_PART('year', AGE(c.fecha_nacimiento))",
        telefono: "c.telefono",
        departamento: "c.departamento",
        nombre_producto: "cp.nombre_producto",
        precio: "cp.precio",
        fecha_baja: "cp.fecha_baja"
      };

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const limit = Math.min(200, Math.max(1, Number(getQueryParam(event, "limit") || 50)));
      const offset = (page - 1) * limit;
      const client = createDbClient();
      await client.connect();
      try {
        const { data, emptyCondition } = await fetchRecuperoContactos({
          client,
          producto,
          departamento,
          search,
          motivoBaja,
          tab,
          sortField: sort,
          sortDir: dir,
          page,
          limit,
          filters: null,
          organizationId
        });
        return safeResponse({
          data,
          emptyCondition,
          meta: { source: "recupero-contactos", request_id: requestId, empty_payload: false }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        status: "error",
        message: "Failed to list recupero contacts",
        error: error.message,
        meta: { request_id: requestId }
      });
    } finally {
      console.log("[recupero/contactos]", {
        request_id: requestId,
        user_id: dbUser?.id || null,
        duration_ms: Date.now() - startedAt
      });
    }
  }

  if (method === "POST" && path.endsWith("/api/recupero/contactos/search")) {
    const requestId = getRequestId(event);
    const startedAt = Date.now();
    let dbUser = null;
    let payloadHash = null;
    let rulesCount = 0;
    let emptyPayload = false;
    let responseSource = null;
    try {
      const authContext = await getCurrentDbUserFromEvent(event);
      const authUser = authContext.authUser;
      dbUser = authContext.dbUser;

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const body = safeParseBody(event);
      if (body === null) {
        return json(400, { ok: false, message: "Invalid JSON body" });
      }

      const producto = body?.producto ? String(body.producto).trim() : "";
      const departamento = body?.departamento ? String(body.departamento).trim() : "";
      const search = body?.search ? String(body.search).trim() : "";
      const motivoBaja = body?.motivo_baja ? String(body.motivo_baja).trim() : "";
      const tab = body?.tab ? String(body.tab).trim().toLowerCase() : "";
      const sortField = body?.sort?.field ? String(body.sort.field).trim() : "";
      const sortDir = body?.sort?.dir === "desc" ? "DESC" : "ASC";
      const filters = body?.filters || null;
      const page = Math.max(1, Number(body?.page || 1));
      const limit = Math.min(200, Math.max(1, Number(body?.limit || 50)));
      emptyPayload = isEmptySearchPayload(body);
      const validation = validateFilterTree(filters);
      if (!validation.valid) {
        return json(400, {
          ok: false,
          status: "error",
          message: validation.message || "Filtros invalidos",
          meta: { request_id: requestId }
        });
      }
      const simpleValidation = validateSimpleFilters(filters);
      if (!simpleValidation.valid) {
        return json(400, {
          ok: false,
          status: "error",
          message: simpleValidation.message || "Filtros invalidos",
          meta: { request_id: requestId }
        });
      }

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      payloadHash = hashPayload({
        producto,
        departamento,
        search,
        motivoBaja,
        tab,
        sortField,
        sortDir,
        page,
        limit,
        filters: emptyPayload ? null : filters
      });
      rulesCount = countFilterRules(filters);

      const cached = recuperoSearchCache.get(payloadHash);
      if (cached && Date.now() - cached.ts < 5000) {
        responseSource = "cache";
        return safeResponse({
          data: cached.data,
          emptyCondition: cached.emptyCondition,
          meta: {
            source: "cache",
            request_id: requestId,
            payload_hash: payloadHash,
            empty_payload: emptyPayload,
            rules_count: rulesCount
          }
        });
      }

      if (recuperoSearchInflight.has(payloadHash)) {
        const inflight = await recuperoSearchInflight.get(payloadHash);
        responseSource = "dedupe";
        return safeResponse({
          data: inflight.data,
          emptyCondition: inflight.emptyCondition,
          meta: {
            source: "dedupe",
            request_id: requestId,
            payload_hash: payloadHash,
            empty_payload: emptyPayload,
            rules_count: rulesCount
          }
        });
      }

      const runQuery = async () => {
        const client = createDbClient();
        await client.connect();
        try {
          return await fetchRecuperoContactos({
            client,
            producto,
            departamento,
            search,
            motivoBaja,
            tab,
            sortField,
            sortDir,
            page,
            limit,
            filters: emptyPayload ? null : filters,
            organizationId
          });
        } finally {
          await client.end();
        }
      };

      const promise = runQuery();
      recuperoSearchInflight.set(payloadHash, promise);
      let result;
      try {
        result = await promise;
      } finally {
        recuperoSearchInflight.delete(payloadHash);
      }

      recuperoSearchCache.set(payloadHash, {
        ts: Date.now(),
        data: result.data,
        emptyCondition: result.emptyCondition
      });

      responseSource = emptyPayload ? "base-list-fallback" : "recupero-search";
      return safeResponse({
        data: result.data,
        emptyCondition: result.emptyCondition,
        meta: {
          source: responseSource,
          request_id: requestId,
          payload_hash: payloadHash,
          empty_payload: emptyPayload,
          rules_count: rulesCount
        }
      });
    } catch (error) {
      return json(500, {
        ok: false,
        status: "error",
        message: "Failed to search recupero contacts",
        error: error.message,
        meta: { request_id: requestId }
      });
    } finally {
      console.log("[recupero/contactos/search]", {
        request_id: requestId,
        user_id: dbUser?.id || null,
        duration_ms: Date.now() - startedAt,
        payload_hash: payloadHash,
        rules_count: rulesCount,
        empty_payload: emptyPayload,
        source: responseSource
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/recupero/lotes")) {
    const requestId = getRequestId(event);
    const startedAt = Date.now();
    let dbUser = null;
    try {
      const { authUser, dbUser: currentUser } = await getCurrentDbUserFromEvent(event);
      dbUser = currentUser;

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const limit = Math.min(200, Math.max(1, Number(getQueryParam(event, "limit") || 50)));
      const offset = (page - 1) * limit;

      const client = createDbClient();
      await client.connect();
      try {
        const [itemsRes, totalRes] = await Promise.all([
          client.query(
            `
            SELECT
              lb.id,
              lb.nombre,
              lb.estado,
              lb.created_at,
              lb.criterios,
              lb.seller_id,
              lb.asignado_a,
              COUNT(lbc.id) AS cantidad,
              COALESCE(NULLIF(TRIM(CONCAT(u.nombre, ' ', u.apellido)), ''), u.nombre) AS vendedor_asignado_nombre
            FROM lead_batches lb
            LEFT JOIN lead_batch_contacts lbc ON lbc.batch_id = lb.id
            LEFT JOIN users u ON u.id = COALESCE(lb.seller_id, lb.asignado_a)
            WHERE lb.tipo = 'recupero'
            GROUP BY lb.id, u.nombre, u.apellido, u.id
            ORDER BY lb.created_at DESC
            LIMIT $1 OFFSET $2
            `,
            [limit, offset]
          ),
          client.query(
            `
            SELECT COUNT(*) AS total
            FROM lead_batches
            WHERE tipo = 'recupero'
            `
          )
        ]);

        const total = Number(totalRes.rows[0]?.total || 0);
        const data = {
          items: itemsRes.rows.map((row) => ({
            id: row.id,
            nombre: row.nombre,
            estado: row.estado,
            created_at: row.created_at,
            cantidad: Number(row.cantidad || 0),
            cantidad_datos: Number(row.cantidad || 0),
            configuracion: row.criterios,
            criterios: row.criterios,
            vendedor_asignado_id: row.seller_id || row.asignado_a || null,
            vendedor_asignado_nombre: row.vendedor_asignado_nombre,
            vendedor_asignado: row.vendedor_asignado_nombre
          })),
          total,
          page,
          limit
        };

        return safeResponse({
          data,
          emptyCondition: total === 0,
          meta: { source: "recupero-lotes", request_id: requestId }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        status: "error",
        message: "Failed to load recupero lots",
        error: error.message,
        meta: { request_id: requestId }
      });
    } finally {
      console.log("[recupero/lotes]", {
        request_id: requestId,
        user_id: dbUser?.id || null,
        duration_ms: Date.now() - startedAt
      });
    }
  }

  if (method === "POST" && path.endsWith("/api/recupero/lotes")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const body = safeParseBody(event);
      if (body === null) {
        return json(400, { ok: false, message: "Invalid JSON body" });
      }

      const nombre = body?.nombre;
      const contactIds = Array.isArray(body?.contact_ids) ? body.contact_ids.filter(Boolean) : [];
      const sellerIds = Array.isArray(body?.seller_ids) ? body.seller_ids.filter(Boolean) : [];

      if (!nombre || !contactIds.length || !sellerIds.length) {
        return json(400, { ok: false, message: "nombre, contact_ids y seller_ids son requeridos" });
      }

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");

        const columnsInfo = await getLeadContactColumns(client);
        const dCols = columnsInfo?.d || new Set();
        const hasContactIdCol = dCols.has("contact_id");
        const hasLocalidadCol = dCols.has("localidad");
        const hasOrigenCol = dCols.has("origen_dato");
        const hasEstadoCol = dCols.has("estado");
        const hasCorreoCol = dCols.has("correo_electronico");

        const batchRes = await client.query(
          `
          INSERT INTO lead_batches (nombre, estado, created_by, tipo, seller_id, asignado_a)
          VALUES ($1, 'asignado', $2, 'recupero', $3, $3)
          RETURNING id
          `,
          [nombre, dbUser?.id || null, sellerIds[0] || null]
        );
        const batchId = batchRes.rows[0]?.id;

        const contactsRes = await client.query(
          `
          SELECT id, nombre, apellido, documento, fecha_nacimiento, telefono, celular,
                 direccion, departamento, email
          FROM contacts
          WHERE id = ANY($1::uuid[])
          `,
          [contactIds]
        );
        const contactById = new Map();
        for (const row of contactsRes.rows) contactById.set(row.id, row);

        const dptIdsByContact = new Map();

        for (const contactId of contactIds) {
          const contact = contactById.get(contactId);
          if (!contact) continue;

          let existingId = null;
          if (hasContactIdCol) {
            const existingRes = await client.query(
              `SELECT id FROM datos_para_trabajar WHERE contact_id = $1 LIMIT 1`,
              [contactId]
            );
            existingId = existingRes.rows[0]?.id || null;
          } else if (contact.documento) {
            const existingRes = await client.query(
              `SELECT id FROM datos_para_trabajar WHERE documento = $1 LIMIT 1`,
              [contact.documento]
            );
            existingId = existingRes.rows[0]?.id || null;
          }

          if (!existingId) {
            const columns = [];
            const values = [];
            const params = [];
            let p = 1;

            const pushCol = (name, value) => {
              if (!dCols.has(name)) return;
              columns.push(name);
              values.push(value ?? null);
              params.push(`$${p}`);
              p += 1;
            };

            pushCol("nombre", contact.nombre);
            pushCol("apellido", contact.apellido);
            pushCol("documento", contact.documento);
            pushCol("fecha_nacimiento", contact.fecha_nacimiento);
            pushCol("telefono", contact.telefono);
            pushCol("celular", contact.celular);
            pushCol("direccion", contact.direccion);
            pushCol("departamento", contact.departamento);
            if (hasLocalidadCol) pushCol("localidad", null);
            if (hasCorreoCol) pushCol("correo_electronico", contact.email);
            if (hasOrigenCol) pushCol("origen_dato", "recupero");
            if (hasEstadoCol) pushCol("estado", "nuevo");
            if (hasContactIdCol) pushCol("contact_id", contactId);

            const insertRes = await client.query(
              `
              INSERT INTO datos_para_trabajar (${columns.join(", ")})
              VALUES (${params.join(", ")})
              RETURNING id
              `,
              values
            );
            existingId = insertRes.rows[0]?.id || null;
          }

          if (existingId) {
            dptIdsByContact.set(contactId, existingId);
          }

        }

        for (const sellerId of sellerIds) {
          await client.query(
            `
            INSERT INTO lead_batch_sellers (batch_id, seller_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            `,
            [batchId, sellerId]
          );
        }

        for (let i = 0; i < contactIds.length; i += 1) {
          const contactId = contactIds[i];

          await client.query(
            `
            INSERT INTO lead_batch_contacts (batch_id, client_contact_id, tipo_origen)
            VALUES ($1, $2, 'cliente')
            ON CONFLICT DO NOTHING
            `,
            [batchId, contactId]
          );
        }

        const assignedSellerId = sellerIds[0] || null;
        const dptIds = contactIds
          .map((id) => dptIdsByContact.get(id))
          .filter(Boolean);
        if (dptIds.length) {
          await client.query(
            `
            INSERT INTO lead_contact_status (
              contact_id,
              batch_id,
              assigned_to,
              estado_venta,
              intentos,
              ultimo_intento_at,
              created_at,
              updated_at
            )
            SELECT
              UNNEST($1::uuid[]),
              $2,
              $3,
              'nuevo',
              0,
              NULL,
              now(),
              now()
            ON CONFLICT (contact_id) DO UPDATE
            SET
              assigned_to = COALESCE(EXCLUDED.assigned_to, lead_contact_status.assigned_to),
              batch_id = EXCLUDED.batch_id,
              estado_venta = COALESCE(lead_contact_status.estado_venta, 'nuevo'),
              intentos = COALESCE(lead_contact_status.intentos, 0),
              updated_at = now()
            `,
            [dptIds, batchId, assignedSellerId]
          );
        }

        await client.query("COMMIT");
        return json(201, { ok: true, batch_id: batchId });
      } catch (err) {
        await client.query("ROLLBACK");
        return json(500, { ok: false, message: err.message });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create recupero batch",
        error: error.message
      });
    }
  }
  if (method === "GET" && path.endsWith("/api/recupero/filtros")) {
    const requestId = getRequestId(event);
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const [
          motivosRes,
          estadosRes,
          productosRes,
          departamentosRes,
          vendedoresRes,
          lotesRes,
          hasMotivoNullRes,
          hasEstadoNullRes
        ] = await Promise.all([
          client.query(
            `
            SELECT LOWER(TRIM(val)) AS value, MAX(TRIM(val)) AS label
            FROM (
              SELECT cp.motivo_baja_detalle AS val
              FROM contact_products cp
              WHERE cp.estado = 'baja'
                AND cp.motivo_baja_detalle IS NOT NULL
                AND cp.motivo_baja_detalle <> ''
              UNION ALL
              SELECT ems.motivo_baja AS val
              FROM external_management_status ems
              WHERE ems.motivo_baja IS NOT NULL
                AND ems.motivo_baja <> ''
              UNION ALL
              SELECT cp.motivo_baja AS val
              FROM contact_products cp
              WHERE cp.estado = 'baja'
                AND cp.motivo_baja IS NOT NULL
                AND cp.motivo_baja <> ''
            ) s
            GROUP BY LOWER(TRIM(val))
            ORDER BY label
            `
          ),
          client.query(
            `
            SELECT LOWER(TRIM(val)) AS value, MAX(TRIM(val)) AS label
            FROM (
              SELECT ems.estado_normalizado AS val
              FROM external_management_status ems
              WHERE ems.estado_normalizado IS NOT NULL
                AND ems.estado_normalizado <> ''
              UNION ALL
              SELECT lmh.resultado AS val
              FROM lead_management_history lmh
              JOIN lead_batches lb ON lb.id = lmh.batch_id
              WHERE lb.tipo = 'recupero'
                AND lmh.resultado IS NOT NULL
                AND lmh.resultado <> ''
            ) s
            GROUP BY LOWER(TRIM(val))
            ORDER BY label
            `
          ),
          client.query(
            `
            SELECT LOWER(TRIM(cp.nombre_producto)) AS value, MAX(TRIM(cp.nombre_producto)) AS label
            FROM contact_products cp
            JOIN contacts c ON c.id = cp.contact_id
            WHERE cp.estado = 'baja'
              AND cp.fecha_baja BETWEEN '2000-01-01' AND '2030-12-31'
              AND cp.nombre_producto IS NOT NULL
              AND cp.nombre_producto <> ''
            GROUP BY LOWER(TRIM(cp.nombre_producto))
            ORDER BY label
            `
          ),
          client.query(
            `
            SELECT LOWER(TRIM(c.departamento)) AS value, MAX(TRIM(c.departamento)) AS label
            FROM contacts c
            JOIN contact_products cp ON cp.contact_id = c.id
            WHERE cp.estado = 'baja'
              AND c.departamento IS NOT NULL
              AND c.departamento <> ''
            GROUP BY LOWER(TRIM(c.departamento))
            ORDER BY label
            `
          ),
          client.query(
            `
            SELECT LOWER(TRIM(COALESCE(NULLIF(TRIM(CONCAT(u.nombre, ' ', u.apellido)), ''), u.nombre))) AS value,
                   COALESCE(NULLIF(TRIM(CONCAT(u.nombre, ' ', u.apellido)), ''), u.nombre) AS label
            FROM lead_contact_status lcs
            JOIN lead_batches lb ON lb.id = lcs.batch_id
            JOIN users u ON u.id = lcs.assigned_to
            WHERE lb.tipo = 'recupero'
              AND lcs.assigned_to IS NOT NULL
            GROUP BY value, label
            ORDER BY label
            `
          ),
          client.query(
            `
            SELECT LOWER(TRIM(nombre)) AS value, MAX(TRIM(nombre)) AS label
            FROM lead_batches
            WHERE tipo = 'recupero'
              AND nombre IS NOT NULL
              AND nombre <> ''
            GROUP BY LOWER(TRIM(nombre))
            ORDER BY label
            `
          ),
          client.query(
            `
            SELECT EXISTS(
              SELECT 1
              FROM contact_products cp
              WHERE cp.estado = 'baja'
                AND (cp.motivo_baja_detalle IS NULL OR cp.motivo_baja_detalle = '')
                AND (cp.motivo_baja IS NULL OR cp.motivo_baja = '')
            ) AS has_null
            `
          ),
          client.query(
            `
            SELECT EXISTS(
              SELECT 1
              FROM contact_products cp
              JOIN contacts c ON c.id = cp.contact_id
              LEFT JOIN external_management_status ems ON ems.documento = c.documento
              LEFT JOIN LATERAL (
                SELECT lmh.resultado AS ultimo_estado_gestion
                FROM lead_management_history lmh
                JOIN lead_batches lb ON lb.id = lmh.batch_id
                WHERE lmh.contact_id = c.id
                  AND lb.tipo = 'recupero'
                ORDER BY lmh.fecha_gestion DESC
                LIMIT 1
              ) gestion ON true
              WHERE cp.estado = 'baja'
                AND COALESCE(gestion.ultimo_estado_gestion, ems.estado_normalizado) IS NULL
            ) AS has_null
            `
          )
        ]);

        const toLabel = (value, label) => {
          if (label && label.trim()) return label;
          return normalizeTextValue(value)
            .replace(/_/g, " ")
            .replace(/\b\w/g, (c) => c.toUpperCase());
        };

        const motivos = motivosRes.rows.map((row) => ({
          value: row.value,
          label: toLabel(row.value, row.label)
        }));
        if (hasMotivoNullRes.rows[0]?.has_null) {
          motivos.unshift({ value: "sin motivo", label: "Sin motivo" });
        }

        const estados = estadosRes.rows.map((row) => ({
          value: row.value,
          label: toLabel(row.value, row.label)
        }));
        if (hasEstadoNullRes.rows[0]?.has_null) {
          estados.unshift({ value: "sin estado", label: "Sin estado" });
        }

        const data = {
          motivo_baja: motivos,
          ultimo_estado: estados,
          producto: productosRes.rows.map((row) => ({
            value: row.value,
            label: toLabel(row.value, row.label)
          })),
          departamento: departamentosRes.rows.map((row) => ({
            value: row.value,
            label: toLabel(row.value, row.label)
          })),
          vendedor_asignado: vendedoresRes.rows.map((row) => ({
            value: row.value,
            label: toLabel(row.value, row.label)
          })),
          lote: lotesRes.rows.map((row) => ({
            value: row.value,
            label: toLabel(row.value, row.label)
          }))
        };

        return safeResponse({
          data,
          emptyCondition:
            data.motivo_baja.length === 0 &&
            data.ultimo_estado.length === 0 &&
            data.producto.length === 0 &&
            data.departamento.length === 0 &&
            data.vendedor_asignado.length === 0 &&
            data.lote.length === 0,
          meta: { source: "recupero-filtros", request_id: requestId }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        status: "error",
        message: "Failed to load recupero filters",
        error: error.message,
        meta: { request_id: requestId }
      });
    }
  }
  if (method === "GET" && path.endsWith("/leads/assigned")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const page = parseInt(getQueryParam(event, "page") || "1", 10);
      const limit = parseInt(getQueryParam(event, "limit") || "50", 10);
      const offset = (page - 1) * limit;
      const tab = getQueryParam(event, "tab") || "todos";
      const tipo = getQueryParam(event, "tipo") || null;
      const searchRaw = String(getQueryParam(event, "search") || "").trim();
      const search = searchRaw ? `%${searchRaw}%` : null;
      const origenDatoRaw = String(getQueryParam(event, "origen_dato") || "").trim();
      const origenDato = origenDatoRaw ? `%${origenDatoRaw}%` : null;
      let tabNormalized = tab;
      if (tabNormalized === "nuevos") tabNormalized = "nuevo";

      let tabWhere = "";
      if (tabNormalized === "nuevo") {
        tabWhere = "AND (lcs.intentos = 0 OR lcs.ultimo_intento_at IS NULL)";
      } else if (tabNormalized === "seguimiento") {
        tabWhere = "AND lcs.estado_venta IN ('seguimiento', 'interesado')";
      } else if (tabNormalized === "no_contesta") {
        tabWhere = "AND lcs.estado_venta IN ('no_contesta')";
      } else if (tabNormalized === "no_contacto") {
        tabWhere = "AND lcs.estado_venta IN ('no_contesta')";
      } else if (tabNormalized === "rechazo") {
        tabWhere = "AND lcs.estado_venta = 'rechazo'";
      } else if (tabNormalized === "recuperado") {
        tabWhere = "AND lcs.estado_venta IN ('venta')";
      } else {
        tabWhere = "AND lcs.estado_venta != 'dato_erroneo'";
      }
      const tabWhereCount = tabWhere.replace(/^AND\s+/, "");
      const countExtra =
        tabWhereCount && tabWhereCount !== "lcs.estado_venta != 'dato_erroneo'"
          ? `AND ${tabWhereCount}`
          : "";

      const sellerId = dbUser?.id || null;
      if (!sellerId) {
        return json(401, { ok: false, message: "Seller id requerido" });
      }

      const client = createDbClient();
      await client.connect();
      try {
        const leadCols = await getLeadContactColumns(client);
        const dEmail = leadCols.d.has("email") ? "d.email" : "NULL::text";
        const dDireccion = leadCols.d.has("direccion") ? "d.direccion" : "NULL::text";
        const dLocalidad = leadCols.d.has("localidad") ? "d.localidad" : "NULL::text";
        const dContactId = leadCols.d.has("contact_id") ? "d.contact_id" : "NULL::uuid";
        const cEmail = leadCols.c.has("email") ? "c.email" : "NULL::text";
        const cDireccion = leadCols.c.has("direccion") ? "c.direccion" : "NULL::text";
        const cDepartamento = leadCols.c.has("departamento") ? "c.departamento" : "NULL::text";
        const cLocalidad = leadCols.c.has("localidad") ? "c.localidad" : "NULL::text";
        const contactJoin = leadCols.d.has("contact_id")
          ? "LEFT JOIN contacts c ON c.id = d.contact_id"
          : "LEFT JOIN contacts c ON c.id = lcs.contact_id";
        const countResult = await client.query(
          `
          SELECT COUNT(*) AS count
          FROM lead_contact_status lcs
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          LEFT JOIN datos_para_trabajar d ON d.id = lcs.contact_id
          LEFT JOIN contacts c ON c.id = d.contact_id
          WHERE lcs.assigned_to = $1
            AND lb.estado IN ('activo', 'asignado')
            AND lcs.estado_venta != 'dato_erroneo'
            AND ($2::text IS NULL OR lb.tipo = $2)
            AND ($4::text IS NULL OR COALESCE(d.origen_dato, '') ILIKE $4)
            AND (
              $3::text IS NULL OR (
                COALESCE(d.nombre, c.nombre, '') ILIKE $3
                OR COALESCE(d.apellido, c.apellido, '') ILIKE $3
                OR COALESCE(d.documento, c.documento, '') ILIKE $3
                OR COALESCE(d.telefono, c.telefono, '') ILIKE $3
                OR COALESCE(d.celular, c.celular, '') ILIKE $3
                OR COALESCE(d.email, c.email, '') ILIKE $3
                OR COALESCE(d.departamento, c.departamento, '') ILIKE $3
                OR COALESCE(${dLocalidad}, ${cLocalidad}, '') ILIKE $3
                OR COALESCE(d.direccion, c.direccion, '') ILIKE $3
                OR (COALESCE(d.nombre, c.nombre, '') || ' ' || COALESCE(d.apellido, c.apellido, '')) ILIKE $3
              )
            )
            ${countExtra}
          `,
          [sellerId, tipo, search, origenDato]
        );
        const result = await client.query(
          `
          SELECT
            COALESCE(d.id, c.id)                    AS id,
            COALESCE(d.nombre, c.nombre)            AS nombre,
            COALESCE(d.apellido, c.apellido)        AS apellido,
            COALESCE(d.documento, c.documento)      AS documento,
            COALESCE(d.fecha_nacimiento, c.fecha_nacimiento) AS fecha_nacimiento,
            COALESCE(d.created_at, c.created_at)    AS created_at,
            DATE_PART('year', AGE(
              COALESCE(d.fecha_nacimiento, c.fecha_nacimiento)
            ))::int                                 AS edad,
            COALESCE(d.telefono, c.telefono)        AS telefono,
            COALESCE(d.celular, c.celular)          AS celular,
            COALESCE(${dEmail}, ${cEmail})          AS correo_electronico,
            COALESCE(${dDireccion}, ${cDireccion})  AS direccion,
            COALESCE(d.departamento, ${cDepartamento}) AS departamento,
            ${dLocalidad}                           AS localidad,
            d.nota                                  AS nota,
            COALESCE(d.origen_dato, 'recupero')     AS origen_dato,
            lb.tipo                                 AS lote_tipo,
            lcs.estado_venta,
            lcs.batch_id,
            lb.nombre                               AS lote_nombre,
            (SELECT MAX(lmh.created_at)
             FROM lead_management_history lmh
             WHERE lmh.contact_id = COALESCE(d.id, c.id)
               AND lmh.batch_id = lcs.batch_id
            ) AS ultima_gestion_real
          FROM lead_contact_status lcs
          LEFT JOIN datos_para_trabajar d ON d.id = lcs.contact_id
          ${contactJoin}
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE lcs.assigned_to = $1
            AND lb.estado IN ('activo', 'asignado')
            AND ($2::text IS NULL OR lb.tipo = $2)
            AND ($4::text IS NULL OR COALESCE(d.origen_dato, '') ILIKE $4)
            AND (
              $3::text IS NULL OR (
                COALESCE(d.nombre, c.nombre, '') ILIKE $3
                OR COALESCE(d.apellido, c.apellido, '') ILIKE $3
                OR COALESCE(d.documento, c.documento, '') ILIKE $3
                OR COALESCE(d.telefono, c.telefono, '') ILIKE $3
                OR COALESCE(d.celular, c.celular, '') ILIKE $3
                OR COALESCE(d.email, c.email, '') ILIKE $3
                OR COALESCE(d.departamento, c.departamento, '') ILIKE $3
                OR COALESCE(${dLocalidad}, ${cLocalidad}, '') ILIKE $3
                OR COALESCE(d.direccion, c.direccion, '') ILIKE $3
                OR (COALESCE(d.nombre, c.nombre, '') || ' ' || COALESCE(d.apellido, c.apellido, '')) ILIKE $3
              )
            )
            ${tabWhere}
          ORDER BY lcs.intentos ASC, lcs.updated_at DESC, lcs.contact_id ASC
          LIMIT $5 OFFSET $6
          `,
          [sellerId, tipo, search, origenDato, limit, offset]
        );
        const total = parseInt(countResult.rows[0]?.count || "0", 10);

        return json(200, {
          ok: true,
          success: true,
          data: {
            contactos: result.rows,
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit)
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list assigned leads",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/leads/next")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const tipo = (getQueryParam(event, "tipo") || "").trim() || null;
        const isRecupero = tipo === "recupero";
        const batchRes = await client.query(
          `
          SELECT
            lb.id AS batch_id,
            lb.max_intentos,
            lb.franja_ola1_inicio,
            lb.franja_ola1_fin,
            lb.franja_ola2_inicio,
            lb.franja_ola2_fin,
            lb.dias_entre_olas
          FROM lead_batches lb
          JOIN lead_batch_sellers lbs ON lbs.batch_id = lb.id
          WHERE lbs.seller_id = $1
            AND lb.estado IN ('activo', 'asignado')
            AND ($2::text IS NULL OR lb.tipo = $2)
          ORDER BY lb.created_at DESC
          LIMIT 1
          `,
          [dbUser.id, tipo]
        );

        if (!batchRes.rows.length) {
          return json(200, {
            ok: true,
            success: true,
            data: null,
            message: "No tenï¿½s lotes activos asignados",
            error: null
          });
        }

        const batch = batchRes.rows[0];
        const now = new Date();
        const horaActual = now.toTimeString().slice(0, 5);
        const ola1Inicio = String(batch.franja_ola1_inicio || "10:00").slice(0, 5);
        const ola1Fin = String(batch.franja_ola1_fin || "13:00").slice(0, 5);
        const ola2Inicio = String(batch.franja_ola2_inicio || "17:00").slice(0, 5);
        const ola2Fin = String(batch.franja_ola2_fin || "20:00").slice(0, 5);

        const enOla1 = horaActual >= ola1Inicio && horaActual <= ola1Fin;
        const enOla2 = horaActual >= ola2Inicio && horaActual <= ola2Fin;

        let estadosPrioridad = [];
        if (isRecupero) {
          estadosPrioridad = [
            "seguimiento",
            "interesado",
            "rellamar",
            "volver_a_llamar",
            "no_contesta",
            "nuevo"
          ];
        } else if (enOla1 || (!enOla1 && !enOla2)) {
          estadosPrioridad = ["rellamar", "nuevo", "no_contesta"];
        } else {
          estadosPrioridad = ["rellamar", "no_contesta", "nuevo"];
        }

        const orderBy = isRecupero
          ? `
            CASE
              WHEN lcs.estado_venta IN ('seguimiento', 'interesado') THEN 1
              WHEN lcs.estado_venta = 'no_contesta' THEN 2
              WHEN lcs.intentos = 0 THEN 3
              ELSE 4
            END,
            lcs.intentos ASC,
            lcs.contact_id ASC
          `
          : `
            prioridad ASC,
            lcs.intentos ASC,
            lcs.contact_id ASC
          `;

        const minimoEntreIntentos = Number(batch.dias_entre_olas || 0) * 24 * 60 * 60;

        const nextRes = await client.query(
          `
          SELECT
            d.id,
            d.nombre,
            d.apellido,
            d.telefono,
            d.celular,
            d.email AS correo_electronico,
            d.direccion,
            d.departamento,
            d.localidad,
            lcs.estado_venta,
            lcs.intentos,
            lcs.ola_actual,
            lcs.ultimo_intento_at,
            CASE lcs.estado_venta
              WHEN 'rellamar' THEN 1
              WHEN 'nuevo' THEN 2
              WHEN 'no_contesta' THEN 3
              ELSE 99
            END AS prioridad
          FROM lead_contact_status lcs
          JOIN datos_para_trabajar d ON d.id = lcs.contact_id
          WHERE lcs.batch_id = $1
            AND lcs.assigned_to = $2
            AND lcs.estado_venta = ANY($3)
            AND lcs.intentos < $4
            AND (
              lcs.ultimo_intento_at IS NULL
              OR EXTRACT(EPOCH FROM (NOW() - lcs.ultimo_intento_at)) > $5
            )
          ORDER BY ${orderBy}
          LIMIT 1
          `,
          [
            batch.batch_id,
            dbUser.id,
            estadosPrioridad,
            batch.max_intentos,
            minimoEntreIntentos
          ]
        );

        if (!nextRes.rows.length) {
          const pendingRes = await client.query(
            `
            SELECT COUNT(*)::int AS total
            FROM lead_contact_status
            WHERE batch_id = $1
              AND assigned_to = $2
              AND estado_venta = ANY($3)
              AND intentos < $4
            `,
            [batch.batch_id, dbUser.id, estadosPrioridad, batch.max_intentos]
          );
          const pendientes = pendingRes.rows[0]?.total || 0;
          if (pendientes > 0) {
            return json(200, {
              ok: true,
              success: true,
              data: { gestion_id: existingGestionId },
              message: enOla2
                ? `No hay contactos disponibles en esta franja. Volvï¿½ a las ${ola1Inicio}`
                : `No hay contactos disponibles en esta franja. Volvï¿½ a las ${ola2Inicio}`,
              error: null
            });
          }

          return json(200, {
            ok: true,
            success: true,
            data: null,
            message: "Todos los contactos del lote fueron gestionados. ï¿½Buen trabajo!",
            error: null
          });
        }

        return json(200, {
          ok: true,
          success: true,
          data: nextRes.rows[0],
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load next lead",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/leads/daily-stats")) {
    const requestId = getRequestId(event);
    const startedAt = Date.now();
    let dbUser = null;
    let fecha = null;
    let batchTipo = null;
    try {
      const authContext = await getCurrentDbUserFromEvent(event);
      const authUser = authContext.authUser;
      dbUser = authContext.dbUser;

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const sellerId = dbUser?.id || null;
      fecha = parseFechaParam(getQueryParam(event, "fecha"));
      const tipoRaw = getQueryParam(event, "tipo");
      const tipo = tipoRaw ? String(tipoRaw).trim().toLowerCase() : "";
      const hasTipo = tipo === "recupero" || tipo === "captacion";
      batchTipo = hasTipo ? tipo : null;
      console.log("[daily-stats] userId:", sellerId, "fecha:", fecha);

      const client = createDbClient();
      await client.connect();
      try {
        const lotesResult = await client.query(
          `
          SELECT
            COUNT(DISTINCT lcs.contact_id) AS total_asignados,
            COUNT(DISTINCT lcs.contact_id) FILTER (WHERE lcs.estado_venta = 'nuevo') AS nuevos
          FROM lead_contact_status lcs
          JOIN lead_batch_sellers lbs ON lbs.batch_id = lcs.batch_id
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE lbs.seller_id = $1
            AND lcs.assigned_to = $1
            AND lb.estado IN ('activo', 'asignado')
            AND ($2::text IS NULL OR lb.tipo = $2)
          `,
          [sellerId, batchTipo]
        );

        const statsResult = await client.query(
          `
          SELECT
            COUNT(*) FILTER (WHERE resultado <> 'dato_erroneo')::int AS tocados,
            COUNT(*) FILTER (WHERE resultado = 'no_contesta')::int AS no_contesta,
            COUNT(*) FILTER (WHERE resultado = 'rellamar')::int AS rellamar,
            COUNT(*) FILTER (WHERE resultado = 'seguimiento')::int AS seguimiento,
            COUNT(*) FILTER (WHERE resultado = 'rechazo')::int AS rechazos,
            COUNT(*) FILTER (WHERE resultado = 'venta')::int AS ventas,
            COUNT(*) FILTER (WHERE resultado = 'dato_erroneo')::int AS dato_erroneo,
            ROUND(
              100.0
              * COUNT(*) FILTER (WHERE resultado = 'venta')
              / NULLIF(COUNT(*) FILTER (WHERE resultado <> 'dato_erroneo'), 0),
              1
            ) AS efectividad_pct
          FROM (
            SELECT DISTINCT ON (lmh.contact_id)
              lmh.contact_id,
              lmh.resultado
            FROM lead_management_history lmh
            LEFT JOIN lead_batches lb ON lb.id = lmh.batch_id
            WHERE lmh.user_id = $1
              AND (lmh.fecha_gestion AT TIME ZONE 'America/Montevideo')::date = $2::date
              AND ($3::text IS NULL OR lb.tipo = $3)
            ORDER BY lmh.contact_id, lmh.fecha_gestion DESC
          ) last_gestiones
          `,
          [sellerId, fecha, batchTipo]
        );
        const salesStatsRes = await client.query(
          `
          SELECT
            COUNT(*) AS total_contratos,
            COUNT(*) FILTER (WHERE s.gestion_id IS NOT NULL) AS ventas_reales,
            COUNT(*) FILTER (WHERE s.relation = 'titular') AS ventas_titular,
            COUNT(*) FILTER (WHERE s.relation = 'familiar') AS ventas_familiar,
            COUNT(*) FILTER (WHERE s.relation = 'familiar' OR s.relation != 'titular') AS ventas_adicionales,
            COALESCE(SUM(si.price), 0) AS ingresos_hoy
          FROM sales s
          LEFT JOIN sale_items si ON si.sale_id = s.id
          WHERE s.seller_user_id = $1
            AND (s.created_at AT TIME ZONE 'America/Montevideo')::date = $2::date
          `,
          [sellerId, fecha]
        );
        const s = statsResult.rows[0] || {};
        const ss = salesStatsRes.rows[0] || {};
        const l = lotesResult.rows[0] || {};
        const ventasLead = parseInt(s.ventas || "0", 10);
        const ventasTotal = ventasLead;
        const rechazosTotal = parseInt(s.rechazos || "0", 10);
        const seguimientoTotal = parseInt(s.seguimiento || "0", 10);
        const noContestaTotal = parseInt(s.no_contesta || "0", 10);
        const rellamarTotal = parseInt(s.rellamar || "0", 10);
        const datosErroneosTotal = parseInt(s.dato_erroneo || "0", 10);
        const finalVentas = parseInt(ss.total_contratos || 0, 10);
        const ventasReales = parseInt(ss.ventas_reales || 0, 10);
        const ventasTitular = parseInt(ss.ventas_titular || 0, 10);
        const ventasFamiliar = parseInt(ss.ventas_familiar || 0, 10);
        const ingresosHoy = parseFloat(ss.ingresos_hoy || 0);

        const utiles = ventasTotal + rechazosTotal + seguimientoTotal;
        const inutiles = noContestaTotal + rellamarTotal + datosErroneosTotal;
        const totalGestionado = utiles + inutiles;

        const contactoPct = totalGestionado > 0 ? Math.round((utiles / totalGestionado) * 100) : 0;
        const efectividadPct = utiles > 0 ? Math.round((ventasTotal / utiles) * 100) : 0;

        const totalAsignados = parseInt(l.total_asignados || "0", 10);
        const data = {
          total_asignados: totalAsignados,
          nuevos: parseInt(l.nuevos || "0", 10),
          no_contesta: noContestaTotal,
          seguimiento: seguimientoTotal,
          rechazos: rechazosTotal,
          ventas: finalVentas,
          gestiones_venta: ventasTotal,
          ventas_reales: ventasReales,
          ventas_titular: ventasTitular,
          ventas_familiar: ventasFamiliar,
          ingresos_hoy: ingresosHoy,
          tocados: totalGestionado,
          contactos_reales: utiles,
          pct_contacto: contactoPct,
          pct_efectividad: efectividadPct,
          gestiones_hoy: totalGestionado,
          ventas_hoy: finalVentas,
          no_contesta_hoy: noContestaTotal,
          tipificados_seguimiento_hoy: seguimientoTotal,
          rechazos_hoy: rechazosTotal,
          rellamar_hoy: rellamarTotal,
          pct_contacto_hoy: contactoPct,
          pct_efectividad_hoy: efectividadPct
        };
        const emptyCondition = totalAsignados === 0 && totalGestionado === 0;
        return safeResponse({
          data,
          emptyCondition,
          message: emptyCondition ? "Sin actividad para la fecha" : undefined,
          meta: { fecha, tipo: batchTipo || "all", source: "daily-stats", request_id: requestId }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        status: "error",
        message: "Failed to load daily stats",
        error: error.message,
        meta: { request_id: requestId }
      });
    } finally {
      console.log("[daily-stats]", {
        request_id: requestId,
        user_id: dbUser?.id || null,
        fecha,
        tipo: batchTipo || "all",
        duration_ms: Date.now() - startedAt
      });
    }
  }

  if (method === "GET" && path.endsWith("/leads/status")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `
          SELECT
            lcs.estado_venta,
            COUNT(*)::int AS total,
            lcs.ola_actual
          FROM lead_contact_status lcs
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          JOIN lead_batch_sellers lbs ON lbs.batch_id = lb.id
          WHERE lbs.seller_id = $1
            AND lb.estado IN ('activo', 'asignado')
            AND lcs.assigned_to = $1
          GROUP BY lcs.estado_venta, lcs.ola_actual
          ORDER BY lcs.ola_actual, lcs.estado_venta
          `,
          [dbUser.id]
        );
        return json(200, {
          ok: true,
          success: true,
          data: result.rows,
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load leads status",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/leads/new")) {
    const bodyRaw = safeParseBody(event);
    const body = normalizeEmptyStringsToNull(sanitizeUuidFields(bodyRaw));
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const contactPayload = body?.contact && typeof body.contact === "object"
        ? body.contact
        : body;

      const buildContactFields = (payload) => {
        const nombre = normalizeText(payload?.nombre);
        const apellido = normalizeText(payload?.apellido);
        const documento = normalizeText(payload?.documento) || null;
        const fechaNacimiento = parseDate(payload?.fecha_nacimiento || payload?.fechaNacimiento || null);
        const telefono = normalizeText(payload?.telefono) || null;
        const celular = normalizeText(payload?.celular) || null;
        const correo = normalizeEmail(payload?.correo_electronico || payload?.email);
        const email = correo ? correo : null;
        const direccion = normalizeText(payload?.direccion) || null;
        const departamento = normalizeText(payload?.departamento) || null;
        const localidad = normalizeText(payload?.localidad) || null;
        const pais = normalizeText(payload?.pais) || "Uruguay";
        const origenDato = normalizeText(payload?.origen_dato || payload?.origen) || null;
        return {
          nombre,
          apellido,
          documento,
          fechaNacimiento,
          telefono,
          celular,
          email,
          direccion,
          departamento,
          localidad,
          pais,
          origenDato
        };
      };

      const fields = buildContactFields(contactPayload || {});
      if (!fields.nombre || !fields.apellido) {
        return json(422, { ok: false, message: "nombre y apellido requeridos" });
      }

      const isValidUuid = (value) =>
        typeof value === "string" &&
        /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(value);

      const principalContactRaw = normalizeText(
        body?.principal_contact_id ||
        body?.principalContactId ||
        body?.main_contact_id ||
        body?.mainContactId ||
        body?.parent_contact_id ||
        body?.parentContactId ||
        body?.contacto_principal_id ||
        body?.contactIdPrincipal ||
        body?.contacto_principal
      );
      const principalContactId = isValidUuid(principalContactRaw) ? principalContactRaw : null;

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");

        leadContactColumnsCache = null;
        const leadCols = await getLeadContactColumns(client);
        const dCols = leadCols?.d || new Set();
        const hasContactIdCol = dCols.has("contact_id");
        const leadIdColumn = dCols.has("id") ? "id" : (dCols.has("contact_id") ? "contact_id" : null);
        if (!leadIdColumn) {
          await client.query("ROLLBACK");
          return json(500, { ok: false, message: "No se puede resolver columna de lead" });
        }

        const resolveBatchId = async () => {
          if (principalContactId && hasContactIdCol) {
            const leadRes = await client.query(
              `SELECT ${leadIdColumn} AS lead_id FROM datos_para_trabajar WHERE contact_id = $1 LIMIT 1`,
              [principalContactId]
            );
            const principalLeadId = leadRes.rows[0]?.lead_id || null;
            if (principalLeadId) {
              const statusRes = await client.query(
                `SELECT batch_id FROM lead_contact_status
                 WHERE contact_id = $1
                 ORDER BY updated_at DESC LIMIT 1`,
                [principalLeadId]
              );
              const batchId = statusRes.rows[0]?.batch_id || null;
              if (batchId && isValidUuid(batchId)) return batchId;
            }
          }

          const safeSellerId = isValidUuid(dbUser?.id) ? dbUser.id : null;
          if (!safeSellerId) return null;

          // Fallback 1: lote propio en lead_batches
          const batchRes = await client.query(
            `SELECT id FROM lead_batches
             WHERE estado IN ('activo','asignado')
               AND (seller_id = $1 OR asignado_a = $1)
             ORDER BY created_at DESC LIMIT 1`,
            [safeSellerId]
          );
          if (batchRes.rows[0]?.id) return batchRes.rows[0].id;

          // Fallback 2: lote mÃ¡s reciente asignado al vendedor vÃ­a lead_contact_status
          const lcsRes = await client.query(
            `SELECT lcs.batch_id
             FROM lead_contact_status lcs
             JOIN lead_batches lb ON lb.id = lcs.batch_id
             WHERE lcs.assigned_to = $1
               AND lb.estado IN ('activo','asignado')
             ORDER BY lcs.updated_at DESC LIMIT 1`,
            [safeSellerId]
          );
          return lcsRes.rows[0]?.batch_id || null;
        };

        const batchId = await resolveBatchId();
        if (!batchId) {
          await client.query("ROLLBACK");
          return json(409, { ok: false, message: "No hay lote activo para asignar" });
        }

        const docValue = normalizeText(fields.documento || "") || null;
        const telValue = normalizePhoneDigits(fields.telefono || "");
        const celValue = normalizePhoneDigits(fields.celular || "");
        let existingLeadId = null;

        if (docValue || telValue || celValue) {
          const existingRes = await client.query(
            `
            SELECT ${leadIdColumn} AS lead_id
            FROM datos_para_trabajar
            WHERE ($1::text IS NOT NULL AND documento = $1)
               OR ($2::text <> '' AND regexp_replace(telefono, '\\D', '', 'g') = $2)
               OR ($3::text <> '' AND regexp_replace(celular, '\\D', '', 'g') = $3)
            ORDER BY updated_at DESC NULLS LAST, created_at DESC
            LIMIT 1
            `,
            [docValue, telValue, celValue]
          );
          existingLeadId = existingRes.rows[0]?.lead_id || null;
        }

        let leadId = existingLeadId;
        let validContactId = null;
        if (hasContactIdCol && principalContactId) {
          const checkRes = await client.query(
            `SELECT id FROM contacts WHERE id = $1 LIMIT 1`,
            [principalContactId]
          );
          validContactId = checkRes.rows[0]?.id ?? null;
        }
        if (!leadId) {
          const columns = [];
          const values = [];
          const params = [];
          let p = 1;
          const pushCol = (name, value) => {
            if (!dCols.has(name)) return;
            columns.push(name);
            values.push(value ?? null);
            params.push(`$${p}`);
            p += 1;
          };

          pushCol("nombre", fields.nombre);
          pushCol("apellido", fields.apellido);
          pushCol("documento", docValue);
          pushCol("fecha_nacimiento", fields.fechaNacimiento);
          pushCol("telefono", fields.telefono);
          pushCol("celular", fields.celular);
          pushCol("direccion", fields.direccion);
          pushCol("departamento", fields.departamento);
          if (dCols.has("localidad")) pushCol("localidad", fields.localidad);
          if (dCols.has("correo_electronico")) pushCol("correo_electronico", fields.email);
          if (dCols.has("email")) pushCol("email", fields.email);
          if (dCols.has("pais")) pushCol("pais", fields.pais);
          if (dCols.has("origen_dato")) pushCol("origen_dato", fields.origenDato || null);
          if (dCols.has("estado")) pushCol("estado", "nuevo");
          if (hasContactIdCol && validContactId) pushCol("contact_id", validContactId);

          if (!columns.length) {
            await client.query("ROLLBACK");
            return json(500, { ok: false, message: "No se pudieron mapear campos de lead" });
          }

          const insertRes = await client.query(
            `
            INSERT INTO datos_para_trabajar (${columns.join(", ")})
            VALUES (${params.join(", ")})
            RETURNING ${leadIdColumn} AS lead_id
            `,
            values
          );
          leadId = insertRes.rows[0]?.lead_id || null;
        }

        if (!leadId) {
          await client.query("ROLLBACK");
          return json(500, { ok: false, message: "No se pudo crear lead" });
        }

        const statusRes = await client.query(
          `
          SELECT 1
          FROM lead_contact_status
          WHERE contact_id = $1 AND batch_id = $2
          LIMIT 1
          `,
          [leadId, batchId]
        );
        if (statusRes.rows.length) {
          await client.query(
            `
            UPDATE lead_contact_status
            SET estado_venta = 'nuevo',
                intentos = COALESCE(intentos, 0),
                assigned_to = $3,
                ola_actual = COALESCE(ola_actual, 1),
                ultimo_intento_at = now(),
                updated_at = now()
            WHERE contact_id = $1 AND batch_id = $2
            `,
            [leadId, batchId, dbUser?.id || null]
          );
        } else {
          await client.query(
            `
            INSERT INTO lead_contact_status (
              contact_id,
              estado_venta,
              intentos,
              proxima_accion,
              batch_id,
              assigned_to,
              ola_actual,
              ultimo_intento_at
            )
            VALUES ($1, 'nuevo', 0, NULL, $2, $3, 1, now())
            ON CONFLICT (contact_id) DO UPDATE
            SET
              estado_venta = 'nuevo',
              intentos = COALESCE(lead_contact_status.intentos, 0),
              proxima_accion = NULL,
              batch_id = EXCLUDED.batch_id,
              assigned_to = EXCLUDED.assigned_to,
              ola_actual = COALESCE(lead_contact_status.ola_actual, 1),
              ultimo_intento_at = now(),
              updated_at = now()
            `,
            [leadId, batchId, dbUser?.id || null]
          );
        }

        await client.query("COMMIT");

        return json(200, {
          ok: true,
          success: true,
          lead_id: leadId,
          batch_id: batchId,
          status: "nuevo"
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create lead",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.match(/\/leads\/([^/]+)$/)) {
    const match = path.match(/\/leads\/([^/]+)$/);
    const leadId = match?.[1];
    if (!leadId) {
      return json(400, { ok: false, message: "Lead id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const leadRes = await client.query(
          `
          SELECT
            d.id,
            d.nombre,
            d.apellido,
            d.documento,
            d.telefono,
            d.celular,
            d.departamento,
            d.direccion,
            d.localidad,
            d.origen_dato,
            d.estado,
            d.created_at,
            lcs.estado_venta,
            lcs.intentos,
            lcs.proxima_accion,
            lcs.batch_id,
            lcs.assigned_to,
            lb.nombre AS batch_nombre,
            u.nombre AS assigned_nombre,
            u.apellido AS assigned_apellido
          FROM datos_para_trabajar d
          LEFT JOIN lead_contact_status lcs ON lcs.contact_id = d.id
          LEFT JOIN lead_batches lb ON lb.id = lcs.batch_id
          LEFT JOIN users u ON u.id = lcs.assigned_to
          WHERE d.id = $1
          LIMIT 1
          `,
          [leadId]
        );

        if (!leadRes.rows.length) {
          return json(404, { ok: false, message: "Lead not found" });
        }

        const lead = leadRes.rows[0];
        const historyRes = await client.query(
          `
          SELECT
            lm.id,
            lm.resultado,
            lm.nota,
            lm.fecha_gestion,
            lm.proxima_accion,
            u.nombre AS user_nombre,
            u.apellido AS user_apellido
          FROM lead_management_history lm
          LEFT JOIN users u ON u.id = lm.user_id
          WHERE lm.contact_id = $1
          ORDER BY lm.fecha_gestion DESC
          LIMIT 20
          `,
          [leadId]
        );

        const assignedTo = [lead.assigned_nombre, lead.assigned_apellido].filter(Boolean).join(" ").trim();
        const history = historyRes.rows.map((row) => ({
          id: row.id,
          status: row.resultado,
          note: row.nota,
          at: row.fecha_gestion,
          by: [row.user_nombre, row.user_apellido].filter(Boolean).join(" ").trim()
        }));

        const leadPayload = {
            id: lead.id,
            nombre: lead.nombre,
            apellido: lead.apellido,
            documento: lead.documento,
            telefono: lead.telefono,
            celular: lead.celular,
            departamento: lead.departamento,
            direccion: lead.direccion,
            localidad: lead.localidad,
            origen_dato: lead.origen_dato,
            estado: lead.estado || "nuevo",
            created_at: lead.created_at,
            estado_venta: lead.estado_venta || "nuevo",
            intentos: Number(lead.intentos || 0),
            proxima_accion: lead.proxima_accion,
            batch_id: lead.batch_id,
            batch_nombre: lead.batch_nombre,
            assigned_to: lead.assigned_to,
            assigned_to_name: assignedTo,
            history
          };

        return json(200, {
          ok: true,
          success: true,
          lead: leadPayload,
          data: { lead: leadPayload },
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load lead",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.match(/\/leads\/([^/]+)\/familiares$/)) {
    const match = path.match(/\/leads\/([^/]+)\/familiares$/);
    const leadId = match?.[1];
    if (!leadId) {
      return json(400, { ok: false, message: "Lead id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const leadCols = await getLeadContactColumns(client);
        const dCols = leadCols?.d || new Set();
        const hasContactIdCol = dCols.has("contact_id");

        const leadRes = await client.query(
          `
          SELECT id, nombre, apellido, telefono, celular, ${hasContactIdCol ? "contact_id" : "NULL::uuid AS contact_id"}
          FROM datos_para_trabajar
          WHERE id = $1
          LIMIT 1
          `,
          [leadId]
        );

        const lead = leadRes.rows[0];
        if (!lead) {
          return json(404, { ok: false, message: "Lead not found" });
        }

        const contactId = lead.contact_id || null;

        const normalizeDigits = (value) => String(value || "").replace(/\D/g, "");
        const isDummyNumber = (value) => {
          const digits = normalizeDigits(value);
          if (!digits || digits.length < 8) return true;
          if (/^0+$/.test(digits)) return true;
          if (/^(0?9)+$/.test(digits)) return true; // common dummy 099999999, 09999999
          if (/^(\d)\1+$/.test(digits)) return true;
          return false;
        };

        if (!contactId) {
          return json(200, { ok: true, success: true, data: { items: [] } });
        }

        const contactRes = await client.query(
          `
          SELECT id, nombre, apellido, telefono, celular, documento, status
          FROM contacts
          WHERE id = $1
          LIMIT 1
          `,
          [contactId]
        );
        const contact = contactRes.rows[0];
        if (!contact) {
          return json(200, { ok: true, success: true, data: { items: [] } });
        }

        const relationsRes = await client.query(
          `
          SELECT
            CASE WHEN cr.contact_id_a = $1 THEN cr.contact_id_b
                 ELSE cr.contact_id_a END AS related_contact_id,
            cr.relation
          FROM contact_relations cr
          WHERE cr.contact_id_a = $1 OR cr.contact_id_b = $1
          `,
          [contactId]
        );
        const relationByContactId = new Map();
        const relatedIds = [];
        for (const row of relationsRes.rows) {
          const relId = row.related_contact_id;
          if (!relId || relId === contactId) continue;
          if (!relationByContactId.has(relId)) {
            relationByContactId.set(relId, row.relation || null);
            relatedIds.push(relId);
          }
        }

        let relatedContacts = [];
        if (relatedIds.length) {
          const relatedRes = await client.query(
            `
            SELECT id, nombre, apellido, telefono, celular, documento
            FROM contacts
            WHERE id = ANY($1)
              AND id <> $2
              AND status = 'activo'
            `,
            [relatedIds, contactId]
          );
          relatedContacts = relatedRes.rows || [];
        }

        const telefono = normalizeText(contact.telefono || "");
        const celular = normalizeText(contact.celular || "");
        const basePhones = [telefono, celular].filter(Boolean).filter((v) => !isDummyNumber(v));
        let phoneFallback = [];
        if (basePhones.length) {
          const phone1 = basePhones[0] || "";
          const phone2 = basePhones[1] || phone1;
          const fallbackRes = await client.query(
            `
            SELECT id, nombre, apellido, telefono, celular, documento
            FROM contacts
            WHERE (telefono = $1 OR celular = $1 OR telefono = $2 OR celular = $2)
              AND id <> $3
              AND status = 'activo'
            `,
            [phone1, phone2, contactId]
          );
          phoneFallback = fallbackRes.rows || [];
        }

        const items = [];
        const seen = new Set();
        const pushUnique = (row) => {
          if (isDummyNumber(row.telefono) && isDummyNumber(row.celular)) return;
          const key = [
            row.nombre || "",
            row.apellido || "",
            row.telefono || "",
            row.celular || ""
          ].join("|");
          if (seen.has(key)) return;
          seen.add(key);
          items.push({
            id: row.id,
            nombre: row.nombre || null,
            apellido: row.apellido || null,
            telefono: row.telefono || null,
            celular: row.celular || null,
            documento: row.documento || null,
            relation: relationByContactId.get(row.id) || null
          });
        };

        for (const row of relatedContacts) pushUnique(row);
        for (const row of phoneFallback) pushUnique(row);

        return json(200, {
          ok: true,
          success: true,
          data: { items }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load familiares",
        error: error.message
      });
    }
  }

  if (method === "PUT" && path.match(/\/leads\/([^/]+)$/)) {
    const match = path.match(/\/leads\/([^/]+)$/);
    const leadId = match?.[1];
    const body = safeParseBody(event);
    if (!leadId) {
      return json(400, { ok: false, message: "Lead id requerido" });
    }
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const leadCols = await getLeadContactColumns(client);
        const dCols = leadCols?.d || new Set();
        const hasContactIdCol = dCols.has("contact_id");

        const leadRes = await client.query(
          `SELECT * FROM datos_para_trabajar WHERE id = $1 LIMIT 1`,
          [leadId]
        );
        const existing = leadRes.rows[0];
        if (!existing) {
          return json(404, { ok: false, message: "Lead not found" });
        }

        const hasField = (key) => Object.prototype.hasOwnProperty.call(body || {}, key);
        const normTextOrNull = (val) => {
          const t = normalizeText(val);
          return t ? t : null;
        };

        const updates = [];
        const values = [];
        let idx = 1;
        const push = (col, val) => {
          if (val === undefined) return;
          updates.push(`${col} = $${idx}`);
          values.push(val);
          idx += 1;
        };

        push("nombre", hasField("nombre") ? normTextOrNull(body?.nombre) : undefined);
        push("apellido", hasField("apellido") ? normTextOrNull(body?.apellido) : undefined);
        push("telefono", hasField("telefono") ? normTextOrNull(body?.telefono) : undefined);
        push("celular", hasField("celular") ? normTextOrNull(body?.celular) : undefined);
        push("documento", hasField("documento") ? normTextOrNull(body?.documento) : undefined);
        push("direccion", hasField("direccion") ? normTextOrNull(body?.direccion) : undefined);
        push("departamento", hasField("departamento") ? normTextOrNull(body?.departamento) : undefined);
        push("localidad", hasField("localidad") ? normTextOrNull(body?.localidad) : undefined);

        if (!updates.length) {
          return json(200, { ok: true, success: true, lead: existing, data: { lead: existing }, error: null });
        }

        await client.query(
          `
          UPDATE datos_para_trabajar
          SET ${updates.join(", ")}, updated_at = now()
          WHERE id = $${idx}
          `,
          [...values, leadId]
        );

        // Sync celular (and other contact fields if provided) to contacts when possible
        const shouldSyncContact =
          hasField("celular") || hasField("telefono") || hasField("nombre") || hasField("apellido") || hasField("documento");
        if (shouldSyncContact) {
          let contactWhere = null;
          let contactValues = [];
          let cIdx = 1;
          if (hasContactIdCol && existing.contact_id) {
            contactWhere = `id = $${cIdx}`;
            contactValues.push(existing.contact_id);
            cIdx += 1;
          } else if ((hasField("documento") ? normTextOrNull(body?.documento) : existing.documento)) {
            contactWhere = `documento = $${cIdx}`;
            contactValues.push(hasField("documento") ? normTextOrNull(body?.documento) : existing.documento);
            cIdx += 1;
          }

          if (contactWhere) {
            const contactUpdates = [];
            const contactSetValues = [];
            let sIdx = cIdx;
            const pushContact = (col, val) => {
              if (val === undefined) return;
              contactUpdates.push(`${col} = $${sIdx}`);
              contactSetValues.push(val);
              sIdx += 1;
            };
            pushContact("celular", hasField("celular") ? normTextOrNull(body?.celular) : undefined);
            pushContact("telefono", hasField("telefono") ? normTextOrNull(body?.telefono) : undefined);
            pushContact("nombre", hasField("nombre") ? normTextOrNull(body?.nombre) : undefined);
            pushContact("apellido", hasField("apellido") ? normTextOrNull(body?.apellido) : undefined);
            pushContact("documento", hasField("documento") ? normTextOrNull(body?.documento) : undefined);
            if (contactUpdates.length) {
              await client.query(
                `
                UPDATE contacts
                SET ${contactUpdates.join(", ")}, updated_at = now()
                WHERE ${contactWhere}
                `,
                [...contactValues, ...contactSetValues]
              );
            }
          }
        }

        const refreshed = await client.query(
          `SELECT * FROM datos_para_trabajar WHERE id = $1 LIMIT 1`,
          [leadId]
        );
        const updatedLead = refreshed.rows[0] || existing;

        return json(200, {
          ok: true,
          success: true,
          lead: updatedLead,
          data: { lead: updatedLead },
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to update lead",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.match(/\/leads\/([^/]+)\/management$/)) {
    const match = path.match(/\/leads\/([^/]+)\/management$/);
    const leadId = match?.[1];
    const body = safeParseBody(event);
    if (!leadId) {
      return json(400, { ok: false, message: "Lead id requerido" });
    }
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      console.log("[management] method:", method, "path:", path);
      console.log("[management] dbUser:", JSON.stringify({
        id: dbUser?.id,
        role_key: dbUser?.role_key,
        sub: dbUser?.sub
      }));

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const resultadoInput = normalizeLeadResultado(body?.status || body?.resultado);
      const nota = normalizeText(body?.note || body?.nota || "");
      const proximaAccion = normalizeNextAction(body?.nextAction || body?.proxima_accion);
      const fechaAgenda = normalizeNextAction(body?.fecha_agenda || body?.fechaAgenda);

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");

        const currentStatusRes = await client.query(
          `
          SELECT intentos, batch_id, assigned_to, estado_venta, ola_actual
          FROM lead_contact_status
          WHERE contact_id = $1
            AND assigned_to = $2
          LIMIT 1
          `,
          [leadId, dbUser.id]
        );

        if (!currentStatusRes.rows.length) {
          await client.query("ROLLBACK");
          return json(404, {
            ok: false,
            success: false,
            data: null,
            error: {
              message: "Contacto no encontrado en tu lote"
            }
          });
        }

        const currentAttempts = currentStatusRes.rows[0]?.intentos || 0;
        const nextAttempts = currentAttempts + 1;
        const batchId = currentStatusRes.rows[0]?.batch_id || null;
        const assignedTo = currentStatusRes.rows[0]?.assigned_to || dbUser?.id || null;
        const currentEstadoVenta = currentStatusRes.rows[0]?.estado_venta || null;
        const currentOla = currentStatusRes.rows[0]?.ola_actual || 1;

        const validationErrors = [];

        if (!resultadoInput || resultadoInput === "nuevo") {
          validationErrors.push({ field: "estado_venta", message: "Estado invï¿½lido" });
        }

        const desiredCatalog = await getLeadStatusCatalogEntry(client, resultadoInput);
        if (!desiredCatalog) {
          validationErrors.push({ field: "estado_venta", message: "Estado no existe en catï¿½logo" });
        }

        if (resultadoInput === "seguimiento" && !fechaAgenda) {
          validationErrors.push({ field: "fecha_agenda", message: "fecha_agenda requerida para seguimiento" });
        }

        if (currentEstadoVenta) {
          // Venta y dato_erroneo son siempre finales
          const estadosFinalesPermanentes = ["venta", "dato_erroneo"];
          if (estadosFinalesPermanentes.includes(currentEstadoVenta)) {
            const latestGestion = await client.query(
              `
              SELECT id
              FROM lead_management_history
              WHERE contact_id = $1
              ORDER BY fecha_gestion DESC
              LIMIT 1
              `,
              [leadId]
            );
            const existingGestionId = latestGestion.rows[0]?.id ?? null;
            await client.query("ROLLBACK");
            return json(409, {
              ok: false,
              success: false,
              data: { gestion_id: existingGestionId },
              error: {
                message: "Contacto ya estï¿½ en estado final",
                estado_actual: currentEstadoVenta
              }
            });
          }

          // Rechazo solo se puede corregir el mismo dï¿½a
          if (currentEstadoVenta === "rechazo") {
            const ultimaGestionRes = await client.query(
              `
              SELECT (fecha_gestion AT TIME ZONE 'America/Montevideo')::date AS fecha_uy
              FROM lead_management_history
              WHERE contact_id = $1
                AND user_id = $2
              ORDER BY fecha_gestion DESC
              LIMIT 1
              `,
              [contactId, userId]
            );

            const fechaUltimaGestion = ultimaGestionRes.rows[0]?.fecha_uy;
            const hoy = new Date().toLocaleDateString("en-CA", { timeZone: "America/Montevideo" });

            if (!fechaUltimaGestion || fechaUltimaGestion.toString() !== hoy) {
              await client.query("ROLLBACK");
              return json(409, {
                ok: false,
                success: false,
                data: null,
                error: {
                  message: "El rechazo solo puede corregirse el mismo dï¿½a",
                  estado_actual: currentEstadoVenta
                }
              });
            }
          }
        }

        if (validationErrors.length) {
          await client.query("ROLLBACK");
          return json(422, {
            ok: false,
            success: false,
            data: null,
            error: {
              message: "Validaciï¿½n",
              errors: validationErrors
            }
          });
        }

        let effectiveResultado = resultadoInput;
        let nuevaOla = currentOla;
        if (effectiveResultado === "no_contesta" && currentOla === 1) {
          nuevaOla = 2;
        }

        const mgmtResult = await client.query(
          `
          INSERT INTO lead_management_history (
            contact_id,
            batch_id,
            user_id,
            resultado,
            nota,
            fecha_gestion,
            proxima_accion
          )
          VALUES ($1, $2, $3, $4, $5, now(), $6)
          RETURNING id
          `,
          [leadId, batchId, dbUser?.id || null, effectiveResultado, nota || null, proximaAccion]
        );
        const gestionId = mgmtResult.rows[0]?.id ?? null;

        const updateLeadStatus = await client.query(
          `
          UPDATE lead_contact_status
          SET estado_venta = $2,
              intentos = $3,
              proxima_accion = $4,
              assigned_to = $6,
              ola_actual = $7,
              ultimo_intento_at = now(),
              updated_at = now()
          WHERE contact_id = $1
            AND batch_id = $5
          RETURNING contact_id
          `,
          [leadId, effectiveResultado, nextAttempts, proximaAccion, batchId, assignedTo, nuevaOla]
        );
        if (!updateLeadStatus.rows.length) {
          await client.query(
            `
            INSERT INTO lead_contact_status (
              contact_id,
              estado_venta,
              intentos,
              proxima_accion,
              batch_id,
              assigned_to,
              ola_actual,
              ultimo_intento_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, now())
            ON CONFLICT (contact_id) DO UPDATE
            SET
              estado_venta = EXCLUDED.estado_venta,
              intentos = EXCLUDED.intentos,
              proxima_accion = EXCLUDED.proxima_accion,
              batch_id = EXCLUDED.batch_id,
              assigned_to = EXCLUDED.assigned_to,
              ola_actual = EXCLUDED.ola_actual,
              ultimo_intento_at = now(),
              updated_at = now()
            `,
            [leadId, effectiveResultado, nextAttempts, proximaAccion, batchId, assignedTo, nuevaOla]
          );
        }

        if (["rechazo", "venta", "dato_erroneo"].includes(effectiveResultado)) {
          await client.query(
            `
            UPDATE lead_agenda
            SET cumplida = true
            WHERE contact_id = $1
              AND batch_id = $2
              AND cumplida = false
            `,
            [leadId, batchId]
          );
        }

        if ((effectiveResultado === "seguimiento" || effectiveResultado === "rellamar") && fechaAgenda) {
          const agendaRes = await client.query(
            `
            SELECT id
            FROM lead_agenda
            WHERE contact_id = $1
              AND batch_id = $2
              AND cumplida = false
            ORDER BY created_at DESC
            LIMIT 1
            `,
            [leadId, batchId]
          );

          if (agendaRes.rows.length) {
            const agendaId = agendaRes.rows[0].id;
            await client.query(
              `
              UPDATE lead_agenda
              SET fecha_agenda = $2,
                  nota = $3,
                  seller_id = $4
              WHERE id = $1
              `,
              [agendaId, fechaAgenda, nota || null, assignedTo]
            );
          } else {
            await client.query(
              `
              INSERT INTO lead_agenda (
                contact_id,
                seller_id,
                batch_id,
                fecha_agenda,
                nota
              )
              VALUES ($1, $2, $3, $4, $5)
              `,
              [leadId, assignedTo, batchId, fechaAgenda, nota || null]
            );
          }
        }

        await client.query(
          `
          UPDATE datos_para_trabajar
          SET estado = 'trabajado', updated_at = now()
          WHERE id = $1 AND estado <> 'bloqueado'
          `,
          [leadId]
        );

        await client.query("COMMIT");

        const summary = await getTeamSummary(client, formatDateYmd(new Date()), new Date());
        await emitRealtime("new_call", {
          agente_id: dbUser?.id || null,
          llamada: {
            resultado: effectiveResultado
          }
        });
        await emitRealtime("team_update", summary);

        return json(200, {
          ok: true,
          success: true,
          data: { resultado: effectiveResultado, intentos: nextAttempts, gestion_id: gestionId },
          error: null
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to register lead management",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/agenda")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const sellerIdParam = getQueryParam(event, "seller_id");
      const dateParam = getQueryParam(event, "fecha");
      const incluirCumplidas = getQueryParam(event, "incluir_cumplidas") === "true";
      const sellerId = dbUser?.role_key === "vendedor" ? dbUser.id : (sellerIdParam || dbUser.id);
      console.log("[agenda] dbUser.id:", dbUser?.id);
      console.log("[agenda] dbUser.role_key:", dbUser?.role_key);
      console.log("[agenda] sellerIdParam:", sellerIdParam);
      console.log("[agenda] sellerId usado en query:", sellerId);

      const values = [sellerId];
      const whereParts = ["a.seller_id = $1"];
      let idx = 2;

      if (dateParam) {
        whereParts.push(`a.fecha_agenda::date = $${idx}::date`);
      }
      if (!incluirCumplidas) {
        whereParts.push("a.cumplida = false");
      }

      const whereClause = `WHERE ${whereParts.join(" AND ")}`;

      const client = createDbClient();
      await client.connect();
      try {
        const res = await client.query(
          `
          SELECT
            a.id,
            a.contact_id,
            a.seller_id,
            a.batch_id,
            a.fecha_agenda,
            a.nota,
            a.cumplida,
            d.nombre,
            d.apellido,
            d.telefono,
            d.celular,
            d.documento,
            d.fecha_nacimiento,
            DATE_PART('year', AGE(d.fecha_nacimiento))::int AS edad,
            d.departamento,
            d.localidad,
            d.email AS correo_electronico,
            d.origen_dato,
            d.created_at,
            lcs.intentos,
            lcs.estado_venta,
            (
              SELECT lmh.resultado
              FROM lead_management_history lmh
              WHERE lmh.contact_id = a.contact_id
                AND lmh.batch_id = a.batch_id
                AND lmh.resultado IN ('seguimiento', 'rellamar')
              ORDER BY lmh.fecha_gestion DESC
              LIMIT 1
            ) AS tipo_agenda,
            (
              SELECT JSON_AGG(
                JSON_BUILD_OBJECT(
                  'resultado', lmh.resultado,
                  'nota', lmh.nota,
                  'fecha', lmh.fecha_gestion
                ) ORDER BY lmh.created_at DESC
              )
              FROM lead_management_history lmh
              WHERE lmh.contact_id = a.contact_id
                AND lmh.batch_id = a.batch_id
            ) AS historial
          FROM lead_agenda a
          JOIN datos_para_trabajar d ON d.id = a.contact_id
          LEFT JOIN lead_contact_status lcs
            ON lcs.contact_id = a.contact_id
            AND lcs.batch_id = a.batch_id
          ${whereClause}
          ORDER BY a.fecha_agenda ASC
          `,
          values
        );

        return json(200, {
          ok: true,
          success: true,
          data: { items: res.rows },
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load agenda",
        error: error.message
      });
    }
  }

  if (method === "PATCH" && path.match(/\/agenda\/([^/]+)\/complete$/)) {
    const match = path.match(/\/agenda\/([^/]+)\/complete$/);
    const agendaId = match?.[1];
    if (!agendaId) {
      return json(400, { ok: false, message: "Agenda id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        await client.query(
          `
          UPDATE lead_agenda
          SET cumplida = true
          WHERE id = $1
          `,
          [agendaId]
        );

        return json(200, {
          ok: true,
          success: true,
          data: { id: agendaId, cumplida: true },
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to update agenda",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/lead-batches")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const values = [];
        const orgFilter = organizationId ? "WHERE lb.organization_id = $1" : "";
        if (organizationId) values.push(organizationId);
        const result = await client.query(
          `
          SELECT
            lb.*,
            u.nombre AS assigned_nombre,
            u.apellido AS assigned_apellido,
            COALESCE(cnt.total, 0) AS total_contactos,
            COALESCE(vnd.vendedores, '[]') AS vendedores
          FROM lead_batches lb
          LEFT JOIN users u ON u.id = lb.asignado_a
          LEFT JOIN (
            SELECT batch_id, COUNT(*) AS total
            FROM lead_batch_contacts
            GROUP BY batch_id
          ) cnt ON cnt.batch_id = lb.id
          LEFT JOIN (
            SELECT
              lbs.batch_id,
              JSON_AGG(
                JSON_BUILD_OBJECT(
                  'id', u.id,
                  'nombre', u.nombre,
                  'apellido', u.apellido,
                  'email', u.email,
                  'total_contactos', COALESCE(vc.total, 0),
                  'gestionados', COALESCE(vc.gestionados, 0)
                )
              ) AS vendedores
            FROM lead_batch_sellers lbs
            JOIN users u ON u.id = lbs.seller_id
            LEFT JOIN (
              SELECT
                batch_id,
                assigned_to,
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE estado_venta != 'nuevo') AS gestionados
              FROM lead_contact_status
              GROUP BY batch_id, assigned_to
            ) vc ON vc.batch_id = lbs.batch_id AND vc.assigned_to = lbs.seller_id
            GROUP BY lbs.batch_id
          ) vnd ON vnd.batch_id = lb.id
          ${orgFilter}
          ORDER BY lb.created_at DESC
          `,
          values
        );
        console.log('[lead-batches] primer item tipo:', result.rows[0]?.tipo);
        const items = result.rows.map((row) => {
          const totalContactos = Number.parseInt(row.total_contactos, 10) || 0;
          let vendedores = row.vendedores || [];
          if (typeof vendedores === "string") {
            try {
              vendedores = JSON.parse(vendedores);
            } catch {
              vendedores = [];
            }
          }
          return {
            id: row.id,
            nombre: row.nombre,
            tipo: row.tipo,
            estado: row.estado,
            seller_id: row.seller_id,
            max_intentos: row.max_intentos,
            fecha_vencimiento: row.fecha_vencimiento,
            criterios: row.criterios,
            franja_ola1_inicio: row.franja_ola1_inicio,
            franja_ola1_fin: row.franja_ola1_fin,
            franja_ola2_inicio: row.franja_ola2_inicio,
            franja_ola2_fin: row.franja_ola2_fin,
            dias_entre_olas: row.dias_entre_olas,
            created_at: row.created_at,
            assigned_to_name: [row.assigned_nombre, row.assigned_apellido].filter(Boolean).join(" ").trim(),
            total_contactos: totalContactos,
            cantidad_contactos: totalContactos,
            vendedores
          };
        });
        return json(200, {
          ok: true,
          success: true,
          items,
          data: { items },
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list lead batches",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.match(/\/lead-batches\/([^/]+)\/metrics$/)) {
    const match = path.match(/\/lead-batches\/([^/]+)\/metrics$/);
    const batchId = match?.[1];
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const statusValues = [batchId];
        const statusOrgClause = organizationId ? "AND organization_id = $2" : "";
        if (organizationId) statusValues.push(organizationId);
        const statusRes = await client.query(
          `
          SELECT estado_venta, ola_actual, COUNT(*)::int AS total
          FROM lead_contact_status
          WHERE batch_id = $1
          ${statusOrgClause}
          GROUP BY estado_venta, ola_actual
          ORDER BY ola_actual, estado_venta
          `,
          statusValues
        );
        const totalValues = [batchId];
        const totalOrgClause = organizationId ? "AND organization_id = $2" : "";
        if (organizationId) totalValues.push(organizationId);
        const totalRes = await client.query(
          `
          SELECT COUNT(*)::int AS total
          FROM lead_batch_contacts
          WHERE batch_id = $1
          ${totalOrgClause}
          `,
          totalValues
        );
        return json(200, {
          ok: true,
          success: true,
          data: {
            total_contactos: totalRes.rows[0]?.total || 0,
            estados: statusRes.rows
          },
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load lead batch metrics",
        error: error.message
      });
    }
  }

  if (method === "GET" && path === "/sellers") {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const values = [];
        const whereClause = organizationId ? "WHERE s.organization_id = $1" : "";
        if (organizationId) values.push(organizationId);
        const result = await client.query(
          `
          SELECT
            s.id,
            s.nombre,
            s.apellido,
            u.email
          FROM sellers s
          LEFT JOIN users u ON u.id = s.user_id
          ${whereClause}
          ORDER BY s.nombre
          `,
          values
        );
        return json(200, {
          ok: true,
          success: true,
          data: result.rows,
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list sellers",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/lead-sources")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const values = [];
        const orgClause = organizationId ? "AND organization_id = $1" : "";
        if (organizationId) values.push(organizationId);
        const result = await client.query(
          `
          SELECT DISTINCT origen_dato AS id, origen_dato AS nombre
          FROM datos_para_trabajar
          WHERE origen_dato IS NOT NULL
            AND origen_dato <> ''
            AND estado = 'nuevo'
            ${orgClause}
          ORDER BY origen_dato
          `,
          values
        );
        return json(200, {
          ok: true,
          success: true,
          data: result.rows,
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list lead sources",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/departamentos")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const values = [];
        const orgClause = organizationId ? "AND organization_id = $1" : "";
        if (organizationId) values.push(organizationId);
        const result = await client.query(
          `
          SELECT DISTINCT departamento AS id, departamento AS nombre
          FROM datos_para_trabajar
          WHERE departamento IS NOT NULL
            AND departamento <> ''
            AND estado = 'nuevo'
            ${orgClause}
          ORDER BY departamento
          `,
          values
        );
        return json(200, {
          ok: true,
          success: true,
          data: result.rows,
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list departamentos",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/localidades")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const departamento = getQueryParam(event, "departamento");
      const values = [];
      let where = `
        localidad IS NOT NULL
        AND localidad <> ''
        AND estado = 'nuevo'
      `;
      if (departamento) {
        where += ` AND departamento = $1`;
        values.push(departamento);
      }
      if (organizationId) {
        values.push(organizationId);
        where += ` AND organization_id = $${values.length}`;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `
          SELECT DISTINCT localidad AS id, localidad AS nombre
          FROM datos_para_trabajar
          WHERE ${where}
          ORDER BY localidad
          `,
          values
        );
        return json(200, {
          ok: true,
          success: true,
          data: result.rows,
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list localidades",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/area-codes")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const values = [];
        const orgClause = organizationId ? "AND organization_id = $1" : "";
        if (organizationId) values.push(organizationId);
        const result = await client.query(
          `
          SELECT DISTINCT code AS id, code AS nombre
          FROM (
            SELECT SUBSTRING(regexp_replace(celular, '\\D', '', 'g') FROM 1 FOR 2) AS code
            FROM datos_para_trabajar
            WHERE celular IS NOT NULL
              AND celular <> ''
              AND estado = 'nuevo'
              AND LENGTH(regexp_replace(celular, '\\D', '', 'g')) >= 8
              ${orgClause}
            UNION
            SELECT SUBSTRING(regexp_replace(telefono, '\\D', '', 'g') FROM 1 FOR 2) AS code
            FROM datos_para_trabajar
            WHERE telefono IS NOT NULL
              AND telefono <> ''
              AND estado = 'nuevo'
              AND LENGTH(regexp_replace(telefono, '\\D', '', 'g')) >= 8
              ${orgClause}
          ) t
          WHERE code IS NOT NULL AND code <> ''
          ORDER BY code
          `,
          values
        );
        return json(200, {
          ok: true,
          success: true,
          data: result.rows,
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list area codes",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/datos-para-trabajar/import-jobs")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const values = [];
        let whereClause = "WHERE status = 'completed'";
        if (organizationId) {
          values.push(organizationId);
          whereClause += " AND organization_id = $1";
        }
        const res = await client.query(
          `
          SELECT id, file_name, created_at
          FROM datos_para_trabajar_import_jobs
          ${whereClause}
          ORDER BY created_at DESC
          `,
          values
        );
        return json(200, { ok: true, items: res.rows });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list datos para trabajar import jobs",
        error: error.message
      });
    }
  }

  if (method === "GET" && (path.endsWith("/datos-para-trabajar/preview") || path.endsWith("/preview"))) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const conditions = ["estado = 'nuevo'"];
      const params = [];
      let i = 1;
      let orgParamIndex = null;

      const nombre = getQueryParam(event, "nombre");
      if (nombre) {
        conditions.push(`(nombre ILIKE $${i} OR apellido ILIKE $${i})`);
        params.push(`%${nombre}%`);
        i += 1;
      }

      const departamento = getQueryParam(event, "departamento");
      if (departamento) {

        const deptos = String(departamento).split(",").map((v) => v.trim()).filter(Boolean);
        if (deptos.length) {
          conditions.push(`departamento = ANY($${i})`);
          params.push(deptos);
          i += 1;
        }
      }

      const localidad = getQueryParam(event, "localidad");
      if (localidad) {
        const locs = String(localidad).split(",").map((v) => v.trim()).filter(Boolean);
        if (locs.length) {
          conditions.push(`localidad = ANY($${i})`);
          params.push(locs);
          i += 1;
        }
      }

      const origenDato = getQueryParam(event, "origen_dato");
      if (origenDato) {
        const origenes = String(origenDato).split(",").map((v) => v.trim()).filter(Boolean);
        if (origenes.length) {
          conditions.push(`origen_dato = ANY($${i})`);
          params.push(origenes);
          i += 1;
        }
      } else {
        // Por defecto, excluir datos de recupero en creaciÃ³n de lotes (solo CSV / guÃ­a telefÃ³nica)
        conditions.push(`(origen_dato IS NULL OR origen_dato = '' OR origen_dato = 'Guia telefonica')`);
      }

      if (organizationId) {
        conditions.push(`organization_id = $${i}`);
        params.push(organizationId);
        orgParamIndex = i;
        i += 1;
      }

      const edadDesde = getQueryParam(event, "edad_desde");
      if (edadDesde) {
        conditions.push(`DATE_PART('year', AGE(fecha_nacimiento)) >= $${i}`);
        params.push(parseInt(edadDesde, 10));
        i += 1;
      }

      const edadHasta = getQueryParam(event, "edad_hasta");
      if (edadHasta) {
        conditions.push(`DATE_PART('year', AGE(fecha_nacimiento)) <= $${i}`);
        params.push(parseInt(edadHasta, 10));
        i += 1;
      }

      const telefonoTipo = getQueryParam(event, "telefono_tipo");
      if (telefonoTipo) {
        if (telefonoTipo === "solo_celular") {
          conditions.push("celular IS NOT NULL AND celular <> '' AND (telefono IS NULL OR telefono = '')");
        } else if (telefonoTipo === "solo_fijo") {
          conditions.push("telefono IS NOT NULL AND telefono <> '' AND (celular IS NULL OR celular = '')");
        } else if (telefonoTipo === "ambos") {
          conditions.push("celular IS NOT NULL AND celular <> '' AND telefono IS NOT NULL AND telefono <> ''");
        }
      }

      const importJobId = getQueryParam(event, "import_job_id");
      if (importJobId) {
        conditions.push(`import_job_id = $${i}`);
        params.push(importJobId);
        i += 1;
      }

      const diasSinGestion = getQueryParam(event, "dias_sin_gestion");
      if (diasSinGestion) {
        conditions.push(`
          id NOT IN (
            SELECT DISTINCT contact_id
            FROM lead_management_history
            WHERE created_at >= NOW() - ($${i}::text || ' days')::interval
            ${orgParamIndex ? `AND organization_id = $${orgParamIndex}` : ""}
          )
        `);
        params.push(parseInt(diasSinGestion, 10));
        i += 1;
      }

      const where = conditions.join(" AND ");

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `SELECT COUNT(*)::int AS total FROM datos_para_trabajar WHERE ${where}`,
          params
        );
        return json(200, {
          ok: true,
          success: true,
          data: { total: result.rows[0]?.total || 0 },
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to preview datos para trabajar",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/datos-para-trabajar/list")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const conditions = ["estado = 'nuevo'"];
      const params = [];
      let i = 1;
      let orgParamIndex = null;

      const nombre = getQueryParam(event, "nombre");
      if (nombre) {
        conditions.push(`(nombre ILIKE $${i} OR apellido ILIKE $${i})`);
        params.push(`%${nombre}%`);
        i += 1;
      }

      const departamento = getQueryParam(event, "departamento");
      if (departamento) {
        const deptos = String(departamento).split(",").map((v) => v.trim()).filter(Boolean);
        if (deptos.length) {
          conditions.push(`departamento = ANY($${i})`);
          params.push(deptos);
          i += 1;
        }
      }

      const localidad = getQueryParam(event, "localidad");
      if (localidad) {
        const locs = String(localidad).split(",").map((v) => v.trim()).filter(Boolean);
        if (locs.length) {
          conditions.push(`localidad = ANY($${i})`);
          params.push(locs);
          i += 1;
        }
      }

      const origenDato = getQueryParam(event, "origen_dato");
      if (origenDato) {
        const origenes = String(origenDato).split(",").map((v) => v.trim()).filter(Boolean);
        if (origenes.length) {
          conditions.push(`origen_dato = ANY($${i})`);
          params.push(origenes);
          i += 1;
        }
      } else {
        // Por defecto, excluir datos de recupero en creaciÃ³n de lotes (solo CSV / guÃ­a telefÃ³nica)
        conditions.push(`(origen_dato IS NULL OR origen_dato = '' OR origen_dato = 'Guia telefonica')`);
      }

      if (organizationId) {
        conditions.push(`organization_id = $${i}`);
        params.push(organizationId);
        orgParamIndex = i;
        i += 1;
      }

      const edadDesde = getQueryParam(event, "edad_desde");
      if (edadDesde) {
        conditions.push(`DATE_PART('year', AGE(fecha_nacimiento)) >= $${i}`);
        params.push(parseInt(edadDesde, 10));
        i += 1;
      }

      const edadHasta = getQueryParam(event, "edad_hasta");
      if (edadHasta) {
        conditions.push(`DATE_PART('year', AGE(fecha_nacimiento)) <= $${i}`);
        params.push(parseInt(edadHasta, 10));
        i += 1;
      }

      const telefonoTipo = getQueryParam(event, "telefono_tipo");
      if (telefonoTipo) {
        if (telefonoTipo === "solo_celular") {
          conditions.push("celular IS NOT NULL AND celular <> '' AND (telefono IS NULL OR telefono = '')");
        } else if (telefonoTipo === "solo_fijo") {
          conditions.push("telefono IS NOT NULL AND telefono <> '' AND (celular IS NULL OR celular = '')");
        } else if (telefonoTipo === "ambos") {
          conditions.push("celular IS NOT NULL AND celular <> '' AND telefono IS NOT NULL AND telefono <> ''");
        }
      }

      const importJobId = getQueryParam(event, "import_job_id");
      if (importJobId) {
        conditions.push(`import_job_id = $${i}`);
        params.push(importJobId);
        i += 1;
      }

      const diasSinGestion = getQueryParam(event, "dias_sin_gestion");
      if (diasSinGestion) {
        conditions.push(`
          id NOT IN (
            SELECT DISTINCT contact_id
            FROM lead_management_history
            WHERE created_at >= NOW() - ($${i}::text || ' days')::interval
            ${orgParamIndex ? `AND organization_id = $${orgParamIndex}` : ""}
          )
        `);
        params.push(parseInt(diasSinGestion, 10));
        i += 1;
      }

      const limite = Math.min(5000, Math.max(1, parseInt(getQueryParam(event, "limite") || "50", 10)));
      const pagina = Math.max(1, parseInt(getQueryParam(event, "pagina") || "1", 10));
      const offset = (pagina - 1) * limite;
      const where = conditions.join(" AND ");

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `SELECT id, nombre, apellido, departamento, localidad, telefono, celular,
                  origen_dato AS fuente,
                  DATE_PART('year', AGE(fecha_nacimiento))::int AS edad
           FROM datos_para_trabajar
           WHERE ${where}
           ORDER BY id ASC
           LIMIT $${i} OFFSET $${i + 1}`,
          [...params, limite, offset]
        );
        return json(200, {
          success: true,
          data: { contactos: result.rows, pagina, limite }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list datos para trabajar for batch",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/lead-batches")) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const nombre = normalizeText(body?.nombre || body?.name);
      const sellerIdsRaw = Array.isArray(body?.sellerIds)
        ? body.sellerIds
        : Array.isArray(body?.seller_ids)
        ? body.seller_ids
        : null;
      const sellerId = body?.sellerId || body?.seller_id || null;
      const sellerIds = sellerIdsRaw && sellerIdsRaw.length ? sellerIdsRaw : (sellerId ? [sellerId] : []);

      if (!nombre || !sellerIds.length) {
        return json(422, {
          ok: false,
          success: false,
          data: null,
          error: {
            message: "nombre y sellerIds son requeridos"
          }
        });
      }

      const estado = normalizeText(body?.estado || "sin_asignar");
      const maxIntentosRaw = body?.max_intentos ?? body?.maxIntentos;
      const maxIntentos = Number.isFinite(Number(maxIntentosRaw))
        ? Math.max(1, Number(maxIntentosRaw))
        : 3;
      const fechaVencimiento = body?.fecha_vencimiento || body?.fechaVencimiento || null;
      let criteriosJson = body?.criterios ?? null;
      if (typeof criteriosJson === "string") {
        try {
          criteriosJson = JSON.parse(criteriosJson);
        } catch {
          criteriosJson = {};
        }
      }
      if (!criteriosJson) criteriosJson = {};
      const criterios = JSON.stringify(criteriosJson);
      const franjaOla1Inicio = body?.franja_ola1_inicio || body?.franjaOla1Inicio || '10:00';
      const franjaOla1Fin = body?.franja_ola1_fin || body?.franjaOla1Fin || '13:00';
      const franjaOla2Inicio = body?.franja_ola2_inicio || body?.franjaOla2Inicio || '17:00';
      const franjaOla2Fin = body?.franja_ola2_fin || body?.franjaOla2Fin || '20:00';
      const diasEntreOlasRaw = body?.dias_entre_olas ?? body?.diasEntreOlas ?? 1;
      const diasEntreOlas = Number.isFinite(Number(diasEntreOlasRaw))
        ? Math.max(0, Number(diasEntreOlasRaw))
        : 1;
      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");
        const result = await client.query(
          `
          INSERT INTO lead_batches (
            nombre,
            estado,
            created_by,
            seller_id,
            asignado_a,
            max_intentos,
            fecha_vencimiento,
            criterios,
            franja_ola1_inicio,
            franja_ola1_fin,
            franja_ola2_inicio,
            franja_ola2_fin,
            dias_entre_olas,
            organization_id
          )
          VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
          RETURNING *
          `,
          [
            nombre,
            estado,
            dbUser?.id || null,
            sellerIds[0] || null,
            maxIntentos,
            fechaVencimiento,
            criterios,
            franjaOla1Inicio,
            franjaOla1Fin,
            franjaOla2Inicio,
            franjaOla2Fin,
            diasEntreOlas,
            organizationId
          ]
        );
        const batchId = result.rows[0]?.id;
        for (const sid of sellerIds) {
          await client.query(
            `
            INSERT INTO lead_batch_sellers (batch_id, seller_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            `,
            [batchId, sid]
          );
        }
        await client.query("COMMIT");
        return json(201, {
          ok: true,
          success: true,
          data: { item: result.rows[0], sellerIds },
          error: null
        });
      } finally {
        await client.query("ROLLBACK").catch(() => {});
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create lead batch",
        error: error.message
      });
    }
  }

  if (method === "PUT" && path.match(/\/lead-batches\/([^/]+)$/)) {
    const match = path.match(/\/lead-batches\/([^/]+)$/);
    const batchId = match?.[1];
    const body = safeParseBody(event);
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const updates = [];
      const values = [];
      let idx = 1;

      if (body?.nombre) {
        updates.push(`nombre = $${idx}`);
        values.push(body.nombre);
        idx += 1;
      }

      if (body?.estado) {
        updates.push(`estado = $${idx}`);
        values.push(body.estado);
        idx += 1;
      }

      if (!updates.length) return json(200, { ok: true });

      const client = createDbClient();
      await client.connect();
      try {
        const updateValues = [...values, batchId];
        let orgClause = "";
        if (organizationId) {
          updateValues.push(organizationId);
          orgClause = `AND organization_id = $${updateValues.length}`;
        }
        await client.query(
          `
          UPDATE lead_batches
          SET ${updates.join(", ")}, updated_at = now()
          WHERE id = $${idx}
          ${orgClause}
          `,
          updateValues
        );
      } finally {
        await client.end();
      }
      return json(200, { ok: true, success: true, data: null, error: null });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to update lead batch",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.match(/\/lead-batches\/([^/]+)\/assign$/)) {
    const match = path.match(/\/lead-batches\/([^/]+)\/assign$/);
    const batchId = match?.[1];
    const body = safeParseBody(event);
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const sellerId = body?.sellerId || null;
      const sellerName = body?.sellerName || body?.seller_name || null;

      const client = createDbClient();
      await client.connect();
      try {
        let resolvedSellerId = sellerId;
        if (!resolvedSellerId && sellerName) {
          const userRes = await client.query(
            `SELECT id FROM users WHERE nombre ILIKE $1 OR email ILIKE $1 LIMIT 1`,
            [sellerName]
          );
          resolvedSellerId = userRes.rows[0]?.id || null;
        }

        if (resolvedSellerId) {
          await client.query(
            `
            INSERT INTO lead_batch_sellers (batch_id, seller_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            `,
            [batchId, resolvedSellerId]
          );
        }

        const updateValues = [resolvedSellerId, batchId];
        let updateOrgClause = "";
        if (organizationId) {
          updateValues.push(organizationId);
          updateOrgClause = `AND organization_id = $3`;
        }
        await client.query(
          `
          UPDATE lead_batches
          SET asignado_a = $1,
              seller_id = $1,
              estado = 'asignado',
              updated_at = now()
          WHERE id = $2
          ${updateOrgClause}
          `,
          updateValues
        );

        const statusValues = [resolvedSellerId, batchId];
        let statusOrgClause = "";
        let statusSubOrgClause = "";
        if (organizationId) {
          statusValues.push(organizationId);
          statusOrgClause = `AND lcs.organization_id = $3`;
          statusSubOrgClause = `AND organization_id = $3`;
        }
        await client.query(
          `
          UPDATE lead_contact_status lcs
          SET assigned_to = $1,
              batch_id = COALESCE(lcs.batch_id, $2),
              updated_at = now()
          WHERE lcs.contact_id IN (
            SELECT contact_id FROM lead_batch_contacts WHERE batch_id = $2
            ${statusSubOrgClause}
          )
          ${statusOrgClause}
          `,
          statusValues
        );
      } finally {
        await client.end();
      }

      return json(200, {
        ok: true,
        success: true,
        data: { batchId, sellerId: resolvedSellerId },
        error: null
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to assign lead batch",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.match(/\/lead-batches\/([^/]+)\/close$/)) {
    const match = path.match(/\/lead-batches\/([^/]+)\/close$/);
    const batchId = match?.[1];
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");

        const contactsValues = [batchId];
        let contactsOrgClause = "";
        let statusOrgClause = "";
        if (organizationId) {
          contactsValues.push(organizationId);
          contactsOrgClause = "AND lbc.organization_id = $2";
          statusOrgClause = "AND lcs.organization_id = $2";
        }
        const contactsRes = await client.query(
          `
          SELECT
            lbc.contact_id,
            lcs.estado_venta,
            c.es_final,
            c.libera_al_cerrar
          FROM lead_batch_contacts lbc
          LEFT JOIN lead_contact_status lcs ON lcs.contact_id = lbc.contact_id ${statusOrgClause}
          LEFT JOIN lead_status_catalog c ON c.nombre = lcs.estado_venta
          WHERE lbc.batch_id = $1
          ${contactsOrgClause}
          `,
          contactsValues
        );

        const rows = contactsRes.rows;
        const liberar = rows.filter((row) => row.libera_al_cerrar).map((row) => row.contact_id);
        const finales = rows.filter((row) => row.es_final).map((row) => row.contact_id);
        const seguimiento = rows.filter((row) => row.estado_venta === "seguimiento").map((row) => row.contact_id);

        if (liberar.length) {
          const liberarValues = [liberar];
          let liberarOrgClause = "";
          if (organizationId) {
            liberarValues.push(organizationId);
            liberarOrgClause = `AND organization_id = $2`;
          }
          await client.query(
            `
            UPDATE datos_para_trabajar
            SET estado = 'nuevo', updated_at = now()
            WHERE id = ANY($1::uuid[])
              AND estado <> 'bloqueado'
              ${liberarOrgClause}
            `,
            liberarValues
          );
        }

        const batchValues = [batchId];
        let batchOrgClause = "";
        if (organizationId) {
          batchValues.push(organizationId);
          batchOrgClause = `AND organization_id = $2`;
        }
        await client.query(
          `
          UPDATE lead_batches
          SET estado = 'finalizado', updated_at = now()
          WHERE id = $1
          ${batchOrgClause}
          `,
          batchValues
        );

        await client.query("COMMIT");

        return json(200, {
          ok: true,
          success: true,
          data: {
            batchId,
            total: rows.length,
            liberados: liberar.length,
            finales: finales.length,
            seguimiento: seguimiento.length
          },
          warning: seguimiento.length
            ? "Hay contactos en seguimiento; revisar agenda antes de cerrar definitivamente."
            : null,
          error: null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to close lead batch",
        error: error.message
      });
    }
  }

  // POST /lead-batches/:id/remove-seller
  // Body: { seller_id, mode: "specific"|"roundrobin"|"pool", new_seller_id? }
  if (method === "POST" && path.match(/\/lead-batches\/([^/]+)\/remove-seller$/)) {
    const match = path.match(/\/lead-batches\/([^/]+)\/remove-seller$/);
    const batchId = match?.[1];
    if (!batchId) return json(400, { ok: false, message: "Batch id requerido" });

    const body = safeParseBody(event);
    if (body === null) return json(400, { ok: false, message: "Invalid JSON body" });

    const sellerId = body?.seller_id || null;
    const mode = body?.mode || "specific";
    const newSellerId = body?.new_seller_id || null;

    if (!sellerId) return json(400, { ok: false, message: "seller_id es requerido" });
    if (mode === "specific" && !newSellerId) return json(400, { ok: false, message: "new_seller_id es requerido para mode=specific" });
    if (mode === "specific" && sellerId === newSellerId) return json(400, { ok: false, message: "El vendedor destino debe ser distinto al vendedor a retirar" });

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser); if (authError) return authError;
      let dbError = requireDbUser(event, dbUser); if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser); if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES); if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) return json(error.status, { ok: false, message: error.message });
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");

        const orgClause = organizationId ? ` AND organization_id = $4` : "";
        const orgParams = organizationId ? [organizationId] : [];

        // SIEMPRE: rellamar y seguimiento van al vendedor destino especÃ­fico (tienen contexto)
        // Solo aplica si hay new_seller_id (mode specific o roundrobin con destino)
        if (newSellerId) {
          await client.query(
            `UPDATE lead_contact_status
             SET assigned_to = $1, updated_at = now()
             WHERE batch_id = $2 AND assigned_to = $3
               AND estado_venta IN ('rellamar', 'seguimiento')${orgClause}`,
            [newSellerId, batchId, sellerId, ...orgParams]
          );
        }

        // nuevo y no_contesta segÃºn el mode elegido
        if (mode === "specific") {
          // Van al vendedor destino
          await client.query(
            `UPDATE lead_contact_status
             SET assigned_to = $1, updated_at = now()
             WHERE batch_id = $2 AND assigned_to = $3
               AND estado_venta IN ('nuevo', 'no_contesta')${orgClause}`,
            [newSellerId, batchId, sellerId, ...orgParams]
          );
        } else if (mode === "roundrobin") {
          // Distribuir en round-robin entre vendedores restantes del lote
          const sellersRes = await client.query(
            `SELECT lbs.seller_id FROM lead_batch_sellers lbs
             JOIN users u ON u.id = lbs.seller_id
             WHERE lbs.batch_id = $1
               AND lbs.seller_id != $2
               AND lower(coalesce(u.status, 'approved')) != 'pausado'
             ORDER BY lbs.seller_id ASC`,
            [batchId, sellerId]
          );
          const sellerIds = sellersRes.rows.map((r) => r.seller_id);
          if (sellerIds.length > 0) {
            const contactsRes = await client.query(
              `SELECT id FROM lead_contact_status
               WHERE batch_id = $1 AND assigned_to = $2
                 AND estado_venta IN ('nuevo', 'no_contesta')
               ORDER BY id ASC`,
              [batchId, sellerId]
            );
            for (let i = 0; i < contactsRes.rows.length; i += 1) {
              const destSeller = sellerIds[i % sellerIds.length];
              await client.query(
                `UPDATE lead_contact_status SET assigned_to = $1, updated_at = now() WHERE id = $2`,
                [destSeller, contactsRes.rows[i].id]
              );
            }
          }
        } else if (mode === "pool") {
          // Dejar sin asignar (assigned_to = null)
          await client.query(
            `UPDATE lead_contact_status
             SET assigned_to = NULL, updated_at = now()
             WHERE batch_id = $1 AND assigned_to = $2
               AND estado_venta IN ('nuevo', 'no_contesta')${orgClause.replace("$4", "$3")}`,
            [batchId, sellerId, ...orgParams]
          );
        }

        // Agregar nuevo vendedor a lead_batch_sellers si aplica
        if (newSellerId) {
          await client.query(
            `INSERT INTO lead_batch_sellers (batch_id, seller_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
            [batchId, newSellerId]
          );
        }

        // Retirar vendedor saliente
        const deleteParams = [batchId, sellerId];
        let orgLbsClause = "";
        if (organizationId) {
          deleteParams.push(organizationId);
          orgLbsClause = ` AND EXISTS (SELECT 1 FROM lead_batches lb WHERE lb.id = lead_batch_sellers.batch_id AND lb.organization_id = $3)`;
        }
        await client.query(
          `DELETE FROM lead_batch_sellers WHERE batch_id = $1 AND seller_id = $2${orgLbsClause}`,
          deleteParams
        );

        await client.query("COMMIT");
        return json(200, { ok: true, message: "Vendedor retirado correctamente" });
      } catch (err) {
        await client.query("ROLLBACK");
        return json(500, { ok: false, message: err.message });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: error.message });
    }
  }

  // POST /lead-batches/:id/add-seller
  // Body: { seller_id: uuid }
  if (method === "POST" && path.match(/\/lead-batches\/([^/]+)\/add-seller$/)) {
    const match = path.match(/\/lead-batches\/([^/]+)\/add-seller$/);
    const batchId = match?.[1];
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }

    const body = safeParseBody(event);
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    const sellerId = body?.seller_id || null;
    if (!sellerId) {
      return json(400, { ok: false, message: "seller_id es requerido" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const batchParams = [batchId];
        let orgBatchClause = "";
        if (organizationId) {
          batchParams.push(organizationId);
          orgBatchClause = " AND organization_id = $2";
        }
        const batchRes = await client.query(
          `SELECT id FROM lead_batches WHERE id = $1${orgBatchClause}`,
          batchParams
        );
        if (!batchRes.rows.length) {
          return json(404, { ok: false, message: "Lote no encontrado" });
        }

        await client.query(
          `INSERT INTO lead_batch_sellers (batch_id, seller_id)
           VALUES ($1, $2)
           ON CONFLICT DO NOTHING`,
          [batchId, sellerId]
        );
        return json(200, { ok: true, message: "Vendedor agregado al lote" });
      } catch (err) {
        return json(500, { ok: false, message: err.message });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to add seller to lead batch",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/lead-batches/assign")) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const contactIds = Array.isArray(body?.contactIds) ? body.contactIds : [];
      const batchId = body?.batchId || null;
      console.log("[assign] body recibido:", JSON.stringify(body));
      console.log("[assign] batchId:", batchId, "contactIds count:", contactIds?.length);

      if (!batchId || !contactIds.length) {
        return json(422, { ok: false, message: "batchId y contactIds requeridos" });
      }

      const client = createDbClient();
      await client.connect();
      try {
        const sellerValues = [batchId];
        const sellerOrgClause = "";
        const sellersRes = await client.query(
          `
          SELECT seller_id
          FROM lead_batch_sellers
          WHERE batch_id = $1
          ${sellerOrgClause}
          ORDER BY id ASC
          `,
          sellerValues
        );
        const sellers = sellersRes.rows.map((row) => row.seller_id);
        if (!sellers.length) {
          return json(422, {
            ok: false,
            success: false,
            data: null,
            error: {
              message: "El lote no tiene vendedores asignados"
            }
          });
        }

        const contactosValues = [contactIds];
        let contactosOrgClause = "";
        if (organizationId) {
          contactosValues.push(organizationId);
          contactosOrgClause = "AND organization_id = $2";
        }
        const contactosRes = await client.query(
          `
          SELECT id, estado
          FROM datos_para_trabajar
          WHERE id = ANY($1::uuid[])
          ${contactosOrgClause}
          `,
          contactosValues
        );

        const found = new Map(contactosRes.rows.map((row) => [row.id, row.estado]));
        const errors = [];

        for (const id of contactIds) {
          if (!found.has(id)) {
            errors.push({ id, reason: "no_existe" });
            continue;
          }
          const estado = found.get(id);
          if (estado === "bloqueado") {
            errors.push({ id, reason: "bloqueado" });
          } else if (estado !== "nuevo") {
            errors.push({ id, reason: "no_nuevo" });
          }
        }

        if (errors.length) {
          return json(422, {
            ok: false,
            success: false,
            data: null,
            error: {
              message: "Contactos invï¿½lidos para asignar",
              errors
            }
          });
        }

        await client.query("BEGIN");

        const batchValues = [sellers[0] || null, batchId];
        let batchOrgClause = "";
        if (organizationId) {
          batchValues.push(organizationId);
          batchOrgClause = "AND organization_id = $3";
        }
        await client.query(
          `
          UPDATE lead_batches
          SET asignado_a = $1,
              seller_id = $1,
              estado = 'asignado',
              updated_at = now()
          WHERE id = $2
          ${batchOrgClause}
          `,
          batchValues
        );

        const distribution = new Map();
        for (let i = 0; i < contactIds.length; i += 1) {
          const contactId = contactIds[i];
          const assignedTo = sellers[i % sellers.length];
          distribution.set(assignedTo, (distribution.get(assignedTo) || 0) + 1);

          await client.query(
            `
            INSERT INTO lead_batch_contacts (batch_id, contact_id, organization_id)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
            `,
            [batchId, contactId, organizationId]
          );

          const updateValues = [contactId, batchId, assignedTo];
          let updateOrgClause = "";
          if (organizationId) {
            updateValues.push(organizationId);
            updateOrgClause = "AND organization_id = $4";
          }
          const updateStatus = await client.query(
            `
            UPDATE lead_contact_status
            SET batch_id = $2,
                assigned_to = $3,
                estado_venta = 'nuevo',
                intentos = 0,
                updated_at = now()
            WHERE contact_id = $1
            ${updateOrgClause}
            RETURNING contact_id
            `,
            updateValues
          );
          if (!updateStatus.rows.length) {
            await client.query(
              `
              INSERT INTO lead_contact_status (
                contact_id,
                estado_venta,
                intentos,
                batch_id,
                assigned_to,
                organization_id
              )
              VALUES ($1, 'nuevo', 0, $2, $3, $4)
              ON CONFLICT (contact_id) DO UPDATE
              SET
                batch_id = EXCLUDED.batch_id,
                assigned_to = EXCLUDED.assigned_to,
                organization_id = COALESCE(EXCLUDED.organization_id, lead_contact_status.organization_id),
                estado_venta = 'nuevo',
                intentos = 0,
                updated_at = now()
              `,
              [contactId, batchId, assignedTo, organizationId]
            );
          }
        }

        const updateContactosValues = [contactIds];
        let updateContactosOrgClause = "";
        if (organizationId) {
          updateContactosValues.push(organizationId);
          updateContactosOrgClause = "AND organization_id = $2";
        }
        await client.query(
          `
          UPDATE datos_para_trabajar
          SET estado = 'trabajado', updated_at = now()
          WHERE id = ANY($1::uuid[])
            AND estado <> 'bloqueado'
            ${updateContactosOrgClause}
          `,
          updateContactosValues
        );

        await client.query("COMMIT");

        const distribucion = Array.from(distribution.entries()).map(([seller_id, contactos]) => ({
          seller_id,
          contactos
        }));

        return json(200, {
          ok: true,
          success: true,
          data: {
            asignados: contactIds.length,
            vendedores: sellers.length,
            distribucion
          },
          error: null
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to assign leads to batch",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/imports/sample")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const importTypeRaw = normalizeText(event?.queryStringParameters?.type || "clientes");
      const importType = importTypeRaw.replace(/-/g, "_");
      const csv = buildImportSampleCsv(importType);
      const safeType = importType || "clientes";
      const filename = `import_${safeType}_sample.csv`;

      return {
        statusCode: 200,
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="${filename}"`,
          ...CORS_HEADERS
        },
        body: csv
      };
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to generate import sample",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/no-llamar/stats")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const statsResult = await client.query(
          `
          SELECT
            COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE fuente = 'celular')::int AS celulares,
            COUNT(*) FILTER (WHERE departamento = 'Montevideo')::int AS montevideo,
            COUNT(*) FILTER (WHERE departamento IS NOT NULL AND departamento <> 'Montevideo')::int AS interior
          FROM no_call_entries
          `
        );

        return json(200, statsResult.rows[0] || {
          total: 0,
          celulares: 0,
          montevideo: 0,
          interior: 0
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load no-llamar stats",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/imports")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const pageSize = Math.max(1, Number(getQueryParam(event, "pageSize") || 8));
      const search = normalizeText(getQueryParam(event, "search") || "");
      const importType = normalizeText(getQueryParam(event, "importType") || "todos").toLowerCase();
      const statusParam = normalizeText(getQueryParam(event, "status") || "");
      const statusList = statusParam
        ? statusParam
          .split(",")
          .map((value) => value.trim().toLowerCase())
          .filter(Boolean)
        : [];
      if (statusList.includes("processed") && !statusList.includes("completed")) {
        statusList.push("completed");
      }
      const offset = (page - 1) * pageSize;

      const client = createDbClient();
      await client.connect();
      try {
        const whereParts = [];
        const values = [];
        let idx = 1;

        // Definir orgParamIndex ANTES de usarlo en los SQL templates
        let orgParamIndex = null;
        if (organizationId) {
          orgParamIndex = idx;
          values.push(organizationId);
          idx += 1;
        }

        if (search) {
          whereParts.push(`file_name ILIKE $${idx}`);
          values.push(`%${search}%`);
          idx += 1;
        }

        if (importType && importType !== "todos") {
          whereParts.push(`import_type = $${idx}`);
          values.push(importType);
          idx += 1;
        }

        if (statusList.length > 0) {
          const expandedStatus = Array.from(new Set([
            ...statusList,
            ...(statusList.includes("processed") ? ["completed"] : [])
          ]));
          whereParts.push(`status = ANY($${idx})`);
          values.push(expandedStatus);
          idx += 1;
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

        const countResult = await client.query(
          `
          WITH all_imports AS (
            SELECT
              b.id,
              b.file_name,
              b.import_type,
              b.status,
              b.total_rows,
              b.valid_rows,
              b.error_rows,
              b.rejected_missing_documento,
              NULL::int AS processed_rows,
              b.created_at,
              u.nombre AS user_nombre,
              u.apellido AS user_apellido,
              'batches'::text AS source,
              b.organization_id
            FROM contact_import_batches b
            LEFT JOIN users u ON u.id = b.created_by
            ${organizationId ? `WHERE b.organization_id = $${orgParamIndex}` : ""}

            UNION ALL

            SELECT
              j.id,
              j.file_name,
              'no_llamar'::text AS import_type,
              j.status,
              j.total_rows,
              j.inserted_rows AS valid_rows,
              j.skipped_rows AS error_rows,
              0 AS rejected_missing_documento,
              j.processed_rows,
              j.created_at,
              u.nombre AS user_nombre,
              u.apellido AS user_apellido,
              'no_call_jobs'::text AS source,
              NULL::uuid AS organization_id
            FROM no_call_import_jobs j
            LEFT JOIN users u ON u.id = j.created_by

            UNION ALL

            SELECT
              gen_random_uuid() AS id,
              'CSV Datos para trabajar'::text AS file_name,
              'datos_para_trabajar'::text AS import_type,
              'processed'::text AS status,
              stats.total_rows,
              stats.total_rows AS valid_rows,
              0 AS error_rows,
              0 AS rejected_missing_documento,
              NULL::int AS processed_rows,
              stats.created_at,
              NULL AS user_nombre,
              NULL AS user_apellido,
              'datos_virtual'::text AS source,
              stats.organization_id
            FROM (
              SELECT
                COUNT(*)::int AS total_rows,
                MAX(created_at) AS created_at,
                organization_id
              FROM datos_para_trabajar
              ${organizationId ? `WHERE organization_id = $${orgParamIndex}` : ""}
              GROUP BY organization_id
            ) stats
            WHERE stats.total_rows > 0
              AND NOT EXISTS (
                SELECT 1 FROM contact_import_batches WHERE import_type = 'datos_para_trabajar'
              )
          )
          SELECT COUNT(*)::int AS total
          FROM all_imports
          ${whereClause}
          `,
          values
        );

        const total = countResult.rows[0]?.total || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        const itemsResult = await client.query(
          `
          WITH all_imports AS (
            SELECT
              b.id,
              b.file_name,
              b.import_type,
              b.status,
              b.total_rows,
              b.valid_rows,
              b.error_rows,
              b.rejected_missing_documento,
              NULL::int AS processed_rows,
              b.created_at,
              u.nombre AS user_nombre,
              u.apellido AS user_apellido,
              'batches'::text AS source,
              b.organization_id
            FROM contact_import_batches b
            LEFT JOIN users u ON u.id = b.created_by
            ${organizationId ? `WHERE b.organization_id = $${orgParamIndex}` : ""}

            UNION ALL

            SELECT
              j.id,
              j.file_name,
              'no_llamar'::text AS import_type,
              j.status,
              j.total_rows,
              j.inserted_rows AS valid_rows,
              j.skipped_rows AS error_rows,
              0 AS rejected_missing_documento,
              j.processed_rows,
              j.created_at,
              u.nombre AS user_nombre,
              u.apellido AS user_apellido,
              'no_call_jobs'::text AS source,
              NULL::uuid AS organization_id
            FROM no_call_import_jobs j
            LEFT JOIN users u ON u.id = j.created_by

            UNION ALL

            SELECT
              gen_random_uuid() AS id,
              'CSV Datos para trabajar'::text AS file_name,
              'datos_para_trabajar'::text AS import_type,
              'processed'::text AS status,
              stats.total_rows,
              stats.total_rows AS valid_rows,
              0 AS error_rows,
              0 AS rejected_missing_documento,
              NULL::int AS processed_rows,
              stats.created_at,
              NULL AS user_nombre,
              NULL AS user_apellido,
              'datos_virtual'::text AS source,
              stats.organization_id
            FROM (
              SELECT
                COUNT(*)::int AS total_rows,
                MAX(created_at) AS created_at,
                organization_id
              FROM datos_para_trabajar
              ${organizationId ? `WHERE organization_id = $${orgParamIndex}` : ""}
              GROUP BY organization_id
            ) stats
            WHERE stats.total_rows > 0
              AND NOT EXISTS (
                SELECT 1 FROM contact_import_batches WHERE import_type = 'datos_para_trabajar'
              )
          )
          SELECT
            id,
            file_name,
            import_type,
            status,
            total_rows,
            valid_rows,
            error_rows,
            rejected_missing_documento,
            processed_rows,
            created_at,
            user_nombre,
            user_apellido,
            source
          FROM all_imports
          ${whereClause}
          ORDER BY created_at DESC
          LIMIT $${idx} OFFSET $${idx + 1}
          `,
          [...values, pageSize, offset]
        );

        const items = itemsResult.rows.map((row) => {
          const usuario = [row.user_nombre, row.user_apellido].filter(Boolean).join(" ").trim() || "Sistema";
          let estado = "Cargada";
          if (row.source === "no_call_jobs") {
            estado = row.status === "completed"
              ? "Completada"
              : row.status === "processing"
              ? "En proceso"
              : row.status === "failed"
              ? "Fallida"
              : "En cola";
          } else {
            estado = row.status === "processed"
              ? (Number(row.error_rows || 0) ? "Con observaciones" : "Completada")
              : row.status === "validated"
              ? "Validada"
              : row.status === "failed"
              ? "Fallida"
              : "Cargada";
          }
          const totalRows = Number(row.total_rows || 0);
          const processedRows = Number(row.processed_rows || 0);
          const progressPercent =
            row.source === "no_call_jobs" && totalRows > 0
              ? Math.min(100, Math.round((processedRows / totalRows) * 100))
              : null;
          return {
            id: row.id,
            archivo: row.file_name,
            fecha: formatEsUyDateTime(row.created_at),
            total: Number(row.total_rows || 0),
            importados: Number(row.valid_rows || 0),
            rechazados: Number(row.error_rows || 0),
            estado,
            usuario,
            tipo: row.import_type,
            tipoLabel: IMPORT_TYPE_LABEL[row.import_type] || row.import_type,
            rejectedMissingDocumento: Number(row.rejected_missing_documento || 0),
            progressPercent,
            processedRows
          };
        });

        const normalizedImportType = importType ? importType.replace(/-/g, "_") : "";
        const wantsDatosParaTrabajar = !normalizedImportType || normalizedImportType === "datos_para_trabajar";
        const statusAllowsProcessed = statusList.length === 0 || statusList.includes("processed") || statusList.includes("completed");

        let addedFallback = false;
        if (wantsDatosParaTrabajar && statusAllowsProcessed) {
          const hasDatosBatch = items.some((item) => item.tipo === "datos_para_trabajar");
          if (!hasDatosBatch) {
            const fallbackResult = await client.query(
              `
              SELECT COUNT(*)::int AS total,
                     MAX(created_at) AS last_created_at
              FROM datos_para_trabajar
              `
            );
            const fallbackTotal = fallbackResult.rows[0]?.total || 0;
            const fallbackDate = fallbackResult.rows[0]?.last_created_at || null;
            if (fallbackTotal > 0) {
              items.unshift({
                id: "datos-para-trabajar-virtual",
                archivo: "datos_para_trabajar.csv",
                fecha: formatEsUyDateTime(fallbackDate),
                total: fallbackTotal,
                importados: fallbackTotal,
                rechazados: 0,
                estado: "Completada",
                usuario: "Sistema",
                tipo: "datos_para_trabajar",
                tipoLabel: IMPORT_TYPE_LABEL.datos_para_trabajar || "datos_para_trabajar",
                rejectedMissingDocumento: 0
              });
              addedFallback = true;
            }
          }
        }

        if (addedFallback) {
          total += 1;
          totalPages = Math.max(1, Math.ceil(total / pageSize));
        }

        return json(200, {
          items,
          page,
          pageSize,
          total,
          totalPages
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list imports",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/imports/no-llamar")) {
    const fileName =
      event?.headers?.["x-file-name"] ||
      event?.headers?.["X-File-Name"] ||
      event?.headers?.["x-filename"] ||
      event?.headers?.["X-Filename"] ||
      "import_no_llamar.csv";
    const contentType = event?.headers?.["content-type"] || event?.headers?.["Content-Type"] || "";
    const rawBody = event?.body || "";
    const bodyText = event?.isBase64Encoded
      ? Buffer.from(rawBody, "base64").toString("utf8")
      : typeof rawBody === "string"
      ? rawBody
      : JSON.stringify(rawBody);

    let csvText = bodyText;
    if (contentType.includes("application/json")) {
      const parsed = safeParseBody(event);
      if (parsed && parsed.csv) {
        csvText = parsed.csv;
      }
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const parsedRows = parseCsv(csvText);
      const rows = parsedRows.slice(1);
      const client = createDbClient();
      await client.connect();

      let inserted = 0;
      let skipped = 0;

      try {
        await client.query("BEGIN");
        const batchResult = await client.query(
          `
          INSERT INTO contact_import_batches (
            file_name,
            status,
            import_type,
            total_rows,
            valid_rows,
            error_rows,
            created_by
          )
          VALUES ($1, 'uploaded', 'no_llamar', 0, 0, 0, $2)
          RETURNING *
          `,
          [fileName, dbUser?.id || null]
        );
        const batch = batchResult.rows[0];

        for (const row of rows) {
          const rawValue = row[0];
          const numero = normalizeUyNumber(rawValue);
          if (!numero) {
            skipped += 1;
            continue;
          }
          const fuente = getFuenteFromNumber(numero);
          const departamento = fuente === "tel_fijo" ? getDepartamentoFromFixed(numero) : null;
          const localidad = fuente === "tel_fijo" ? getLocalidadFromFixed(numero) : null;

          const result = await client.query(
            `
            INSERT INTO no_call_entries (numero, fuente, departamento, localidad)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (numero) DO NOTHING
            `,
            [numero, fuente, departamento, localidad]
          );
          if (result.rowCount > 0) inserted += 1;
          else skipped += 1;
        }

        const normalizedCelular = buildNormalizedPhoneSql("d.celular");
        const normalizedTelefono = buildNormalizedPhoneSql("d.telefono");
        await client.query(
          `
          UPDATE datos_para_trabajar d
          SET estado = 'bloqueado', updated_at = now()
          WHERE EXISTS (
            SELECT 1
            FROM no_call_entries n
            WHERE n.numero IN (${normalizedCelular}, ${normalizedTelefono})
          )
          `
        );

        const finalStatus =
          rows.length > 0 && inserted === 0 && skipped > 0
            ? "failed"
            : "processed";

        await client.query(
          `
          UPDATE contact_import_batches
          SET total_rows = $1,
              valid_rows = $2,
              error_rows = $3,
              status = $4,
              updated_at = now()
          WHERE id = $5
          `,
          [rows.length, inserted, skipped, finalStatus, batch.id]
        );

        await client.query("COMMIT");
        return json(201, {
          ok: true,
          total: rows.length,
          inserted,
          skipped,
          batchId: batch.id
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to import no-llamar CSV",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/no-llamar")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const pageSize = Math.max(1, Number(getQueryParam(event, "pageSize") || 20));
      const search = normalizeText(getQueryParam(event, "search") || "");
      const fuente = normalizeText(getQueryParam(event, "fuente") || "");
      const departamento = normalizeText(getQueryParam(event, "departamento") || "");
      const localidad = normalizeText(getQueryParam(event, "localidad") || "");
      const offset = (page - 1) * pageSize;

      const client = createDbClient();
      await client.connect();
      try {
        const whereParts = [];
        const values = [];
        let idx = 1;

        if (search) {
          whereParts.push(`(numero ILIKE $${idx} OR departamento ILIKE $${idx} OR localidad ILIKE $${idx})`);
          values.push(`%${search}%`);
          idx += 1;
        }

        if (fuente) {
          whereParts.push(`fuente = $${idx}`);
          values.push(fuente);
          idx += 1;
        }

        if (departamento) {
          whereParts.push(`departamento ILIKE $${idx}`);
          values.push(`%${departamento}%`);
          idx += 1;
        }

        if (localidad) {
          whereParts.push(`localidad ILIKE $${idx}`);
          values.push(`%${localidad}%`);
          idx += 1;
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

        const countResult = await client.query(
          `
          SELECT COUNT(*)::int AS total
          FROM no_call_entries
          ${whereClause}
          `,
          values
        );

        const total = countResult.rows[0]?.total || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        const itemsResult = await client.query(
          `
          SELECT
            id,
            numero,
            fuente,
            departamento,
            localidad,
            fecha_carga,
            created_at
          FROM no_call_entries
          ${whereClause}
          ORDER BY created_at DESC
          LIMIT $${idx} OFFSET $${idx + 1}
          `,
          [...values, pageSize, offset]
        );

        const items = itemsResult.rows.map((row) => ({
          id: row.id,
          numero: row.numero,
          fuente: row.fuente,
          departamento: row.departamento,
          localidad: row.localidad,
          fecha_carga: row.fecha_carga,
          created_at: row.created_at
        }));

        return json(200, { items, page, pageSize, total, totalPages });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list no-llamar entries",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/imports/no-llamar/jobs")) {
    const contentType = event?.headers?.["content-type"] || event?.headers?.["Content-Type"] || "";
    const fileName =
      event?.headers?.["x-file-name"] ||
      event?.headers?.["X-File-Name"] ||
      event?.headers?.["x-filename"] ||
      event?.headers?.["X-Filename"] ||
      "import_no_llamar.csv";
    const rawBody = event?.body || "";
    const bodyText = event?.isBase64Encoded
      ? Buffer.from(rawBody, "base64").toString("utf8")
      : typeof rawBody === "string"
      ? rawBody
      : JSON.stringify(rawBody);

    let csvText = bodyText;
    if (contentType.includes("application/json")) {
      const parsed = safeParseBody(event);
      if (parsed && parsed.csv) {
        csvText = parsed.csv;
      }
    }

    if (!csvText || !csvText.trim()) {
      return json(400, { ok: false, message: "CSV vacio" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const jobResult = await client.query(
          `
          INSERT INTO no_call_import_jobs (
            file_name,
            status,
            total_rows,
            processed_rows,
            inserted_rows,
            skipped_rows,
            csv_text,
            created_by
          )
          VALUES ($1, 'queued', 0, 0, 0, 0, $2, $3)
          RETURNING id, status, file_name, created_at
          `,
          [fileName, csvText, dbUser?.id || null]
        );
        const job = jobResult.rows[0];
        const jobId = job.id;
        await enqueueNoCallJob(jobId);
        return json(201, {
          ok: true,
          job: {
            id: jobId,
            status: job.status,
            fileName: job.file_name,
            createdAt: job.created_at,
            total: 0,
            processed: 0,
            inserted: 0,
            skipped: 0,
            progressPercent: 0
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create no-llamar job",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/config")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      const client = createDbClient();
      await client.connect();
      try {
        const config = await getConfigMap(client);

        // Agregar logo_url de la organizaciÃ³n del usuario
        const orgId = await resolveOrganizationIdForRequest(dbUser, event).catch(() => null);
        if (orgId) {
          const orgResult = await client.query(
            `SELECT logo_url FROM organizations WHERE id = $1 LIMIT 1`,
            [orgId]
          );
          config.logo_url = orgResult.rows[0]?.logo_url || null;
        } else {
          config.logo_url = null;
        }

        return json(200, config);
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load config",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/superadmin/stats")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      console.log("STATS_ORG_ID", organizationId, event.queryStringParameters);
      const client = createDbClient();
      await client.connect();
      try {
        const orgFilter = organizationId ? "AND organization_id = $1" : "";
        const orgFilterAlias = organizationId ? "AND s.organization_id = $1" : "";
        const orgValues = organizationId ? [organizationId] : [];

        const safeCount = async (queryText, values = []) => {
          try {
            const res = await client.query(queryText, values);
            return Number(res.rows[0]?.total || 0);
          } catch {
            return 0;
          }
        };

        const [
          ventasHoy,
          lotesActivos,
          usuariosActivos,
          importacionesHoy,
          ticketsAbiertos,
          solicitudesEnCurso
        ] = await Promise.all([
          safeCount(
            `
            SELECT COUNT(*)::int AS total
            FROM sales s
            WHERE s.fecha_venta >= now() - interval '1 day'
            ${organizationId ? "AND s.organization_id = $1" : ""}
            `,
            orgValues
          ),
          safeCount(
            `
            SELECT COUNT(*)::int AS total
            FROM lead_batches
            WHERE estado NOT IN ('finalizado', 'cancelado')
            ${orgFilter}
            `,
            orgValues
          ),
          safeCount(
            `
            SELECT COUNT(DISTINCT et.agente_id)::int AS total
            FROM eventos_turno et
            JOIN organization_users ou ON ou.user_id = et.agente_id
              AND ou.activo = true
            WHERE et.inicio >= now() - interval '1 day'
            ${organizationId ? "AND ou.organization_id = $1" : ""}
            `,
            orgValues
          ),
          safeCount(
            `
            SELECT COUNT(*)::int AS total
            FROM contact_import_batches
            WHERE created_at >= now() - interval '1 day'
            ${orgFilter}
            `,
            orgValues
          ),
          safeCount(
            `
            SELECT COUNT(*)::int AS total
            FROM manual_tickets
            WHERE estado = 'nuevo'
            ${orgFilter}
            `,
            orgValues
          ),
          safeCount(
            `
            SELECT COUNT(*)::int AS total
            FROM manual_tickets
            WHERE estado IN ('en_proceso', 'pendiente')
            ${orgFilter}
            `,
            orgValues
          )
        ]);

        return json(200, {
          ok: true,
          ventas_hoy: ventasHoy,
          lotes_activos: lotesActivos,
          usuarios_activos: usuariosActivos,
          importaciones_hoy: importacionesHoy,
          tickets_abiertos: ticketsAbiertos,
          solicitudes_en_curso: solicitudesEnCurso
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load superadmin stats",
        error: error.message
      });
    }
  }

  // GET /campanas/origenes â€” lista de origenes disponibles para filtros del dashboard
  if (method === "GET" && (path.endsWith("/campanas/origenes") || path.endsWith("/api/campanas/origenes"))) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador", "director", "supervisor"]);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) return json(error.status, { ok: false, message: error.message });
        throw error;
      }

      if (!organizationId) {
        return json(400, { ok: false, message: "organization_id requerido" });
      }

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `
          SELECT DISTINCT origen_dato, COUNT(*) as total
          FROM datos_para_trabajar
          WHERE organization_id = $1
            AND origen_dato IS NOT NULL AND origen_dato != ''
          GROUP BY origen_dato
          ORDER BY total DESC
          `,
          [organizationId]
        );
        return json(200, { ok: true, origenes: result.rows.map((r) => r.origen_dato) });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to load campaign origins", error: error.message });
    }
  }

  // GET /campanas/stats â€” mÃ©tricas del dashboard de campaÃ±as
  if (method === "GET" && (path.endsWith("/campanas/stats") || path.endsWith("/api/campanas/stats"))) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador", "director", "supervisor"]);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) return json(error.status, { ok: false, message: error.message });
        throw error;
      }

      const periodoRaw = getQueryParam(event, "periodo");
      let periodo = String(periodoRaw || "mes").trim().toLowerCase();
      if (periodo === "este_mes") periodo = "mes";
      if (periodo === "ultimos_7_dias") periodo = "semana";
      if (periodo === "hoy") periodo = "dia";
      const origenDatoRaw = getQueryParam(event, "origen_dato");
      const origenDato = String(origenDatoRaw || "facebook").trim().toLowerCase();
      const origenDatoFilter = origenDato && origenDato !== "todos" ? origenDato : null;

      const client = createDbClient();
      await client.connect();
      try {
        // Definir rango de fechas
        let dateFilter = "";
        if (periodo === "dia") dateFilter = "AND d.created_at >= now() - interval '1 day'";
        else if (periodo === "semana") dateFilter = "AND d.created_at >= now() - interval '7 days'";
        else if (periodo === "mes") dateFilter = "AND d.created_at >= now() - interval '30 days'";

        const orgFilter = organizationId ? `AND d.organization_id = '${organizationId}'` : "";
        const origenFilter = origenDatoFilter ? "AND lower(coalesce(d.origen_dato, '')) = $1" : "";
        const origenValues = origenDatoFilter ? [origenDatoFilter] : [];

        // MÃ©tricas generales
        const metricsRes = await client.query(
          `
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE d.estado = 'nuevo') AS nuevos,
            COUNT(*) FILTER (WHERE d.estado = 'bloqueado') AS bloqueados,
            COUNT(*) FILTER (WHERE d.estado = 'trabajado') AS trabajados,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'venta') AS convertidos,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'no_contesta') AS no_contesta,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'rechazo') AS rechazados,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'dato_erroneo') AS datos_erroneos,
            COUNT(*) FILTER (WHERE lcs.estado_venta IS NULL OR lcs.estado_venta = 'nuevo') AS sin_gestion,
            COUNT(*) FILTER (WHERE lcs.estado_venta IN ('seguimiento', 'rellamar')) AS en_proceso,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'rellamar') AS rellamar,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'seguimiento') AS seguimiento
          FROM datos_para_trabajar d
          LEFT JOIN lead_contact_status lcs ON lcs.contact_id = d.id
          WHERE 1=1
          ${origenFilter}
          ${orgFilter}
          ${dateFilter}
          `,
          origenValues
        );

        // Ingresos por dÃ­a (Ãºltimos 30 dÃ­as)
        const dailyRes = await client.query(
          `
          SELECT
            DATE(d.created_at AT TIME ZONE 'America/Montevideo') AS fecha,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE d.estado = 'bloqueado') AS bloqueados,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'venta') AS convertidos
          FROM datos_para_trabajar d
          LEFT JOIN lead_contact_status lcs ON lcs.contact_id = d.id
          WHERE 1=1
            ${origenFilter}
            AND d.created_at >= now() - interval '30 days'
            ${organizationId ? `AND d.organization_id = '${organizationId}'` : ""}
          GROUP BY DATE(d.created_at AT TIME ZONE 'America/Montevideo')
          ORDER BY fecha DESC
          `,
          origenValues
        );

        // DistribuciÃ³n por vendedor
        const vendedoresRes = await client.query(
          `
          SELECT
            u.nombre,
            u.apellido,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'venta') AS convertidos,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'no_contesta') AS no_contesta,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'rechazo') AS rechazados,
            COUNT(*) FILTER (WHERE lcs.estado_venta IS NULL OR lcs.estado_venta = 'nuevo') AS sin_gestion
          FROM lead_contact_status lcs
          JOIN datos_para_trabajar d ON d.id = lcs.contact_id
          JOIN users u ON u.id = lcs.assigned_to
          WHERE 1=1
            ${origenFilter}
            AND u.status = 'activo'
            ${organizationId ? `AND d.organization_id = '${organizationId}'` : ""}
            ${dateFilter.replace("d.created_at", "d.created_at")}
          GROUP BY u.id, u.nombre, u.apellido
          ORDER BY total DESC
          `,
          origenValues
        );

        return json(200, {
          ok: true,
          periodo,
          origen_dato: origenDatoFilter || "todos",
          metricas: metricsRes.rows[0],
          por_dia: dailyRes.rows,
          por_vendedor: vendedoresRes.rows
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to load campaign stats", error: error.message });
    }
  }

  // GET /campanas/leads â€” tabla de leads de campaÃ±a
  if (method === "GET" && (path.endsWith("/campanas/leads") || path.endsWith("/api/campanas/leads"))) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador", "director", "supervisor"]);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) return json(error.status, { ok: false, message: error.message });
        throw error;
      }

      const periodoRaw = getQueryParam(event, "periodo");
      let periodo = String(periodoRaw || "mes").trim().toLowerCase();
      if (periodo === "este_mes") periodo = "mes";
      if (periodo === "ultimos_7_dias") periodo = "semana";
      if (periodo === "hoy") periodo = "dia";
      const origenDatoRaw = getQueryParam(event, "origen_dato");
      const origenDato = String(origenDatoRaw || "facebook").trim().toLowerCase();
      const origenDatoFilter = origenDato && origenDato !== "todos" ? origenDato : null;
      const page = Math.max(1, parseInt(getQueryParam(event, "page") || "1", 10));
      const limit = Math.min(100, Math.max(1, parseInt(getQueryParam(event, "limit") || "50", 10)));
      const offset = (page - 1) * limit;

      const client = createDbClient();
      await client.connect();
      try {
        let dateFilter = "";
        if (periodo === "dia") dateFilter = "AND d.created_at >= now() - interval '1 day'";
        else if (periodo === "semana") dateFilter = "AND d.created_at >= now() - interval '7 days'";
        else if (periodo === "mes") dateFilter = "AND d.created_at >= now() - interval '30 days'";

        const filters = [];
        const filterValues = [];
        let filterIdx = 1;
        if (origenDatoFilter) {
          filters.push(`lower(coalesce(d.origen_dato, '')) = $${filterIdx}`);
          filterValues.push(origenDatoFilter);
          filterIdx += 1;
        }
        if (organizationId) {
          filters.push(`d.organization_id = $${filterIdx}`);
          filterValues.push(organizationId);
          filterIdx += 1;
        }
        const whereClause = filters.length ? `AND ${filters.join(" AND ")}` : "";

        const countRes = await client.query(
          `
          SELECT COUNT(*) AS total
          FROM datos_para_trabajar d
          WHERE 1=1
          ${whereClause}
          ${dateFilter}
          `,
          filterValues
        );

        const result = await client.query(
          `
          SELECT
            d.id,
            d.nombre,
            d.apellido,
            d.telefono,
            d.celular,
            d.email,
            d.fecha_nacimiento,
            d.estado,
            d.origen_dato,
            d.created_at,
            lcs.estado_venta,
            lcs.intentos,
            lcs.ultimo_intento_at,
            lcs.assigned_to,
            CONCAT_WS(' ', u.nombre, u.apellido) AS assigned_to_name,
            last_m.fecha_gestion AS last_gestion_at,
            last_m.resultado AS last_resultado,
            last_m.nota AS last_nota,
            last_m.user_nombre AS last_user_nombre,
            last_m.user_apellido AS last_user_apellido
          FROM datos_para_trabajar d
          LEFT JOIN lead_contact_status lcs ON lcs.contact_id = d.id
          LEFT JOIN users u ON u.id = lcs.assigned_to
          LEFT JOIN LATERAL (
            SELECT
              lm.fecha_gestion,
              lm.resultado,
              lm.nota,
              u2.nombre AS user_nombre,
              u2.apellido AS user_apellido
            FROM lead_management_history lm
            LEFT JOIN users u2 ON u2.id = lm.user_id
            WHERE lm.contact_id = d.id
            ORDER BY lm.fecha_gestion DESC
            LIMIT 1
          ) last_m ON true
          WHERE 1=1
          ${whereClause}
          ${dateFilter}
          ORDER BY d.created_at DESC
          LIMIT $${filterIdx} OFFSET $${filterIdx + 1}
          `,
          [...filterValues, limit, offset]
        );

        return json(200, {
          ok: true,
          periodo,
          origen_dato: origenDatoFilter || "todos",
          items: result.rows.map((row) => {
            const lastBy = [row.last_user_nombre, row.last_user_apellido].filter(Boolean).join(" ").trim();
            return {
              ...row,
              last_by: lastBy || ""
            };
          }),
          total: parseInt(countRes.rows[0].total, 10),
          page,
          limit
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to load campaign leads", error: error.message });
    }
  }

  if (method === "GET" && path.endsWith("/api/supervisor/team-summary")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const fecha = parseFechaParam(getQueryParam(event, "fecha"));
      const tipoRaw = getQueryParam(event, "tipo");
      const tipo = tipoRaw ? String(tipoRaw).trim().toLowerCase() : "";
      const batchTipo = (tipo === "recupero" || tipo === "captacion") ? tipo : null;
      const client = createDbClient();
      await client.connect();
      try {
        const summary = await getTeamSummary(client, fecha, new Date());
        return json(200, summary);
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load team summary",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/agente/estado-actual")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const timezone = getQueryParam(event, "timezone") || LOCAL_TZ;
      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");
        await applyInactividadSiCorresponde(client, dbUser.id, new Date());
        await client.query("COMMIT");
        const estado = await getEstadoAgenteActual(client, dbUser.id, timezone);
        return json(200, {
          ok: true,
          estado: estado || {
            tipo: "TRABAJO",
            inicio: null,
            inicio_local: null,
            requiere_bloqueo: false
          }
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load estado actual",
        error: error.message
      });
    }
  }
  if (
    method === "POST" &&
    (path.endsWith("/api/recupero/importaciones") ||
      path.endsWith("/api/recupero/importar-bajas"))
  ) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const multipart = parseMultipartFormData(event);
      if (!multipart) {
        return json(400, { ok: false, message: "Archivo invalido" });
      }

      const fileEntry =
        multipart.files?.file ||
        multipart.files?.archivo ||
        Object.values(multipart.files || {})[0];
      const fileNameHeader =
        event?.headers?.["x-file-name"] ||
        event?.headers?.["X-File-Name"] ||
        event?.headers?.["x-filename"] ||
        event?.headers?.["X-Filename"] ||
        "recupero.csv";
      const fileName = fileEntry?.filename || fileNameHeader || "recupero.csv";
      const csvText = fileEntry?.content || "";

      if (!fileName.toLowerCase().endsWith(".csv")) {
        return json(400, { ok: false, message: "Formato invalido" });
      }

      if (!csvText || !csvText.trim()) {
        return json(400, { ok: false, message: "CSV vacio" });
      }

      const sizeBytes = Buffer.byteLength(csvText, "utf8");
      if (sizeBytes > 5 * 1024 * 1024) {
        return json(400, { ok: false, message: "Archivo demasiado grande" });
      }

      const delimiterRaw = String(multipart.fields?.delimiter || "").trim();
      const delimiter = delimiterRaw && delimiterRaw.length === 1 ? delimiterRaw : null;
      const iterator = iterateCsvLines(csvText.replace(/^\uFEFF/, ""));
      const headerResult = iterator.next();
      const headerLine = headerResult.done ? "" : headerResult.value || "";
      const headerDelimiter = delimiter || detectCsvDelimiter(headerLine);
      const headers = parseCsvLine(headerLine, headerDelimiter).map((h) =>
        normalizeImportValue(h)
      );
      const hasDocumento = headers.includes("documento");
      const hasMotivo = headers.some(
        (h) => h === "motivo de la baja" || h === "motivo de baja"
      );
      const hasEstado = headers.some(
        (h) => h === "ultimo estado" || h === "Ãºltimo estado"
      );
      if (!hasDocumento || !hasMotivo || !hasEstado) {
        return json(400, { ok: false, message: "Headers invalidos" });
      }

      const fileHash = crypto.createHash("sha256").update(csvText).digest("hex");
      const client = createDbClient();
      await client.connect();
      try {
        const existingRes = await client.query(
          `
          SELECT id, status
          FROM recupero_import_jobs
          WHERE file_hash = $1
            AND status IN ('queued', 'processing', 'done')
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [fileHash]
        );
        if (existingRes.rows.length) {
          return json(200, {
            ok: true,
            job_id: existingRes.rows[0].id,
            status: existingRes.rows[0].status,
            duplicated: true
          });
        }

        const jobRes = await client.query(
          `
          INSERT INTO recupero_import_jobs (
            file_name,
            status,
            total_rows,
            processed_rows,
            updated_rows,
            error_rows,
            duplicate_rows,
            invalid_rows,
            not_found_rows,
            csv_text,
            created_by,
            file_hash,
            delimiter
          )
          VALUES ($1, 'queued', 0, 0, 0, 0, 0, 0, 0, $2, $3, $4, $5)
          RETURNING id, status
          `,
          [fileName, csvText, dbUser?.id || null, fileHash, headerDelimiter]
        );

        await enqueueRecuperoImportJob(jobRes.rows[0].id);
        return json(201, {
          ok: true,
          job_id: jobRes.rows[0].id,
          status: jobRes.rows[0].status
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create recupero import job",
        error: error.message
      });
    }
  }
  if (method === "GET" && path.match(/\/api\/recupero\/importaciones\/([^/]+)\/errores\.csv$/)) {
    const match = path.match(/\/api\/recupero\/importaciones\/([^/]+)\/errores\.csv$/);
    const jobId = match ? match[1] : null;
    if (!isValidUuid(jobId)) {
      return json(400, { ok: false, message: "job_id invalido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const jobRes = await client.query(
          `
          SELECT id, error_report_csv
          FROM recupero_import_jobs
          WHERE id = $1
          LIMIT 1
          `,
          [jobId]
        );
        if (!jobRes.rows.length) {
          return json(404, { ok: false, message: "Job no encontrado" });
        }
        const csv = jobRes.rows[0].error_report_csv || "";
        return {
          statusCode: 200,
          headers: {
            ...CORS_HEADERS,
            "Content-Type": "text/csv; charset=utf-8"
          },
          body: csv
        };
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load error report",
        error: error.message
      });
    }
  }
  if (method === "GET" && path.match(/\/api\/recupero\/importaciones\/([^/]+)$/)) {
    const match = path.match(/\/api\/recupero\/importaciones\/([^/]+)$/);
    const jobId = match ? match[1] : null;
    if (!isValidUuid(jobId)) {
      return json(400, { ok: false, message: "job_id invalido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, LEAD_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const jobRes = await client.query(
          `
          SELECT
            id,
            status,
            total_rows,
            processed_rows,
            updated_rows,
            error_rows,
            duplicate_rows,
            invalid_rows,
            not_found_rows,
            error_rows_detail,
            error_report_csv
          FROM recupero_import_jobs
          WHERE id = $1
          LIMIT 1
          `,
          [jobId]
        );
        if (!jobRes.rows.length) {
          return json(404, { ok: false, message: "Job no encontrado" });
        }
        const row = jobRes.rows[0];
        const total = Number(row.total_rows || 0);
        const processed = Number(row.processed_rows || 0);
        const percentage = total ? Math.round((processed / total) * 100) : 0;
        const errors = Array.isArray(row.error_rows_detail)
          ? row.error_rows_detail
          : row.error_rows_detail
          ? JSON.parse(row.error_rows_detail)
          : [];
        return json(200, {
          ok: true,
          job_id: row.id,
          status: row.status,
          duplicate_policy: "last_wins",
          progress: {
            processed_rows: processed,
            total_rows: total,
            percentage
          },
          summary: {
            total,
            actualizadas: Number(row.updated_rows || 0),
            no_encontradas: Number(row.not_found_rows || 0),
            duplicadas: Number(row.duplicate_rows || 0),
            invalidas: Number(row.invalid_rows || 0)
          },
          errores: errors,
          error_report_url: row.error_report_csv
            ? `/api/recupero/importaciones/${row.id}/errores.csv`
            : null
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load recupero import job",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/codificaciones/ultimos")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const limit = Math.min(200, Math.max(1, Number(getQueryParam(event, "limit") || 10)));
      const searchPhone = normalizeText(getQueryParam(event, "search_phone"));
      const sellerId = normalizeText(getQueryParam(event, "seller_id"));
      const from = normalizeText(getQueryParam(event, "from"));
      const to = normalizeText(getQueryParam(event, "to"));

      const { items, total } = await fetchCodificaciones({
        limit,
        offset: 0,
        searchPhone,
        sellerId,
        from,
        to
      });

      return json(200, {
        ok: true,
        success: true,
        items,
        limit,
        total
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list codificaciones",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/codificaciones/catalogo")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const res = await client.query(
          `
          SELECT nombre, es_final, libera_al_cerrar
          FROM lead_status_catalog
          ORDER BY nombre
          `
        );

        return json(200, {
          ok: true,
          success: true,
          items: res.rows
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load codificaciones catalog",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/codificaciones")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const limit = Math.min(200, Math.max(1, Number(getQueryParam(event, "limit") || 10)));
      const offset = (page - 1) * limit;

      const searchPhone = normalizeText(getQueryParam(event, "search_phone"));
      const sellerId = normalizeText(getQueryParam(event, "seller_id"));
      const from = normalizeText(getQueryParam(event, "from"));
      const to = normalizeText(getQueryParam(event, "to"));
      const resultado = normalizeText(getQueryParam(event, "resultado"));
      const resultadoCorregido = normalizeText(getQueryParam(event, "resultado_corregido"));
      const estado = normalizeText(getQueryParam(event, "estado")).toLowerCase();

      const { items, total } = await fetchCodificaciones({
        limit,
        offset,
        searchPhone,
        sellerId,
        from,
        to,
        resultado,
        resultadoCorregido,
        estado
      });

      return json(200, {
        ok: true,
        success: true,
        items,
        page,
        limit,
        total
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list codificaciones",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.match(/\/api\/codificaciones\/([^/]+)\/historial$/)) {
    const match = path.match(/\/api\/codificaciones\/([^/]+)\/historial$/);
    const managementId = match?.[1];
    if (!managementId || !isValidUuid(managementId)) {
      return json(400, { ok: false, message: "Management id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const managementRes = await client.query(
          `
          SELECT
            lmh.id AS management_id,
            lmh.contact_id,
            lmh.batch_id,
            lmh.fecha_gestion,
            lmh.resultado AS resultado_original,
            lmh.nota,
            d.telefono,
            d.celular,
            COALESCE(NULLIF(d.telefono, ''), NULLIF(d.celular, '')) AS telefono_display,
            u.nombre AS vendedor_nombre,
            u.apellido AS vendedor_apellido,
            TRIM(CONCAT(u.nombre, ' ', u.apellido)) AS vendedor_nombre_completo
          FROM lead_management_history lmh
          LEFT JOIN datos_para_trabajar d ON d.id = lmh.contact_id
          LEFT JOIN users u ON u.id = lmh.user_id
          WHERE lmh.id = $1
          LIMIT 1
          `,
          [managementId]
        );

        const management = managementRes.rows[0];
        if (!management) {
          return json(404, { ok: false, message: "Gestiï¿½n no encontrada" });
        }

        const auditsRes = await client.query(
          `
          SELECT
            a.id,
            a.management_id,
            a.contact_id,
            a.batch_id,
            a.resultado_original,
            a.resultado_corregido,
            a.motivo,
            a.corrected_by,
            a.corrected_at,
            TRIM(CONCAT(u.nombre, ' ', u.apellido)) AS supervisor_nombre_completo
          FROM lead_coding_audit a
          LEFT JOIN users u ON u.id = a.corrected_by
          WHERE a.management_id = $1
          ORDER BY a.corrected_at DESC
          `,
          [managementId]
        );

        return json(200, {
          ok: true,
          success: true,
          management,
          audits: auditsRes.rows
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load codificacion history",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.match(/\/api\/codificaciones\/([^/]+)$/)) {
    const match = path.match(/\/api\/codificaciones\/([^/]+)$/);
    const managementId = match?.[1];
    if (!managementId || !isValidUuid(managementId)) {
      return json(400, { ok: false, message: "Management id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const detailRes = await client.query(
          `
          WITH latest_audit AS (
            SELECT
              a.*,
              ROW_NUMBER() OVER (PARTITION BY a.management_id ORDER BY a.corrected_at DESC) AS rn
            FROM lead_coding_audit a
          )
          SELECT
            lmh.id AS management_id,
            lmh.contact_id,
            lmh.batch_id,
            lmh.fecha_gestion,
            lmh.resultado AS resultado_original,
            lmh.nota,
            d.telefono,
            d.celular,
            COALESCE(NULLIF(d.telefono, ''), NULLIF(d.celular, '')) AS telefono_display,
            u.nombre AS vendedor_nombre,
            u.apellido AS vendedor_apellido,
            TRIM(CONCAT(u.nombre, ' ', u.apellido)) AS vendedor_nombre_completo,
            la.resultado_corregido,
            la.corrected_at,
            la.corrected_by,
            TRIM(CONCAT(sup.nombre, ' ', sup.apellido)) AS supervisor_nombre_completo,
            CASE WHEN la.id IS NULL THEN 'pendiente' ELSE 'corregida' END AS estado_auditoria
          FROM lead_management_history lmh
          LEFT JOIN datos_para_trabajar d ON d.id = lmh.contact_id
          LEFT JOIN users u ON u.id = lmh.user_id
          LEFT JOIN latest_audit la ON la.management_id = lmh.id AND la.rn = 1
          LEFT JOIN users sup ON sup.id = la.corrected_by
          WHERE lmh.id = $1
          LIMIT 1
          `,
          [managementId]
        );

        const detail = detailRes.rows[0];
        if (!detail) {
          return json(404, { ok: false, message: "Gestiï¿½n no encontrada" });
        }

        return json(200, {
          ok: true,
          success: true,
          data: detail
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load codificacion detail",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.match(/\/api\/codificaciones\/([^/]+)\/correccion$/)) {
    const match = path.match(/\/api\/codificaciones\/([^/]+)\/correccion$/);
    const managementIdFromPath = match?.[1];
    const body = safeParseBody(event);
    const managementIdFromBody = body?.management_id;
    const managementId = managementIdFromPath || managementIdFromBody;
    console.log("managementId:", managementId);
    console.log("path:", path);
    console.log("body:", body);
    if (!managementId) {
      return json(400, { ok: false, message: "management_id requerido" });
    }
    if (!isValidUuid(managementId)) {
      return json(400, { ok: false, message: "management_id invï¿½lido" });
    }
    if (body === null) {
      return json(400, { ok: false, message: "Invalid JSON body" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const resultadoInput = normalizeLeadResultado(body?.resultado_corregido);
      const motivoRaw = normalizeText(body?.motivo || "");
      const motivo = motivoRaw ? motivoRaw : null;

      if (!resultadoInput || resultadoInput === "nuevo") {
        return json(400, { ok: false, message: "resultado_corregido requerido" });
      }

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");

        const managementRes = await client.query(
          `
          SELECT id, contact_id, batch_id, resultado
          FROM lead_management_history
          WHERE id = $1
          LIMIT 1
          `,
          [managementId]
        );

        const management = managementRes.rows[0];
        if (!management) {
          await client.query("ROLLBACK");
          return json(404, { ok: false, message: "Gestiï¿½n no encontrada" });
        }

        const desiredCatalog = await getLeadStatusCatalogEntry(client, resultadoInput);
        if (!desiredCatalog) {
          await client.query("ROLLBACK");
          return json(400, { ok: false, message: "resultado_corregido no existe en catï¿½logo" });
        }

        const insertRes = await client.query(
          `
          INSERT INTO lead_coding_audit (
            management_id,
            contact_id,
            batch_id,
            resultado_original,
            resultado_corregido,
            motivo,
            corrected_by
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          RETURNING id, management_id, contact_id, batch_id, resultado_original, resultado_corregido, motivo, corrected_by, corrected_at
          `,
          [
            management.id,
            management.contact_id,
            management.batch_id,
            management.resultado,
            resultadoInput,
            motivo,
            dbUser.id
          ]
        );

        await client.query("COMMIT");

        const audit = insertRes.rows[0];

        return json(201, {
          ok: true,
          success: true,
          audit: {
            ...audit,
            supervisor_nombre_completo: [dbUser?.nombre, dbUser?.apellido].filter(Boolean).join(" ").trim()
          },
          resultado_vigente: audit?.resultado_corregido || management.resultado
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create codificacion correction",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/api/agente/estado")) {
    const body = safeParseBody(event) || {};
    const tipo = normalizeEstadoTipo(body.tipo);
    if (!["BANO", "DESCANSO", "SUPERVISOR", "BA?O"].includes(tipo)) {
      return json(400, { ok: false, message: "Tipo de estado no valido" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");
        const config = await getConfigMap(client);
        const now = new Date();
        const fecha = formatDateYmd(now);
        const currentRes = await client.query(
          `SELECT tipo, inicio, session_id FROM estado_agente_actual WHERE agente_id = $1 LIMIT 1`,
          [dbUser.id]
        );
        const current = currentRes.rows[0] || null;

        if (current && current.tipo === tipo) {
          await client.query("COMMIT");
          const estado = await getEstadoAgenteActual(client, dbUser.id, LOCAL_TZ);
          return json(200, { ok: true, estado });
        }
        if (current && current.tipo && current.tipo !== "TRABAJO") {
          await client.query("COMMIT");
          return json(409, { ok: false, message: "Debe volver al trabajo antes de cambiar de estado" });
        }

        const activeRes = await client.query(
          `
          SELECT *
          FROM eventos_turno
          WHERE agente_id = $1
            AND fecha = $2
            AND fin IS NULL
          ORDER BY inicio DESC
          LIMIT 1
          `,
          [dbUser.id, fecha]
        );
        const activeEvent = activeRes.rows[0] || null;
        if (activeEvent) {
          await closeActiveTurnEvent(client, activeEvent, now, config);
        }

        await client.query(
          `
          INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
          VALUES ($1, $2, $3, NULL, $4)
          `,
          [dbUser.id, tipo, now, fecha]
        );

        await upsertEstadoAgenteActual(client, dbUser.id, tipo, now, body.session_id || current?.session_id || null, now);
        await client.query("COMMIT");
        const estado = await getEstadoAgenteActual(client, dbUser.id, LOCAL_TZ);
        return json(201, { ok: true, estado });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to update estado",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/api/agente/volver-al-trabajo")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");
        const config = await getConfigMap(client);
        const now = new Date();
        const fecha = formatDateYmd(now);
        const currentRes = await client.query(
          `SELECT tipo, session_id, last_seen_at FROM estado_agente_actual WHERE agente_id = $1 LIMIT 1`,
          [dbUser.id]
        );
        const current = currentRes.rows[0] || null;

        const activeRes = await client.query(
          `
          SELECT *
          FROM eventos_turno
          WHERE agente_id = $1
            AND fecha = $2
            AND fin IS NULL
          ORDER BY inicio DESC
          LIMIT 1
          `,
          [dbUser.id, fecha]
        );
        const activeEvent = activeRes.rows[0] || null;
        if (activeEvent && activeEvent.tipo !== "TRABAJO") {
          await closeActiveTurnEvent(client, activeEvent, now, config);
        }

        if (!activeEvent || activeEvent.tipo !== "TRABAJO") {
          await client.query(
            `
            INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
            VALUES ($1, 'TRABAJO', $2, NULL, $3)
            `,
            [dbUser.id, now, fecha]
          );
        }

        await upsertEstadoAgenteActual(client, dbUser.id, "TRABAJO", now, current?.session_id || null, now);
        await client.query("COMMIT");
        const estado = await getEstadoAgenteActual(client, dbUser.id, LOCAL_TZ);
        return json(200, { ok: true, estado: estado || { tipo: "TRABAJO", inicio: now } });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to return to work",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/api/agente/heartbeat")) {
    const body = safeParseBody(event) || {};
    if (body.timestamp !== undefined && !Number.isFinite(Number(body.timestamp))) {
      return json(400, { ok: false, message: "timestamp invalido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const now = new Date();
      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");
        const currentRes = await client.query(
          `SELECT tipo, inicio, session_id, last_seen_at FROM estado_agente_actual WHERE agente_id = $1 LIMIT 1`,
          [dbUser.id]
        );
        const current = currentRes.rows[0] || null;

        const inactivityResult = await applyInactividadSiCorresponde(client, dbUser.id, now);
        const currentAfterInactivity = inactivityResult.state || current;

        if (currentAfterInactivity && currentAfterInactivity.tipo === "INACTIVO") {
          const fecha = formatDateYmd(now);
          await client.query(
            `
            INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
            VALUES ($1, 'TRABAJO', $2, NULL, $3)
            `,
            [dbUser.id, now, fecha]
          );
          await upsertEstadoAgenteActual(
            client,
            dbUser.id,
            "TRABAJO",
            now,
            currentAfterInactivity.session_id || null,
            now
          );
        } else if (currentAfterInactivity && currentAfterInactivity.tipo === "TRABAJO") {
          await upsertEstadoAgenteActual(
            client,
            dbUser.id,
            "TRABAJO",
            currentAfterInactivity.inicio,
            currentAfterInactivity.session_id || null,
            now
          );
        } else if (currentAfterInactivity && isPausaTipo(currentAfterInactivity.tipo)) {
          // No alterar pausas por heartbeat
        } else if (!currentAfterInactivity) {
          await upsertEstadoAgenteActual(client, dbUser.id, "TRABAJO", now, null, now);
        }

        await client.query("COMMIT");
        const estado = await getEstadoAgenteActual(client, dbUser.id, LOCAL_TZ);
        return json(200, { ok: true, estado });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to register heartbeat",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/reportes/jornada-diaria")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const fecha = parseFechaParam(getQueryParam(event, "fecha"));
      const timezone = getQueryParam(event, "timezone") || LOCAL_TZ;
      const filterUserId = getQueryParam(event, "user_id") || null;
      const effectiveFilterUserId = dbUser?.role_key === "vendedor" ? dbUser.id : filterUserId;
      const client = createDbClient();
      await client.connect();
      try {
        const items = await getDailyWorkReport(client, fecha, timezone, new Date(), effectiveFilterUserId);
        return json(200, { ok: true, fecha, timezone, items });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load jornada diaria",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/supervisor/sellers-summary")) {
    const requestId = getRequestId(event);
    const startedAt = Date.now();
    let dbUser = null;
    let fecha = null;
    let batchTipo = "";
    try {
      const authContext = await getCurrentDbUserFromEvent(event);
      const authUser = authContext.authUser;
      dbUser = authContext.dbUser;
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      fecha = parseFechaParam(getQueryParam(event, "fecha"));
      const tipoRaw = getQueryParam(event, "tipo");
      const tipo = tipoRaw ? String(tipoRaw).trim().toLowerCase() : "";
      batchTipo = (tipo === "recupero" || tipo === "captacion") ? tipo : "";
      const client = createDbClient();
      await client.connect();
      try {
      const sellersRes = await client.query(
        `
        SELECT id, nombre, apellido
        FROM users
        WHERE role_key = 'vendedor'
          AND status = 'approved'
          AND (is_test IS NULL OR is_test = false)
        ORDER BY nombre
        `
      );
        const sellers = sellersRes.rows || [];
        const sellerIds = sellers.map((row) => row.id);
        if (!sellerIds.length) {
          return safeResponse({
            data: { items: [] },
            emptyCondition: true,
            message: "No hay vendedores asignados",
            meta: { fecha, tipo: batchTipo || "all", source: "sellers-summary", request_id: requestId }
          });
        }

        const columnsInfo = await getLeadContactColumns(client);
        const dCols = columnsInfo?.d || new Set();
        const hasDptContactId = dCols.has("contact_id");

        const assignedRes = await client.query(
          `
          SELECT lcs.assigned_to AS user_id,
                 COUNT(DISTINCT lcs.contact_id)::int AS asignados
          FROM lead_contact_status lcs
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE lcs.assigned_to = ANY($1::uuid[])
            AND lb.estado IN ('activo', 'asignado')
            AND ($2::text IS NULL OR lb.tipo = $2)
          GROUP BY lcs.assigned_to
          `,
          [sellerIds, batchTipo]
        );
        const assignedMap = new Map(assignedRes.rows.map((row) => [row.user_id, Number(row.asignados || 0)]));

        const dailyRes = await client.query(
          `
          WITH day_events AS (
            SELECT lmh.user_id,
                   lmh.contact_id,
                   lmh.resultado,
                   lmh.fecha_gestion
            FROM lead_management_history lmh
            JOIN lead_batches lb ON lb.id = lmh.batch_id
            WHERE lmh.user_id = ANY($1::uuid[])
              AND (lmh.fecha_gestion AT TIME ZONE 'America/Montevideo')::date = $2::date
              AND (
                $3::text IS NULL
                OR lb.tipo = $3
              )
          ), last_result AS (
            SELECT DISTINCT ON (user_id, contact_id)
              user_id,
              contact_id,
              resultado
            FROM day_events
            ORDER BY user_id, contact_id, fecha_gestion DESC
          )
          SELECT user_id,
                 COUNT(*)::int AS gestiones,
                 COUNT(*) FILTER (WHERE resultado = 'venta')::int AS ventas,
                 COUNT(*) FILTER (WHERE resultado = 'seguimiento')::int AS seguimientos,
                 COUNT(*) FILTER (WHERE resultado = 'rellamar')::int AS rellamadas,
                 COUNT(*) FILTER (WHERE resultado = 'no_contesta')::int AS no_contesta,
                 COUNT(*) FILTER (WHERE resultado = 'rechazo')::int AS rechazos,
                 COUNT(*) FILTER (WHERE resultado = 'dato_erroneo')::int AS datos_erroneos
          FROM last_result
          GROUP BY user_id
          `,
          [sellerIds, fecha, batchTipo]
        );
        const dailyMap = new Map(dailyRes.rows.map((row) => [row.user_id, row]));

        const warnings = [];
        const manualJoin = `
            JOIN contacts c ON c.id = s.contact_id
            JOIN datos_para_trabajar d ON d.contact_id = c.id
            JOIN lead_contact_status lcs ON lcs.contact_id = d.id
            JOIN lead_batches lb ON lb.id = lcs.batch_id
          `;

        let manualSalesMap = new Map();
        try {
          const manualSalesRes = await client.query(
            `
            SELECT s.seller_user_id AS user_id,
                   COUNT(*)::int AS manual_ventas
            FROM sales s
            ${manualJoin}
            WHERE s.seller_user_id = ANY($1::uuid[])
              AND (COALESCE(s.fecha_venta, s.created_at) AT TIME ZONE 'America/Montevideo')::date = $2::date
              AND ($3::text IS NULL OR lb.tipo = $3)
            GROUP BY s.seller_user_id
            `,
            [sellerIds, fecha, batchTipo]
          );
          manualSalesMap = new Map(manualSalesRes.rows.map((row) => [row.user_id, Number(row.manual_ventas || 0)]));
        } catch (error) {
          warnings.push({ code: "MANUAL_SALES_FAILED", message: "No se pudieron calcular ventas manuales" });
        }

        const items = sellers.map((seller) => {
          const daily = dailyMap.get(seller.id) || {};
          const manualVentas = manualSalesMap.get(seller.id) || 0;
          const ventas = manualVentas;
          const seguimientos = Number(daily.seguimientos || 0);
          const rellamadas = Number(daily.rellamadas || 0);
          const noContesta = Number(daily.no_contesta || 0);
          const rechazos = Number(daily.rechazos || 0);
          const datosErroneos = Number(daily.datos_erroneos || 0);
          const gestionesVenta = Number(daily.ventas || 0);
          const totalGestionado =
            ventas +
            seguimientos +
            rellamadas +
            noContesta +
            rechazos +
            datosErroneos;
          const datosUtiles = ventas + seguimientos + rechazos;
          const contacto = totalGestionado > 0
            ? Math.round((datosUtiles / totalGestionado) * 100)
            : 0;
          const efectividad = datosUtiles > 0
            ? Math.round((ventas / datosUtiles) * 100)
            : 0;

          return {
            id: seller.id,
            nombre: seller.nombre,
            apellido: seller.apellido,
            gestiones: totalGestionado,
            asignados: assignedMap.get(seller.id) || 0,
            ventas,
            gestiones_venta: gestionesVenta,
            seguimientos,
            rellamadas,
            no_contesta: noContesta,
            rechazos,
            datos_erroneos: datosErroneos,
            contacto,
            efectividad
          };
        });

        return safeResponse({
          data: { items },
          emptyCondition: items.length === 0,
          warnings,
          meta: { fecha, tipo: batchTipo || "all", source: "sellers-summary", request_id: requestId }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        status: "error",
        message: "Failed to load sellers summary",
        error: error.message,
        meta: { request_id: requestId }
      });
    } finally {
      console.log("[sellers-summary]", {
        request_id: requestId,
        user_id: dbUser?.id || null,
        fecha,
        tipo: batchTipo || "all",
        duration_ms: Date.now() - startedAt
      });
    }
  }
  const agentDetailMatch = path.match(/\/api\/supervisor\/agent-detail\/([^/]+)$/);
  if (method === "GET" && agentDetailMatch) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const fecha = parseFechaParam(getQueryParam(event, "fecha"));
      const client = createDbClient();
      await client.connect();
      try {
        const data = await getAgentDetail(client, agentDetailMatch[1], fecha, new Date());
        if (!data) {
          return json(404, { ok: false, message: "Agente no encontrado" });
        }
        return json(200, data);
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load agent detail",
        error: error.message
      });
    }
  }

  const agentWeekMatch = path.match(/\/api\/supervisor\/agent-week\/([^/]+)$/);
  if (method === "GET" && agentWeekMatch) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const fecha = parseFechaParam(getQueryParam(event, "fecha"));
      const client = createDbClient();
      await client.connect();
      try {
        const data = await getAgentWeek(client, agentWeekMatch[1], fecha);
        return json(200, data);
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load agent week",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/api/agent/event")) {
    const body = safeParseBody(event) || {};
    const agenteId = body.agente_id || body.agenteId;
    const tipo = String(body.tipo || "").toUpperCase();
    if (!agenteId || !tipo) {
      return json(400, { ok: false, message: "agente_id y tipo son requeridos" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const now = new Date();
        const fecha = formatDateYmd(now);
        const config = await getConfigMap(client);

        const activeRes = await client.query(
          `
          SELECT *
          FROM eventos_turno
          WHERE agente_id = $1
            AND fecha = $2
            AND fin IS NULL
          ORDER BY inicio DESC
          LIMIT 1
          `,
          [agenteId, fecha]
        );
        const activeEvent = activeRes.rows[0] || null;

        const normalizeTipo = (rawTipo) => {
          if (rawTipo === "CON_SUPERVISOR") return "SUPERVISOR";
          return rawTipo;
        };
        const isBanoType = (t) => t === "BA?O" || t === "BANO";
        const isPauseType = (t) => isBanoType(t) || t === "DESCANSO" || t === "SUPERVISOR";
        const getPauseLimit = (t) =>
          isBanoType(t) ? config.limite_bano_minutos : config.limite_descanso_minutos;
        const closeEvent = async (eventRow) => {
          if (!eventRow) return null;
          const fin = now;
          let excedido = false;
          let exceso = 0;
          if (isPauseType(eventRow.tipo)) {
            const limite = getPauseLimit(eventRow.tipo);
            const dur = minutesBetween(new Date(eventRow.inicio), fin);
            excedido = dur > limite;
            exceso = Math.max(0, dur - limite);
          }
          const result = await client.query(
            `
            UPDATE eventos_turno
            SET fin = $1,
                excedido = $2,
                exceso_minutos = $3
            WHERE id = $4
            RETURNING *
            `,
            [fin, excedido, exceso, eventRow.id]
          );
          return result.rows[0];
        };

        let createdAlert = null;
        const tipoNormalized = normalizeTipo(tipo);

        if (tipoNormalized === "LOGIN") {
          await client.query(
            `
            INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
            VALUES ($1, 'LOGIN', $2, $2, $3)
            `,
            [agenteId, now, fecha]
          );
          await client.query(
            `
            INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
            VALUES ($1, 'TRABAJO', $2, NULL, $3)
            `,
            [agenteId, now, fecha]
          );
          await upsertEstadoAgenteActual(client, agenteId, "TRABAJO", now, null, now);
        } else if (tipoNormalized === "LOGOUT") {
          if (activeEvent) {
            await closeEvent(activeEvent);
          }
          await client.query(
            `
            INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
            VALUES ($1, 'LOGOUT', $2, $2, $3)
            `,
            [agenteId, now, fecha]
          );
          await upsertEstadoAgenteActual(client, agenteId, "LOGOUT", now, null, now);
        } else if (isPauseType(tipoNormalized)) {
          if (activeEvent && activeEvent.tipo === "TRABAJO") {
            await closeEvent(activeEvent);
          }
          await client.query(
            `
            INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
            VALUES ($1, $2, $3, NULL, $4)
            `,
            [agenteId, tipoNormalized, now, fecha]
          );
          await upsertEstadoAgenteActual(client, agenteId, tipoNormalized, now, null, now);
        } else if (tipoNormalized === "TRABAJO") {
          if (activeEvent && isPauseType(activeEvent.tipo)) {
            const closed = await closeEvent(activeEvent);
            if (closed?.excedido) {
              const limite = getPauseLimit(closed.tipo);
              const semanaRes = await client.query(
                `
                SELECT COUNT(*)::int AS veces
                FROM alertas
                WHERE agente_id = $1
                  AND tipo = 'pausa_excedida'
                  AND subtipo = $2
                  AND fecha >= date_trunc('week', $3::date)
                  AND fecha <= $3::date
                `,
                [agenteId, closed.tipo.toLowerCase(), fecha]
              );
              createdAlert = await createAlert(client, {
                agente_id: agenteId,
                tipo: "pausa_excedida",
                subtipo: closed.tipo.toLowerCase(),
                descripcion: `${closed.tipo} extendido`,
                hora_evento: closed.inicio,
                duracion_minutos: minutesBetween(new Date(closed.inicio), new Date(closed.fin)),
                limite_minutos: limite,
                exceso_minutos: closed.exceso_minutos,
                veces_en_semana: Number(semanaRes.rows[0]?.veces || 0),
                fecha
              });
            }
          }
          await client.query(
            `
            INSERT INTO eventos_turno (agente_id, tipo, inicio, fin, fecha)
            VALUES ($1, 'TRABAJO', $2, NULL, $3)
            `,
            [agenteId, now, fecha]
          );
          await upsertEstadoAgenteActual(client, agenteId, "TRABAJO", now, null, now);
        } else {
          return json(400, { ok: false, message: "Tipo de evento no valido" });
        }

        const summary = await getTeamSummary(client, fecha, now);
        await emitRealtime("agent_event", {
          agente_id: agenteId,
          evento: { tipo: tipoNormalized, inicio: formatTimeHm(now), fin: tipoNormalized === "LOGOUT" || tipoNormalized === "LOGIN" ? formatTimeHm(now) : null }
        });
        if (createdAlert) {
          await emitRealtime("new_alert", {
            agente_id: agenteId,
            alerta: {
              tipo: createdAlert.tipo,
              subtipo: createdAlert.subtipo,
              descripcion: createdAlert.descripcion,
              hora_evento: createdAlert.hora_evento
            }
          });
        }
        await emitRealtime("team_update", summary);

        return json(201, { ok: true });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to register agent event",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/api/agent/call")) {
    const body = safeParseBody(event) || {};
    const agenteId = body.agente_id || body.agenteId;
    if (!agenteId) {
      return json(400, { ok: false, message: "agente_id es requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const now = new Date();
        const fecha = formatDateYmd(now);
        const duracion = Number(body.duracion_segundos || body.duracionSegundos || 0);
        const resultado = String(body.resultado || "").toLowerCase();
        const corta = duracion < 60 && resultado !== "venta";

        await client.query(
          `
          INSERT INTO llamadas (
            agente_id,
            cliente_nombre,
            cliente_telefono,
            inicio,
            duracion_segundos,
            resultado,
            fecha,
            corta
          )
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
          `,
          [
            agenteId,
            body.cliente_nombre || body.clienteNombre || null,
            body.cliente_telefono || body.clienteTelefono || null,
            now,
            duracion,
            resultado,
            fecha,
            corta
          ]
        );

        const config = await getConfigMap(client);
        const statsRes = await client.query(
          `
          SELECT COUNT(*)::int AS llamadas,
                 COUNT(*) FILTER (WHERE resultado = 'venta')::int AS ventas
          FROM llamadas
          WHERE agente_id = $1
            AND fecha = $2
          `,
          [agenteId, fecha]
        );
        const row = statsRes.rows[0];
        const conversion = computeConversion(Number(row.ventas || 0), Number(row.llamadas || 0));

        let createdAlert = null;
        const tipoNormalized = normalizeTipo(tipo);
        if (conversion < config.conversion_minima_porcentaje) {
          const exists = await client.query(
            `
            SELECT 1
            FROM alertas
            WHERE agente_id = $1
              AND fecha = $2
              AND tipo = 'conversion_baja'
              AND resuelta = false
            LIMIT 1
            `,
            [agenteId, fecha]
          );
          if (!exists.rows.length) {
            createdAlert = await createAlert(client, {
              agente_id: agenteId,
              tipo: "conversion_baja",
              descripcion: `${conversion}% actual vs mï¿½nimo ${config.conversion_minima_porcentaje}%`,
              hora_evento: now,
              fecha
            });
          }
        }

        await emitRealtime("new_call", {
          agente_id: agenteId,
          llamada: { resultado, duracion_segundos: duracion }
        });
        if (createdAlert) {
          await emitRealtime("new_alert", {
            agente_id: agenteId,
            alerta: {
              tipo: createdAlert.tipo,
              descripcion: createdAlert.descripcion,
              hora_evento: createdAlert.hora_evento
            }
          });
        }
        const summary = await getTeamSummary(client, fecha, now);
        await emitRealtime("team_update", summary);

        return json(201, { ok: true });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to register call",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/api/supervisor/agents")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const search = normalizeText(getQueryParam(event, "search") || "");
      const items = await listUsersService({
        role: "vendedor",
        status: "approved",
        search: search || null
      });

      const mapped = items.map((user) => ({
        id: user.id,
        nombre: user.nombre,
        apellido: user.apellido,
        email: user.email,
        status: "Activo"
      }));

      return json(200, {
        ok: true,
        agents: mapped
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list agents",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/sellers")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const search = normalizeText(getQueryParam(event, "search") || "");
      const values = [];
      const whereParts = [];
      if (organizationId) {
        values.push(organizationId);
        whereParts.push(`s.organization_id = $${values.length}`);
      }
      if (search) {
        values.push(`%${search.toLowerCase()}%`);
        const idx = values.length;
        whereParts.push(`(lower(s.nombre) LIKE $${idx} OR lower(s.apellido) LIKE $${idx} OR lower(coalesce(u.email,'')) LIKE $${idx})`);
      }
      const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

      const client = createDbClient();
      await client.connect();
      let mapped = [];
      try {
        const result = await client.query(
          `
          SELECT
            s.id,
            s.nombre,
            s.apellido,
            u.email,
            u.telefono
          FROM sellers s
          LEFT JOIN users u ON u.id = s.user_id
          ${whereClause}
          ORDER BY s.nombre ASC
          `,
          values
        );
        mapped = result.rows.map((row) => ({
          id: row.id,
          nombre: row.nombre,
          apellido: row.apellido,
          email: row.email,
          telefono: row.telefono
        }));
      } finally {
        await client.end();
      }

      return json(200, {
        ok: true,
        success: true,
        data: mapped,
        items: mapped
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list sellers",
        error: error.message
      });
    }
  }

  if (method === "DELETE" && path.match(/\/imports\/no-llamar\/jobs\/([^/]+)$/)) {
    const match = path.match(/\/imports\/no-llamar\/jobs\/([^/]+)$/);
    const jobId = match?.[1];
    if (!jobId) {
      return json(400, { ok: false, message: "Job id requerido" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const statusRes = await client.query(
          `
          SELECT status
          FROM no_call_import_jobs
          WHERE id = $1
          LIMIT 1
          `,
          [jobId]
        );
        if (!statusRes.rows.length) {
          return json(404, { ok: false, message: "Job no encontrado" });
        }
        const status = statusRes.rows[0]?.status || "";
        if (status === "processing") {
          return json(409, { ok: false, message: "El job estï¿½ en proceso" });
        }
        const deleted = await client.query(
          `
          DELETE FROM no_call_import_jobs
          WHERE id = $1
          `,
          [jobId]
        );
        return json(200, { ok: true, deleted: deleted.rowCount || 0 });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to delete no-llamar job",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.match(/\/imports\/no-llamar\/jobs\/([^/]+)$/)) {
    const match = path.match(/\/imports\/no-llamar\/jobs\/([^/]+)$/);
    const jobId = match?.[1];
    if (!jobId) {
      return json(400, { ok: false, message: "Job id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const jobRes = await client.query(
          `
          SELECT
            id,
            file_name,
            status,
            total_rows,
            processed_rows,
            inserted_rows,
            skipped_rows,
            error_message,
            created_at,
            started_at,
            completed_at
          FROM no_call_import_jobs
          WHERE id = $1
          LIMIT 1
          `,
          [jobId]
        );
        if (!jobRes.rows.length) {
          return json(404, { ok: false, message: "Job not found" });
        }
        const row = jobRes.rows[0];
        const totalRows = Number(row.total_rows || 0);
        const processedRows = Number(row.processed_rows || 0);
        const progressPercent = totalRows > 0
          ? Math.min(100, Math.round((processedRows / totalRows) * 100))
          : 0;
        return json(200, {
          ok: true,
          job: {
            id: row.id,
            fileName: row.file_name,
            status: row.status,
            total: totalRows,
            processed: processedRows,
            inserted: Number(row.inserted_rows || 0),
            skipped: Number(row.skipped_rows || 0),
            error: row.error_message || null,
            createdAt: row.created_at,
            startedAt: row.started_at,
            completedAt: row.completed_at,
            progressPercent
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load no-llamar job",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/imports/datos-para-trabajar")) {
    const fileName =
      event?.headers?.["x-file-name"] ||
      event?.headers?.["X-File-Name"] ||
      event?.headers?.["x-filename"] ||
      event?.headers?.["X-Filename"] ||
      "datos_para_trabajar.csv";
    const contentType = event?.headers?.["content-type"] || event?.headers?.["Content-Type"] || "";
    const rawBody = event?.body || "";
    const bodyText = event?.isBase64Encoded
      ? Buffer.from(rawBody, "base64").toString("utf8")
      : typeof rawBody === "string"
      ? rawBody
      : JSON.stringify(rawBody);

    let csvText = bodyText;
    if (contentType.includes("application/json")) {
      const parsed = safeParseBody(event);
      if (parsed && parsed.csv) {
        csvText = parsed.csv;
      }
    }

    if (!csvText || !csvText.trim()) {
      return json(400, { ok: false, message: "CSV vacio" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const { rows, ignoredEmptyRows } = mapDatosParaTrabajarCsv(csvText);
      const client = createDbClient();
      await client.connect();

      try {
        await client.query("BEGIN");
        let batchRes;
        try {
          batchRes = await client.query(
            `
            INSERT INTO contact_import_batches (
              file_name,
              status,
              import_type,
              total_rows,
              valid_rows,
              error_rows,
              created_by,
              organization_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            `,
            [
              fileName,
              "processed",
              "datos_para_trabajar",
              rows.length,
              0,
              0,
              dbUser?.id || null,
              organizationId
            ]
          );
        } catch (err) {
          const message = String(err?.message || '');
          if (message.includes('contact_import_batches_type_check')) {
            await client.query(
              `
              ALTER TABLE public.contact_import_batches
              DROP CONSTRAINT IF EXISTS contact_import_batches_type_check;
              `
            );
            await client.query(
              `
              ALTER TABLE public.contact_import_batches
              ADD CONSTRAINT contact_import_batches_type_check
              CHECK (import_type IN ('clientes', 'no_llamar', 'resultados', 'datos_para_trabajar'));
              `
            );
            batchRes = await client.query(
              `
              INSERT INTO contact_import_batches (
                file_name,
                status,
                import_type,
                total_rows,
                valid_rows,
                error_rows,
                created_by,
                organization_id
              )
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
              RETURNING id
              `,
              [
                fileName,
                "processed",
                "datos_para_trabajar",
                rows.length,
                0,
                0,
                dbUser?.id || null,
                organizationId
              ]
            );
          } else if (message.includes('contact_import_batches_status_check')) {
            await client.query(
              `
              ALTER TABLE public.contact_import_batches
              DROP CONSTRAINT IF EXISTS contact_import_batches_status_check;
              `
            );
            await client.query(
              `
              ALTER TABLE public.contact_import_batches
              ADD CONSTRAINT contact_import_batches_status_check
              CHECK (status IN ('uploaded', 'validated', 'processed', 'processing', 'failed'));
              `
            );
            batchRes = await client.query(
              `
              INSERT INTO contact_import_batches (
                file_name,
                status,
                import_type,
                total_rows,
                valid_rows,
                error_rows,
                created_by,
                organization_id
              )
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
              RETURNING id
              `,
              [
                fileName,
                "processed",
                "datos_para_trabajar",
                rows.length,
                0,
                0,
                dbUser?.id || null,
                organizationId
              ]
            );
          } else {
            throw err;
          }
        }
        const batchId = batchRes.rows[0]?.id || null;
        await ensureDatosTrabajarJobTable(client);
        const jobRes = await client.query(
          `
          INSERT INTO datos_para_trabajar_import_jobs (
            batch_id,
            file_name,
            status,
            total_rows,
            processed_rows,
            inserted_rows,
            blocked_rows,
            skipped_rows,
            csv_text,
            created_by,
            organization_id
          )
          VALUES ($1, $2, 'queued', $3, 0, 0, 0, 0, $4, $5, $6)
          RETURNING id
          `,
          [batchId, fileName, rows.length, csvText, dbUser?.id || null, organizationId]
        );

        const jobId = jobRes.rows[0]?.id || null;
        if (!jobId) {
          throw new Error("Failed to create datos_para_trabajar job");
        }
        await enqueueDatosTrabajarJob(jobId);

        await client.query(
          `
          UPDATE contact_import_batches
          SET status = 'processing',
              total_rows = $2,
              valid_rows = 0,
              error_rows = 0,
              updated_at = now()
          WHERE id = $1
          ${organizationId ? "AND organization_id = $3" : ""}
          `,
          organizationId ? [batchId, rows.length, organizationId] : [batchId, rows.length]
        );
        await client.query("COMMIT");
        return json(201, {
          ok: true,
          batchId,
          jobId,
          total: rows.length,
          ignoredEmptyRows
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to import datos para trabajar",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/datos-para-trabajar")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const organizationId = await resolveOrganizationIdForRequest(dbUser, event);

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const pageSize = Math.max(1, Number(getQueryParam(event, "pageSize") || 20));
      const search = normalizeText(getQueryParam(event, "search") || "");
      const blockedFilterRaw = getQueryParam(event, "bloqueado_no_llamar");
      const blockedFilter =
        blockedFilterRaw === undefined || blockedFilterRaw === null || blockedFilterRaw === ""
          ? null
          : String(blockedFilterRaw).toLowerCase();
      const estadoFilterRaw = getQueryParam(event, "estado");
      const estadoFilter = estadoFilterRaw ? normalizeText(estadoFilterRaw) : null;
      const offset = (page - 1) * pageSize;

      const client = createDbClient();
      await client.connect();
      try {
        const whereParts = [];
        const values = [];
        let idx = 1;

        if (organizationId) {
          whereParts.push(`organization_id = $${idx}`);
          values.push(organizationId);
          idx += 1;
        }

        if (search) {
          whereParts.push(`(
            d.nombre ILIKE $${idx}
            OR d.apellido ILIKE $${idx}
            OR d.documento ILIKE $${idx}
            OR d.telefono ILIKE $${idx}
            OR d.celular ILIKE $${idx}
            OR d.email ILIKE $${idx}
            OR d.departamento ILIKE $${idx}
            OR d.localidad ILIKE $${idx}
          )`);
          values.push(`%${search}%`);
          idx += 1;
        }

        const normalizedCelular = buildNormalizedPhoneSql("d.celular");
        const normalizedTelefono = buildNormalizedPhoneSql("d.telefono");
        const blockedExistsSql = `
          EXISTS (
            SELECT 1
            FROM no_call_entries n
            WHERE n.numero IN (${normalizedCelular}, ${normalizedTelefono})
          )
        `;

        if (blockedFilter === "true") {
          whereParts.push(blockedExistsSql);
        } else if (blockedFilter === "false") {
          whereParts.push(`NOT ${blockedExistsSql}`);
        }

        if (estadoFilter) {
          if (estadoFilter === "bloqueado") {
            whereParts.push(blockedExistsSql);
          } else if (estadoFilter === "nuevo") {
            whereParts.push(`(d.estado IS NULL OR d.estado = 'nuevo')`);
            whereParts.push(`NOT ${blockedExistsSql}`);
          } else if (estadoFilter === "trabajado") {
            whereParts.push(`d.estado = 'trabajado'`);
            whereParts.push(`NOT ${blockedExistsSql}`);
          }
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

        const countResult = await client.query(
          `
          SELECT COUNT(*)::int AS total
          FROM datos_para_trabajar d
          ${whereClause}
          `,
          values
        );

        const total = countResult.rows[0]?.total || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        const itemsResult = await client.query(
          `
          SELECT
            d.id,
            d.nombre,
            d.apellido,
            d.documento,
            d.fecha_nacimiento,
            d.telefono,
            d.celular,
            d.email,
            d.direccion,
            d.departamento,
            d.localidad,
            d.origen_dato,
            d.estado,
            d.created_at,
            ${blockedExistsSql} AS bloqueado_no_llamar
          FROM datos_para_trabajar d
          ${whereClause}
          ORDER BY created_at DESC
          LIMIT $${idx} OFFSET $${idx + 1}
          `,
          [...values, pageSize, offset]
        );

        const items = itemsResult.rows.map((row) => {
          const estado =
            row.bloqueado_no_llamar ? "bloqueado" : (row.estado || "nuevo");
          const estadoLabel =
            estado === "bloqueado"
              ? "Bloqueado"
              : estado === "trabajado"
              ? "Trabajado"
              : "Nuevo";

          return {
            ...row,
            bloqueado_no_llamar: Boolean(row.bloqueado_no_llamar),
            estado,
            estado_label: estadoLabel
          };
        });

        return json(200, {
          items,
          page,
          pageSize,
          total,
          totalPages
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list datos para trabajar",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/imports/clients/analyze-diff")) {
    // Intento directo de leer CSV del body
    let csvText = "";
    try {
      const rawBody = event?.body || "";
      const bodyStr = event?.isBase64Encoded
        ? Buffer.from(rawBody, "base64").toString("latin1")
        : typeof rawBody === "string"
        ? rawBody
        : JSON.stringify(rawBody);

      // Intentar JSON primero
      try {
        const parsed = JSON.parse(bodyStr);
        if (parsed?.csv) {
          csvText = parsed.csv;
          console.log("analyze-diff: CSV desde JSON, length:", csvText.length);
        }
      } catch {
        // No es JSON, usar como texto directo
        csvText = bodyStr;
        console.log(
          "analyze-diff: CSV como texto directo, length:",
          csvText.length
        );
      }
    } catch (e) {
      console.log("analyze-diff: error leyendo body:", e.message);
    }

    if (!csvText?.trim()) {
      return json(400, { ok: false, message: "CSV vacio" });
    }

    const parsedMultipart = null;
    const rawCsv = csvText;

    if (!csvText || !csvText.trim()) {
      return json(400, { ok: false, message: "CSV vacio" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const parseContext = getClientsCsvParseContext(csvText);
      if (parseContext.error) {
        return json(400, { ok: false, message: "CSV vacio" });
      }
      const { lineIterator, separator, headerKeys } = parseContext;
      const lines = String(rawCsv || "").replace(/^\uFEFF/, "").split(/\r?\n/);

      const client = createDbClient();
      await client.connect();
      try {
        let totalCsv = 0;
        let coinciden = 0;
        let altaBdBajaCsv = 0;
        let bajaBdAltaCsv = 0;
        let noEncontrados = 0;

        const detalleAltaBdBaja = [];
        const detalleBajaBdAlta = [];
        const detalleNoEncontrados = [];

        const rows = [];
        let rowNumber = 0;
        for (const line of lineIterator) {
          if (!line || !line.trim()) continue;
          let cells = parseCsvLine(line, separator);
          if (cells.length === 1 && line.includes(";")) {
            cells = parseCsvLine(line, ";");
          }
          if (cells.length === 1 && line.includes(";")) {
            cells = line.split(";");
          } else if (cells.length === 1 && line.includes("\t")) {
            cells = line.split("\t");
          }
          const item = {};
          for (let j = 0; j < headerKeys.length; j += 1) {
            const key = headerKeys[j];
            if (!key) continue;
            item[key] = normalizeCsvValue(cells[j]);
          }
          const hasValues = Object.values(item).some(
            (value) => value !== null && String(value).trim() !== ""
          );
          if (!hasValues) continue;

          rows.push(item);
          rowNumber += 1;
          totalCsv += 1;

          const nombre = item.nombre || "";
          const apellido = item.apellido || "";
          const documento = item.documento || "";
          const estadoCsvRaw = normalizeText(item.producto_estado || item.estado || "");
          const estadoCsvNorm = estadoCsvRaw.toLowerCase();
          const csvIsAlta = estadoCsvNorm === "alta" || estadoCsvNorm === "activo";
          const csvIsBaja = estadoCsvNorm === "baja";

          let contactId = null;
          if (documento && nombre && apellido) {
            const contactRes = await client.query(
              `
              SELECT id
              FROM contacts
              WHERE documento = $1
                AND lower(unaccent_simple(nombre)) = lower(unaccent_simple($2))
                AND lower(unaccent_simple(apellido)) = lower(unaccent_simple($3))
              LIMIT 1
              `,
              [documento, nombre, apellido]
            );
            contactId = contactRes.rows[0]?.id ?? null;
          }

          if (!contactId) {
            noEncontrados += 1;
            if (detalleNoEncontrados.length < 50) {
              detalleNoEncontrados.push({
                row_number: rowNumber,
                documento: documento || null,
                nombre: nombre || null,
                apellido: apellido || null,
                estado_csv: estadoCsvRaw || null
              });
            }
            continue;
          }

          const estadoRes = await client.query(
            `
            SELECT estado
            FROM contact_products
            WHERE contact_id = $1
            ORDER BY fecha_alta DESC NULLS LAST, created_at DESC
            LIMIT 1
            `,
            [contactId]
          );
          const estadoBdRaw = estadoRes.rows[0]?.estado || null;
          const estadoBdNorm = String(estadoBdRaw || "").toLowerCase();
          const bdIsAlta = estadoBdNorm === "alta";

          if (csvIsBaja && bdIsAlta) {
            altaBdBajaCsv += 1;
            if (detalleAltaBdBaja.length < 50) {
              detalleAltaBdBaja.push({
                row_number: rowNumber,
                documento: documento || null,
                nombre: nombre || null,
                apellido: apellido || null,
                estado_csv: estadoCsvRaw || null,
                estado_bd: estadoBdRaw || null
              });
            }
          } else if (csvIsAlta && !bdIsAlta) {
            bajaBdAltaCsv += 1;
            if (detalleBajaBdAlta.length < 50) {
              detalleBajaBdAlta.push({
                row_number: rowNumber,
                documento: documento || null,
                nombre: nombre || null,
                apellido: apellido || null,
                estado_csv: estadoCsvRaw || null,
                estado_bd: estadoBdRaw || null
              });
            }
          } else {
            coinciden += 1;
          }
        }

        console.log("analyze-diff: content-type", event?.headers?.["content-type"]);
        console.log("analyze-diff: body length", event?.body?.length);
        console.log("analyze-diff: isBase64", event?.isBase64Encoded);
        console.log("analyze-diff: rawCsv length despuÃ©s de decode", rawCsv?.length);
        console.log("analyze-diff: csvText length desde JSON:", rawCsv?.length);
        console.log(
          "analyze-diff: multipart fields",
          Object.keys(parsedMultipart?.fields || {})
        );
        console.log(
          "analyze-diff: multipart files",
          Object.keys(parsedMultipart?.files || {})
        );
        console.log(
          "analyze-diff: file content length",
          parsedMultipart?.files?.file?.content?.length
        );
        console.log("analyze-diff: lÃ­neas detectadas", lines?.length);
        console.log("analyze-diff: separador detectado", separator);
        console.log("analyze-diff: primera lÃ­nea", lines?.[0]?.substring(0, 100));
        console.log("analyze-diff rows:", rows.length);
        return json(200, {
          resumen: {
            total_csv: totalCsv,
            coinciden,
            alta_bd_baja_csv: altaBdBajaCsv,
            baja_bd_alta_csv: bajaBdAltaCsv,
            no_encontrados: noEncontrados
          },
          detalle: {
            alta_bd_baja_csv: detalleAltaBdBaja,
            baja_bd_alta_csv: detalleBajaBdAlta,
            no_encontrados: detalleNoEncontrados
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to analyze diff",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/imports/clients")) {
    const fileNameHeader =
      event?.headers?.["x-file-name"] ||
      event?.headers?.["X-File-Name"] ||
      event?.headers?.["x-filename"] ||
      event?.headers?.["X-Filename"] ||
      "import_clientes.csv";
    const { csvText, fileName: multipartFileName } = extractClientsImportCsv(event);
    const fileName = multipartFileName || fileNameHeader || "import_clientes.csv";

    if (!csvText || !csvText.trim()) {
      return json(400, { ok: false, message: "CSV vacio" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const orgClient = createDbClient();
      await orgClient.connect();
      let organizationId = null;
      try {
        organizationId = await resolveOrganizationId(orgClient, dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      } finally {
        await orgClient.end();
      }

      const autoProcessParam = String(getQueryParam(event, "autoProcess") || "")
        .trim()
        .toLowerCase();
      const autoProcess = !["false", "0", "no"].includes(autoProcessParam);
      const createProductsParam = String(getQueryParam(event, "createProducts") || "")
        .trim()
        .toLowerCase();
      const createProducts = !["false", "0", "no"].includes(createProductsParam);

      const parseContext = getClientsCsvParseContext(csvText);
      if (parseContext.error) {
        return json(400, { ok: false, message: "CSV vacio" });
      }
      const { lineIterator, separator, headerKeys } = parseContext;
      let ignoredEmptyRows = 0;
      const client = createDbClient();
      await client.connect();

      try {
        await client.query("BEGIN");
        const batchResult = await client.query(
          `
          INSERT INTO contact_import_batches (
            file_name,
            status,
            import_type,
            total_rows,
            valid_rows,
            error_rows,
            rejected_missing_documento,
            created_by,
            organization_id
          )
          VALUES ($1, 'uploaded', 'clientes', 0, 0, 0, 0, $2, $3)
          RETURNING *
          `,
          [fileName, dbUser?.id || null, organizationId]
        );

        const batch = batchResult.rows[0];
        let validRows = 0;
        let errorRows = 0;
        let missingDocumentoRows = 0;
        const productNamesSet = new Set();
        let totalRows = 0;
        const batchRows = [];

        const flushBatch = async () => {
          if (!batchRows.length) return;
          const { sql, values } = buildContactImportInsertBatch(batchRows);
          await client.query(sql, values);
          batchRows.length = 0;
        };

        for (const line of lineIterator) {
          if (!line || !line.trim()) {
            ignoredEmptyRows += 1;
            continue;
          }
          let cells = parseCsvLine(line, separator);
          if (cells.length === 1 && line.includes(";")) {
            cells = parseCsvLine(line, ";");
          }
          if (cells.length === 1 && line.includes(";")) {
            cells = line.split(";");
          } else if (cells.length === 1 && line.includes("\t")) {
            cells = line.split("\t");
          }
          const item = {};
          for (let j = 0; j < headerKeys.length; j += 1) {
            const key = headerKeys[j];
            if (!key) continue;
            item[key] = normalizeCsvValue(cells[j]);
          }
          const hasValues = Object.values(item).some(
            (value) => value !== null && String(value).trim() !== ""
          );
          if (!hasValues) {
            ignoredEmptyRows += 1;
            continue;
          }

          totalRows += 1;
          const errors = validateImportRow(item);
          const importStatus = errors.length ? "error" : "validated";
          if (importStatus === "validated") validRows += 1;
          else {
            errorRows += 1;
            if (errors.includes("documento requerido")) missingDocumentoRows += 1;
          }

          const productName = normalizeText(item.producto_nombre);
          if (productName) productNamesSet.add(productName);

          const rowValues = buildContactImportRowValues(
            batch.id,
            totalRows,
            item,
            importStatus,
            errors.length ? JSON.stringify(errors) : null
          );
          batchRows.push(rowValues);

          if (batchRows.length >= CONTACT_IMPORT_BATCH_SIZE) {
            await flushBatch();
          }
        }

        await flushBatch();

        const productNames = Array.from(productNamesSet).filter(Boolean);
        let missingProducts = [];
        if (productNames.length > 0) {
          const existingProducts = await client.query(
            `
            SELECT lower(nombre) AS nombre
            FROM products
            WHERE lower(nombre) = ANY($1)
            `,
            [productNames.map((name) => name.toLowerCase())]
          );
          const existingSet = new Set(
            existingProducts.rows.map((row) => row.nombre)
          );
          missingProducts = productNames.filter(
            (name) => !existingSet.has(name.toLowerCase())
          );
        }

        const finalStatus =
          totalRows > 0 && validRows === 0 && errorRows > 0
            ? "failed"
            : "validated";

        await client.query(
          `
          UPDATE contact_import_batches
          SET total_rows = $1,
              valid_rows = $2,
              error_rows = $3,
              rejected_missing_documento = $4,
              status = $5,
              updated_at = now()
          WHERE id = $6
          `,
          [totalRows, validRows, errorRows, missingDocumentoRows, finalStatus, batch.id]
        );

        await client.query("COMMIT");

        let processResult = null;
        let enqueued = false;
        if (autoProcess) {
          await enqueueContactImportJob(batch.id, { createProducts });
          enqueued = true;
        }

        return json(201, {
          ok: true,
          batchId: batch.id,
          total: totalRows,
          valid: validRows,
          errors: errorRows,
          rejectedMissingDocumento: missingDocumentoRows,
          ignoredEmptyRows,
          newProducts: missingProducts,
          newProductsCount: missingProducts.length,
          processed: Boolean(processResult),
          enqueued,
          process: processResult
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to import CSV",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.match(/\/imports\/clients\/([^/]+)\/status$/)) {
    const match = path.match(/\/imports\/clients\/([^/]+)\/status$/);
    const batchId = match?.[1];
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        let organizationId = null;
        try {
          organizationId = await resolveOrganizationId(client, dbUser, event);
        } catch (error) {
          if (error?.status) {
            return json(error.status, { ok: false, message: error.message });
          }
          throw error;
        }

        const batchResult = await client.query(
          `
          SELECT
            id,
            file_name,
            status,
            import_type,
            total_rows,
            valid_rows,
            error_rows,
            rejected_missing_documento,
            report_products_detected,
            report_products_created,
            report_sellers_detected,
            report_new_contacts,
            created_at,
            updated_at
          FROM contact_import_batches
          WHERE id = $1
            ${organizationId ? "AND organization_id = $2" : ""}
          LIMIT 1
          `,
          organizationId ? [batchId, organizationId] : [batchId]
        );

        if (!batchResult.rows.length) {
          return json(404, { ok: false, message: "Batch no encontrado" });
        }

        const progressResult = await client.query(
          `
          SELECT
            COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE import_status = 'created')::int AS created,
            COUNT(*) FILTER (WHERE import_status = 'updated')::int AS updated,
            COUNT(*) FILTER (WHERE import_status = 'error')::int AS errors,
            COUNT(*) FILTER (WHERE import_status = 'imported')::int AS imported,
            COUNT(*) FILTER (WHERE import_status IS NULL OR import_status = 'pending')::int AS pending
          FROM contact_import_rows
          WHERE batch_id = $1
          ${organizationId ? "AND organization_id = $2" : ""}
          `,
          organizationId ? [batchId, organizationId] : [batchId]
        );

        const batch = batchResult.rows[0];
        const progress = progressResult.rows[0] || {};
        const totalRows = Number(batch.total_rows || progress.total || 0);
        const created = Number(progress.created || 0);
        const updated = Number(progress.updated || 0);
        const imported = Number(progress.imported || 0);
        const errors = Number(progress.errors || 0);
        const pending = Number(progress.pending || 0);
        const processed = created + updated + imported + errors;
        const pct = totalRows > 0 ? Math.round((processed / totalRows) * 100) : 0;

        return json(200, {
          ok: true,
          data: {
            batchId: batch.id,
            status: batch.status,
            fileName: batch.file_name,
            totalRows: totalRows,
            validRows: Number(batch.valid_rows || 0),
            errorRows: Number(batch.error_rows || 0),
            progress: {
              created,
              updated,
              errors,
              imported,
              pending,
              processed,
              pct
            },
            report: {
              productosDetectados: Number(batch.report_products_detected || 0),
              productosCreados: Number(batch.report_products_created || 0),
              vendedoresDetectados: Number(batch.report_sellers_detected || 0),
              nuevosContactos: Number(batch.report_new_contacts || 0)
            }
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load import status",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.match(/\/imports\/([^/]+)\/rows$/)) {
    const match = path.match(/\/imports\/([^/]+)\/rows$/);
    const batchId = match?.[1];
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        let organizationId = null;
        try {
          organizationId = await resolveOrganizationId(client, dbUser, event);
        } catch (error) {
          if (error?.status) {
            return json(error.status, { ok: false, message: error.message });
          }
          throw error;
        }

        const rowsResult = await client.query(
          `
          SELECT
            id,
            row_number,
            import_status,
            error_detail,
            raw_payload,
            resolved_contact_id
          FROM contact_import_rows
          WHERE batch_id = $1
            ${organizationId ? "AND organization_id = $2" : ""}
          ORDER BY row_number ASC
          `,
          organizationId ? [batchId, organizationId] : [batchId]
        );

        return json(200, {
          items: rowsResult.rows
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load import rows",
        error: error.message
      });
    }
  }

  if (method === "DELETE" && path.match(/\/imports\/clients\/([^/]+)$/)) {
    const match = path.match(/\/imports\/clients\/([^/]+)$/);
    const batchId = match?.[1];
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        let organizationId = null;
        try {
          organizationId = await resolveOrganizationId(client, dbUser, event);
        } catch (error) {
          if (error?.status) {
            return json(error.status, { ok: false, message: error.message });
          }
          throw error;
        }

        await client.query("BEGIN");
        await client.query(
          `
          DELETE FROM contact_import_rows
          WHERE batch_id = $1
            ${organizationId ? "AND organization_id = $2" : ""}
          `,
          organizationId ? [batchId, organizationId] : [batchId]
        );
        const deleteBatch = await client.query(
          `
          DELETE FROM contact_import_batches
          WHERE id = $1
            ${organizationId ? "AND organization_id = $2" : ""}
          `,
          organizationId ? [batchId, organizationId] : [batchId]
        );
        await client.query("COMMIT");
        return json(200, { ok: true, deleted: deleteBatch.rowCount || 0 });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to delete import batch",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.match(/\/imports\/clients\/([^/]+)\/process$/)) {
    const match = path.match(/\/imports\/clients\/([^/]+)\/process$/);
    const batchId = match?.[1];
    if (!batchId) {
      return json(400, { ok: false, message: "Batch id requerido" });
    }
    const createProductsParam = String(getQueryParam(event, "createProducts") || "")
      .trim()
      .toLowerCase();
    // Default behavior: auto-create missing products using name + price.
    // Allow explicit opt-out with createProducts=false/0/no.
    const createProducts = !["false", "0", "no"].includes(createProductsParam);

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, INTERNAL_CONTACT_ACCESS_ROLES);
      if (roleError) return roleError;

      const orgClient = createDbClient();
      await orgClient.connect();
      let organizationId = null;
      try {
        organizationId = await resolveOrganizationId(orgClient, dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      } finally {
        await orgClient.end();
      }

      await enqueueContactImportJob(batchId, { createProducts, organizationId });
      return json(200, { ok: true, batchId, enqueued: true });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to process import batch",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/products")) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const validation = validateProductPayload(body);
    if (!validation.valid) {
      return json(422, {
        ok: false,
        message: "Validation failed",
        errors: validation.errors
      });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const item = await createProductRecord(validation.data, organizationId);
      return json(201, { ok: true, item });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to create product",
        error: error.message
      });
    }
  }

  if (method === "PUT" && productMatch) {
    const body = safeParseBody(event);
    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const validation = validateProductPayload(body, { partial: true });
    if (!validation.valid) {
      return json(422, {
        ok: false,
        message: "Validation failed",
        errors: validation.errors
      });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const item = await updateProductRecord(productMatch[1], validation.data, organizationId);
      if (!item) {
        return json(404, { ok: false, message: "Product not found" });
      }
      return json(200, { ok: true, item });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to update product",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/org/users")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, [
        "superadministrador", "director", "supervisor"
      ]);
      if (roleError) return roleError;

      const organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      if (!organizationId) {
        return json(403, { ok: false, message: "Sin organizacion activa" });
      }

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `SELECT
             u.id,
             u.nombre,
             u.apellido,
             u.email,
             u.telefono,
             u.role_key,
             u.status,
             u.created_at,
             ou.role_in_org
           FROM organization_users ou
           JOIN users u ON u.id = ou.user_id
           WHERE ou.organization_id = $1
             AND ou.activo = true
             AND u.role_key IN ('vendedor', 'atencion_cliente')
           ORDER BY u.nombre ASC`,
          [organizationId]
        );
        return json(200, { ok: true, items: result.rows });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list org users",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/org/users")) {
    const body = safeParseBody(event);
    if (body === null) return json(400, { ok: false, message: "Invalid JSON body" });

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, [
        "superadministrador", "director", "supervisor"
      ]);
      if (roleError) return roleError;

      const organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      if (!organizationId) {
        return json(403, { ok: false, message: "Sin organizacion activa" });
      }

      const rol = String(body?.role || body?.rol || '').trim();
      if (!['vendedor', 'atencion_cliente'].includes(rol)) {
        return json(422, {
          ok: false,
          message: "Solo se pueden crear usuarios con rol vendedor o atencion_cliente"
        });
      }

      const validation = validateSuperadminUserPayload({
        ...body,
        rol,
        status: body?.status || 'approved'
      });
      if (!validation.valid) {
        return json(422, {
          ok: false,
          message: "Validation failed",
          errors: validation.errors
        });
      }

      const DEFAULT_VENDOR_PASSWORD = 'Rednacrem@2026';

      const payload = {
        nombre: validation.data.nombre,
        apellido: validation.data.apellido,
        email: validation.data.email,
        telefono: normalizePhoneValidation(validation.data.telefono),
        role: rol,
        status: validation.data.status,
        reason: validation.data.reason || 'Alta desde modulo equipo',
        temporaryPassword: body?.temporaryPassword || DEFAULT_VENDOR_PASSWORD
      };

      const createdUser = await createManualUser(payload, dbUser);

      const clientOrg = createDbClient();
      await clientOrg.connect();
      try {
        await clientOrg.query(
          `INSERT INTO organization_users
             (organization_id, user_id, role_in_org, activo, created_at)
           VALUES ($1, $2, $3, true, now())
           ON CONFLICT (organization_id, user_id)
           DO UPDATE SET activo = true, role_in_org = EXCLUDED.role_in_org`,
          [organizationId, createdUser.id, rol]
        );
      } finally {
        await clientOrg.end();
      }

      return json(201, mapUserRowToApi(createdUser));
    } catch (error) {
      if (error instanceof AppError) {
        return json(error.statusCode, {
          ok: false,
          message: error.message,
          code: error.code,
          details: error.details
        });
      }
      return json(500, {
        ok: false,
        message: "Failed to create org user",
        error: error.message
      });
    }
  }

  // GET /module-states — carga estados para el rol del usuario
  if (method === "GET" && path.endsWith("/module-states")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `SELECT role_key, module_path, estado
           FROM module_states
           ORDER BY role_key, module_path`
        );
        const states = {};
        for (const row of result.rows) {
          if (!states[row.role_key]) states[row.role_key] = {};
          states[row.role_key][row.module_path] = row.estado;
        }
        return json(200, { ok: true, states });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load module states",
        error: error.message
      });
    }
  }

  // PUT /module-states — actualiza un estado (solo superadmin)
  if (method === "PUT" && path.endsWith("/module-states")) {
    const body = safeParseBody(event);
    if (body === null) return json(400, { ok: false, message: "Invalid JSON body" });

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const role_key = normalizeText(body?.role_key || "").toLowerCase();
      const module_path = normalizeText(body?.module_path || "");
      const estado = normalizeText(body?.estado || "");
      if (!role_key || !module_path || !estado) {
        return json(422, { ok: false, message: "role_key, module_path y estado son obligatorios" });
      }

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `INSERT INTO module_states (role_key, module_path, estado, updated_at)
           VALUES ($1, $2, $3, now())
           ON CONFLICT (role_key, module_path)
           DO UPDATE SET estado = EXCLUDED.estado, updated_at = now()
           RETURNING role_key, module_path, estado`,
          [role_key, module_path, estado]
        );
        return json(200, { ok: true, item: result.rows[0] });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to update module state",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/superadmin/users")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const items = await listSuperadminUsers();

      return json(200, { items });
    } catch (error) {
      console.error("SUPERADMIN_LIST_USERS_ERROR", {
        message: error.message,
        code: error.code || null
      });

      return json(500, {
        ok: false,
        message: "Failed to list users",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/superadmin/users")) {
    const body = safeParseBody(event);

    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const validation = validateSuperadminUserPayload(body);
    if (!validation.valid) {
      return json(422, {
        ok: false,
        message: "Validation failed",
        errors: validation.errors
      });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const payload = {
        nombre: validation.data.nombre,
        apellido: validation.data.apellido,
        email: validation.data.email,
        telefono: normalizePhoneValidation(validation.data.telefono),
        role: validation.data.rol,
        status: validation.data.status,
        reason: validation.data.reason || undefined,
        temporaryPassword: body?.temporaryPassword || undefined
      };

      const createdUser = await createManualUser(payload, dbUser);

      // AUTO-ASIGNACIÃ“N: si el superadmin tiene una org activa, asignar el usuario a ella
      const orgIdParam = getQueryParam(event, "organization_id");
      if (orgIdParam) {
        const clientOrg = createDbClient();
        await clientOrg.connect();
        try {
          await clientOrg.query(
            `INSERT INTO organization_users (organization_id, user_id, role_in_org, activo, created_at)
             VALUES ($1, $2, $3, true, now())
             ON CONFLICT (organization_id, user_id) DO UPDATE SET activo = true, role_in_org = EXCLUDED.role_in_org`,
            [orgIdParam, createdUser.id, payload.role]
          );
        } finally {
          await clientOrg.end();
        }
      }

      return json(201, mapUserRowToApi(createdUser));
    } catch (error) {
      if (error instanceof AppError) {
        return json(error.statusCode, {
          ok: false,
          message: error.message,
          code: error.code,
          details: error.details
        });
      }
      console.error("SUPERADMIN_CREATE_USER_ERROR", {
        message: error.message,
        code: error.code || null
      });

      return json(500, {
        ok: false,
        message: "Failed to create user",
        error: error.message
      });
    }
  }

  const superadminUserMatch = path.match(/\/superadmin\/users\/([^/]+)$/);

  if (method === "PUT" && superadminUserMatch) {
    const body = safeParseBody(event);

    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const validation = validateSuperadminUserPayload(body);
    if (!validation.valid) {
      return json(422, {
        ok: false,
        message: "Validation failed",
        errors: validation.errors
      });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const payload = {
        userId: superadminUserMatch[1],
        nombre: validation.data.nombre,
        apellido: validation.data.apellido,
        email: validation.data.email,
        telefono: normalizePhoneValidation(validation.data.telefono),
        role: validation.data.rol,
        status: validation.data.status,
        reason: validation.data.reason || undefined
      };

      const updatedUser = await updateUser(payload, dbUser);
      return json(200, mapUserRowToApi(updatedUser));
    } catch (error) {
      if (error instanceof AppError) {
        return json(error.statusCode, {
          ok: false,
          message: error.message,
          code: error.code,
          details: error.details
        });
      }
      console.error("SUPERADMIN_UPDATE_USER_ERROR", {
        message: error.message,
        code: error.code || null,
        userId: superadminUserMatch[1]
      });

      return json(500, {
        ok: false,
        message: "Failed to update user",
        error: error.message
      });
    }
  }

  // â”€â”€â”€ ORGANIZATIONS ENDPOINTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // PATCH /api/users/:id/pausar
  if (method === "PATCH" && path.match(/\/api\/users\/([^/]+)\/pausar$/)) {
    const match = path.match(/\/api\/users\/([^/]+)\/pausar$/);
    const userId = match?.[1];
    if (!userId) {
      return json(400, { ok: false, message: "User id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const values = [userId];
        let orgClause = "";
        if (organizationId) {
          values.push(organizationId);
          orgClause = `
            AND EXISTS (
              SELECT 1
              FROM organization_users ou
              WHERE ou.user_id = users.id
                AND ou.organization_id = $2
                AND ou.activo = true
            )
          `;
        }

        const res = await client.query(
          `UPDATE users
           SET status = 'pausado', updated_at = NOW()
           WHERE id = $1
           ${orgClause}
           RETURNING id, nombre, apellido, status`,
          values
        );
        if (!res.rows.length) return json(404, { ok: false, message: "Usuario no encontrado" });

        const pausedUser = res.rows[0];

        // Reasignar leads activos (no_contesta, seguimiento, nuevo) a vendedores activos del mismo lote
        const leadsToReassign = await client.query(
          `SELECT lcs.contact_id, lbc.batch_id
           FROM lead_contact_status lcs
           JOIN lead_batch_contacts lbc ON lbc.contact_id = lcs.contact_id
           WHERE lcs.assigned_to = $1
           AND lcs.estado_venta IN ('no_contesta', 'seguimiento', 'nuevo')`,
          [userId]
        );

        if (leadsToReassign.rows.length > 0) {
          // Obtener vendedores activos por lote
          const batchIds = [...new Set(leadsToReassign.rows.map((r) => r.batch_id))];

          for (const batchId of batchIds) {
            const activeVendors = await client.query(
              `SELECT DISTINCT lcs2.assigned_to
               FROM lead_contact_status lcs2
               JOIN lead_batch_contacts lbc2 ON lbc2.contact_id = lcs2.contact_id
               JOIN users u ON u.id = lcs2.assigned_to
               WHERE lbc2.batch_id = $1
               AND u.status = 'approved'
               AND lcs2.assigned_to != $2`,
              [batchId, userId]
            );

            if (activeVendors.rows.length === 0) continue;

            const vendors = activeVendors.rows.map((r) => r.assigned_to);
            const batchLeads = leadsToReassign.rows.filter((r) => r.batch_id === batchId);

            // Round-robin
            for (let i = 0; i < batchLeads.length; i++) {
              const newVendor = vendors[i % vendors.length];
              await client.query(
                `UPDATE lead_contact_status SET assigned_to = $1 WHERE contact_id = $2`,
                [newVendor, batchLeads[i].contact_id]
              );
            }
          }
        }

        // Sacar al usuario de todos los lotes activos
        await client.query(
          `DELETE FROM lead_batch_sellers WHERE seller_id = $1`,
          [userId]
        );

        return json(200, {
          ok: true,
          user: pausedUser,
          leads_reasignados: leadsToReassign.rows.length
        });
      } finally {
        await client.end();
      }
    } catch (err) {
      return json(500, { ok: false, message: err.message });
    }
  }

  // PATCH /api/users/:id/reactivar
  if (method === "PATCH" && path.match(/\/api\/users\/([^/]+)\/reactivar$/)) {
    const match = path.match(/\/api\/users\/([^/]+)\/reactivar$/);
    const userId = match?.[1];
    if (!userId) {
      return json(400, { ok: false, message: "User id requerido" });
    }
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      let organizationId = null;
      try {
        organizationId = await resolveOrganizationIdForRequest(dbUser, event);
      } catch (error) {
        if (error?.status) {
          return json(error.status, { ok: false, message: error.message });
        }
        throw error;
      }

      const client = createDbClient();
      await client.connect();
      try {
        const values = [userId];
        let orgClause = "";
        if (organizationId) {
          values.push(organizationId);
          orgClause = `
            AND EXISTS (
              SELECT 1
              FROM organization_users ou
              WHERE ou.user_id = users.id
                AND ou.organization_id = $2
                AND ou.activo = true
            )
          `;
        }

        const res = await client.query(
          `UPDATE users
           SET status = 'approved', updated_at = NOW()
           WHERE id = $1
           ${orgClause}
           RETURNING id, nombre, apellido, status`,
          values
        );
        if (!res.rows.length) return json(404, { ok: false, message: "Usuario no encontrado" });
        return json(200, { ok: true, user: res.rows[0] });
      } finally {
        await client.end();
      }
    } catch (err) {
      return json(500, { ok: false, message: err.message });
    }
  }

  if (method === "GET" && path.endsWith("/me/organizations")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `SELECT
             o.id,
             o.nombre,
             o.logo_url,
             o.status,
             ou.role_in_org,
             ou.activo AS activo_en_org,
             COUNT(ou2.user_id)::int AS total_usuarios
           FROM organization_users ou
           JOIN organizations o ON o.id = ou.organization_id
           LEFT JOIN organization_users ou2
             ON ou2.organization_id = o.id AND ou2.activo = true
           WHERE ou.user_id = $1
             AND ou.activo = true
             AND o.status != 'inactivo'
           GROUP BY o.id, o.nombre, o.logo_url, o.status,
                    ou.role_in_org, ou.activo
           ORDER BY o.nombre ASC`,
          [dbUser.id]
        );
        return json(200, { ok: true, items: result.rows });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list user organizations",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/organizations")) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(`
          SELECT
            o.id,
            o.nombre,
            o.logo_url,
            o.created_at,
            o.updated_at,
            COUNT(ou.user_id)::int AS total_usuarios
          FROM organizations o
          LEFT JOIN organization_users ou ON ou.organization_id = o.id AND ou.activo = true
          GROUP BY o.id
          ORDER BY o.created_at DESC
        `);
        return json(200, { ok: true, items: result.rows });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to list organizations", error: error.message });
    }
  }

  if (method === "POST" && path.endsWith("/organizations")) {
    const body = safeParseBody(event);
    if (body === null) return json(400, { ok: false, message: "Invalid JSON body" });

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const nombre = normalizeText(body?.nombre);
      const descripcion = normalizeText(body?.descripcion || "");
      if (!nombre) return json(422, { ok: false, message: "nombre es obligatorio" });

      const client = createDbClient();
      await client.connect();
      try {
        const existing = await client.query(
          `SELECT id FROM organizations WHERE lower(nombre) = lower($1) LIMIT 1`,
          [nombre]
        );
        if (existing.rows.length) {
          return json(409, { ok: false, message: "Ya existe una organizaciÃ³n con ese nombre" });
        }

        const rut = String(body?.rut || '').trim() || null;
        const email_admin = String(body?.email_admin || '').trim().toLowerCase() || null;
        const telefono = String(body?.telefono || '').trim() || null;
        const pais = String(body?.pais || 'UY').trim() || 'UY';

        const result = await client.query(
          `
          INSERT INTO organizations (nombre, rut, email_admin, telefono, pais, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, now(), now())
          RETURNING id, nombre, rut, email_admin, telefono, pais, logo_url, created_at, updated_at
          `,
          [nombre, rut, email_admin, telefono, pais]
        );

        return json(201, { ok: true, item: result.rows[0] });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to create organization", error: error.message });
    }
  }

  // POST /organizations/:id/logo
  const orgLogoMatch = path.match(/\/organizations\/([^/]+)\/logo$/);
  if (method === "POST" && orgLogoMatch) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const orgId = orgLogoMatch[1];

      const dbCheck = createDbClient();
      await dbCheck.connect();
      let currentLogoUrl = null;
      try {
        const check = await dbCheck.query(
          `SELECT id, logo_url FROM organizations WHERE id = $1 LIMIT 1`,
          [orgId]
        );
        if (!check.rows.length) {
          return json(404, { ok: false, message: "OrganizaciÃ³n no encontrada" });
        }
        currentLogoUrl = check.rows[0].logo_url || null;
      } finally {
        await dbCheck.end();
      }

      const body = event.body;
      if (!body) return json(400, { ok: false, message: "Sin imagen en el body" });

      const isBase64 = Boolean(event.isBase64Encoded);
      const imageBuffer = isBase64
        ? Buffer.from(body, "base64")
        : Buffer.from(body, "binary");

      const rawContentType =
        event.headers?.["content-type"] ||
        event.headers?.["Content-Type"] ||
        "image/png";
      const contentType = String(rawContentType).split(";")[0].trim() || "image/png";
      const ext = contentType.includes("jpeg") || contentType.includes("jpg")
        ? "jpg"
        : contentType.includes("png")
          ? "png"
          : contentType.includes("svg")
            ? "svg"
            : contentType.includes("webp")
              ? "webp"
              : "png";

      const key = `logos/${orgId}.${ext}`;

      if (currentLogoUrl) {
        const currentUrlBase = String(currentLogoUrl).split("?")[0];
        const prefix = `${S3_BASE_URL}/`;
        const oldKey = currentUrlBase.startsWith(prefix)
          ? currentUrlBase.slice(prefix.length)
          : null;
        if (oldKey && oldKey !== key) {
          try {
            await s3Client.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: oldKey }));
          } catch {}
        }
      }

      await s3Client.send(new PutObjectCommand({
        Bucket: S3_BUCKET,
        Key: key,
        Body: imageBuffer,
        ContentType: contentType,
        CacheControl: "public, max-age=31536000"
      }));

      const logoUrl = `${S3_BASE_URL}/${key}?v=${Date.now()}`;

      const dbUpdate = createDbClient();
      await dbUpdate.connect();
      let updatedOrg = null;
      try {
        const result = await dbUpdate.query(
          `UPDATE organizations SET logo_url = $1, updated_at = now() WHERE id = $2
           RETURNING id, nombre, logo_url`,
          [logoUrl, orgId]
        );
        updatedOrg = result.rows[0] || null;
      } finally {
        await dbUpdate.end();
      }

      return json(200, { ok: true, logo_url: updatedOrg?.logo_url || logoUrl, item: updatedOrg });
    } catch (error) {
      return json(500, { ok: false, message: "Failed to upload logo", error: error.message });
    }
  }

  const orgDetailMatch = path.match(/\/organizations\/([^/]+)$/);
  if (method === "PUT" && orgDetailMatch) {
    const body = safeParseBody(event);
    if (body === null) return json(400, { ok: false, message: "Invalid JSON body" });

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const orgId = orgDetailMatch[1];
      const nombre = body?.nombre !== undefined ? normalizeText(body.nombre) : undefined;
      const rut = body?.rut !== undefined ? String(body.rut || '').trim() : undefined;
      const email_admin = body?.email_admin !== undefined ? String(body.email_admin || '').trim().toLowerCase() : undefined;
      const telefono = body?.telefono !== undefined ? String(body.telefono || '').trim() : undefined;
      const pais = body?.pais !== undefined ? String(body.pais || '').trim() : undefined;
      const updates = [];
      const values = [];
      let idx = 1;
      if (nombre !== undefined) { updates.push(`nombre = $${idx}`); values.push(nombre); idx += 1; }
      if (rut !== undefined) { updates.push(`rut = $${idx}`); values.push(rut); idx += 1; }
      if (email_admin !== undefined) { updates.push(`email_admin = $${idx}`); values.push(email_admin); idx += 1; }
      if (telefono !== undefined) { updates.push(`telefono = $${idx}`); values.push(telefono); idx += 1; }
      if (pais !== undefined) { updates.push(`pais = $${idx}`); values.push(pais); idx += 1; }
      if (!updates.length) return json(400, { ok: false, message: "Sin campos para actualizar" });

      const client = createDbClient();
      await client.connect();
      try {
        values.push(orgId);
        const result = await client.query(
          `
          UPDATE organizations
          SET ${updates.join(", ")}, updated_at = now()
          WHERE id = $${idx}
          RETURNING id, nombre, logo_url, created_at, updated_at
          `,
          values
        );

        if (!result.rows.length) return json(404, { ok: false, message: "OrganizaciÃ³n no encontrada" });
        return json(200, { ok: true, item: result.rows[0] });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to update organization", error: error.message });
    }
  }

  // GET /organizations/:id/users â€” listar usuarios de una organizaciÃ³n
  const orgUsersMatch = path.match(/\/organizations\/([^/]+)\/users$/);

  if (method === "GET" && orgUsersMatch) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const orgId = orgUsersMatch[1];
      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `SELECT
             u.id,
             u.nombre,
             u.apellido,
             u.email,
             u.telefono,
             u.role_key,
             u.status,
             u.created_at,
             ou.role_in_org,
             ou.activo AS activo_en_org,
             ou.created_at AS asignado_en
           FROM organization_users ou
           JOIN users u ON u.id = ou.user_id
           WHERE ou.organization_id = $1
           ORDER BY u.nombre ASC`,
          [orgId]
        );
        return json(200, { ok: true, items: result.rows });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to list org users", error: error.message });
    }
  }

  // POST /organizations/:id/users â€” asignar usuario a una organizaciÃ³n
  if (method === "POST" && orgUsersMatch) {
    const body = safeParseBody(event);
    if (body === null) return json(400, { ok: false, message: "Invalid JSON body" });

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const orgId = orgUsersMatch[1];
      const userId = body?.user_id;
      const roleInOrg = body?.role_in_org || "operaciones";

      if (!userId) return json(422, { ok: false, message: "user_id es obligatorio" });

      const client = createDbClient();
      await client.connect();
      try {
        // Verificar que la org existe
        const orgCheck = await client.query(
          `SELECT id FROM organizations WHERE id = $1 LIMIT 1`, [orgId]
        );
        if (!orgCheck.rows.length) {
          return json(404, { ok: false, message: "OrganizaciÃ³n no encontrada" });
        }

        // Verificar que el usuario existe
        const userCheck = await client.query(
          `SELECT id, nombre, apellido, email, role_key FROM users WHERE id = $1 LIMIT 1`, [userId]
        );
        if (!userCheck.rows.length) {
          return json(404, { ok: false, message: "Usuario no encontrado" });
        }

        // Upsert: si ya existe lo reactiva, si no lo crea
        const result = await client.query(
          `INSERT INTO organization_users (organization_id, user_id, role_in_org, activo, created_at)
           VALUES ($1, $2, $3, true, now())
           ON CONFLICT (organization_id, user_id)
           DO UPDATE SET activo = true, role_in_org = EXCLUDED.role_in_org
           RETURNING *`,
          [orgId, userId, roleInOrg]
        );

        return json(201, { ok: true, item: result.rows[0] });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to assign user to org", error: error.message });
    }
  }

  // DELETE /organizations/:id/users/:userId â€” desasociar usuario de una organizaciÃ³n
  const orgUserItemMatch = path.match(/\/organizations\/([^/]+)\/users\/([^/]+)$/);

  if (method === "DELETE" && orgUserItemMatch) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);
      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;
      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;
      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;
      let roleError = requireRole(event, dbUser, ["superadministrador"]);
      if (roleError) return roleError;

      const orgId = orgUserItemMatch[1];
      const targetUserId = orgUserItemMatch[2];

      const client = createDbClient();
      await client.connect();
      try {
        await client.query(
          `UPDATE organization_users SET activo = false
           WHERE organization_id = $1 AND user_id = $2`,
          [orgId, targetUserId]
        );
        return json(200, { ok: true });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, { ok: false, message: "Failed to remove user from org", error: error.message });
    }
  }

  const approveVendorRequestMatch =
    method === "POST" ? matchVendorRequestActionPath(path, "approve") : null;

  if (approveVendorRequestMatch) {
    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const { requestId } = approveVendorRequestMatch;
      const result = await approveVendorRequest({
        requestId,
        reviewerUserId: dbUser.id
      });

      if (result.notFound) {
        return json(404, {
          ok: false,
          message: "Solicitud no encontrada"
        });
      }

      if (result.invalidState) {
        return json(409, {
          ok: false,
          message: result.message
        });
      }

      if (result.conflict) {
        return json(409, {
          ok: false,
          message: result.message
        });
      }

      return json(200, {
        ok: true,
        message: "Solicitud aprobada correctamente",
        user: result.user
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to approve vendor request",
        error: error.message
      });
    }
  }

  const rejectVendorRequestMatch =
    method === "POST" ? matchVendorRequestActionPath(path, "reject") : null;

  if (rejectVendorRequestMatch) {
    const body = safeParseBody(event);

    if (body === null) {
      return json(400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    try {
      const { authUser, dbUser } = await getCurrentDbUserFromEvent(event);

      let authError = requireAuthenticated(event, authUser);
      if (authError) return authError;

      let dbError = requireDbUser(event, dbUser);
      if (dbError) return dbError;

      let statusError = requireApproved(event, dbUser);
      if (statusError) return statusError;

      let roleError = requireRole(event, dbUser, ["supervisor", "superadministrador"]);
      if (roleError) return roleError;

      const { requestId } = rejectVendorRequestMatch;
      const result = await rejectVendorRequest({
        requestId,
        reviewerUserId: dbUser.id,
        reviewNotes: normalizeText(body.review_notes || body.reviewNotes || "")
      });

      if (result.notFound) {
        return json(404, {
          ok: false,
          message: "Solicitud no encontrada"
        });
      }

      if (result.invalidState) {
        return json(409, {
          ok: false,
          message: result.message
        });
      }

      return json(200, {
        ok: true,
        message: "Solicitud rechazada correctamente",
        request: result.request
      });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to reject vendor request",
        error: error.message
      });
    }
  }

  return json(404, {
    ok: false,
    message: "Route not found",
    path,
    method
  });
  } catch (error) {
    console.error("Unhandled error in handler", error);
    return json(500, {
      ok: false,
      message: "Unhandled error",
      error: error?.message || String(error)
    });
  }
};

export const __testables = {
  isActiveFromStatus,
  statusFromActivo,
  mapUserRowToApi,
  validateSuperadminUserPayload,
  requireRole
};

export {
  createDbClient,
  getConfigMap,
  getTeamSummary,
  getAgentDetail,
  getAgentWeek,
  createAlert,
  parseFechaParam,
  formatDateYmd,
  formatTimeHm,
  LOCAL_TZ
};
















































