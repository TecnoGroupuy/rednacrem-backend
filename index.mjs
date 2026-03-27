import fs from "node:fs";
import { Client } from "pg";
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminAddUserToGroupCommand,
  ListUsersCommand
} from "@aws-sdk/client-cognito-identity-provider";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { AppError } from "./src/lib/errors.js";
import { handleOptions, getMethod as getMethodFromHttp, CORS_HEADERS } from "./src/lib/http.js";
import { normalizePhone } from "./src/lib/validation.js";
import { createManualUser, updateUser, listUsers as listUsersService } from "./src/services/userService.js";
import { emitRealtime } from "./src/monitoring/realtimeBus.js";
import { findCurrentUserFromClaims } from "./src/services/userService.js";
import { generateCertificatePdf, buildClientDocumentFilename } from "./src/lib/certificatePdf.js";

const sqs = new SQSClient({ region: process.env.AWS_REGION || "us-east-2" });

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
    createProducts: options.createProducts !== false
  };
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
  "inactive"
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
  const raw =
    event?.rawQueryString ||
    event?.queryString ||
    event?.queryStringParameters ||
    "";
  if (!raw) return null;
  if (typeof raw === "object") {
    return raw[key] || null;
  }
  const params = new URLSearchParams(String(raw));
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

function splitFullName(value) {
  const text = normalizeText(value);
  if (!text) return { nombre: "", apellido: "" };
  const parts = text.split(/\s+/);
  if (parts.length === 1) return { nombre: parts[0], apellido: "" };
  return { nombre: parts.slice(0, -1).join(" "), apellido: parts.slice(-1).join(" ") };
}

let userProfileColumnsReady = false;
async function ensureUserProfileColumns(client) {
  if (userProfileColumnsReady) return;
  await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS extension TEXT");
  await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS department TEXT");
  userProfileColumnsReady = true;
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
  if (n.startsWith("472")) return "Paysandú";
  if (n.startsWith("456")) return "Río Negro";
  if (n.startsWith("453")) return "Soriano";
  if (n.startsWith("434")) return "San José";
  if (n.startsWith("447")) return "Rocha";
  if (n.startsWith("445")) return "Treinta y Tres";
  if (n.startsWith("464")) return "Cerro Largo";
  if (n.startsWith("462")) return "Rivera";
  if (n.startsWith("463")) return "Tacuarembó";
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
  const parsed = new Date(value);
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
  "2320": "Colón",
  "2222": "Piedras Blancas",
  "2401": "Cordón",
  "2487": "Hosp. Clínicas",
  "2292": "Pando",
  "2294": "Sauce",
  "2295": "Empalme Olmos",
  "2296": "Toledo",
  "2902": "Plaza Centro",
  "2712": "Punta Carretas",
  "2312": "Paso de la Arena",
  "2355": "Sayago",
  "2409": "Tres Cruces",
  "2506": "Unión",
  "2347": "Autódromo",
  "2362": "La Paz",
  "2364": "Las Piedras",
  "2369": "Progreso",
  "2372": "Atlántida",
  "2682": "Lagomar",
  "2696": "Solymar",
  "4332": "Canelones",
  "4530": "Cañada Nieto",
  "4222": "Maldonado",
  "4223": "Maldonado",
  "4224": "Maldonado",
  "4225": "Maldonado",
  "4244": "Punta del Este (Península)",
  "4248": "Punta del Este Parada 5",
  "4249": "Punta del Este Parada 5",
  "4255": "Laguna del Sauce",
  "4257": "Portezuelo",
  "4266": "San Carlos",
  "4277": "La Barra",
  "4311": "Casupá",
  "4312": "San Ramón",
  "4313": "San Antonio",
  "4315": "Tala",
  "4317": "Miguez",
  "4318": "Cerro Colorado",
  "4319": "Chamizo",
  "4334": "Santa Lucía",
  "4335": "Juanicó",
  "4336": "Los Cerrillos",
  "4338": "Colonia Etchepare",
  "4339": "Cardal",
  "4342": "San José",
  "4345": "Kiyú",
  "4346": "Rafael Peraza",
  "4348": "Villa Rodriguez",
  "4349": "Colonia Agra.Delta",
  "4352": "Florida",
  "4354": "Sarandí Grande",
  "4360": "Blanquillo",
  "4362": "Durazno",
  "4364": "Trinidad",
  "4365": "Carmen",
  "4367": "Sarandí del Yi",
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
  "4432": "Piriápolis",
  "4434": "Pan de Azúcar",
  "4438": "Balneario Solís",
  "4442": "Minas",
  "4446": "Aiguá",
  "4447": "Solís de Mataojo",
  "4448": "Pirarajá",
  "4449": "Mariscala",
  "4452": "Treinta y Tres",
  "4455": "José P. Varela",
  "4456": "Lascano",
  "4457": "Velázquez",
  "4458": "Vergara",
  "4459": "Cebollatí",
  "4463": "Zapicán",
  "4464": "Santa Clara de Olimar",
  "4466": "Cerro Chato",
  "4469": "Batlle y Ordoñez",
  "4472": "Rocha",
  "4474": "Barra del Chuy",
  "4475": "Aguas Dulces",
  "4476": "La Coronilla",
  "4477": "Santa Teresa",
  "4479": "La Paloma (Rocha)",
  "4486": "Faro José Ignacio",
  "4522": "Colonia",
  "4534": "Dolores",
  "4536": "Cardona",
  "4537": "Palmitas",
  "4538": "José E. Rodó",
  "4539": "Ismael Cortinas",
  "4542": "Balneario Zagarazú",
  "4544": "Nueva Palmira",
  "4552": "Rosario",
  "4554": "Nueva Helvecia",
  "4558": "Colonia Valdense",
  "4562": "Fray Bentos",
  "4567": "Young",
  "4568": "Nuevo Berlín",
  "4569": "San Javier",
  "4574": "Semillero",
  "4575": "Colonia Miguelete",
  "4576": "Ombúes de Lavalle",
  "4577": "Conchillas",
  "4586": "Juan Lacaze",
  "4587": "Playa Fomento",
  "4588": "Santa Ana",
  "4622": "Rivera",
  "4632": "Tacuarembó",
  "4640": "Aceguá",
  "4642": "Melo",
  "4654": "Vichadero",
  "4656": "Tranqueras",
  "4658": "Minas de Corrales",
  "4664": "Paso de los Toros",
  "4675": "Río Branco",
  "4679": "Lago Merín",
  "4722": "Paysandú",
  "4730": "Defensa (Salto)",
  "4732": "Pueblo Lavalleja",
  "4733": "Cuchilla de Salto",
  "4742": "Guichón",
  "4747": "Piedras Coloradas",
  "4754": "Quebracho",
  "4764": "Constitución",
  "4766": "Belén",
  "4772": "Artigas",
  "4776": "Baltasar Brum",
  "4777": "Tomás Gomensoro",
  "4778": "Mones Quintela",
  "4779": "Bella Unión",
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
  return !["inactive", "blocked", "rejected"].includes(status);
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

function buildContactSummarySelect() {
  return `
    SELECT
      c.id,
      c.nombre,
      c.apellido,
      c.email,
      c.telefono,
      c.documento,
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
    GROUP BY
      c.id,
      c.nombre,
      c.apellido,
      c.email,
      c.telefono,
      c.documento,
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
    documento: row.documento || "",
    tipoPersona: row.tipo_persona,
    contactoEstado: row.contacto_estado,
    productoEstado: row.producto_estado,
    cuotasPagas: Number(row.cuotas_pagas || 0),
    carenciaCuotas: Number(row.carencia_cuotas || 0),
    createdAt: row.created_at || null,
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
  resultados: "CSV de resultados telefónicos",
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
  "documento": "documento",
  "fecha de nacimiento": "fecha_nacimiento",
  "telefono": "telefono",
  "celular": "telefono_celular",
  "correo electronico": "email",
  "direccion": "direccion",
  "departamento": "departamento_residencia",
  "pais": "pais",
  "nombre del familiar": "nombre_familiar",
  "apellido del familiar": "apellido_familiar",
  "telefono del familiar": "telefono_familiar",
  "vinculo": "parentesco",
  "vendedor": "vendedor_nombre",
  "fecha de venta": "fecha_venta",
  "producto": "producto_nombre",
  "precio": "precio",
  "medio de pago": "medio_pago",
  "estado": "producto_estado",
  "fecha de baja": "fecha_baja"
};

function parseDate(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) return text;
  const slashMatch = text.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (slashMatch) {
    const day = slashMatch[1].padStart(2, "0");
    const month = slashMatch[2].padStart(2, "0");
    const year = slashMatch[3];
    return `${year}-${month}-${day}`;
  }
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return null;
  const year = String(parsed.getFullYear());
  const month = String(parsed.getMonth() + 1).padStart(2, "0");
  const day = String(parsed.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
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

async function getTeamSummary(client, fecha, now = new Date()) {
  const config = await getConfigMap(client);
  const sellersRes = await client.query(
    `
    SELECT id, nombre, apellido
    FROM users
    WHERE role_key = 'vendedor'
      AND status = 'approved'
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
      FROM lead_management_history
      WHERE (fecha_gestion AT TIME ZONE $3)::date = $1::date
        AND user_id = ANY($2::uuid[])
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

  const pauseTypes = ["DESCANSO", "SUPERVISOR", "BA?O", "BAÑO"];
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

  const pauseTypes = new Set(["DESCANSO", "SUPERVISOR", "BA?O", "BAÑO"]);
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
      descripcion: `${conversion}% actual vs mínimo ${config.conversion_minima_porcentaje}%`,
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
  const candidates = [",", ";", "\t"];
  let best = { separator: ",", count: 0 };
  for (const separator of candidates) {
    let inQuotes = false;
    let count = 0;
    for (let i = 0; i < headerLine.length; i += 1) {
      const char = headerLine[i];
      if (char === "\"") {
        if (inQuotes && headerLine[i + 1] === "\"") {
          i += 1;
        } else {
          inQuotes = !inQuotes;
        }
        continue;
      }
      if (!inQuotes && char === separator) count += 1;
    }
    if (count > best.count) best = { separator, count };
  }
  return best.count > 0 ? best.separator : ",";
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
  "correo electrónico": "correo_electronico",
  "email": "correo_electronico",
  "direccion": "direccion",
  "dirección": "direccion",
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
    item.vendedor_nombre,
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
    values.push(...row);
    const params = CONTACT_IMPORT_COLUMNS.map((_, colIndex) => `$${base + colIndex + 1}`);
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

function buildDatosTrabajarInsertBatch(batchRows) {
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
    "estado"
  ];
  const values = [];
  const placeholders = batchRows.map((row, index) => {
    const base = index * columns.length;
    values.push(...row);
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

export async function processDatosTrabajarJob(jobId, options = {}) {
  const client = createDbClient();
  await client.connect();

  try {
    const jobRes = await client.query(
      `
      SELECT id, batch_id, csv_text, processed_rows, inserted_rows, blocked_rows, skipped_rows
      FROM datos_para_trabajar_import_jobs
      WHERE id = $1
      LIMIT 1
      `,
      [jobId]
    );
    if (!jobRes.rows.length) return;

    const job = jobRes.rows[0];
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
        const { sql, values } = buildDatosTrabajarInsertBatch(buffer);
        await client.query(sql, values);
        buffer = [];
      }

      if (maxMillis && Date.now() - startedAt > maxMillis) {
        if (buffer.length) {
          const { sql, values } = buildDatosTrabajarInsertBatch(buffer);
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
      const { sql, values } = buildDatosTrabajarInsertBatch(buffer);
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

async function processClientImportBatch(batchId, { createProducts = true } = {}) {
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
    if (createProducts) {
      const pendingProducts = await client.query(
        `
        SELECT
          producto_nombre,
          MAX(precio)::numeric AS precio
        FROM contact_import_rows
        WHERE batch_id = $1
          AND import_status = 'validated'
          AND producto_nombre IS NOT NULL
          AND trim(producto_nombre) <> ''
        GROUP BY producto_nombre
        `,
        [batchId]
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
          LIMIT 1
          `,
          [productName]
        );
        if (exists.rowCount > 0) continue;
        await client.query(
          `
          INSERT INTO products (nombre, categoria, precio, activo)
          VALUES ($1, 'General', $2, true)
          `,
          [productName, row.precio || 0]
        );
        productsCreated += 1;
      }
    }

    const rowsResult = await client.query(
      `
      SELECT *
      FROM contact_import_rows
      WHERE batch_id = $1
        AND import_status = 'validated'
      ORDER BY row_number ASC
      `,
      [batchId]
    );

    for (const row of rowsResult.rows) {
      try {
        await client.query("BEGIN");

        const documentoRaw = normalizeText(row.documento);
        const documento = documentoRaw || null;
        const email = normalizeText(row.email).toLowerCase() || null;
        const vendedorNombre = normalizeText(row.vendedor_nombre);
        const medioPago = normalizeText(row.medio_pago);
        const productoNombre = buildProductDisplayName(row.producto_nombre, row.precio);
        const phones = normalizeContactPhones(row.telefono, row.telefono_celular);

        if (vendedorNombre) sellersSeen.add(vendedorNombre.toLowerCase());
        if (medioPago) paymentMethodsSeen.add(medioPago.toLowerCase());
        if (productoNombre) productsSeen.add(productoNombre.toLowerCase());

        const contactPayload = {
          nombre: row.nombre || null,
          apellido: row.apellido || null,
          email,
          telefono: phones.telefono || null,
          celular: phones.celular || null,
          documento: documento || null,
          fecha_nacimiento: row.fecha_nacimiento || null,
          direccion: row.direccion || null,
          departamento: row.departamento_residencia || null,
          pais: row.pais || null
        };

        // Siempre crear un contacto nuevo para imports de clientes (sin deduplicar por documento).
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
            status
          )
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'activo')
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
            contactPayload.pais || "Uruguay"
          ]
        );
        const contact = insertContact.rows[0];
        newContacts += 1;
        const nombreFamiliar = String(row.nombre_familiar || "").trim();
        if (nombreFamiliar) {
          const relativeExists = await client.query(
            `
            SELECT id
            FROM contact_relatives
            WHERE contact_id = $1
              AND lower(coalesce(nombre, '')) = lower($2)
              AND lower(coalesce(apellido, '')) = lower($3)
              AND coalesce(telefono, '') = $4
              AND lower(coalesce(parentesco, '')) = lower($5)
            LIMIT 1
            `,
            [
              contact.id,
              nombreFamiliar,
              row.apellido_familiar || "",
              row.telefono_familiar || "",
              row.parentesco || ""
            ]
          );

          if (relativeExists.rowCount === 0) {
            await client.query(
              `
              INSERT INTO contact_relatives (
                contact_id,
                nombre,
                apellido,
                telefono,
                parentesco
              )
              VALUES ($1,$2,$3,$4,$5)
              `,
              [
                contact.id,
                nombreFamiliar,
                row.apellido_familiar || null,
                row.telefono_familiar || null,
                row.parentesco || null
              ]
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
              LIMIT 1
              `,
              [productName]
            )
            : { rows: [] };

          let productId = productResult.rows[0]?.id || null;

          if (!productId && productName && !createProducts) {
            throw new Error(`Producto no existe: ${productName}`);
          }

          if (!productId && productName && createProducts) {
            const productInsert = await client.query(
              `
              INSERT INTO products (nombre, categoria, precio, activo)
              VALUES ($1, 'General', $2, true)
              RETURNING id
              `,
              [productName, precio || 0]
            );
            productId = productInsert.rows[0].id;
          }

          const saleInsert = await client.query(
            `
            INSERT INTO sales (contact_id, seller_user_id, medio_pago, seller_name_snapshot, seller_origin, fecha_venta)
            VALUES ($1, $2, $3, $4, 'importado', $5)
            RETURNING id
            `,
            [contact.id, null, row.medio_pago || null, row.vendedor_nombre || null, fechaVenta]
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
          const fechaBaja = isBaja ? (row.fecha_baja || fechaVenta || new Date().toISOString().slice(0, 10)) : null;
          const motivoBaja = isBaja ? "otro" : null;
          const motivoBajaDetalle = isBaja ? (estadoRaw || "importado") : null;

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
              sale_id
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            `,
            [
              contact.id,
              productName || "Producto",
              row.plan || null,
              precio || 0,
              fechaVenta || new Date().toISOString().slice(0, 10),
              row.cuotas_pagas || 0,
              row.carencia_cuotas || 0,
              isBaja ? "baja" : "alta",
              motivoBaja,
              motivoBajaDetalle,
              fechaBaja,
              null,
              row.vendedor_nombre || null,
              "importado",
              saleId
            ]
          );
        }

        await client.query(
          `
          UPDATE contact_import_rows
          SET import_status = 'imported',
              error_detail = NULL,
              resolved_contact_id = $1,
              updated_at = now()
          WHERE id = $2
          `,
          [contact.id, row.id]
        );

        await client.query("COMMIT");
        imported += 1;
      } catch (rowError) {
        await client.query("ROLLBACK");
        failed += 1;
        await client.query(
          `
          UPDATE contact_import_rows
          SET import_status = 'error',
              error_detail = $1,
              updated_at = now()
          WHERE id = $2
          `,
          [rowError.message, row.id]
        );
      }
    }

    const summaryResult = await client.query(
      `
      SELECT
        COUNT(*)::int AS total_rows,
        COUNT(*) FILTER (WHERE import_status = 'imported')::int AS imported_rows,
        COUNT(*) FILTER (WHERE import_status = 'error')::int AS error_rows
      FROM contact_import_rows
      WHERE batch_id = $1
      `,
      [batchId]
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
      `,
      [
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
    "Dirección",
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
    "Dirección": "18 de Julio 1234",
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
    errors.precio = ["precio inválido"];
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
      errors.email = "El email no es válido";
    }
  }

  if (!options.partial || body?.telefono !== undefined) {
    if (!telefono) {
      errors.telefono = "El teléfono es obligatorio";
    }
  }

  if (!options.partial || body?.rol !== undefined || body?.role !== undefined) {
    if (!rol) {
      errors.rol = "El rol es obligatorio";
    } else if (!VALID_ROLES.includes(rol)) {
      errors.rol = "El rol no es válido";
    }
  }

  if (!options.partial || body?.status !== undefined) {
    if (!status) {
      errors.status = "El estado es obligatorio";
    } else if (!VALID_USER_STATUSES.includes(status)) {
      errors.status = "El estado no es válido";
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
  if (!telefono) errors.telefono = "El teléfono es obligatorio";

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
      ${buildUserSelect(metadata)}
      ORDER BY created_at DESC
      `
    );

    return result.rows.map(mapUserRowToApi);
  } finally {
    await client.end();
  }
}

async function listContacts() {
  const client = createDbClient();

  try {
    await client.connect();

    const result = await client.query(
      `
      ${buildContactSummarySelect()}
      ORDER BY created_at DESC, nombre ASC, apellido ASC
      `
    );

    return result.rows.map(mapContactRowToApi);
  } finally {
    await client.end();
  }
}

async function listClientsDirectory({ page = 1, limit = 50, search = "" } = {}) {
  const client = createDbClient();

  try {
    await client.connect();

    const safePage = Math.max(1, Number(page) || 1);
    const safeLimit = Math.min(200, Math.max(1, Number(limit) || 50));
    const offset = (safePage - 1) * safeLimit;
    const searchText = String(search || "").trim().toLowerCase();

    const whereParts = ["s.productos_total > 0"];
    const values = [];

    if (searchText) {
      values.push(`%${searchText}%`);
      const idx = values.length;
      whereParts.push(
        `(lower(s.nombre) LIKE $${idx} OR lower(s.apellido) LIKE $${idx} OR lower(coalesce(s.email, '')) LIKE $${idx} OR lower(coalesce(s.telefono, '')) LIKE $${idx} OR lower(coalesce(s.documento, '')) LIKE $${idx})`
      );
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

    values.push(safeLimit, offset);
    const limitIdx = values.length - 1;
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
async function getClientMetrics() {
  const client = createDbClient();

  try {
    await client.connect();

    const result = await client.query(
      `
      WITH summary AS (
        ${buildContactSummarySelect()}
      ),
      active_products AS (
        SELECT precio
        FROM contact_products
        WHERE estado = 'alta'
      )
      SELECT
        (SELECT COUNT(*)::int FROM summary WHERE tipo_persona = 'cliente_actual') AS activos,
        (SELECT COUNT(*)::int FROM summary WHERE tipo_persona = 'cliente_historico') AS en_baja,
        (SELECT COALESCE(AVG(precio), 0)::numeric(12,2) FROM active_products) AS cuota_promedio
      `
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

async function getClientDocumentData(clientId) {
  const client = createDbClient();

  try {
    await client.connect();
    const metadata = await getUsersTableMetadata(client);

    const userSelect = metadata.hasUsersTable
      ? "u.nombre AS seller_nombre, u.apellido AS seller_apellido"
      : "NULL::text AS seller_nombre, NULL::text AS seller_apellido";
    const userJoin = metadata.hasUsersTable ? "LEFT JOIN users u ON u.id = s.seller_user_id" : "";

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
        ORDER BY fecha_alta DESC NULLS LAST, created_at DESC
        LIMIT 1
      ) cp ON true
      LEFT JOIN sales s
        ON s.id = cp.sale_id
      ${userJoin}
      WHERE c.id = $1
      LIMIT 1
      `,
      [clientId]
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

async function getClientDetailData(clientId) {
  const client = createDbClient();

  try {
    await client.connect();
    const metadata = await getUsersTableMetadata(client);

    const contactResult = await client.query(
      `
      SELECT *
      FROM contacts
      WHERE id = $1
      LIMIT 1
      `,
      [clientId]
    );

    const contact = contactResult.rows[0];
    if (!contact) return null;

    const userSelect = metadata.hasUsersTable
      ? "u.nombre AS seller_nombre, u.apellido AS seller_apellido"
      : "NULL::text AS seller_nombre, NULL::text AS seller_apellido";
    const userJoin = metadata.hasUsersTable ? "LEFT JOIN users u ON u.id = s.seller_user_id" : "";

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
      ORDER BY cp.fecha_alta DESC NULLS LAST, cp.created_at DESC
      `,
      [clientId]
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

    const salesResult = await client.query(
      `
      SELECT
        s.*,
        ${userSelect}
      FROM sales s
      ${userJoin}
      WHERE s.contact_id = $1
      ORDER BY s.created_at DESC
      `,
      [clientId]
    );

    const salesHistory = salesResult.rows.map((row) => {
      const sellerName = row.seller_origin === "externo"
        ? row.seller_name_snapshot
        : [row.seller_nombre, row.seller_apellido].filter(Boolean).join(" ").trim() || row.seller_name_snapshot;

      return {
        id: row.id,
        fecha: row.created_at,
        fecha_alta: row.created_at,
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

async function listProducts() {
  const client = createDbClient();

  try {
    await client.connect();
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
      ORDER BY created_at DESC, nombre ASC
      `
    );

    return result.rows.map(mapProductRowToApi);
  } finally {
    await client.end();
  }
}

async function createProductRecord(payload) {
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
        activo
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
      `,
      [
        payload.nombre,
        payload.categoria,
        payload.descripcion,
        payload.observaciones,
        payload.precio,
        payload.activo
      ]
    );

    return mapProductRowToApi(result.rows[0]);
  } finally {
    await client.end();
  }
}

async function updateProductRecord(productId, payload) {
  const client = createDbClient();

  try {
    await client.connect();
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
      RETURNING *
      `,
      [
        productId,
        payload.nombre || null,
        payload.categoria || null,
        payload.descripcion || null,
        payload.observaciones || null,
        payload.precio ?? null,
        payload.activo === undefined ? null : payload.activo
      ]
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

async function createManualTicket(payload) {
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
        producto_contrato_id
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
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
        payload.productoContratoId
      ]
    );

    return mapManualTicketRowToApi(result.rows[0]);
  } finally {
    await client.end();
  }
}

async function listManualTickets({ clienteId } = {}) {
  const client = createDbClient();

  try {
    await client.connect();
    const values = [];
    let where = "";
    if (clienteId) {
      values.push(clienteId);
      where = `WHERE cliente_id = $${values.length}`;
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

async function getManualTicketById(ticketId) {
  const client = createDbClient();

  try {
    await client.connect();
    const result = await client.query(
      `
      SELECT *
      FROM manual_tickets
      WHERE id = $1
      LIMIT 1
      `,
      [ticketId]
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

async function updateManualTicket(ticketId, patch) {
  const client = createDbClient();

  try {
    await client.connect();
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
      RETURNING *
      `,
      [
        ticketId,
        patch.tipoSolicitud || null,
        patch.tipoSolicitudManual || null,
        patch.resumen || null,
        patch.serviceRequest ? JSON.stringify(patch.serviceRequest) : null,
        patch.prioridad || null,
        patch.estado || null,
        patch.productoContratoId || null
      ]
    );

    if (!result.rows[0]) return null;
    return mapManualTicketRowToApi(result.rows[0]);
  } finally {
    await client.end();
  }
}

async function addManualTicketNote(ticketId, { texto, autor }) {
  const client = createDbClient();

  try {
    await client.connect();
    await client.query(
      `
      UPDATE manual_tickets
      SET estado = 'en_proceso',
          updated_at = now()
      WHERE id = $1
      `,
      [ticketId]
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

async function closeManualTicket({ ticketId, outcome, note, actorName }) {
  const client = createDbClient();

  try {
    await client.connect();
    await client.query("BEGIN");

    const ticketResult = await client.query(
      `SELECT * FROM manual_tickets WHERE id = $1 LIMIT 1`,
      [ticketId]
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
          `,
          [ticket.producto_contrato_id, note || "Baja confirmada"]
        );
      }
    }

    await client.query(
      `
      UPDATE manual_tickets
      SET estado = 'finalizada',
          updated_at = now()
      WHERE id = $1
      `,
      [ticketId]
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
    values.push(excludeUserId);
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
          "Actualización desde superadmin/users"
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
          "Actualización desde superadmin/users"
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
  console.log("[role-check] ¿tiene acceso?:", allowedRoles.includes(dbUser?.role_key));
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
        message: "La solicitud ya no está pendiente"
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
        "Aprobación de solicitud de vendedor"
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
        message: "La solicitud ya no está pendiente"
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
  if (Array.isArray(event?.Records) && event.Records[0]?.eventSource === "aws:sqs") {
    for (const record of event.Records) {
      let payload = null;
      try {
        payload = JSON.parse(record.body || "{}");
      } catch {
        continue;
      }
      if (!payload) continue;
      if (payload.type && payload.type !== "contact_import" && payload.type !== "clientes") {
        continue;
      }
      const batchId = payload.batchId || payload.jobId;
      if (!batchId) continue;
      const createProducts = payload.createProducts !== false;
      await processClientImportBatch(batchId, { createProducts });
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

      const items = await listContacts();

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

      const contactPayload = body?.contact && typeof body.contact === "object"
        ? body.contact
        : body;

      const nombre = normalizeText(contactPayload?.nombre);
      const apellido = normalizeText(contactPayload?.apellido);

      if (!nombre || !apellido) {
        return json(422, {
          ok: false,
          message: "Nombre y apellido son requeridos"
        });
      }

      const documento = normalizeText(contactPayload?.documento) || null;
      const fechaNacimiento = parseDate(contactPayload?.fecha_nacimiento || contactPayload?.fechaNacimiento || null);
      const telefono = normalizeText(contactPayload?.telefono) || null;
      const celular = normalizeText(contactPayload?.celular) || null;
      const correo = normalizeEmail(contactPayload?.correo_electronico || contactPayload?.email);
      const email = correo ? correo : null;
      const direccion = normalizeText(contactPayload?.direccion) || null;
      const departamento = normalizeText(contactPayload?.departamento) || null;
      const pais = normalizeText(contactPayload?.pais) || "Uruguay";
      const status = normalizeText(contactPayload?.estado || contactPayload?.status || "activo") || "activo";

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");
        const result = await client.query(
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
            created_at,
            updated_at
          )
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now(), now())
          RETURNING id
          `,
          [
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
          ]
        );

        const contactId = result.rows[0]?.id;
        const products = Array.isArray(body?.products) ? body.products : [];
        if (contactId && products.length) {
          const sellerId = body?.vendedor_id || dbUser?.id || null;
          const sellerNameSnapshot = normalizeText(
            products[0]?.sellerName ||
            products[0]?.seller_name ||
            [dbUser?.nombre, dbUser?.apellido].filter(Boolean).join(" ").trim() ||
            dbUser?.email ||
            ""
          ) || null;
          const sellerOrigin = sellerId ? "interno" : "externo";

          for (const product of products) {
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
            const medioPago = normalizeText(product?.medio_pago || product?.medioPago) || null;
            const fechaVenta = fechaAlta;

            let productId = null;
            if (productName) {
              const productRes = await client.query(
                `SELECT id FROM products WHERE lower(nombre) = lower($1) LIMIT 1`,
                [productName]
              );
              productId = productRes.rows[0]?.id || null;
              if (!productId) {
                const productInsert = await client.query(
                  `
                  INSERT INTO products (nombre, categoria, precio, activo)
                  VALUES ($1, 'General', $2, true)
                  RETURNING id
                  `,
                  [productName, precio || 0]
                );
                productId = productInsert.rows[0]?.id || null;
              }
            }

            const saleInsert = await client.query(
              `
              INSERT INTO sales (contact_id, seller_user_id, medio_pago, seller_name_snapshot, seller_origin, fecha_venta)
              VALUES ($1, $2, $3, $4, $5, $6)
              RETURNING id
              `,
              [contactId, sellerId || null, medioPago, sellerNameSnapshot, sellerOrigin, fechaVenta]
            );
            const saleId = saleInsert.rows[0]?.id;

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
                sale_id
              )
              VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
              `,
              [
                contactId,
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
                sellerId,
                sellerNameSnapshot,
                sellerOrigin,
                saleId
              ]
            );
          }
        }

        await client.query("COMMIT");

        return json(200, {
          ok: true,
          success: true,
          data: { id: contactId }
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

      const page = Math.max(1, Number(getQueryParam(event, "page") || 1));
      const limit = Math.min(200, Math.max(1, Number(getQueryParam(event, "limit") || 50)));
      const search = normalizeText(getQueryParam(event, "search") || "");

      const result = await listClientsDirectory({ page, limit, search });

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

      const metrics = await getClientMetrics();

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

      const sellerId = dbUser?.id || null;
      const client = createDbClient();
      await client.connect();
      try {
              const result = await client.query(
          `
          SELECT
            s.id AS sale_id,
            s.medio_pago,
            s.fecha_venta,
            s.seller_name_snapshot,
            cp.nombre_producto,
            cp.plan,
            cp.precio,
            cp.estado AS producto_estado,
            c.nombre AS contact_nombre,
            c.apellido AS contact_apellido,
            c.telefono,
            c.ubicacion,
            c.documento,
            c.email,
            c.direccion
          FROM sales s
          JOIN contact_products cp ON cp.sale_id = s.id
          JOIN contacts c ON c.id = s.contact_id
          WHERE s.seller_user_id = $1
          ORDER BY s.fecha_venta DESC
          `,
          [sellerId]
        );
const items = result.rows.map((row) => ({
          id: row.sale_id,
          sale_id: row.sale_id,
          medio_pago: row.medio_pago || null,
          fecha_venta: row.fecha_venta || null,
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
          ubicacion: row.ubicacion || null,
          documento: row.documento || null,
          email: row.email || null,
          direccion: row.direccion || null
        }));

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

      const sellerId = dbUser?.id || null;
      const client = createDbClient();
      await client.connect();

      try {
        const result = await client.query(
          `
          SELECT 
            d.id,
            d.nombre,
            d.apellido,
            d.telefono,
            d.celular,
            d.departamento,
            d.localidad,
            d.origen_dato AS fuente,
            lcs.ultimo_intento_at AS fecha_venta,
            lb.nombre AS nombre_lote,
            lb.id AS batch_id,
            (
              SELECT lmh.nota 
              FROM lead_management_history lmh
              WHERE lmh.contact_id = d.id
                AND lmh.batch_id = lcs.batch_id
                AND lmh.resultado = 'venta'
              ORDER BY lmh.fecha_gestion DESC
              LIMIT 1
            ) AS nota_venta
          FROM lead_contact_status lcs
          JOIN datos_para_trabajar d ON d.id = lcs.contact_id
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE lcs.assigned_to = $1
            AND lcs.estado_venta = 'venta'
          ORDER BY lcs.ultimo_intento_at DESC
          `,
          [sellerId]
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

      const clientId = clientDocumentMatch[1];
      const data = await getClientDocumentData(clientId);

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

      const item = await createManualTicket(validation.data);
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

      const clienteId = event?.queryStringParameters?.clienteId || event?.queryStringParameters?.cliente_id;
      const items = await listManualTickets({ clienteId: normalizeText(clienteId) || null });
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

      const item = await updateManualTicket(manualTicketMatch[1], validation.data);
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

      const autor = [dbUser?.nombre, dbUser?.apellido].filter(Boolean).join(" ").trim() || dbUser?.email || "Usuario";
      const note = await addManualTicketNote(manualTicketNotesMatch[1], {
        texto,
        autor
      });

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

      const result = await closeManualTicket({
        ticketId: manualTicketCloseMatch[1],
        outcome: normalizeText(body.outcome || ""),
        note: normalizeText(body.note || ""),
        actorName: body.actorName || body.actor_name || dbUser?.nombre || ""
      });

      if (result?.notFound) {
        return json(404, { ok: false, message: "Manual ticket not found" });
      }

      if (result?.error) {
        return json(422, { ok: false, message: result.error });
      }

      const item = await getManualTicketById(manualTicketCloseMatch[1]);
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

      const item = await getManualTicketById(manualTicketMatch[1]);
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

      const item = await getClientDetailData(clientDetailMatch[1]);

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

      const items = await listProducts();
      return json(200, { ok: true, items });
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to list products",
        error: error.message
      });
    }
  }

  if (method === "GET" && path.endsWith("/leads")) {
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
          values.push(dbUser.id);
          idx += 1;
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

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
            d.created_at,
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
            created_at: row.created_at,
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
      const tabFiltros = {
        nuevo: "AND lcs.estado_venta = 'nuevo'",
        no_contesta: "AND lcs.estado_venta IN ('no_contesta', 'rellamar')",
        seguimiento: "AND lcs.estado_venta = 'seguimiento'",
        rechazo: "AND lcs.estado_venta = 'rechazo'",
        todos: "AND lcs.estado_venta != 'dato_erroneo'"
      };
      const tabWhere = tabFiltros[tab] || tabFiltros.todos;
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
        const countResult = await client.query(
          `
          SELECT COUNT(*) AS count
          FROM lead_contact_status lcs
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE lcs.assigned_to = $1
            AND lb.estado IN ('activo', 'asignado')
            AND lcs.estado_venta != 'dato_erroneo'
            ${countExtra}
          `,
          [sellerId]
        );
        const result = await client.query(
          `
          SELECT
            d.id,
            d.nombre,
            d.apellido,
            d.documento,
            d.fecha_nacimiento,
            DATE_PART('year', AGE(d.fecha_nacimiento))::int AS edad,
            d.telefono,
            d.celular,
            d.email AS correo_electronico,
            d.direccion,
            d.departamento,
            d.localidad,
            NULL::text AS pais,
            d.origen_dato,
            lcs.estado_venta,
            lcs.intentos,
            lcs.batch_id,
            lcs.ultimo_intento_at,
            lb.nombre AS nombre_lote,
            (SELECT MAX(lmh.created_at)
             FROM lead_management_history lmh
             WHERE lmh.contact_id = d.id
               AND lmh.batch_id = lcs.batch_id
            ) AS ultima_gestion_real
          FROM lead_contact_status lcs
          JOIN datos_para_trabajar d ON d.id = lcs.contact_id
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE lcs.assigned_to = $1
            AND lb.estado IN ('activo', 'asignado')
            ${tabWhere}
          ORDER BY lcs.intentos ASC, lcs.contact_id ASC
          LIMIT $2 OFFSET $3
          `,
          [sellerId, limit, offset]
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
          ORDER BY lb.created_at DESC
          LIMIT 1
          `,
          [dbUser.id]
        );

        if (!batchRes.rows.length) {
          return json(200, {
            ok: true,
            success: true,
            data: null,
            message: "No tenés lotes activos asignados",
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
        if (enOla1 || (!enOla1 && !enOla2)) {
          estadosPrioridad = ["rellamar", "nuevo", "no_contesta"];
        } else {
          estadosPrioridad = ["rellamar", "no_contesta", "nuevo"];
        }

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
          ORDER BY prioridad ASC, lcs.intentos ASC, lcs.contact_id ASC
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
            [batch.batch_id, dbUser.id, ["nuevo", "no_contesta", "rellamar"], batch.max_intentos]
          );
          const pendientes = pendingRes.rows[0]?.total || 0;
          if (pendientes > 0) {
            return json(200, {
              ok: true,
              success: true,
              data: null,
              message: enOla2
                ? `No hay contactos disponibles en esta franja. Volvé a las ${ola1Inicio}`
                : `No hay contactos disponibles en esta franja. Volvé a las ${ola2Inicio}`,
              error: null
            });
          }

          return json(200, {
            ok: true,
            success: true,
            data: null,
            message: "Todos los contactos del lote fueron gestionados. ¡Buen trabajo!",
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

      const sellerId = dbUser?.id || null;
      const hoy = new Date().toISOString().split("T")[0];

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
          `,
          [sellerId]
        );

        const statsResult = await client.query(
          `
          SELECT
            COUNT(DISTINCT contact_id) AS tocados,
            COUNT(DISTINCT contact_id) FILTER (WHERE resultado = 'no_contesta') AS no_contesta,
            COUNT(DISTINCT contact_id) FILTER (WHERE resultado = 'rellamar') AS rellamar,
            COUNT(DISTINCT contact_id) FILTER (WHERE resultado = 'seguimiento') AS seguimiento,
            COUNT(DISTINCT contact_id) FILTER (WHERE resultado = 'rechazo') AS rechazos,
            COUNT(DISTINCT contact_id) FILTER (WHERE resultado = 'venta') AS ventas,
            ROUND(
              100.0
              * COUNT(DISTINCT contact_id) FILTER (WHERE resultado = 'venta')
              / NULLIF(COUNT(DISTINCT contact_id), 0),
              1
            ) AS efectividad_pct
          FROM lead_management_history
          WHERE user_id = $1
            AND (fecha_gestion AT TIME ZONE 'America/Montevideo')::date = $2::date
          `,
          [sellerId, hoy]
        );

        const s = statsResult.rows[0] || {};
        const l = lotesResult.rows[0] || {};
        const tocadosRaw = parseInt(s.tocados || "0", 10);
        const tocados = tocadosRaw > 0 ? tocadosRaw : 1;
        const noContestaTotal = parseInt(s.no_contesta || "0", 10);
        const contactosReales = Math.max(0, tocadosRaw - noContestaTotal);

        return json(200, {
          ok: true,
          success: true,
          data: {
            total_asignados: parseInt(l.total_asignados || "0", 10),
            nuevos: parseInt(l.nuevos || "0", 10),
            no_contesta: parseInt(s.no_contesta || "0", 10),
            seguimiento: parseInt(s.seguimiento || "0", 10),
            rechazos: parseInt(s.rechazos || "0", 10),
            ventas: parseInt(s.ventas || "0", 10),
            tocados: parseInt(s.tocados || "0", 10),
            contactos_reales: contactosReales,
            pct_contacto: Math.round(contactosReales / tocados * 100),
            pct_efectividad: parseFloat(s.efectividad_pct || "0"),
            gestiones_hoy: parseInt(s.tocados || "0", 10),
            ventas_hoy: parseInt(s.ventas || "0", 10),
            no_contesta_hoy: parseInt(s.no_contesta || "0", 10),
            tipificados_seguimiento_hoy: parseInt(s.seguimiento || "0", 10),
            rechazos_hoy: parseInt(s.rechazos || "0", 10),
            rellamar_hoy: parseInt(s.rellamar || "0", 10),
            pct_contacto_hoy: Math.round(contactosReales / tocados * 100),
            pct_efectividad_hoy: parseFloat(s.efectividad_pct || "0")
          }
        });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load daily stats",
        error: error.message
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

      const updates = [];
      const values = [];
      let idx = 1;

      const fields = {
        nombre: normalizeText(body?.nombre),
        apellido: normalizeText(body?.apellido),
        telefono: normalizeText(body?.telefono),
        celular: normalizeText(body?.celular),
        documento: normalizeText(body?.documento),
        direccion: normalizeText(body?.direccion),
        departamento: normalizeText(body?.departamento),
        localidad: normalizeText(body?.localidad)
      };

      for (const [key, value] of Object.entries(fields)) {
        if (!value) continue;
        updates.push(`${key} = $${idx}`);
        values.push(value);
        idx += 1;
      }

      if (!updates.length) {
        return json(200, { ok: true, success: true, data: null, error: null });
      }

      values.push(leadId);
      const client = createDbClient();
      await client.connect();
      try {
        await client.query(
          `
          UPDATE datos_para_trabajar
          SET ${updates.join(", ")}, updated_at = now()
          WHERE id = $${idx}
          `,
          values
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
          validationErrors.push({ field: "estado_venta", message: "Estado inválido" });
        }

        const desiredCatalog = await getLeadStatusCatalogEntry(client, resultadoInput);
        if (!desiredCatalog) {
          validationErrors.push({ field: "estado_venta", message: "Estado no existe en catálogo" });
        }

        if (resultadoInput === "seguimiento" && !fechaAgenda) {
          validationErrors.push({ field: "fecha_agenda", message: "fecha_agenda requerida para seguimiento" });
        }

        if (currentEstadoVenta) {
          const estadosVerdaderamenteFinales = ["venta", "rechazo", "dato_erroneo"];
          if (estadosVerdaderamenteFinales.includes(currentEstadoVenta)) {
            await client.query("ROLLBACK");
            return json(409, {
              ok: false,
              success: false,
              data: null,
              error: {
                message: "Contacto ya está en estado final",
                estado_actual: currentEstadoVenta
              }
            });
          }
        }

        if (validationErrors.length) {
          await client.query("ROLLBACK");
          return json(422, {
            ok: false,
            success: false,
            data: null,
            error: {
              message: "Validación",
              errors: validationErrors
            }
          });
        }

        let effectiveResultado = resultadoInput;
        let nuevaOla = currentOla;
        if (effectiveResultado === "no_contesta" && currentOla === 1) {
          nuevaOla = 2;
        }

        await client.query(
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
          `,
          [leadId, batchId, dbUser?.id || null, effectiveResultado, nota || null, proximaAccion]
        );

          const updateLeadStatus = await client.query(
            `
            UPDATE lead_contact_status
            SET estado_venta = $2,
                intentos = $3,
                proxima_accion = $4,
                batch_id = COALESCE(lead_contact_status.batch_id, $5),
                assigned_to = COALESCE(lead_contact_status.assigned_to, $6),
                ola_actual = $7,
                ultimo_intento_at = now(),
                updated_at = now()
            WHERE contact_id = $1
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
          data: { resultado: effectiveResultado, intentos: nextAttempts },
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
        values.push(dateParam);
        idx += 1;
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

      const client = createDbClient();
      await client.connect();
      try {
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
                  'email', u.email
                )
              ) AS vendedores
            FROM lead_batch_sellers lbs
            JOIN users u ON u.id = lbs.seller_id
            GROUP BY lbs.batch_id
          ) vnd ON vnd.batch_id = lb.id
          ORDER BY lb.created_at DESC
          `
        );
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

      const client = createDbClient();
      await client.connect();
      try {
        const statusRes = await client.query(
          `
          SELECT estado_venta, ola_actual, COUNT(*)::int AS total
          FROM lead_contact_status
          WHERE batch_id = $1
          GROUP BY estado_venta, ola_actual
          ORDER BY ola_actual, estado_venta
          `,
          [batchId]
        );
        const totalRes = await client.query(
          `
          SELECT COUNT(*)::int AS total
          FROM lead_batch_contacts
          WHERE batch_id = $1
          `,
          [batchId]
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

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `
          SELECT id, nombre, apellido, email
          FROM users
          WHERE role_key = 'vendedor'
            AND status = 'approved'
          ORDER BY nombre
          `
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

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `
          SELECT DISTINCT origen_dato AS id, origen_dato AS nombre
          FROM datos_para_trabajar
          WHERE origen_dato IS NOT NULL
            AND origen_dato <> ''
            AND estado = 'nuevo'
          ORDER BY origen_dato
          `
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

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `
          SELECT DISTINCT departamento AS id, departamento AS nombre
          FROM datos_para_trabajar
          WHERE departamento IS NOT NULL
            AND departamento <> ''
            AND estado = 'nuevo'
          ORDER BY departamento
          `
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

      const departamento = getQueryParam(event, "departamento");
      const values = [];
      let where = `
        localidad IS NOT NULL
        AND localidad <> ''
        AND estado = 'nuevo'
      `;
      if (departamento) {
        values.push(departamento);
        where += ` AND departamento = $1`;
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

      const client = createDbClient();
      await client.connect();
      try {
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
            UNION
            SELECT SUBSTRING(regexp_replace(telefono, '\\D', '', 'g') FROM 1 FOR 2) AS code
            FROM datos_para_trabajar
            WHERE telefono IS NOT NULL
              AND telefono <> ''
              AND estado = 'nuevo'
              AND LENGTH(regexp_replace(telefono, '\\D', '', 'g')) >= 8
          ) t
          WHERE code IS NOT NULL AND code <> ''
          ORDER BY code
          `
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

      const conditions = ["estado = 'nuevo'"];
      const params = [];
      let i = 1;

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

      const diasSinGestion = getQueryParam(event, "dias_sin_gestion");
      if (diasSinGestion) {
        conditions.push(`
          id NOT IN (
            SELECT DISTINCT contact_id
            FROM lead_management_history
            WHERE created_at >= NOW() - ($${i}::text || ' days')::interval
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

      const conditions = ["estado = 'nuevo'"];
      const params = [];
      let i = 1;

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

      const diasSinGestion = getQueryParam(event, "dias_sin_gestion");
      if (diasSinGestion) {
        conditions.push(`
          id NOT IN (
            SELECT DISTINCT contact_id
            FROM lead_management_history
            WHERE created_at >= NOW() - ($${i}::text || ' days')::interval
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
            dias_entre_olas
          )
          VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
            diasEntreOlas
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

      const updates = [];
      const values = [];
      let idx = 1;

      if (body?.nombre) {
        updates.push(`nombre = $${idx}`);
        values.push(normalizeText(body.nombre));
        idx += 1;
      }

      if (body?.estado) {
        updates.push(`estado = $${idx}`);
        values.push(normalizeText(body.estado));
        idx += 1;
      }

      if (!updates.length) return json(200, { ok: true });

      values.push(batchId);
      const client = createDbClient();
      await client.connect();
      try {
        await client.query(
          `
          UPDATE lead_batches
          SET ${updates.join(", ")}, updated_at = now()
          WHERE id = $${idx}
          `,
          values
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
      if (roleError) return roleError;      const sellerId = body?.sellerId || null;

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

        await client.query(
          `
          UPDATE lead_batches
          SET asignado_a = $1,
              seller_id = $1,
              estado = 'asignado',
              updated_at = now()
          WHERE id = $2
          `,
          [resolvedSellerId, batchId]
        );

        await client.query(
          `
          UPDATE lead_contact_status lcs
          SET assigned_to = $1,
              batch_id = COALESCE(lcs.batch_id, $2),
              updated_at = now()
          WHERE lcs.contact_id IN (
            SELECT contact_id FROM lead_batch_contacts WHERE batch_id = $2
          )
          `,
          [resolvedSellerId, batchId]
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

      const client = createDbClient();
      await client.connect();
      try {
        await client.query("BEGIN");

        const contactsRes = await client.query(
          `
          SELECT
            lbc.contact_id,
            lcs.estado_venta,
            c.es_final,
            c.libera_al_cerrar
          FROM lead_batch_contacts lbc
          LEFT JOIN lead_contact_status lcs ON lcs.contact_id = lbc.contact_id
          LEFT JOIN lead_status_catalog c ON c.nombre = lcs.estado_venta
          WHERE lbc.batch_id = $1
          `,
          [batchId]
        );

        const rows = contactsRes.rows;
        const liberar = rows.filter((row) => row.libera_al_cerrar).map((row) => row.contact_id);
        const finales = rows.filter((row) => row.es_final).map((row) => row.contact_id);
        const seguimiento = rows.filter((row) => row.estado_venta === "seguimiento").map((row) => row.contact_id);

        if (liberar.length) {
          await client.query(
            `
            UPDATE datos_para_trabajar
            SET estado = 'nuevo', updated_at = now()
            WHERE id = ANY($1::uuid[])
              AND estado <> 'bloqueado'
            `,
            [liberar]
          );
        }

        await client.query(
          `
          UPDATE lead_batches
          SET estado = 'finalizado', updated_at = now()
          WHERE id = $1
          `,
          [batchId]
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
        const sellersRes = await client.query(
          `
          SELECT seller_id
          FROM lead_batch_sellers
          WHERE batch_id = $1
          ORDER BY id ASC
          `,
          [batchId]
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

        const contactosRes = await client.query(
          `
          SELECT id, estado
          FROM datos_para_trabajar
          WHERE id = ANY($1::uuid[])
          `,
          [contactIds]
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
              message: "Contactos inválidos para asignar",
              errors
            }
          });
        }

        await client.query("BEGIN");

        await client.query(
          `
          UPDATE lead_batches
          SET asignado_a = $1,
              seller_id = $1,
              estado = 'asignado',
              updated_at = now()
          WHERE id = $2
          `,
          [sellers[0] || null, batchId]
        );

        const distribution = new Map();
        for (let i = 0; i < contactIds.length; i += 1) {
          const contactId = contactIds[i];
          const assignedTo = sellers[i % sellers.length];
          distribution.set(assignedTo, (distribution.get(assignedTo) || 0) + 1);

          await client.query(
            `
            INSERT INTO lead_batch_contacts (batch_id, contact_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            `,
            [batchId, contactId]
          );

          const updateStatus = await client.query(
            `
            UPDATE lead_contact_status
            SET batch_id = $2,
                assigned_to = $3,
                estado_venta = 'nuevo',
                intentos = 0,
                updated_at = now()
            WHERE contact_id = $1
            RETURNING contact_id
            `,
            [contactId, batchId, assignedTo]
          );
          if (!updateStatus.rows.length) {
            await client.query(
              `
              INSERT INTO lead_contact_status (
                contact_id,
                estado_venta,
                intentos,
                batch_id,
                assigned_to
              )
              VALUES ($1, 'nuevo', 0, $2, $3)
              `,
              [contactId, batchId, assignedTo]
            );
          }
        }

        await client.query(
          `
          UPDATE datos_para_trabajar
          SET estado = 'trabajado', updated_at = now()
          WHERE id = ANY($1::uuid[])
            AND estado <> 'bloqueado'
          `,
          [contactIds]
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
              'batches'::text AS source
            FROM contact_import_batches b
            LEFT JOIN users u ON u.id = b.created_by

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
              'no_call_jobs'::text AS source
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
              'datos_virtual'::text AS source
            FROM (
              SELECT COUNT(*)::int AS total_rows, MAX(created_at) AS created_at
              FROM datos_para_trabajar
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
              'batches'::text AS source
            FROM contact_import_batches b
            LEFT JOIN users u ON u.id = b.created_by

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
              'no_call_jobs'::text AS source
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
              'datos_virtual'::text AS source
            FROM (
              SELECT COUNT(*)::int AS total_rows, MAX(created_at) AS created_at
              FROM datos_para_trabajar
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

  if (method === "GET" && path.endsWith("/api/supervisor/sellers-summary")) {
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
        const sellersRes = await client.query(
          `
          SELECT id, nombre, apellido
          FROM users
          WHERE role_key = 'vendedor'
            AND status = 'approved'
          ORDER BY nombre
          `
        );
        const sellers = sellersRes.rows || [];
        const sellerIds = sellers.map((row) => row.id);
        if (!sellerIds.length) {
          return json(200, { ok: true, fecha, items: [] });
        }

        const assignedRes = await client.query(
          `
          SELECT lcs.assigned_to AS user_id,
                 COUNT(DISTINCT lcs.contact_id)::int AS asignados
          FROM lead_contact_status lcs
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE lcs.assigned_to = ANY($1::uuid[])
            AND lb.estado IN ('activo', 'asignado')
          GROUP BY lcs.assigned_to
          `,
          [sellerIds]
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
            WHERE lmh.user_id = ANY($1::uuid[])
              AND (lmh.fecha_gestion AT TIME ZONE 'America/Montevideo')::date = $2::date
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
          [sellerIds, fecha]
        );
        const dailyMap = new Map(dailyRes.rows.map((row) => [row.user_id, row]));

        const items = sellers.map((seller) => {
          const daily = dailyMap.get(seller.id) || {};
          const gestiones = Number(daily.gestiones || 0);
          const ventas = Number(daily.ventas || 0);
          const seguimientos = Number(daily.seguimientos || 0);
          const rellamadas = Number(daily.rellamadas || 0);
          const noContesta = Number(daily.no_contesta || 0);
          const rechazos = Number(daily.rechazos || 0);
          const datosErroneos = Number(daily.datos_erroneos || 0);
          const gestionesTotal = gestiones;
          const contacto = gestionesTotal > 0
            ? Math.round(((gestionesTotal - noContesta) / gestionesTotal) * 100)
            : 0;
          const efectividad = gestionesTotal > 0
            ? Math.round((ventas / gestionesTotal) * 100)
            : 0;

          return {
            id: seller.id,
            nombre: seller.nombre,
            apellido: seller.apellido,
            gestiones: gestionesTotal,
            asignados: assignedMap.get(seller.id) || 0,
            ventas,
            seguimientos,
            rellamadas,
            no_contesta: noContesta,
            rechazos,
            datos_erroneos: datosErroneos,
            contacto,
            efectividad
          };
        });

        return json(200, { ok: true, fecha, items });
      } finally {
        await client.end();
      }
    } catch (error) {
      return json(500, {
        ok: false,
        message: "Failed to load sellers summary",
        error: error.message
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
        const isBanoType = (t) => t === "BA?O" || t === "BAÑO";
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
              descripcion: `${conversion}% actual vs mínimo ${config.conversion_minima_porcentaje}%`,
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
        telefono: user.telefono
      }));

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
          return json(409, { ok: false, message: "El job está en proceso" });
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
              created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            `,
            [
              fileName,
              "processed",
              "datos_para_trabajar",
              rows.length,
              0,
              0,
              dbUser?.id || null
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
                created_by
              )
              VALUES ($1, $2, $3, $4, $5, $6, $7)
              RETURNING id
              `,
              [
                fileName,
                "processed",
                "datos_para_trabajar",
                rows.length,
                0,
                0,
                dbUser?.id || null
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
                created_by
              )
              VALUES ($1, $2, $3, $4, $5, $6, $7)
              RETURNING id
              `,
              [
                fileName,
                "processed",
                "datos_para_trabajar",
                rows.length,
                0,
                0,
                dbUser?.id || null
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
            created_by
          )
          VALUES ($1, $2, 'queued', $3, 0, 0, 0, 0, $4, $5)
          RETURNING id
          `,
          [batchId, fileName, rows.length, csvText, dbUser?.id || null]
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
          `,
          [batchId, rows.length]
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

  if (method === "POST" && path.endsWith("/imports/clients")) {
    const contentType = event?.headers?.["content-type"] || event?.headers?.["Content-Type"] || "";
    const fileName =
      event?.headers?.["x-file-name"] ||
      event?.headers?.["X-File-Name"] ||
      event?.headers?.["x-filename"] ||
      event?.headers?.["X-Filename"] ||
      "import_clientes.csv";

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

      const autoProcessParam = String(getQueryParam(event, "autoProcess") || "")
        .trim()
        .toLowerCase();
      const autoProcess = !["false", "0", "no"].includes(autoProcessParam);
      const createProductsParam = String(getQueryParam(event, "createProducts") || "")
        .trim()
        .toLowerCase();
      const createProducts = !["false", "0", "no"].includes(createProductsParam);

      const lineIterator = iterateCsvLines(csvText.replace(/^\uFEFF/, ""));
      const headerLineResult = lineIterator.next();
      const headerLine = headerLineResult.done ? "" : headerLineResult.value || "";
      if (!headerLine.trim()) {
        return json(400, { ok: false, message: "CSV vacio" });
      }
      const separator = detectCsvSeparator(headerLine);
      const headerKeys = parseCsvLine(headerLine, separator).map(
        (header) => CSV_HEADER_MAP[normalizeCsvHeader(header)] || null
      );
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
            created_by
          )
          VALUES ($1, 'uploaded', 'clientes', 0, 0, 0, 0, $2)
          RETURNING *
          `,
          [fileName, dbUser?.id || null]
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
          const cells = parseCsvLine(line, separator);
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
          ORDER BY row_number ASC
          `,
          [batchId]
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
        await client.query("BEGIN");
        await client.query(
          `
          DELETE FROM contact_import_rows
          WHERE batch_id = $1
          `,
          [batchId]
        );
        const deleteBatch = await client.query(
          `
          DELETE FROM contact_import_batches
          WHERE id = $1
          `,
          [batchId]
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

      await enqueueContactImportJob(batchId, { createProducts });
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

      const item = await createProductRecord(validation.data);
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

      const item = await updateProductRecord(productMatch[1], validation.data);
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
        telefono: normalizePhone(validation.data.telefono),
        role: validation.data.rol,
        status: validation.data.status,
        reason: validation.data.reason || undefined
      };

      const createdUser = await createManualUser(payload, dbUser);
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
        telefono: normalizePhone(validation.data.telefono),
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







































