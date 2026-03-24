import fs from "node:fs";
import { Client } from "pg";
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminAddUserToGroupCommand,
  ListUsersCommand
} from "@aws-sdk/client-cognito-identity-provider";
import { AppError } from "./src/lib/errors.js";
import { handleOptions, getMethod as getMethodFromHttp, CORS_HEADERS } from "./src/lib/http.js";
import { normalizePhone } from "./src/lib/validation.js";
import { createManualUser, updateUser } from "./src/services/userService.js";
import { generateCertificatePdf, buildClientDocumentFilename } from "./src/lib/certificatePdf.js";

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
    return groups.split(",").map((g) => g.trim()).filter(Boolean);
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
    ssl:
      process.env.PGSSL === "true"
        ? { rejectUnauthorized: false }
        : undefined
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
  if (n.startsWith("472")) return "PaysandÃº";
  if (n.startsWith("456")) return "RÃ­o Negro";
  if (n.startsWith("453")) return "Soriano";
  if (n.startsWith("434")) return "San JosÃ©";
  if (n.startsWith("447")) return "Rocha";
  if (n.startsWith("445")) return "Treinta y Tres";
  if (n.startsWith("464")) return "Cerro Largo";
  if (n.startsWith("462")) return "Rivera";
  if (n.startsWith("463")) return "TacuarembÃ³";
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
    SELECT id, nombre, es_final, libera_al_cerrar
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
  "2320": "ColÃ³n",
  "2222": "Piedras Blancas",
  "2401": "CordÃ³n",
  "2487": "Hosp. ClÃ­nicas",
  "2292": "Pando",
  "2294": "Sauce",
  "2295": "Empalme Olmos",
  "2296": "Toledo",
  "2902": "Plaza Centro",
  "2712": "Punta Carretas",
  "2312": "Paso de la Arena",
  "2355": "Sayago",
  "2409": "Tres Cruces",
  "2506": "UniÃ³n",
  "2347": "AutÃ³dromo",
  "2362": "La Paz",
  "2364": "Las Piedras",
  "2369": "Progreso",
  "2372": "AtlÃ¡ntida",
  "2682": "Lagomar",
  "2696": "Solymar",
  "4332": "Canelones",
  "4530": "CaÃ±ada Nieto",
  "4222": "Maldonado",
  "4223": "Maldonado",
  "4224": "Maldonado",
  "4225": "Maldonado",
  "4244": "Punta del Este (PenÃ­nsula)",
  "4248": "Punta del Este Parada 5",
  "4249": "Punta del Este Parada 5",
  "4255": "Laguna del Sauce",
  "4257": "Portezuelo",
  "4266": "San Carlos",
  "4277": "La Barra",
  "4311": "CasupÃ¡",
  "4312": "San RamÃ³n",
  "4313": "San Antonio",
  "4315": "Tala",
  "4317": "Miguez",
  "4318": "Cerro Colorado",
  "4319": "Chamizo",
  "4334": "Santa LucÃ­a",
  "4335": "JuanicÃ³",
  "4336": "Los Cerrillos",
  "4338": "Colonia Etchepare",
  "4339": "Cardal",
  "4342": "San JosÃ©",
  "4345": "KiyÃº",
  "4346": "Rafael Peraza",
  "4348": "Villa Rodriguez",
  "4349": "Colonia Agra.Delta",
  "4352": "Florida",
  "4354": "SarandÃ­ Grande",
  "4360": "Blanquillo",
  "4362": "Durazno",
  "4364": "Trinidad",
  "4365": "Carmen",
  "4367": "SarandÃ­ del Yi",
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
  "4432": "PiriÃ¡polis",
  "4434": "Pan de AzÃºcar",
  "4438": "Balneario SolÃ­s",
  "4442": "Minas",
  "4446": "AiguÃ¡",
  "4447": "SolÃ­s de Mataojo",
  "4448": "PirarajÃ¡",
  "4449": "Mariscala",
  "4452": "Treinta y Tres",
  "4455": "JosÃ© P. Varela",
  "4456": "Lascano",
  "4457": "VelÃ¡zquez",
  "4458": "Vergara",
  "4459": "CebollatÃ­",
  "4463": "ZapicÃ¡n",
  "4464": "Santa Clara de Olimar",
  "4466": "Cerro Chato",
  "4469": "Batlle y OrdoÃ±ez",
  "4472": "Rocha",
  "4474": "Barra del Chuy",
  "4475": "Aguas Dulces",
  "4476": "La Coronilla",
  "4477": "Santa Teresa",
  "4479": "La Paloma (Rocha)",
  "4486": "Faro JosÃ© Ignacio",
  "4522": "Colonia",
  "4534": "Dolores",
  "4536": "Cardona",
  "4537": "Palmitas",
  "4538": "JosÃ© E. RodÃ³",
  "4539": "Ismael Cortinas",
  "4542": "Balneario ZagarazÃº",
  "4544": "Nueva Palmira",
  "4552": "Rosario",
  "4554": "Nueva Helvecia",
  "4558": "Colonia Valdense",
  "4562": "Fray Bentos",
  "4567": "Young",
  "4568": "Nuevo BerlÃ­n",
  "4569": "San Javier",
  "4574": "Semillero",
  "4575": "Colonia Miguelete",
  "4576": "OmbÃºes de Lavalle",
  "4577": "Conchillas",
  "4586": "Juan Lacaze",
  "4587": "Playa Fomento",
  "4588": "Santa Ana",
  "4622": "Rivera",
  "4632": "TacuarembÃ³",
  "4640": "AceguÃ¡",
  "4642": "Melo",
  "4654": "Vichadero",
  "4656": "Tranqueras",
  "4658": "Minas de Corrales",
  "4664": "Paso de los Toros",
  "4675": "RÃ­o Branco",
  "4679": "Lago MerÃ­n",
  "4722": "PaysandÃº",
  "4730": "Defensa (Salto)",
  "4732": "Pueblo Lavalleja",
  "4733": "Cuchilla de Salto",
  "4742": "GuichÃ³n",
  "4747": "Piedras Coloradas",
  "4754": "Quebracho",
  "4764": "ConstituciÃ³n",
  "4766": "BelÃ©n",
  "4772": "Artigas",
  "4776": "Baltasar Brum",
  "4777": "TomÃ¡s Gomensoro",
  "4778": "Mones Quintela",
  "4779": "Bella UniÃ³n",
  "4888": "Fraile Muerto",
  "5432": "Mercedes"
};

function getLocalidadFromFixed(numero) {
  if (!numero || numero.length < 4) return null;
  const prefix = numero.slice(0, 4);
  return NO_CALL_LOCALIDAD_BY_PREFIX[prefix] || null;
}

const NO_CALL_JOB_CHUNK_SIZE = 5000;

async function processNoCallJob(jobId) {
  const client = createDbClient();
  await client.connect();

  try {
    const jobRes = await client.query(
      `
      SELECT id, csv_text
      FROM no_call_import_jobs
      WHERE id = $1
      LIMIT 1
      `,
      [jobId]
    );

    if (!jobRes.rows.length) return;

    const csvText = jobRes.rows[0].csv_text || "";
    const parsedRows = parseCsv(csvText);
    const rows = parsedRows.slice(1);
    const totalRows = rows.length;

    await client.query(
      `
      UPDATE no_call_import_jobs
      SET status = 'processing',
          total_rows = $1,
          processed_rows = 0,
          inserted_rows = 0,
          skipped_rows = 0,
          error_message = NULL,
          started_at = now(),
          updated_at = now()
      WHERE id = $2
      `,
      [totalRows, jobId]
    );

    let index = 0;
    let inserted = 0;
    let skipped = 0;

    const runChunk = async () => {
      const chunk = rows.slice(index, index + NO_CALL_JOB_CHUNK_SIZE);
      if (!chunk.length) {
        await client.query(
          `
          UPDATE no_call_import_jobs
          SET status = 'completed',
              processed_rows = $1,
              inserted_rows = $2,
              skipped_rows = $3,
              completed_at = now(),
              updated_at = now()
          WHERE id = $4
          `,
          [index, inserted, skipped, jobId]
        );
        await client.end();
        return;
      }

      try {
        await client.query("BEGIN");
        for (const row of chunk) {
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
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        await client.query(
          `
          UPDATE no_call_import_jobs
          SET status = 'failed',
              error_message = $1,
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
            updated_at = now()
        WHERE id = $4
        `,
        [index, inserted, skipped, jobId]
      );

      setImmediate(runChunk);
    };

    setImmediate(runChunk);
  } catch (error) {
    await client.query(
      `
      UPDATE no_call_import_jobs
      SET status = 'failed',
          error_message = $1,
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
  return parsed.toLocaleString("es-UY", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
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
  resultados: "CSV de resultados telefÃ³nicos",
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
  "correo electrÃ³nico": "correo_electronico",
  "email": "correo_electronico",
  "direccion": "direccion",
  "direcciÃ³n": "direccion",
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

function validateImportRow(item) {
  const errors = [];
  if (!item.nombre && !item.apellido) {
    errors.push("nombre o apellido requerido");
  }
  if (!item.documento) {
    errors.push("documento requerido");
  }
  return errors;
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

    return lines.join("\r\n");
  }

  const headers = [
    "Nombre",
    "Apellido",
    "Documento",
    "Fecha de nacimiento",
    "telefono",
    "Celular",
    "Correo electronico",
    "DirecciÃ³n",
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
    "DirecciÃ³n": "18 de Julio 1234",
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

  return lines.join("\r\n");
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
    errors.precio = ["precio invÃ¡lido"];
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
      errors.email = "El email no es vÃ¡lido";
    }
  }

  if (!options.partial || body?.telefono !== undefined) {
    if (!telefono) {
      errors.telefono = "El telÃ©fono es obligatorio";
    }
  }

  if (!options.partial || body?.rol !== undefined || body?.role !== undefined) {
    if (!rol) {
      errors.rol = "El rol es obligatorio";
    } else if (!VALID_ROLES.includes(rol)) {
      errors.rol = "El rol no es vÃ¡lido";
    }
  }

  if (!options.partial || body?.status !== undefined) {
    if (!status) {
      errors.status = "El estado es obligatorio";
    } else if (!VALID_USER_STATUSES.includes(status)) {
      errors.status = "El estado no es vÃ¡lido";
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
  if (!telefono) errors.telefono = "El telÃ©fono es obligatorio";

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

  let dbUser = await getUserByAuthUser(authUser);

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

async function listClientsDirectory() {
  const client = createDbClient();

  try {
    await client.connect();

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
      WHERE s.productos_total > 0
      ORDER BY
        CASE WHEN rp.estado = 'alta' THEN 0 ELSE 1 END,
        s.created_at DESC,
        s.nombre ASC,
        s.apellido ASC
      `
    );

    return result.rows.map(mapClientRowToApi);
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
    const userJoin = metadata.hasUsersTable ? "LEFT JOIN users u ON u.id = s.seller_id" : "";

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
        s.fecha AS sale_fecha,
        s.medio_pago,
        s.seller_origin,
        s.seller_name_snapshot,
        s.seller_id,
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
    const userJoin = metadata.hasUsersTable ? "LEFT JOIN users u ON u.id = s.seller_id" : "";

    const productsResult = await client.query(
      `
      SELECT
        cp.*,
        s.fecha AS sale_fecha,
        s.medio_pago,
        s.seller_origin,
        s.seller_name_snapshot,
        s.seller_id,
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
      ORDER BY s.fecha DESC NULLS LAST, s.created_at DESC
      `,
      [clientId]
    );

    const salesHistory = salesResult.rows.map((row) => {
      const sellerName = row.seller_origin === "externo"
        ? row.seller_name_snapshot
        : [row.seller_nombre, row.seller_apellido].filter(Boolean).join(" ").trim() || row.seller_name_snapshot;

      return {
        id: row.id,
        fecha: row.fecha,
        fecha_alta: row.fecha,
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
        created_at,
        updated_at
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
      created_at: row.created_at,
      updatedAt: row.updated_at,
      updated_at: row.updated_at
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
          "ActualizaciÃ³n desde superadmin/users"
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
          "ActualizaciÃ³n desde superadmin/users"
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
  console.log("[role-check] Â¿tiene acceso?:", allowedRoles.includes(dbUser?.role_key));
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
        message: "La solicitud ya no estÃ¡ pendiente"
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
        "AprobaciÃ³n de solicitud de vendedor"
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
        message: "La solicitud ya no estÃ¡ pendiente"
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
  if (getMethodFromHttp(event) === "OPTIONS") {
    return handleOptions();
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
      const dbUser = await getUserByAuthUser(authUser);

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
              INSERT INTO sales (
                contact_id,
                seller_id,
                fecha,
                medio_pago,
                seller_name_snapshot,
                seller_origin
              )
              VALUES ($1, $2, $3, $4, $5, $6)
              RETURNING id
              `,
              [
                contactId,
                sellerId,
                fechaAlta,
                medioPago,
                sellerNameSnapshot,
                sellerOrigin
              ]
            );
            const saleId = saleInsert.rows[0]?.id;

            if (saleId && productId) {
              await client.query(
                `
                INSERT INTO sale_items (
                  sale_id,
                  product_id,
                  cantidad,
                  precio_unitario
                )
                VALUES ($1,$2,1,$3)
                `,
                [saleId, productId, precio || 0]
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

      const items = await listClientsDirectory();

      return json(200, {
        ok: true,
        items
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
      const sellerName = [dbUser?.nombre, dbUser?.apellido].filter(Boolean).join(" ").trim();
      const sellerNamePattern = sellerName ? `%${sellerName}%` : "";

      const client = createDbClient();
      await client.connect();
      try {
        const result = await client.query(
          `
          SELECT
            s.id,
            s.contact_id,
            s.seller_id,
            s.fecha,
            s.created_at,
            s.medio_pago,
            s.seller_name_snapshot,
            c.nombre,
            c.apellido,
            c.telefono,
            c.celular,
            si.product_id,
            si.precio_unitario,
            p.nombre AS producto_nombre
          FROM sales s
          JOIN contacts c ON c.id = s.contact_id
          LEFT JOIN LATERAL (
            SELECT product_id, precio_unitario
            FROM sale_items
            WHERE sale_id = s.id
            ORDER BY created_at DESC NULLS LAST
            LIMIT 1
          ) si ON true
          LEFT JOIN products p ON p.id = si.product_id
          WHERE s.seller_id = $1
             OR ($2 <> '' AND s.seller_name_snapshot ILIKE $3)
          ORDER BY s.created_at DESC NULLS LAST, s.fecha DESC
          `,
          [sellerId, sellerName, sellerNamePattern]
        );

        const items = result.rows.map((row) => ({
          id: row.id,
          contact_id: row.contact_id,
          cliente_nombre: [row.nombre, row.apellido].filter(Boolean).join(" ").trim(),
          telefono: row.celular || row.telefono || "",
          producto_id: row.product_id || null,
          producto_nombre: row.producto_nombre || null,
          cuota: row.precio_unitario !== null && row.precio_unitario !== undefined
            ? Number(row.precio_unitario)
            : null,
          fecha_venta: row.fecha || null,
          fecha_venta_at: row.created_at || null,
          medio_pago: row.medio_pago || null
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
            d.correo_electronico,
            d.direccion,
            d.departamento,
            d.localidad,
            d.pais,
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
            message: "No tenÃ©s lotes activos asignados",
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
            d.correo_electronico,
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
                ? `No hay contactos disponibles en esta franja. VolvÃ© a las ${ola1Inicio}`
                : `No hay contactos disponibles en esta franja. VolvÃ© a las ${ola2Inicio}`,
              error: null
            });
          }

          return json(200, {
            ok: true,
            success: true,
            data: null,
            message: "Todos los contactos del lote fueron gestionados. Â¡Buen trabajo!",
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
        const totalesResult = await client.query(
          `
          SELECT 
            COUNT(*) FILTER (WHERE lcs.estado_venta != 'dato_erroneo') AS total_asignados,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'nuevo') AS nuevos,
            COUNT(*) FILTER (WHERE lcs.estado_venta IN ('no_contesta','rellamar')) AS no_contesta,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'rechazo') AS rechazos,
            COUNT(*) FILTER (WHERE lcs.estado_venta = 'venta') AS ventas,
            COUNT(*) FILTER (WHERE lcs.estado_venta != 'nuevo' AND lcs.estado_venta != 'dato_erroneo') AS tocados
          FROM lead_contact_status lcs
          JOIN lead_batches lb ON lb.id = lcs.batch_id
          WHERE lcs.assigned_to = $1
            AND lb.estado IN ('activo', 'asignado')
          `,
          [sellerId]
        );

        const agendaResult = await client.query(
          `
          SELECT COUNT(*) AS seguimiento_activo
          FROM lead_agenda la
          JOIN lead_batches lb ON lb.id = la.batch_id
          WHERE la.seller_id = $1
            AND la.cumplida = false
            AND lb.estado IN ('activo', 'asignado')
          `,
          [sellerId]
        );

        const hoyResult = await client.query(
          `
          WITH contactos_tocados_hoy AS (
            SELECT DISTINCT contact_id
            FROM lead_management_history
            WHERE user_id = $1
              AND fecha_gestion::date = $2::date
          ),
          ultimo_resultado_hoy AS (
            SELECT DISTINCT ON (lmh.contact_id)
              lmh.contact_id,
              lmh.resultado
            FROM lead_management_history lmh
            JOIN contactos_tocados_hoy cth ON cth.contact_id = lmh.contact_id
            WHERE lmh.user_id = $1
              AND lmh.fecha_gestion::date = $2::date
            ORDER BY lmh.contact_id, lmh.fecha_gestion DESC
          )
          SELECT
            COUNT(*) AS gestiones_hoy,
            COUNT(*) FILTER (WHERE resultado = 'venta') AS ventas_hoy,
            COUNT(*) FILTER (WHERE resultado = 'no_contesta') AS no_contesta_hoy,
            COUNT(*) FILTER (WHERE resultado = 'seguimiento') AS tipificados_seguimiento_hoy,
            COUNT(*) FILTER (WHERE resultado = 'rechazo') AS rechazos_hoy,
            COUNT(*) FILTER (WHERE resultado = 'rellamar') AS rellamar_hoy
          FROM ultimo_resultado_hoy
          `,
          [sellerId, hoy]
        );

        const seguimientoActivoResult = await client.query(
          `
          SELECT COUNT(*) AS seguimiento_activo_hoy
          FROM lead_agenda la
          JOIN lead_contact_status lcs
            ON lcs.contact_id = la.contact_id
            AND lcs.batch_id = la.batch_id
          JOIN lead_batches lb ON lb.id = la.batch_id
          WHERE la.seller_id = $1
            AND la.cumplida = false
            AND lb.estado IN ('activo', 'asignado')
            AND lcs.estado_venta NOT IN ('rechazo', 'venta', 'dato_erroneo')
          `,
          [sellerId]
        );

        const t = totalesResult.rows[0] || {};
        const h = hoyResult.rows[0] || {};
        const sa = seguimientoActivoResult.rows[0] || {};
        const seguimientoActivo = parseInt(agendaResult.rows[0]?.seguimiento_activo || "0", 10);
        const tocados = parseInt(t.tocados || "0", 10) || 1;
        const contactosReales =
          seguimientoActivo +
          parseInt(t.ventas || "0", 10) +
          parseInt(t.rechazos || "0", 10);
        const gestiHoy = parseInt(h.gestiones_hoy || "0", 10) || 1;
        const contactoRealHoy =
          parseInt(sa.seguimiento_activo_hoy || "0", 10) +
          parseInt(h.rechazos_hoy || "0", 10) +
          parseInt(h.ventas_hoy || "0", 10) +
          parseInt(h.rellamar_hoy || "0", 10);

        return json(200, {
          ok: true,
          success: true,
          data: {
            total_asignados: parseInt(t.total_asignados || "0", 10),
            nuevos: parseInt(t.nuevos || "0", 10),
            no_contesta: parseInt(t.no_contesta || "0", 10),
            seguimiento: seguimientoActivo,
            rechazos: parseInt(t.rechazos || "0", 10),
            ventas: parseInt(t.ventas || "0", 10),
            tocados: parseInt(t.tocados || "0", 10),
            contactos_reales: contactosReales,
            pct_contacto: Math.round(contactosReales / tocados * 100),
            pct_efectividad: Math.round(
              parseInt(t.ventas || "0", 10) / tocados * 100
            ),
            gestiones_hoy: parseInt(h.gestiones_hoy || "0", 10),
            ventas_hoy: parseInt(h.ventas_hoy || "0", 10),
            no_contesta_hoy: parseInt(h.no_contesta_hoy || "0", 10),
            tipificados_seguimiento_hoy: parseInt(sa.seguimiento_activo_hoy || "0", 10),
            rechazos_hoy: parseInt(h.rechazos_hoy || "0", 10),
            rellamar_hoy: parseInt(h.rellamar_hoy || "0", 10),
            pct_contacto_hoy: Math.round(contactoRealHoy / gestiHoy * 100),
            pct_efectividad_hoy: Math.round(
              parseInt(h.ventas_hoy || "0", 10) / gestiHoy * 100
            )
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
          validationErrors.push({ field: "estado_venta", message: "Estado invÃ¡lido" });
        }

        const desiredCatalog = await getLeadStatusCatalogEntry(client, resultadoInput);
        if (!desiredCatalog) {
          validationErrors.push({ field: "estado_venta", message: "Estado no existe en catÃ¡logo" });
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
                message: "Contacto ya estÃ¡ en estado final",
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
              message: "ValidaciÃ³n",
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
          ON CONFLICT (contact_id)
          DO UPDATE SET
            estado_venta = EXCLUDED.estado_venta,
            intentos = EXCLUDED.intentos,
            proxima_accion = EXCLUDED.proxima_accion,
            batch_id = COALESCE(lead_contact_status.batch_id, EXCLUDED.batch_id),
            assigned_to = COALESCE(lead_contact_status.assigned_to, EXCLUDED.assigned_to),
            ola_actual = $7,
            ultimo_intento_at = now(),
            updated_at = now()
          `,
          [leadId, effectiveResultado, nextAttempts, proximaAccion, batchId, assignedTo, nuevaOla]
        );

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
            d.correo_electronico,
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

  if (method === "GET" && path === "/lead-sources") {
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

  if (method === "GET" && path === "/departamentos") {
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

  if (method === "GET" && path === "/localidades") {
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

  if (method === "GET" && path === "/area-codes") {
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

  if (method === "GET" && path === "/datos-para-trabajar/preview") {
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

  if (method === "GET" && path === "/datos-para-trabajar/list") {
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
            ON CONFLICT (batch_id, seller_id) DO NOTHING
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
      if (roleError) return roleError;

      const sellerName = normalizeText(body?.sellerName || body?.seller);
      const sellerId = body?.sellerId || null;

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
            ON CONFLICT (batch_id, seller_id) DO NOTHING
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
              message: "Contactos invÃ¡lidos para asignar",
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
            ON CONFLICT (batch_id, contact_id) DO NOTHING
            `,
            [batchId, contactId]
          );

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
            ON CONFLICT (contact_id)
            DO UPDATE SET
              batch_id = EXCLUDED.batch_id,
              assigned_to = EXCLUDED.assigned_to,
              estado_venta = 'nuevo',
              intentos = 0,
              updated_at = now()
            `,
            [contactId, batchId, assignedTo]
          );
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
            rejectedMissingDocumento: Number(row.rejected_missing_documento || 0)
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
          [rows.length, inserted, skipped, batch.id]
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
          RETURNING id
          `,
          [fileName, csvText, dbUser?.id || null]
        );
        const jobId = jobResult.rows[0].id;
        // Fire-and-forget background processing.
        await processNoCallJob(jobId);
        return json(201, { ok: true, jobId });
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
        return json(200, {
          ok: true,
          job: {
            id: row.id,
            fileName: row.file_name,
            status: row.status,
            total: Number(row.total_rows || 0),
            processed: Number(row.processed_rows || 0),
            inserted: Number(row.inserted_rows || 0),
            skipped: Number(row.skipped_rows || 0),
            error: row.error_message || null,
            createdAt: row.created_at,
            startedAt: row.started_at,
            completedAt: row.completed_at
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
          } else {
            throw err;
          }
        }
        const batchId = batchRes.rows[0]?.id || null;
        let inserted = 0;
        const normalizedNumbers = new Set();
        for (const row of rows) {
          const tel = normalizeUyNumber(row.telefono);
          const cel = normalizeUyNumber(row.celular);
          if (tel) normalizedNumbers.add(tel);
          if (cel) normalizedNumbers.add(cel);
        }

        let blockedNumbers = new Set();
        if (normalizedNumbers.size) {
          const res = await client.query(
            `SELECT numero FROM no_call_entries WHERE numero = ANY($1::text[])`,
            [Array.from(normalizedNumbers)]
          );
          blockedNumbers = new Set(res.rows.map((r) => r.numero));
        }

        for (const row of rows) {
          const tel = normalizeUyNumber(row.telefono);
          const cel = normalizeUyNumber(row.celular);
          const isBlocked =
            (tel && blockedNumbers.has(tel)) || (cel && blockedNumbers.has(cel));

          await client.query(
            `
            INSERT INTO datos_para_trabajar (
              nombre,
              apellido,
              documento,
              fecha_nacimiento,
              telefono,
              celular,
              correo_electronico,
              direccion,
              departamento,
              localidad,
              origen_dato,
              pais,
              estado
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            `,
            [
              row.nombre || null,
              row.apellido || null,
              row.documento || null,
              row.fecha_nacimiento || null,
              row.telefono || null,
              row.celular || null,
              row.correo_electronico || null,
              row.direccion || null,
              row.departamento || null,
              row.localidad || null,
              row.origen_dato || null,
              row.pais || null,
              isBlocked ? "bloqueado" : "nuevo"
            ]
          );
          inserted += 1;
        }
        await client.query(
          `
          UPDATE contact_import_batches
          SET valid_rows = $2, error_rows = $3, status = $4
          WHERE id = $1
          `,
          [batchId, inserted, 0, "processed"]
        );
        await client.query("COMMIT");
        return json(201, {
          ok: true,
          batchId,
          total: rows.length,
          inserted,
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
            OR d.correo_electronico ILIKE $${idx}
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
            d.correo_electronico,
            d.direccion,
            d.departamento,
            d.localidad,
            d.origen_dato,
            d.estado,
            d.pais,
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

      const { rows, ignoredEmptyRows } = mapCsvRowsToImport(parseCsv(csvText));
      const client = createDbClient();
      await client.connect();

      try {
        await client.query("BEGIN");
        const productNames = Array.from(
          new Set(
            rows
              .map((row) => normalizeText(row.producto_nombre))
              .filter(Boolean)
          )
        );
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

        for (let i = 0; i < rows.length; i += 1) {
          const item = rows[i];
          const errors = validateImportRow(item);
          const importStatus = errors.length ? "error" : "validated";
          if (importStatus === "validated") validRows += 1;
          else {
            errorRows += 1;
            if (errors.includes("documento requerido")) missingDocumentoRows += 1;
          }

          await client.query(
            `
            INSERT INTO contact_import_rows (
              batch_id,
              row_number,
              nombre,
              apellido,
              email,
              telefono,
              documento,
              contacto_estado,
              producto_nombre,
              plan,
              precio,
              medio_pago,
              fecha_alta,
              cuotas_pagas,
              carencia_cuotas,
              producto_estado,
              motivo_baja,
              motivo_baja_detalle,
              fecha_baja,
              vendedor_nombre,
              vendedor_email,
              fecha_venta,
              documento_beneficiario,
              documento_cobranza,
              telefono_venta,
              telefono_fijo,
              telefono_celular,
              telefono_alternativo,
              consulta_estado,
              evaluacion,
              auditoria_ok,
              auditoria_comentario,
              nombre_asesor,
              fecha_nacimiento,
              departamento_residencia,
              nombre_familiar,
              apellido_familiar,
              telefono_familiar,
              parentesco,
              import_status,
              error_detail,
              raw_payload
            )
            VALUES (
              $1, $2, $3, $4, $5, $6, $7,
              $8, $9, $10, $11, $12, $13,
              $14, $15, $16, $17, $18, $19,
              $20, $21, $22, $23, $24, $25,
              $26, $27, $28, $29, $30, $31,
              $32, $33, $34, $35, $36, $37,
              $38, $39, $40, $41, $42
            )
            `,
            [
              batch.id,
              i + 1,
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
              errors.length ? JSON.stringify(errors) : null,
              item
            ]
          );
        }

        await client.query(
          `
          UPDATE contact_import_batches
          SET total_rows = $1,
              valid_rows = $2,
              error_rows = $3,
              rejected_missing_documento = $4,
              status = 'validated',
              updated_at = now()
          WHERE id = $5
          `,
          [rows.length, validRows, errorRows, missingDocumentoRows, batch.id]
        );

        await client.query("COMMIT");
        return json(201, {
          ok: true,
          batchId: batch.id,
          total: rows.length,
          valid: validRows,
          errors: errorRows,
          rejectedMissingDocumento: missingDocumentoRows,
          ignoredEmptyRows,
          newProducts: missingProducts,
          newProductsCount: missingProducts.length
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

            const documento = normalizeText(row.documento);
            if (!documento) {
              throw new Error("Documento requerido");
            }
            const email = normalizeText(row.email).toLowerCase() || null;
            const vendedorNombre = normalizeText(row.vendedor_nombre);
            const medioPago = normalizeText(row.medio_pago);
            const productoNombre = buildProductDisplayName(row.producto_nombre, row.precio);
            const phones = normalizeContactPhones(row.telefono, row.telefono_celular);

            if (vendedorNombre) sellersSeen.add(vendedorNombre.toLowerCase());
            if (medioPago) paymentMethodsSeen.add(medioPago.toLowerCase());
            if (productoNombre) productsSeen.add(productoNombre.toLowerCase());

            const contactLookupResult = await client.query(
              `
              SELECT *
              FROM contacts
              WHERE documento = $1
              LIMIT 1
              `,
              [documento]
            );

            let contact = contactLookupResult.rows[0];

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

            if (!contact) {
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
              contact = insertContact.rows[0];
              newContacts += 1;
            } else {
              const updates = [];
              const values = [];
              let index = 1;

              function pushUpdate(column, value, allowOverwrite = false) {
                if (value === null || value === undefined || value === "") return;
                if (!allowOverwrite && contact[column] !== null && contact[column] !== undefined && String(contact[column]).trim() !== "") {
                  return;
                }
                updates.push(`${column} = $${index}`);
                values.push(value);
                index += 1;
              }

              pushUpdate("nombre", contactPayload.nombre, true);
              pushUpdate("apellido", contactPayload.apellido, true);
              pushUpdate("email", contactPayload.email, true);
              pushUpdate("telefono", contactPayload.telefono);
              pushUpdate("celular", contactPayload.celular);
              pushUpdate("documento", contactPayload.documento);
              pushUpdate("fecha_nacimiento", contactPayload.fecha_nacimiento);
              pushUpdate("direccion", contactPayload.direccion);
              pushUpdate("departamento", contactPayload.departamento);
              pushUpdate("pais", contactPayload.pais);

              if (updates.length > 0) {
                values.push(contact.id);
                await client.query(
                  `
                  UPDATE contacts
                  SET ${updates.join(", ")}, updated_at = now()
                  WHERE id = $${index}
                  `,
                  values
                );
              }
            }

            if (row.nombre_familiar || row.apellido_familiar || row.telefono_familiar || row.parentesco) {
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
                  row.nombre_familiar || "",
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
                    row.nombre_familiar || null,
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
                INSERT INTO sales (
                  contact_id,
                  seller_id,
                  fecha,
                  medio_pago,
                  seller_name_snapshot,
                  seller_origin
                )
                VALUES ($1, $2, $3, $4, $5, 'importado')
                RETURNING id
                `,
                [
                  contact.id,
                  null,
                  fechaVenta || new Date().toISOString().slice(0, 10),
                  row.medio_pago || null,
                  row.vendedor_nombre || null
                ]
              );
              saleId = saleInsert.rows[0].id;

              if (productId) {
                await client.query(
                  `
                  INSERT INTO sale_items (
                    sale_id,
                    product_id,
                    cantidad,
                    precio_unitario
                  )
                  VALUES ($1,$2,1,$3)
                  `,
                  [saleId, productId, precio || 0]
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

        return json(200, {
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
        });
      } finally {
        await client.end();
      }
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

