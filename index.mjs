import { Client } from "pg";
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminAddUserToGroupCommand,
  ListUsersCommand
} from "@aws-sdk/client-cognito-identity-provider";
import { AppError } from "./src/lib/errors.js";
import { normalizePhone } from "./src/lib/validation.js";
import { createManualUser, updateUser } from "./src/services/userService.js";

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
  "atencion_cliente"
];

const cognitoClient = new CognitoIdentityProviderClient({
  region: process.env.AWS_REGION
});

function json(statusCode, payload) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8"
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

function getPathSegments(path) {
  return path.split("/").filter(Boolean);
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
  const claims = event.requestContext?.authorizer?.jwt?.claims;

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

  const dbUser = await getUserByAuthUser(authUser);
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
  const path = getPath(event);
  const method = getMethod(event);
  const segments = getPathSegments(path);

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

  if (
    method === "POST" &&
    segments.length >= 4 &&
    segments[0] === "supervisor" &&
    segments[1] === "vendor-requests" &&
    segments[3] === "approve"
  ) {
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

      const requestId = segments[2];
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

  if (
    method === "POST" &&
    segments.length >= 4 &&
    segments[0] === "supervisor" &&
    segments[1] === "vendor-requests" &&
    segments[3] === "reject"
  ) {
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

      const requestId = segments[2];
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
