import { Client } from "pg";
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminAddUserToGroupCommand
} from "@aws-sdk/client-cognito-identity-provider";

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

const cognitoClient = new CognitoIdentityProviderClient({
  region: process.env.AWS_REGION
});

function corsHeaders(event) {
  const origin =
    event?.headers?.origin ||
    event?.headers?.Origin ||
    "https://rednacrem.tri.uy";

  return {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "authorization,content-type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  };
}

function json(event, statusCode, payload) {
  return {
    statusCode,
    headers: corsHeaders(event),
    body: JSON.stringify(payload)
  };
}

function empty(event, statusCode = 204) {
  return {
    statusCode,
    headers: corsHeaders(event),
    body: ""
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

    const result = await client.query(
      `
      SELECT
        id,
        cognito_sub,
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
      WHERE cognito_sub = $1
      LIMIT 1
      `,
      [cognitoSub]
    );

    return result.rows[0] || null;
  } finally {
    await client.end();
  }
}

async function getCurrentDbUserFromEvent(event) {
  const authUser = getAuthUser(event);

  if (!authUser || !authUser.sub) {
    return { authUser, dbUser: null };
  }

  const dbUser = await getUserByCognitoSub(authUser.sub);
  return { authUser, dbUser };
}

function requireAuthenticated(event, authUser) {
  if (!authUser) {
    return json(event, 401, {
      ok: false,
      message: "Authorization header is required"
    });
  }

  if (!authUser.sub) {
    return json(event, 401, {
      ok: false,
      message: "JWT claims with sub are required"
    });
  }

  return null;
}

function requireDbUser(event, dbUser) {
  if (!dbUser) {
    return json(event, 404, {
      ok: false,
      message: "User not found in database"
    });
  }

  return null;
}

function requireApproved(event, dbUser) {
  if (!dbUser || dbUser.status !== "approved") {
    return json(event, 403, {
      ok: false,
      message: "User is not approved"
    });
  }

  return null;
}

function requireRole(event, dbUser, allowedRoles) {
  if (!dbUser || !allowedRoles.includes(dbUser.role_key)) {
    return json(event, 403, {
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

    const insertedUser = await client.query(
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
      RETURNING id, email, nombre, apellido, telefono, role_key, status
      `,
      [
        requestRow.email,
        requestRow.nombre,
        requestRow.apellido,
        requestRow.telefono,
        reviewerUserId
      ]
    );

    const newUser = insertedUser.rows[0];

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

  if (method === "OPTIONS") {
    return empty(event, 204);
  }

  if (method === "GET" && path.endsWith("/health")) {
    return json(event, 200, {
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

      return json(event, 200, {
        ok: true,
        database: "connected",
        serverTime: result.server_time,
        path,
        method
      });
    } catch (error) {
      return json(event, 500, {
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
      return json(event, 401, {
        ok: false,
        message: "Authorization header is required"
      });
    }

    if (!authUser.sub) {
      return json(event, 401, {
        ok: false,
        message: "JWT claims with sub are required"
      });
    }

    try {
      const dbUser = await getUserByCognitoSub(authUser.sub);

      if (!dbUser) {
        return json(event, 404, {
          ok: false,
          message: "User not found in database",
          cognitoSub: authUser.sub,
          email: authUser.email
        });
      }

      return json(event, 200, {
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
      return json(event, 500, {
        ok: false,
        message: "Failed to load user from database",
        error: error.message
      });
    }
  }

  if (method === "POST" && path.endsWith("/auth/vendor-registration-request")) {
    const body = safeParseBody(event);

    if (body === null) {
      return json(event, 400, {
        ok: false,
        message: "Invalid JSON body"
      });
    }

    const validation = validateVendorRegistrationPayload(body);

    if (!validation.valid) {
      return json(event, 422, {
        ok: false,
        message: "Validation failed",
        errors: validation.errors
      });
    }

    try {
      const result = await createVendorRegistrationRequest(validation.data);

      if (result.conflict) {
        return json(event, 409, {
          ok: false,
          message: result.message
        });
      }

      return json(event, 201, {
        ok: true,
        message: "Tu solicitud fue enviada. Un supervisor debe aprobarla.",
        request: result.request
      });
    } catch (error) {
      return json(event, 500, {
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

      return json(event, 200, {
        ok: true,
        requests
      });
    } catch (error) {
      return json(event, 500, {
        ok: false,
        message: "Failed to list vendor requests",
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
        return json(event, 404, {
          ok: false,
          message: "Solicitud no encontrada"
        });
      }

      if (result.invalidState) {
        return json(event, 409, {
          ok: false,
          message: result.message
        });
      }

      if (result.conflict) {
        return json(event, 409, {
          ok: false,
          message: result.message
        });
      }

      return json(event, 200, {
        ok: true,
        message: "Solicitud aprobada correctamente",
        user: result.user
      });
    } catch (error) {
      return json(event, 500, {
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
      return json(event, 400, {
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
        return json(event, 404, {
          ok: false,
          message: "Solicitud no encontrada"
        });
      }

      if (result.invalidState) {
        return json(event, 409, {
          ok: false,
          message: result.message
        });
      }

      return json(event, 200, {
        ok: true,
        message: "Solicitud rechazada correctamente",
        request: result.request
      });
    } catch (error) {
      return json(event, 500, {
        ok: false,
        message: "Failed to reject vendor request",
        error: error.message
      });
    }
  }

  return json(event, 404, {
    ok: false,
    message: "Route not found",
    path,
    method
  });
};
