import { AsyncLocalStorage } from "node:async_hooks";
import { AppError } from "./errors.js";

export const ALLOWED_ORIGINS = [
  "https://rednacrem.tri.uy",
  "https://globalassist.tri.uy",
  "https://callcenter.tri.uy",
];

// Solo se aceptan ademas de ALLOWED_ORIGINS cuando LOCAL_DEV_AUTH=true (el
// mismo flag que ya gatea el bypass de autenticacion local en index.mjs), asi
// que en produccion (donde esa env var nunca se setea) el comportamiento es
// identico al de antes: unicamente los 3 origenes de ALLOWED_ORIGINS.
const LOCAL_DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"];

// Pure helper: resolve a whitelisted CORS origin from the incoming request.
export function resolveAllowedOrigin(event) {
  const headers = event?.headers || {};
  const origin = headers.origin || headers.Origin || "";
  if (ALLOWED_ORIGINS.includes(origin)) return origin;
  if (process.env.LOCAL_DEV_AUTH === "true" && LOCAL_DEV_ORIGINS.includes(origin)) {
    return origin;
  }
  return ALLOWED_ORIGINS[0];
}

// AsyncLocalStorage: guarda el origin resuelto para el request en curso,
// aislado por cadena de ejecucion async (a diferencia de una variable mutable
// a nivel de modulo, no se pisa entre requests concurrentes en el mismo
// proceso — relevante en local-server.mjs, que si puede interlazar requests).
const corsOriginStore = new AsyncLocalStorage();

export function withCorsOrigin(event, fn) {
  return corsOriginStore.run(resolveAllowedOrigin(event), fn);
}

export function getCurrentCorsOrigin() {
  return corsOriginStore.getStore() || ALLOWED_ORIGINS[0];
}

export const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://rednacrem.tri.uy",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, x-file-name, x-filename, x-amz-date, x-api-key, x-amz-security-token, x-amz-user-agent",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
  "Access-Control-Expose-Headers": "Content-Disposition",
  "Access-Control-Allow-Credentials": "true",
};

function buildCorsHeaders(event) {
  const headers = event?.headers || {};
  const origin =
    headers.origin ||
    headers.Origin ||
    CORS_HEADERS["Access-Control-Allow-Origin"];
  const requestHeaders =
    headers["access-control-request-headers"] ||
    headers["Access-Control-Request-Headers"] ||
    "";

  const allowHeaders = requestHeaders
    ? `${requestHeaders}, ${CORS_HEADERS["Access-Control-Allow-Headers"]}`
    : CORS_HEADERS["Access-Control-Allow-Headers"];

  return {
    ...CORS_HEADERS,
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": allowHeaders,
    Vary: "Origin",
  };
}

function baseResponse(statusCode, payload) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...CORS_HEADERS,
    },
    body: JSON.stringify(payload, null, 2),
  };
}

export function handleOptions(event) {
  return {
    statusCode: 200,
    headers: buildCorsHeaders(event),
    body: "",
  };
}

export function success(statusCode, data, meta) {
  return baseResponse(statusCode, {
    success: true,
    data,
    ...(meta ? { meta } : {}),
  });
}

export function failure(statusCode, error) {
  return baseResponse(statusCode, {
    success: false,
    error,
  });
}

export function parseJsonBody(event) {
  if (!event.body) {
    return {};
  }

  try {
    return JSON.parse(event.body);
  } catch (error) {
    throw new AppError(400, "INVALID_JSON", "Request body must be valid JSON");
  }
}

export function getHeader(event, name) {
  const headers = event.headers || {};
  return headers[name] || headers[name.toLowerCase()] || headers[name.toUpperCase()] || null;
}

export function getQueryParams(event) {
  return event.queryStringParameters || {};
}

export function getPath(event) {
  return event.rawPath || event.path || event.requestContext?.http?.path || "";
}

export function getMethod(event) {
  return event.requestContext?.http?.method || event.httpMethod || "";
}

export function normalizeError(error) {
  if (error instanceof AppError) {
    return failure(error.statusCode, {
      code: error.code,
      message: error.message,
      ...(error.details ? { details: error.details } : {}),
    });
  }

  console.error("Unhandled error", error);

  return failure(500, {
    code: "INTERNAL_ERROR",
    message: "Internal server error",
  });
}
