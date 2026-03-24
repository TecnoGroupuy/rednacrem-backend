import { AppError } from "./errors.js";

export const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://rednacrem.tri.uy",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, x-file-name, x-filename, x-amz-date, x-api-key",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
};

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

export function handleOptions() {
  return {
    statusCode: 200,
    headers: CORS_HEADERS,
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
