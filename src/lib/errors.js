export class AppError extends Error {
  constructor(statusCode, code, message, details = null) {
    super(message);
    this.name = "AppError";
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export function badRequest(message, details) {
  return new AppError(400, "BAD_REQUEST", message, details);
}

export function unauthorized(message = "Authentication is required") {
  return new AppError(401, "UNAUTHORIZED", message);
}

export function forbidden(message = "You do not have permission to perform this action") {
  return new AppError(403, "FORBIDDEN", message);
}

export function notFound(message = "Resource not found") {
  return new AppError(404, "NOT_FOUND", message);
}

export function conflict(message, details) {
  return new AppError(409, "CONFLICT", message, details);
}

export function unprocessable(message, details) {
  return new AppError(422, "UNPROCESSABLE_ENTITY", message, details);
}

export function internalError(message = "Internal server error") {
  return new AppError(500, "INTERNAL_ERROR", message);
}