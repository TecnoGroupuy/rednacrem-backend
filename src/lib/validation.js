import { badRequest } from "./errors.js";

export function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export function normalizePhone(phone) {
  return String(phone || "").trim();
}

export function requiredString(value, field, maxLength = 255) {
  const normalized = String(value || "").trim();

  if (!normalized) {
    throw badRequest(`${field} is required`);
  }

  if (normalized.length > maxLength) {
    throw badRequest(`${field} exceeds the maximum length of ${maxLength}`);
  }

  return normalized;
}

export function optionalString(value, maxLength = 255) {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = String(value).trim();
  if (!normalized) {
    return null;
  }

  if (normalized.length > maxLength) {
    throw badRequest(`Field exceeds the maximum length of ${maxLength}`);
  }

  return normalized;
}

export function requiredEmail(email) {
  const normalized = normalizeEmail(email);
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailRegex.test(normalized)) {
    throw badRequest("A valid email is required");
  }

  return normalized;
}