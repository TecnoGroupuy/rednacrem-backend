import { CognitoJwtVerifier } from "aws-jwt-verify";
import { config, requireEnv } from "./config.js";
import { getHeader } from "./http.js";
import { forbidden, unauthorized } from "./errors.js";
import { findCurrentUserFromClaims } from "../services/userService.js";

let accessTokenVerifier;
let idTokenVerifier;

function getAccessTokenVerifier() {
  if (!accessTokenVerifier) {
    accessTokenVerifier = CognitoJwtVerifier.create({
      userPoolId: requireEnv("COGNITO_USER_POOL_ID", config.cognitoUserPoolId),
      tokenUse: "access",
      clientId: config.cognitoClientId || undefined,
    });
  }

  return accessTokenVerifier;
}

function getIdTokenVerifier() {
  if (!idTokenVerifier) {
    idTokenVerifier = CognitoJwtVerifier.create({
      userPoolId: requireEnv("COGNITO_USER_POOL_ID", config.cognitoUserPoolId),
      tokenUse: "id",
      clientId: config.cognitoClientId || undefined,
    });
  }

  return idTokenVerifier;
}

export async function requireAuth(event) {
  const authorization = getHeader(event, "Authorization");

  if (!authorization || !authorization.startsWith("Bearer ")) {
    throw unauthorized("Bearer token is required");
  }

  const token = authorization.slice("Bearer ".length).trim();

  if (!token) {
    throw unauthorized("Bearer token is required");
  }

  try {
    return await getAccessTokenVerifier().verify(token);
  } catch (accessError) {
    try {
      return await getIdTokenVerifier().verify(token);
    } catch (idError) {
      throw unauthorized("Invalid or expired token");
    }
  }
}

export async function loadCurrentUser(event) {
  const claims = await requireAuth(event);
  const user = await findCurrentUserFromClaims(claims);

  if (!user) {
    throw forbidden("Authenticated user is not registered in the application database");
  }

  return { claims, user };
}

export async function requireApprovedUser(event) {
  const context = await loadCurrentUser(event);

  if (context.user.status !== "approved") {
    throw forbidden(`User status ${context.user.status} is not allowed for this operation`);
  }

  return context;
}

export async function requireRole(event, allowedRoles, options = {}) {
  const context = options.allowNonApproved ? await loadCurrentUser(event) : await requireApprovedUser(event);

  if (!allowedRoles.includes(context.user.role_key)) {
    throw forbidden(`Role ${context.user.role_key} is not allowed for this operation`);
  }

  return context;
}
