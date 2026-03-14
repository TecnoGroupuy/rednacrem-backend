import { withTransaction } from "../lib/db.js";
import { conflict, notFound } from "../lib/errors.js";
import { isValidRegistrationStatus } from "../lib/constants.js";
import { normalizeEmail, normalizePhone, requiredEmail, requiredString, optionalString } from "../lib/validation.js";
import {
  createRequest,
  findPendingRequestByEmail,
  findRequestById,
  listRequests as listRequestsRepo,
  updateRequestById,
} from "../repositories/registrationRepository.js";
import { findUserByEmail, insertUser } from "../repositories/userRepository.js";
import { insertRoleHistory, insertStatusHistory } from "../repositories/auditRepository.js";
import { createCognitoUser, deleteUser as deleteCognitoUser, extractCognitoSub, syncUserGroup } from "./cognitoService.js";

export async function createVendorRegistrationRequest(input) {
  const payload = {
    nombre: requiredString(input.nombre, "nombre", 120),
    apellido: requiredString(input.apellido, "apellido", 120),
    email: requiredEmail(input.email),
    telefono: normalizePhone(requiredString(input.telefono, "telefono", 40)),
  };

  const existingUser = await findUserByEmail(payload.email);
  if (existingUser) {
    throw conflict("A user with that email already exists");
  }

  const pendingRequest = await findPendingRequestByEmail(payload.email);
  if (pendingRequest) {
    throw conflict("There is already a pending registration request for that email");
  }

  return createRequest(payload);
}

export async function listRegistrationRequests(filters = {}) {
  if (filters.status && !isValidRegistrationStatus(filters.status)) {
    throw conflict("Invalid registration request status");
  }

  return listRequestsRepo(filters);
}

export async function approveRegistrationRequest(requestId, actor, reviewNotes) {
  let cognitoUser;

  try {
    return await withTransaction(async (client) => {
      const request = await findRequestById(requestId, client, true);
      if (!request) {
        throw notFound("Registration request not found");
      }

      if (request.status !== "pending") {
        throw conflict(`Registration request is already ${request.status}`);
      }

      const existingUser = await findUserByEmail(request.email, client);
      if (existingUser) {
        throw conflict("A user with that email already exists");
      }

      cognitoUser = await createCognitoUser({
        email: request.email,
        nombre: request.nombre,
        apellido: request.apellido,
      });
      await syncUserGroup(request.email, "vendedor");

      const user = await insertUser(
        {
          cognitoSub: extractCognitoSub(cognitoUser),
          email: request.email,
          nombre: request.nombre,
          apellido: request.apellido,
          telefono: request.telefono,
          roleKey: "vendedor",
          status: "approved",
          createdBy: actor.id,
          approvedBy: actor.id,
          approvedAt: new Date(),
          rejectedBy: null,
          rejectedAt: null,
          rejectionReason: null,
          lastLoginAt: null,
        },
        client,
      );

      const updatedRequest = await updateRequestById(
        request.id,
        {
          status: "approved",
          reviewed_by: actor.id,
          reviewed_at: new Date(),
          review_notes: optionalString(reviewNotes, 500),
          user_id: user.id,
        },
        client,
      );

      await insertRoleHistory(
        {
          userId: user.id,
          oldRole: null,
          newRole: "vendedor",
          changedBy: actor.id,
          reason: "Vendor registration approval",
        },
        client,
      );

      await insertStatusHistory(
        {
          userId: user.id,
          oldStatus: null,
          newStatus: "approved",
          changedBy: actor.id,
          reason: "Vendor registration approval",
        },
        client,
      );

      return { request: updatedRequest, user };
    });
  } catch (error) {
    if (cognitoUser) {
      await deleteCognitoUser(cognitoUser.Username).catch(() => {});
    }

    throw error;
  }
}

export async function rejectRegistrationRequest(requestId, actor, reviewNotes) {
  return withTransaction(async (client) => {
    const request = await findRequestById(requestId, client, true);
    if (!request) {
      throw notFound("Registration request not found");
    }

    if (request.status !== "pending") {
      throw conflict(`Registration request is already ${request.status}`);
    }

    return updateRequestById(
      request.id,
      {
        status: "rejected",
        reviewed_by: actor.id,
        reviewed_at: new Date(),
        review_notes: optionalString(reviewNotes, 500),
      },
      client,
    );
  });
}