import { withTransaction } from "../lib/db.js";
import { conflict, forbidden, notFound } from "../lib/errors.js";
import { isValidRole, isValidUserStatus } from "../lib/constants.js";
import {
  findUserByCognitoSub,
  findUserByEmail,
  findUserById,
  insertUser,
  listUsers as listUsersRepo,
  updateLastLogin,
  updateUserById,
} from "../repositories/userRepository.js";
import { insertRoleHistory, insertStatusHistory } from "../repositories/auditRepository.js";
import {
  createCognitoUser,
  deleteUser as deleteCognitoUser,
  disableUser,
  enableUser,
  extractCognitoSub,
  syncUserGroup,
} from "./cognitoService.js";

export async function findCurrentUserFromClaims(claims) {
  const sub = claims.sub || claims.username;
  const email = claims.email ? String(claims.email).toLowerCase() : null;

  if (sub) {
    const bySub = await findUserByCognitoSub(sub);
    if (bySub) {
      return bySub;
    }
  }

  if (email) {
    return findUserByEmail(email);
  }

  return null;
}

export async function getBusinessSession({ claims, user, touchLastLogin = true }) {
  if (touchLastLogin && user.status === "approved") {
    await updateLastLogin(user.id);
  }

  return {
    id: user.id,
    nombre: `${user.nombre} ${user.apellido}`.trim(),
    email: user.email,
    role: user.role_key,
    status: user.status,
    permissions: [],
    claims,
  };
}

export async function listUsers(filters) {
  return listUsersRepo(filters);
}

export async function createManualUser(input, actor) {
  if (!isValidRole(input.role)) {
    throw conflict("Invalid role");
  }

  if (!isValidUserStatus(input.status)) {
    throw conflict("Invalid status");
  }

  const existingUser = await findUserByEmail(input.email);
  if (existingUser) {
    throw conflict("A user with that email already exists");
  }

  let cognitoUser;

  try {
    cognitoUser = await createCognitoUser(input);
    await syncUserGroup(input.email, input.role);

    const cognitoSub = extractCognitoSub(cognitoUser);

    return await withTransaction(async (client) => {
      const user = await insertUser(
        {
          cognitoSub,
          email: input.email,
          nombre: input.nombre,
          apellido: input.apellido,
          telefono: input.telefono,
          roleKey: input.role,
          status: input.status,
          createdBy: actor.id,
          approvedBy: input.status === "approved" ? actor.id : null,
          approvedAt: input.status === "approved" ? new Date() : null,
          rejectedBy: input.status === "rejected" ? actor.id : null,
          rejectedAt: input.status === "rejected" ? new Date() : null,
          rejectionReason: input.status === "rejected" ? input.reason || "Rejected at creation" : null,
          lastLoginAt: null,
        },
        client,
      );

      await insertRoleHistory(
        {
          userId: user.id,
          oldRole: null,
          newRole: input.role,
          changedBy: actor.id,
          reason: input.reason || "Manual user creation",
        },
        client,
      );

      await insertStatusHistory(
        {
          userId: user.id,
          oldStatus: null,
          newStatus: input.status,
          changedBy: actor.id,
          reason: input.reason || "Manual user creation",
        },
        client,
      );

      if (input.status === "blocked" || input.status === "inactive") {
        await disableUser(input.email);
      }

      return user;
    });
  } catch (error) {
    if (cognitoUser) {
      await deleteCognitoUser(input.email).catch(() => {});
    }

    throw error;
  }
}

export async function updateUser(input, actor) {
  const existingUser = await findUserById(input.userId);
  if (!existingUser) {
    throw notFound("User not found");
  }

  if (existingUser.id === actor.id && ((input.role && input.role !== existingUser.role_key) || (input.status && input.status !== existingUser.status))) {
    throw forbidden("You cannot change your own role or status");
  }

  if (input.role && !isValidRole(input.role)) {
    throw conflict("Invalid role");
  }

  if (input.status && !isValidUserStatus(input.status)) {
    throw conflict("Invalid status");
  }

  const nextRole = input.role || existingUser.role_key;
  const nextStatus = input.status || existingUser.status;

  return withTransaction(async (client) => {
    if (nextRole !== existingUser.role_key) {
      await syncUserGroup(existingUser.email, nextRole);
    }

    if (existingUser.status !== nextStatus) {
      if (nextStatus === "approved") {
        await enableUser(existingUser.email);
      }

      if (["blocked", "inactive", "rejected"].includes(nextStatus)) {
        await disableUser(existingUser.email);
      }
    }

    const updatedUser = await updateUserById(
      existingUser.id,
      {
        ...(input.nombre !== undefined ? { nombre: input.nombre } : {}),
        ...(input.apellido !== undefined ? { apellido: input.apellido } : {}),
        ...(input.telefono !== undefined ? { telefono: input.telefono } : {}),
        ...(input.role ? { role_key: nextRole } : {}),
        ...(input.status ? { status: nextStatus } : {}),
        ...(input.status === "approved" ? { approved_by: actor.id, approved_at: new Date(), rejected_by: null, rejected_at: null, rejection_reason: null } : {}),
        ...(input.status === "rejected" ? { rejected_by: actor.id, rejected_at: new Date(), rejection_reason: input.reason || "Rejected by superadministrador" } : {}),
      },
      client,
    );

    if (nextRole !== existingUser.role_key) {
      await insertRoleHistory(
        {
          userId: existingUser.id,
          oldRole: existingUser.role_key,
          newRole: nextRole,
          changedBy: actor.id,
          reason: input.reason || "Manual role update",
        },
        client,
      );
    }

    if (nextStatus !== existingUser.status) {
      await insertStatusHistory(
        {
          userId: existingUser.id,
          oldStatus: existingUser.status,
          newStatus: nextStatus,
          changedBy: actor.id,
          reason: input.reason || "Manual status update",
        },
        client,
      );
    }

    return updatedUser;
  });
}
