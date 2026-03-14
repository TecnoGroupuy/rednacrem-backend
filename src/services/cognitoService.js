import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminDisableUserCommand,
  AdminEnableUserCommand,
  AdminListGroupsForUserCommand,
  AdminRemoveUserFromGroupCommand,
  ListUsersCommand,
  CognitoIdentityProviderClient,
} from "@aws-sdk/client-cognito-identity-provider";
import { config, requireEnv } from "../lib/config.js";
import { conflict } from "../lib/errors.js";
import { ROLE_KEYS } from "../lib/constants.js";

const client = new CognitoIdentityProviderClient({ region: config.awsRegion });

function getUserPoolId() {
  return requireEnv("COGNITO_USER_POOL_ID", config.cognitoUserPoolId);
}

export async function findCognitoUserByEmail(email) {
  const command = new ListUsersCommand({
    UserPoolId: getUserPoolId(),
    Filter: `email = \"${email}\"`,
    Limit: 1,
  });

  const result = await client.send(command);
  return result.Users?.[0] || null;
}

export async function createCognitoUser({ email, nombre, apellido, temporaryPassword }) {
  const existing = await findCognitoUserByEmail(email);
  if (existing) {
    throw conflict("A Cognito user with that email already exists");
  }

  const command = new AdminCreateUserCommand({
    UserPoolId: getUserPoolId(),
    Username: email,
    TemporaryPassword: temporaryPassword || config.cognitoDefaultPassword,
    DesiredDeliveryMediums: ["EMAIL"],
    UserAttributes: [
      { Name: "email", Value: email },
      { Name: "email_verified", Value: "true" },
      { Name: "name", Value: `${nombre} ${apellido}`.trim() },
      { Name: "given_name", Value: nombre },
      { Name: "family_name", Value: apellido },
    ],
  });

  const result = await client.send(command);
  return result.User;
}

export async function addUserToGroup(username, groupName) {
  await client.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: getUserPoolId(),
      Username: username,
      GroupName: groupName,
    }),
  );
}

export async function removeUserFromGroup(username, groupName) {
  await client.send(
    new AdminRemoveUserFromGroupCommand({
      UserPoolId: getUserPoolId(),
      Username: username,
      GroupName: groupName,
    }),
  );
}

export async function listUserGroups(username) {
  const result = await client.send(
    new AdminListGroupsForUserCommand({
      UserPoolId: getUserPoolId(),
      Username: username,
    }),
  );

  return (result.Groups || []).map((group) => group.GroupName);
}

export async function syncUserGroup(username, desiredRole) {
  if (!ROLE_KEYS.includes(desiredRole)) {
    throw conflict(`Invalid Cognito group ${desiredRole}`);
  }

  const currentGroups = await listUserGroups(username);

  for (const group of currentGroups) {
    if (ROLE_KEYS.includes(group) && group !== desiredRole) {
      await removeUserFromGroup(username, group);
    }
  }

  if (!currentGroups.includes(desiredRole)) {
    await addUserToGroup(username, desiredRole);
  }
}

export async function disableUser(username) {
  await client.send(new AdminDisableUserCommand({ UserPoolId: getUserPoolId(), Username: username }));
}

export async function enableUser(username) {
  await client.send(new AdminEnableUserCommand({ UserPoolId: getUserPoolId(), Username: username }));
}

export async function deleteUser(username) {
  await client.send(new AdminDeleteUserCommand({ UserPoolId: getUserPoolId(), Username: username }));
}

export function extractCognitoSub(cognitoUser) {
  return cognitoUser?.Attributes?.find((attribute) => attribute.Name === "sub")?.Value || null;
}