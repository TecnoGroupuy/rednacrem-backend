import { query } from "../lib/db.js";

function mapUser(row) {
  return row
    ? {
        id: row.id,
        cognito_sub: row.cognito_sub,
        email: row.email,
        nombre: row.nombre,
        apellido: row.apellido,
        telefono: row.telefono,
        role_key: row.role_key,
        status: row.status,
        created_by: row.created_by,
        approved_by: row.approved_by,
        approved_at: row.approved_at,
        rejected_by: row.rejected_by,
        rejected_at: row.rejected_at,
        rejection_reason: row.rejection_reason,
        last_login_at: row.last_login_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
      }
    : null;
}

export async function findUserById(id, client = null) {
  const result = await query("SELECT * FROM users WHERE id = $1", [id], client);
  return mapUser(result.rows[0]);
}

export async function findUserByEmail(email, client = null) {
  const result = await query("SELECT * FROM users WHERE email = $1", [email], client);
  return mapUser(result.rows[0]);
}

export async function findUserByCognitoSub(cognitoSub, client = null) {
  const result = await query("SELECT * FROM users WHERE cognito_sub = $1", [cognitoSub], client);
  return mapUser(result.rows[0]);
}

export async function insertUser(input, client) {
  const result = await query(
    `INSERT INTO users (
      cognito_sub, email, nombre, apellido, telefono, role_key, status,
      created_by, approved_by, approved_at, rejected_by, rejected_at, rejection_reason, last_login_at
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7,
      $8, $9, $10, $11, $12, $13, $14
    ) RETURNING *`,
    [
      input.cognitoSub,
      input.email,
      input.nombre,
      input.apellido,
      input.telefono,
      input.roleKey,
      input.status,
      input.createdBy,
      input.approvedBy,
      input.approvedAt,
      input.rejectedBy,
      input.rejectedAt,
      input.rejectionReason,
      input.lastLoginAt,
    ],
    client,
  );

  return mapUser(result.rows[0]);
}

export async function updateLastLogin(userId, client = null) {
  await query("UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1", [userId], client);
}

export async function updateUserById(userId, fields, client) {
  const updates = [];
  const values = [];
  let index = 1;

  for (const [column, value] of Object.entries(fields)) {
    updates.push(`${column} = $${index}`);
    values.push(value);
    index += 1;
  }

  updates.push(`updated_at = NOW()`);
  values.push(userId);

  const result = await query(`UPDATE users SET ${updates.join(", ")} WHERE id = $${index} RETURNING *`, values, client);
  return mapUser(result.rows[0]);
}

export async function listUsers(filters = {}, client = null) {
  const clauses = [];
  const values = [];

  if (filters.role) {
    values.push(filters.role);
    clauses.push(`role_key = $${values.length}`);
  }

  if (filters.status) {
    values.push(filters.status);
    clauses.push(`status = $${values.length}`);
  }

  if (filters.search) {
    values.push(`%${filters.search}%`);
    clauses.push(`(email ILIKE $${values.length} OR nombre ILIKE $${values.length} OR apellido ILIKE $${values.length})`);
  }

  const whereClause = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const result = await query(`SELECT * FROM users ${whereClause} ORDER BY created_at DESC LIMIT 200`, values, client);
  return result.rows.map(mapUser);
}