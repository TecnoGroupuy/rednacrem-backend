import { query } from "../lib/db.js";

function mapRequest(row) {
  return row
    ? {
        id: row.id,
        nombre: row.nombre,
        apellido: row.apellido,
        email: row.email,
        telefono: row.telefono,
        status: row.status,
        reviewed_by: row.reviewed_by,
        reviewed_at: row.reviewed_at,
        review_notes: row.review_notes,
        user_id: row.user_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
      }
    : null;
}

export async function findRequestById(id, client = null, forUpdate = false) {
  const suffix = forUpdate ? " FOR UPDATE" : "";
  const result = await query(`SELECT * FROM vendor_registration_requests WHERE id = $1${suffix}`, [id], client);
  return mapRequest(result.rows[0]);
}

export async function findPendingRequestByEmail(email, client = null) {
  const result = await query(
    "SELECT * FROM vendor_registration_requests WHERE email = $1 AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
    [email],
    client,
  );
  return mapRequest(result.rows[0]);
}

export async function createRequest(input, client) {
  const result = await query(
    `INSERT INTO vendor_registration_requests (nombre, apellido, email, telefono, status)
     VALUES ($1, $2, $3, $4, 'pending')
     RETURNING *`,
    [input.nombre, input.apellido, input.email, input.telefono],
    client,
  );

  return mapRequest(result.rows[0]);
}

export async function updateRequestById(id, fields, client) {
  const updates = [];
  const values = [];
  let index = 1;

  for (const [column, value] of Object.entries(fields)) {
    updates.push(`${column} = $${index}`);
    values.push(value);
    index += 1;
  }

  updates.push("updated_at = NOW()");
  values.push(id);

  const result = await query(`UPDATE vendor_registration_requests SET ${updates.join(", ")} WHERE id = $${index} RETURNING *`, values, client);
  return mapRequest(result.rows[0]);
}

export async function listRequests(filters = {}, client = null) {
  const clauses = [];
  const values = [];

  if (filters.status) {
    values.push(filters.status);
    clauses.push(`status = $${values.length}`);
  }

  const whereClause = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const result = await query(
    `SELECT * FROM vendor_registration_requests ${whereClause} ORDER BY created_at ASC LIMIT 200`,
    values,
    client,
  );

  return result.rows.map(mapRequest);
}