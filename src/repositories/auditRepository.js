import { query } from "../lib/db.js";

export async function insertRoleHistory(input, client) {
  await query(
    `INSERT INTO user_role_history (user_id, old_role, new_role, changed_by, changed_at, reason)
     VALUES ($1, $2, $3, $4, NOW(), $5)`,
    [input.userId, input.oldRole, input.newRole, input.changedBy, input.reason],
    client,
  );
}

export async function insertStatusHistory(input, client) {
  await query(
    `INSERT INTO user_status_history (user_id, old_status, new_status, changed_by, changed_at, reason)
     VALUES ($1, $2, $3, $4, NOW(), $5)`,
    [input.userId, input.oldStatus, input.newStatus, input.changedBy, input.reason],
    client,
  );
}