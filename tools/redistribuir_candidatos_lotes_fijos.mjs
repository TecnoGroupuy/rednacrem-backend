#!/usr/bin/env node
// Migración de datos, de una sola vez, para todas las organizaciones:
// mueve a los lotes fijos de Recupero ("Prioritario — 0 a 3 meses" /
// "General de recupero") todos los candidatos de recupero_candidatos que
// todavía se les puede dar gestión (resultado_gestion NOT IN ('venta',
// 'rechazo', 'dato_erroneo')) y que hoy están en un lote viejo (ad-hoc, de
// importación CSV) o sin lote (dataset_id NULL — el hueco de
// aplicarBajaContactProduct ya documentado en esta sesión).
//
// Los candidatos en estado terminal (venta/rechazo/dato_erroneo) NO se
// tocan — quedan en su lote/campaña original para mantener el reporte
// histórico intacto.
//
// Para los que sí se mueven: se reasigna dataset_id + un row_number nuevo
// dentro del lote destino (mismo criterio que POST .../direct-assignments),
// pero NO se toca seller_id, estado, ni resultado_gestion — un candidato
// en_gestion sigue en_gestion, con el mismo vendedor, solo cambia de lote.
//
// Destino: fecha_baja dentro de los últimos 3 meses -> Prioritario;
// si no (o fecha_baja NULL) -> General de recupero.
//
// Uso:
//   MODE=report node tools/redistribuir_candidatos_lotes_fijos.mjs   (default, solo lectura)
//   MODE=apply DRY_RUN=true node tools/redistribuir_candidatos_lotes_fijos.mjs   (corre el UPDATE dentro de una transacción y hace ROLLBACK — para ver el resultado exacto sin aplicarlo)
//   MODE=apply DRY_RUN=false node tools/redistribuir_candidatos_lotes_fijos.mjs  (aplica de verdad — COMMIT)
//
// Variables de conexión: PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE/PGSSL,
// igual que tools/fix_product_encoding.mjs — apuntar a producción o a local
// seteando esas variables antes de correr el script, no hay nada hardcodeado.
import pg from "pg";
import crypto from "crypto";

const { Client } = pg;

const TERMINAL_RESULTADOS = ["venta", "rechazo", "dato_erroneo"];
const FIXED_DATASET_NAMES = {
  prioritario: "Prioritario — 0 a 3 meses",
  general: "General de recupero"
};

function parsePgSsl() {
  const raw = (process.env.PGSSL ?? "").toLowerCase().trim();
  if (raw === "" || raw === "false" || raw === "0" || raw === "no") return false;
  if (raw === "true" || raw === "1" || raw === "yes") return { rejectUnauthorized: false };
  return false;
}

async function ensureFixedDatasetsForOrg(client, organizationId) {
  const existingRes = await client.query(
    `
    SELECT dataset_name
    FROM recupero_import_jobs
    WHERE organization_id = $1
      AND is_system_dataset = true
      AND dataset_name = ANY($2::text[])
    `,
    [organizationId, Object.values(FIXED_DATASET_NAMES)]
  );
  const existingNames = new Set(existingRes.rows.map((row) => row.dataset_name));
  const missingNames = Object.values(FIXED_DATASET_NAMES).filter((name) => !existingNames.has(name));
  for (const datasetName of missingNames) {
    const fileHash = crypto
      .createHash("sha256")
      .update(`system-dataset:${organizationId}:${datasetName}`)
      .digest("hex");
    try {
      await client.query(
        `
        INSERT INTO recupero_import_jobs (
          file_name, file_hash, status, total_rows, processed_rows, updated_rows,
          error_rows, duplicate_rows, invalid_rows, not_found_rows, csv_text,
          organization_id, dataset_name, dataset_source, dataset_status,
          goal, max_attempts, is_system_dataset, started_at, finished_at
        )
        VALUES (
          $1, $2, 'done', 0, 0, 0, 0, 0, 0, 0, '',
          $3, $4, 'clientes.bajas', 'activo',
          0, '{"calls": 3, "whatsapp": 1}'::jsonb, true, NOW(), NOW()
        )
        `,
        [datasetName, fileHash, organizationId, datasetName]
      );
      console.log(`  + creado "${datasetName}" para organización ${organizationId} (no existía)`);
    } catch (error) {
      if (error?.code !== "23505") throw error; // otro proceso ya lo creó, ok
    }
  }
}

async function main() {
  const mode = (process.env.MODE ?? "report").toLowerCase().trim();
  const dryRun = (process.env.DRY_RUN ?? "true").toLowerCase().trim() !== "false";

  const client = new Client({
    host: process.env.PGHOST ?? "localhost",
    port: Number.parseInt(process.env.PGPORT ?? "5432", 10),
    user: process.env.PGUSER ?? "postgres",
    password: process.env.PGPASSWORD ?? "",
    database: process.env.PGDATABASE ?? "postgres",
    ssl: parsePgSsl()
  });
  await client.connect();

  try {
    // 1) Reporte de elegibilidad — SIEMPRE se corre, en report y en apply,
    // para que quede impreso el volumen exacto justo antes de tocar nada.
    const reportRes = await client.query(
      `
      SELECT
        rc.organization_id,
        COUNT(*) FILTER (
          WHERE rc.fecha_baja IS NOT NULL AND rc.fecha_baja >= (CURRENT_DATE - INTERVAL '3 months')
        )::int AS a_prioritario,
        COUNT(*) FILTER (
          WHERE rc.fecha_baja IS NULL OR rc.fecha_baja < (CURRENT_DATE - INTERVAL '3 months')
        )::int AS a_general,
        COUNT(*) FILTER (WHERE rc.estado = 'disponible')::int AS disponibles,
        COUNT(*) FILTER (WHERE rc.estado = 'en_gestion')::int AS en_gestion,
        COUNT(*) FILTER (WHERE rc.dataset_id IS NULL)::int AS sin_dataset,
        COUNT(*)::int AS total_elegibles
      FROM recupero_candidatos rc
      LEFT JOIN recupero_import_jobs rij ON rij.id = rc.dataset_id
      WHERE rc.resultado_gestion NOT IN (${TERMINAL_RESULTADOS.map((_, i) => `$${i + 1}`).join(", ")})
        AND COALESCE(rij.is_system_dataset, false) = false
      GROUP BY rc.organization_id
      ORDER BY rc.organization_id
      `,
      TERMINAL_RESULTADOS
    );

    console.log("=== Reporte de elegibilidad (SELECT COUNT, no toca nada) ===");
    if (!reportRes.rows.length) {
      console.log("Ningún candidato elegible en ninguna organización — nada para migrar.");
    }
    let grandTotal = 0;
    for (const row of reportRes.rows) {
      grandTotal += row.total_elegibles;
      console.log(
        `org ${row.organization_id}: ${row.total_elegibles} elegibles ` +
        `(${row.a_prioritario} -> Prioritario, ${row.a_general} -> General; ` +
        `${row.disponibles} disponibles, ${row.en_gestion} en_gestion, ${row.sin_dataset} sin dataset)`
      );
    }
    console.log(`TOTAL across todas las organizaciones: ${grandTotal}`);

    if (mode !== "apply") {
      console.log('\nMODE=report (default) — no se tocó nada. Correr con MODE=apply para ejecutar.');
      return;
    }

    // 2) Asegurar que los 2 lotes fijos existan para cada organización con
    // candidatos elegibles — normalmente ya existen (Parte 1 de esta tarea
    // corre en cada GET /recovery/datasets), esto es solo una red de
    // seguridad para que ningún candidato quede sin destino por una
    // organización que todavía no abrió la pestaña Lotes de Recupero.
    console.log("\n=== Verificando/creando los 2 lotes fijos por organización ===");
    for (const row of reportRes.rows) {
      await ensureFixedDatasetsForOrg(client, row.organization_id);
    }

    // 3) La migración real — todas las organizaciones en una sola sentencia,
    // usando ROW_NUMBER() OVER (PARTITION BY dataset destino) para continuar
    // la numeración de fila desde el máximo ya existente en cada lote fijo
    // (mismo patrón que la migración 059 usó para su backfill de dataset_id).
    console.log(`\n=== Aplicando (DRY_RUN=${dryRun}) ===`);
    await client.query("BEGIN");
    try {
      const updateRes = await client.query(
        `
        WITH target_datasets AS (
          SELECT organization_id, dataset_name, id AS dataset_id
          FROM recupero_import_jobs
          WHERE is_system_dataset = true
            AND dataset_name = ANY($1::text[])
        ),
        eligible AS (
          SELECT
            rc.id,
            rc.organization_id,
            CASE
              WHEN rc.fecha_baja IS NOT NULL AND rc.fecha_baja >= (CURRENT_DATE - INTERVAL '3 months')
                THEN $2::text
              ELSE $3::text
            END AS target_name,
            rc.fecha_baja,
            rc.created_at
          FROM recupero_candidatos rc
          LEFT JOIN recupero_import_jobs rij ON rij.id = rc.dataset_id
          WHERE rc.resultado_gestion NOT IN (${TERMINAL_RESULTADOS.map((_, i) => `$${i + 4}`).join(", ")})
            AND COALESCE(rij.is_system_dataset, false) = false
        ),
        eligible_with_target AS (
          SELECT
            e.id,
            e.organization_id,
            td.dataset_id AS target_dataset_id,
            e.fecha_baja,
            e.created_at
          FROM eligible e
          JOIN target_datasets td
            ON td.organization_id = e.organization_id
           AND td.dataset_name = e.target_name
        ),
        existing_max AS (
          SELECT dataset_id, COALESCE(MAX(row_number), 0) AS max_row
          FROM recupero_candidatos
          WHERE dataset_id IN (SELECT dataset_id FROM target_datasets)
          GROUP BY dataset_id
        ),
        ranked AS (
          SELECT
            ewt.id,
            ewt.target_dataset_id,
            COALESCE(em.max_row, 0) + ROW_NUMBER() OVER (
              PARTITION BY ewt.target_dataset_id
              ORDER BY ewt.fecha_baja ASC NULLS LAST, ewt.created_at ASC
            ) AS new_row_number
          FROM eligible_with_target ewt
          LEFT JOIN existing_max em ON em.dataset_id = ewt.target_dataset_id
        )
        UPDATE recupero_candidatos rc
        SET dataset_id = ranked.target_dataset_id,
            row_number = ranked.new_row_number,
            updated_at = NOW()
        FROM ranked
        WHERE rc.id = ranked.id
        RETURNING rc.id, rc.organization_id, rc.dataset_id, ranked.new_row_number
        `,
        [Object.values(FIXED_DATASET_NAMES), FIXED_DATASET_NAMES.prioritario, FIXED_DATASET_NAMES.general, ...TERMINAL_RESULTADOS]
      );

      console.log(`Filas movidas: ${updateRes.rowCount}`);

      // Chequeo de integridad: candidatos que la query de elegibilidad
      // detectó pero que NO aparecen en el UPDATE (organización sin match
      // en target_datasets después del paso 2 — no debería pasar nunca,
      // pero si pasa hay que frenar y avisar, no seguir en silencio).
      const missedCheck = await client.query(
        `
        SELECT COUNT(*)::int AS missed
        FROM recupero_candidatos rc
        LEFT JOIN recupero_import_jobs rij ON rij.id = rc.dataset_id
        WHERE rc.resultado_gestion NOT IN (${TERMINAL_RESULTADOS.map((_, i) => `$${i + 1}`).join(", ")})
          AND COALESCE(rij.is_system_dataset, false) = false
        `,
        TERMINAL_RESULTADOS
      );
      const missed = missedCheck.rows[0]?.missed || 0;
      if (missed > 0) {
        throw new Error(
          `Integridad: quedaron ${missed} candidatos elegibles sin mover después del UPDATE ` +
          `(alguna organización sin lotes fijos creados). Revisar antes de confirmar.`
        );
      }

      // Actualizar total_rows de los datasets fijos tocados, para que
      // GET /recovery/datasets muestre un conteo consistente con row_number.
      const affectedDatasetIds = [...new Set(updateRes.rows.map((r) => r.dataset_id))];
      for (const datasetId of affectedDatasetIds) {
        await client.query(
          `
          UPDATE recupero_import_jobs
          SET total_rows = GREATEST(total_rows, (SELECT COALESCE(MAX(row_number), 0) FROM recupero_candidatos WHERE dataset_id = $1)),
              updated_at = NOW()
          WHERE id = $1
          `,
          [datasetId]
        );
      }
      console.log(`Datasets fijos con total_rows actualizado: ${affectedDatasetIds.length}`);

      if (dryRun) {
        console.log("\nDRY_RUN=true -> ROLLBACK (nada quedó aplicado)");
        await client.query("ROLLBACK");
      } else {
        console.log("\nDRY_RUN=false -> COMMIT (aplicado de verdad)");
        await client.query("COMMIT");
      }
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  } finally {
    await client.end();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
