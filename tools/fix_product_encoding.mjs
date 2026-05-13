#!/usr/bin/env node
import pg from "pg";

const { Client } = pg;

function envInt(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) return fallback;
  return value;
}

function parsePgSsl() {
  const raw = (process.env.PGSSL ?? "").toLowerCase().trim();
  if (raw === "" || raw === "false" || raw === "0" || raw === "no") return false;
  if (raw === "true" || raw === "1" || raw === "yes") return { rejectUnauthorized: false };
  return false;
}

async function main() {
  const mode = (process.env.FIX_MODE ?? "report").toLowerCase().trim();
  const limit = envInt("FIX_LIMIT", 50);

  const client = new Client({
    host: process.env.PGHOST ?? "localhost",
    port: envInt("PGPORT", 5432),
    user: process.env.PGUSER ?? "postgres",
    password: process.env.PGPASSWORD ?? "",
    database: process.env.PGDATABASE ?? "postgres",
    ssl: parsePgSsl(),
  });

  await client.connect();

  async function columnExists(tableName, columnName) {
    const r = await client.query(
      `
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = $1
        AND column_name = $2
      LIMIT 1
      `,
      [tableName, columnName],
    );
    return r.rowCount > 0;
  }

  const patterns = [
    { label: "tiene '?'", sqlLike: "%?%" },
    // U+FFFD replacement character (common when decoding fails)
    { label: "tiene '�' (U+FFFD)", sqlLike: "%�%" },
    // Common UTF-8-as-Latin1 mojibake examples for Ó/ó/Ñ/ñ/Á/á/É/é/Í/í/Ú/ú
    { label: "tiene mojibake 'Ã'", sqlLike: "%Ã%" },
  ];

  const reportCounts = {};
  for (const p of patterns) {
    const r = await client.query(
      `SELECT COUNT(*)::int AS n FROM public.contact_products WHERE nombre_producto LIKE $1`,
      [p.sqlLike],
    );
    reportCounts[p.label] = r.rows[0].n;
  }

  console.log("contact_products - conteos de posibles strings rotos:");
  for (const [k, v] of Object.entries(reportCounts)) console.log(`- ${k}: ${v}`);

  const examples = await client.query(
    `SELECT DISTINCT nombre_producto
     FROM public.contact_products
     WHERE nombre_producto LIKE '%?%' OR nombre_producto LIKE '%�%' OR nombre_producto LIKE '%Ã%'
     ORDER BY nombre_producto
     LIMIT $1`,
    [limit],
  );
  if (examples.rows.length) {
    console.log(`\nEjemplos (hasta ${limit}):`);
    for (const row of examples.rows) console.log("-", row.nombre_producto);
  } else {
    console.log("\nNo se encontraron valores candidatos con esos patrones.");
  }

  if (mode !== "apply") {
    await client.end();
    return;
  }

  const dryRun = (process.env.FIX_DRY_RUN ?? "true").toLowerCase().trim() !== "false";

  // Replace only the known mojibake sequences; keep '?' replacement opt-in via env.
  const replaceQuestionMark = (process.env.FIX_REPLACE_QMARK ?? "false").toLowerCase().trim() === "true";

  await client.query("BEGIN");
  try {
    // Fix common mojibake sequences in contact_products.nombre_producto
    const updates = [
      ["Ã“", "Ó"],
      ["Ã³", "ó"],
      ["Ã‘", "Ñ"],
      ["Ã±", "ñ"],
      ["Ã\u0081", "Á"], // rarely seen but harmless
      ["Ã¡", "á"],
      ["Ã‰", "É"],
      ["Ã©", "é"],
      ["Ã\u008d", "Í"],
      ["Ã­", "í"],
      ["Ãš", "Ú"],
      ["Ãº", "ú"],
    ];

    let totalTouched = 0;
    for (const [from, to] of updates) {
      const r = await client.query(
        `UPDATE public.contact_products
         SET nombre_producto = REPLACE(nombre_producto, $1, $2)
         WHERE nombre_producto LIKE '%' || $1 || '%'
         RETURNING 1`,
        [from, to],
      );
      totalTouched += r.rowCount;
    }

    if (replaceQuestionMark) {
      const r = await client.query(
        `UPDATE public.contact_products
         SET nombre_producto = REPLACE(nombre_producto, '?', 'Ó')
         WHERE nombre_producto LIKE '%?%'
         RETURNING 1`,
      );
      totalTouched += r.rowCount;
    }

    // Same transformations for sales.product_snapshot (text)
    let totalSalesTouched = 0;
    const hasProductSnapshot = await columnExists("sales", "product_snapshot");
    if (!hasProductSnapshot) {
      console.log("\napply: sales.product_snapshot no existe -> se omite.");
    } else {
      for (const [from, to] of updates) {
        const r = await client.query(
          `UPDATE public.sales
           SET product_snapshot = REPLACE(product_snapshot, $1, $2)
           WHERE product_snapshot LIKE '%' || $1 || '%'
           RETURNING 1`,
          [from, to],
        );
        totalSalesTouched += r.rowCount;
      }
      if (replaceQuestionMark) {
        const r = await client.query(
          `UPDATE public.sales
           SET product_snapshot = REPLACE(product_snapshot, '?', 'Ó')
           WHERE product_snapshot LIKE '%?%'
           RETURNING 1`,
        );
        totalSalesTouched += r.rowCount;
      }
    }

    console.log(`\napply: contact_products filas tocadas (suma de updates): ${totalTouched}`);
    console.log(`apply: sales filas tocadas (suma de updates): ${totalSalesTouched}`);

    if (dryRun) {
      console.log("\nFIX_DRY_RUN=true -> ROLLBACK");
      await client.query("ROLLBACK");
    } else {
      console.log("\nFIX_DRY_RUN=false -> COMMIT");
      await client.query("COMMIT");
    }
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    await client.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
