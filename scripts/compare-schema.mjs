#!/usr/bin/env node
// Herramienta PERMANENTE: compara el esquema de Postgres local contra el
// esquema real de produccion, exportado como CSV en docs/prod-schema/ (ver
// CLAUDE.md, regla 9 -- correr esto antes de escribir cualquier migracion
// nueva, en vez de confiar solo en divergencias ya documentadas).
//
// Lee docs/prod-schema/prod_columns.csv (obligatorio) y, si existen,
// prod_constraints.csv y prod_indexes.csv -- si no estan, lo avisa y sigue
// solo con columnas.
//
// Los exports de este tipo (pegados/copiados desde CloudShell) pueden llegar
// corruptos -- ya paso una vez (un tar interrumpido dejo un bloque de
// cabecera tar y el CSV completo repetido a mitad de archivo). Este script
// no asume que el CSV esta limpio: detecta filas que no tienen exactamente
// las columnas esperadas y las excluye del comparativo, reportandolas aparte
// en vez de fallar en silencio o inventar datos. Si el header del CSV
// aparece mas de una vez (señal de archivos concatenados), tambien lo avisa.
// Cuando una tabla/columna aparece mas de una vez en el CSV (por ejemplo,
// dos exports concatenados), gana la ULTIMA aparicion -- en la practica esto
// es lo mismo que "el export mas reciente pisa al mas viejo".
//
// Uso: node scripts/compare-schema.mjs

import fs from "node:fs";
import path from "node:path";
import pg from "pg";

const ROOT = path.resolve(new URL(".", import.meta.url).pathname, "..");
const SCHEMA_DIR = path.join(ROOT, "docs", "prod-schema");

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  const text = fs.readFileSync(filePath, "utf8");
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    let value = trimmed.slice(idx + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}
loadEnvFile(path.join(ROOT, ".env"));
loadEnvFile(path.join(ROOT, ".env.local"));

// --- Parseo de CSV tolerante a corrupcion -----------------------------

// Respeta comillas dobles y el escape "" (RFC4180) -- un column_default de
// tipo jsonb/array puede traer una coma dentro de un valor entre comillas
// (ej. '{"calls": 3, "whatsapp": 1}'::jsonb), y un split ingenuo por "," lo
// cuenta como un campo de mas.
function parseCsvLine(line) {
  const fields = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

function parseCsvFile(filePath, expectedHeader) {
  const warnings = [];
  if (!fs.existsSync(filePath)) {
    return { rows: null, warnings, missing: true };
  }

  const raw = fs.readFileSync(filePath);
  const nulCount = raw.filter((b) => b === 0).length;
  if (nulCount > 0) {
    warnings.push(`${nulCount} bytes NUL encontrados en el archivo (señal de corrupcion binaria) -- se descartan.`);
  }
  // Sacar NULs antes de decodificar como texto.
  const text = Buffer.from(raw.filter((b) => b !== 0)).toString("utf8");

  const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
  if (!lines.length) {
    warnings.push("El archivo esta vacio tras limpiar bytes NUL.");
    return { rows: [], warnings, missing: false };
  }

  const headerLine = lines[0];
  const header = parseCsvLine(headerLine);
  if (header.join(",") !== expectedHeader.join(",")) {
    warnings.push(
      `El header no coincide con el esperado. Esperado: [${expectedHeader.join(", ")}]. Encontrado: [${header.join(", ")}].`
    );
  }

  const headerOccurrences = lines.filter((l) => l === headerLine).length;
  if (headerOccurrences > 1) {
    warnings.push(
      `El header "${headerLine.slice(0, 60)}..." aparece ${headerOccurrences} veces en el archivo -- probablemente son ` +
      `varios exports concatenados (posible corrupcion de tar/copia). Se tratan como segmentos independientes; ` +
      `donde una tabla+columna aparece en mas de un segmento, gana la ULTIMA aparicion.`
    );
  }

  const rows = [];
  const parseErrors = [];
  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line === headerLine) continue; // segmento nuevo, no es un dato
    const fields = parseCsvLine(line);
    if (fields.length !== expectedHeader.length) {
      parseErrors.push({ lineNumber: i + 1, raw: line, fieldCount: fields.length });
      continue;
    }
    const row = {};
    expectedHeader.forEach((key, idx) => {
      row[key] = fields[idx] === "" ? null : fields[idx];
    });
    rows.push(row);
  }

  if (parseErrors.length) {
    warnings.push(
      `${parseErrors.length} línea(s) no tienen las ${expectedHeader.length} columnas esperadas -- excluidas del comparativo:`
    );
    for (const err of parseErrors.slice(0, 15)) {
      warnings.push(`  línea ${err.lineNumber} (${err.fieldCount} campos): ${err.raw.slice(0, 100)}`);
    }
    if (parseErrors.length > 15) {
      warnings.push(`  ... y ${parseErrors.length - 15} más.`);
    }
  }

  return { rows, warnings, missing: false };
}

const COLUMNS_HEADER = [
  "table_name", "column_name", "ordinal_position", "data_type", "udt_name",
  "character_maximum_length", "numeric_precision", "numeric_scale",
  "is_nullable", "column_default"
];
const CONSTRAINTS_HEADER = ["table_name", "constraint_name", "constraint_def"];
const INDEXES_HEADER = ["table_name", "index_name", "index_def"];

function buildProdColumnsMap(rows) {
  // Ultima ocurrencia gana -- ver nota arriba sobre segmentos concatenados.
  const tables = new Map();
  for (const row of rows) {
    if (!tables.has(row.table_name)) tables.set(row.table_name, new Map());
    tables.get(row.table_name).set(row.column_name, row);
  }
  return tables;
}

function buildProdGroupedMap(rows, nameField) {
  const tables = new Map();
  for (const row of rows) {
    if (!tables.has(row.table_name)) tables.set(row.table_name, new Map());
    tables.get(row.table_name).set(row[nameField], row);
  }
  return tables;
}

// --- Introspeccion de Postgres local -----------------------------------

async function getLocalSchema(client) {
  const colsRes = await client.query(`
    SELECT table_name, column_name, ordinal_position, data_type, udt_name,
           character_maximum_length, numeric_precision, numeric_scale,
           is_nullable, column_default
    FROM information_schema.columns
    WHERE table_schema = 'public'
    ORDER BY table_name, ordinal_position
  `);
  const tables = new Map();
  for (const row of colsRes.rows) {
    if (!tables.has(row.table_name)) tables.set(row.table_name, new Map());
    tables.get(row.table_name).set(row.column_name, row);
  }
  return tables;
}

// --- Comparacion ----------------------------------------------------

function normalizeDefault(value) {
  if (value === null || value === undefined) return null;
  return String(value).trim();
}

function compareColumns(prodTables, localTables) {
  const missingTables = [];
  const columnDiffs = []; // { table, column, field, prod, local }
  const missingColumns = []; // { table, column }
  const extraTablesLocal = [];
  const extraColumnsLocal = []; // { table, column }

  for (const [tableName, prodCols] of prodTables) {
    const localCols = localTables.get(tableName);
    if (!localCols) {
      missingTables.push(tableName);
      continue;
    }
    for (const [columnName, prodCol] of prodCols) {
      const localCol = localCols.get(columnName);
      if (!localCol) {
        missingColumns.push({ table: tableName, column: columnName, prod: prodCol });
        continue;
      }
      const fieldsToCompare = [
        ["data_type", "data_type"],
        ["udt_name", "udt_name"],
        ["character_maximum_length", "character_maximum_length"],
        ["numeric_precision", "numeric_precision"],
        ["numeric_scale", "numeric_scale"],
        ["is_nullable", "is_nullable"],
        ["column_default", "column_default"]
      ];
      for (const [label, key] of fieldsToCompare) {
        let prodVal = prodCol[key];
        let localVal = localCol[key];
        if (key === "column_default") {
          prodVal = normalizeDefault(prodVal);
          localVal = normalizeDefault(localVal);
        } else {
          prodVal = prodVal === null || prodVal === undefined ? null : String(prodVal);
          localVal = localVal === null || localVal === undefined ? null : String(localVal);
        }
        if (prodVal !== localVal) {
          columnDiffs.push({ table: tableName, column: columnName, field: label, prod: prodVal, local: localVal });
        }
      }
    }
  }

  for (const [tableName, localCols] of localTables) {
    const prodCols = prodTables.get(tableName);
    if (!prodCols) {
      extraTablesLocal.push(tableName);
      continue;
    }
    for (const columnName of localCols.keys()) {
      if (!prodCols.has(columnName)) {
        extraColumnsLocal.push({ table: tableName, column: columnName });
      }
    }
  }

  return { missingTables, columnDiffs, missingColumns, extraTablesLocal, extraColumnsLocal };
}

// --- Reporte ----------------------------------------------------------

function printSection(title) {
  console.log(`\n${"=".repeat(3)} ${title} ${"=".repeat(Math.max(3, 70 - title.length))}`);
}

function printReport({ colsResult, constraintsResult, indexesResult, comparison }) {
  printSection("Advertencias de lectura de CSV");
  const allWarnings = [
    ...colsResult.warnings.map((w) => `[prod_columns.csv] ${w}`),
    ...(constraintsResult.missing ? ["[prod_constraints.csv] no existe todavia -- se sigue solo con columnas."] : constraintsResult.warnings.map((w) => `[prod_constraints.csv] ${w}`)),
    ...(indexesResult.missing ? ["[prod_indexes.csv] no existe todavia -- se sigue solo con columnas."] : indexesResult.warnings.map((w) => `[prod_indexes.csv] ${w}`))
  ];
  if (allWarnings.length) {
    allWarnings.forEach((w) => console.log(`  ! ${w}`));
  } else {
    console.log("  (sin advertencias)");
  }

  printSection("Tablas de produccion ausentes en local");
  if (comparison.missingTables.length) {
    comparison.missingTables.forEach((t) => console.log(`  - ${t}`));
  } else {
    console.log("  (ninguna)");
  }

  printSection("Columnas de produccion ausentes en local");
  if (comparison.missingColumns.length) {
    comparison.missingColumns.forEach(({ table, column, prod }) => {
      console.log(`  - ${table}.${column}  (${prod.data_type}${prod.is_nullable === "NO" ? ", NOT NULL" : ""}${prod.column_default ? `, default ${prod.column_default}` : ""})`);
    });
  } else {
    console.log("  (ninguna)");
  }

  printSection("Diferencias de tipo / nulabilidad / default");
  if (comparison.columnDiffs.length) {
    let lastKey = "";
    comparison.columnDiffs.forEach(({ table, column, field, prod, local }) => {
      const key = `${table}.${column}`;
      if (key !== lastKey) {
        console.log(`  ${key}:`);
        lastKey = key;
      }
      console.log(`      ${field}: prod=${JSON.stringify(prod)}  local=${JSON.stringify(local)}`);
    });
  } else {
    console.log("  (ninguna)");
  }

  printSection("Existe en LOCAL pero no en PRODUCCION");
  if (comparison.extraTablesLocal.length) {
    console.log("  Tablas:");
    comparison.extraTablesLocal.forEach((t) => console.log(`    - ${t}`));
  }
  if (comparison.extraColumnsLocal.length) {
    console.log("  Columnas (en tablas que sí existen en prod):");
    comparison.extraColumnsLocal.forEach(({ table, column }) => console.log(`    - ${table}.${column}`));
  }
  if (!comparison.extraTablesLocal.length && !comparison.extraColumnsLocal.length) {
    console.log("  (nada)");
  }

  printSection("Resumen");
  const affectedTables = new Set([
    ...comparison.missingTables,
    ...comparison.missingColumns.map((c) => c.table),
    ...comparison.columnDiffs.map((c) => c.table)
  ]);
  console.log(`  Tablas con al menos una diferencia (faltante o distinta): ${affectedTables.size}`);
  console.log(`  Columnas de prod ausentes en local: ${comparison.missingColumns.length}`);
  console.log(`  Diferencias de tipo/nulabilidad/default: ${comparison.columnDiffs.length}`);
  console.log(`  Tablas solo en local: ${comparison.extraTablesLocal.length}`);
  console.log(`  Columnas solo en local: ${comparison.extraColumnsLocal.length}`);

  return affectedTables;
}

function printConstraintsIndexesQuery(affectedTables) {
  if (!affectedTables.size) return;
  const tableList = Array.from(affectedTables).sort();
  const arrayLiteral = tableList.map((t) => `'${t.replace(/'/g, "''")}'`).join(",\n  ");

  printSection("SQL para traer constraints + indices SOLO de las tablas con diferencias");
  console.log(`
-- Correr en RDS (psql). Salida chica: solo las ${tableList.length} tablas con diferencias.
WITH tablas AS (
  SELECT unnest(ARRAY[
  ${arrayLiteral}
  ]) AS table_name
)
SELECT 'constraint' AS kind, c.relname AS table_name, con.conname AS name, pg_get_constraintdef(con.oid) AS definition
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN tablas t ON t.table_name = c.relname
WHERE con.connamespace = 'public'::regnamespace
UNION ALL
SELECT 'index' AS kind, c.relname AS table_name, i.indexname AS name, i.indexdef AS definition
FROM pg_indexes i
JOIN pg_class c ON c.relname = i.tablename
JOIN tablas t ON t.table_name = i.tablename
WHERE i.schemaname = 'public'
ORDER BY table_name, kind, name;
`);
}

// --- Main ---------------------------------------------------------------

async function main() {
  const colsResult = parseCsvFile(path.join(SCHEMA_DIR, "prod_columns.csv"), COLUMNS_HEADER);
  if (colsResult.missing) {
    console.error("ERROR: docs/prod-schema/prod_columns.csv no existe. No se puede comparar nada.");
    process.exit(1);
  }

  const constraintsResult = parseCsvFile(path.join(SCHEMA_DIR, "prod_constraints.csv"), CONSTRAINTS_HEADER);
  const indexesResult = parseCsvFile(path.join(SCHEMA_DIR, "prod_indexes.csv"), INDEXES_HEADER);

  const prodColumnsMap = buildProdColumnsMap(colsResult.rows);

  const client = new pg.Client();
  await client.connect();
  let localColumnsMap;
  try {
    localColumnsMap = await getLocalSchema(client);
  } finally {
    await client.end();
  }

  const comparison = compareColumns(prodColumnsMap, localColumnsMap);
  const affectedTables = printReport({ colsResult, constraintsResult, indexesResult, comparison });

  if (!constraintsResult.missing || !indexesResult.missing) {
    printSection("Constraints / indices (TODO)");
    console.log("  Comparacion de constraints/indices todavia no implementada en este script --");
    console.log("  por ahora solo se leen y se avisa si faltan. Se agrega cuando haga falta.");
  }

  printConstraintsIndexesQuery(affectedTables);
}

main().catch((err) => {
  console.error("ERROR", err);
  process.exit(1);
});
