import fs from "node:fs";
import http from "node:http";
import { URL } from "node:url";
import { Server as SocketIOServer } from "socket.io";
import {
  handler,
  createDbClient,
  getConfigMap,
  getTeamSummary,
  createAlert,
  parseFechaParam
} from "./index.mjs";
import { onRealtime } from "./src/monitoring/realtimeBus.js";

function loadEnvFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      return;
    }

    const text = fs.readFileSync(filePath, "utf8");
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const separatorIndex = trimmed.indexOf("=");
      if (separatorIndex === -1) continue;

      const key = trimmed.slice(0, separatorIndex).trim();
      let value = trimmed.slice(separatorIndex + 1).trim();

      if (
        (value.startsWith("\"") && value.endsWith("\"")) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      if (!(key in process.env)) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    console.warn("REALTIME_ENV_LOAD_WARNING", error.message);
  }
}

async function readBody(req) {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(chunk);
  }

  return Buffer.concat(chunks).toString("utf8");
}

function buildEvent(req, body) {
  const host = req.headers.host || `localhost:${process.env.PORT || 3001}`;
  const requestUrl = new URL(req.url || "/", `http://${host}`);

  return {
    version: "2.0",
    routeKey: "$default",
    rawPath: requestUrl.pathname,
    rawQueryString: requestUrl.searchParams.toString(),
    headers: req.headers,
    queryStringParameters: Object.fromEntries(requestUrl.searchParams),
    requestContext: {
      http: {
        method: req.method || "GET",
        path: requestUrl.pathname,
        sourceIp: req.socket.remoteAddress || "127.0.0.1",
        userAgent: req.headers["user-agent"] || "local-server"
      }
    },
    body,
    isBase64Encoded: false
  };
}

loadEnvFile(".env");
loadEnvFile(".env.local");

const port = Number(process.env.PORT || 3001);
const corsOriginRaw = process.env.SOCKETIO_CORS_ORIGIN;
const corsOrigin = corsOriginRaw
  ? corsOriginRaw.split(",").map((origin) => origin.trim()).filter(Boolean)
  : "*";

const server = http.createServer(async (req, res) => {
  try {
    const body = await readBody(req);
    const event = buildEvent(req, body);
    const response = await handler(event);

    res.statusCode = response?.statusCode || 500;

    for (const [key, value] of Object.entries(response?.headers || {})) {
      if (value !== undefined && value !== null) {
        res.setHeader(key, value);
      }
    }

    if (response?.isBase64Encoded) {
      const buffer = Buffer.from(response?.body || "", "base64");
      res.end(buffer);
    } else {
      res.end(response?.body || "");
    }
  } catch (error) {
    console.error("REALTIME_SERVER_ERROR", error);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({
      ok: false,
      message: "Realtime server error",
      error: error.message
    }));
  }
});

const io = new SocketIOServer(server, {
  cors: {
    origin: corsOrigin,
    credentials: true
  }
});

async function emitTeamUpdate() {
  const client = createDbClient();
  await client.connect();
  try {
    const fecha = parseFechaParam("hoy");
    const summary = await getTeamSummary(client, fecha, new Date());
    io.emit("team_update", summary);
  } catch (error) {
    console.error("REALTIME_TEAM_UPDATE_ERROR", error.message);
  } finally {
    await client.end().catch(() => {});
  }
}

async function checkConversionAlerts() {
  const client = createDbClient();
  await client.connect();
  try {
    const fecha = parseFechaParam("hoy");
    const now = new Date();
    const config = await getConfigMap(client);
    const agentsRes = await client.query(
      "SELECT id, nombre FROM agentes WHERE activo = true"
    );
    let createdAny = false;

    for (const agent of agentsRes.rows) {
      const callsRes = await client.query(
        `
        SELECT
          COUNT(*)::int AS total_llamadas,
          COUNT(*) FILTER (WHERE resultado = 'venta')::int AS total_ventas
        FROM llamadas
        WHERE agente_id = $1
          AND fecha = $2
        `,
        [agent.id, fecha]
      );
      const row = callsRes.rows[0] || { total_llamadas: 0, total_ventas: 0 };
      const totalLlamadas = Number(row.total_llamadas || 0);
      const totalVentas = Number(row.total_ventas || 0);
      const conversion = totalLlamadas === 0
        ? 0
        : Math.round((totalVentas / totalLlamadas) * 1000) / 10;

      if (conversion >= config.conversion_minima_porcentaje) continue;

      const existing = await client.query(
        `
        SELECT id
        FROM alertas
        WHERE agente_id = $1
          AND fecha = $2
          AND tipo = 'conversion_baja'
          AND resuelta = false
        LIMIT 1
        `,
        [agent.id, fecha]
      );
      if (existing.rows.length) continue;

      const alert = await createAlert(client, {
        agente_id: agent.id,
        tipo: "conversion_baja",
        descripcion: `${conversion}% actual vs mínimo ${config.conversion_minima_porcentaje}%`,
        hora_evento: now,
        fecha
      });
      createdAny = true;
      io.emit("new_alert", {
        agente_id: agent.id,
        agente_nombre: agent.nombre,
        alerta: {
          tipo: alert.tipo,
          descripcion: alert.descripcion,
          hora_evento: now.toISOString()
        }
      });
    }

    if (createdAny) {
      const summary = await getTeamSummary(client, fecha, now);
      io.emit("team_update", summary);
    }
  } catch (error) {
    console.error("REALTIME_CONVERSION_CHECK_ERROR", error.message);
  } finally {
    await client.end().catch(() => {});
  }
}

const forwardEvents = ["team_update", "agent_event", "new_alert", "new_call"];
for (const event of forwardEvents) {
  onRealtime(event, (payload) => {
    io.emit(event, payload);
  });
}

io.on("connection", async (socket) => {
  try {
    const client = createDbClient();
    await client.connect();
    try {
      const fecha = parseFechaParam("hoy");
      const summary = await getTeamSummary(client, fecha, new Date());
      socket.emit("team_update", summary);
    } finally {
      await client.end().catch(() => {});
    }
  } catch (error) {
    console.error("REALTIME_SOCKET_INIT_ERROR", error.message);
  }
});

const teamUpdateIntervalMs = Number(process.env.TEAM_UPDATE_INTERVAL_MS || 30000);
const conversionCheckIntervalMs = Number(process.env.CONVERSION_CHECK_INTERVAL_MS || 300000);

setInterval(() => {
  emitTeamUpdate();
}, teamUpdateIntervalMs);

setInterval(() => {
  checkConversionAlerts();
}, conversionCheckIntervalMs);

server.listen(port, () => {
  console.log(`Realtime backend listening on http://localhost:${port}`);
});
