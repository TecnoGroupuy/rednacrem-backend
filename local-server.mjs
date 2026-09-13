import fs from "node:fs";
import http from "node:http";
import { URL } from "node:url";
import { handler } from "./index.mjs";

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
    console.warn("LOCAL_ENV_LOAD_WARNING", error.message);
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
    console.error("LOCAL_SERVER_ERROR", error);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({
      ok: false,
      message: "Local server error",
      error: error.message
    }));
  }
});

server.listen(port, () => {
  console.log(`Local backend listening on http://localhost:${port}`);
});
