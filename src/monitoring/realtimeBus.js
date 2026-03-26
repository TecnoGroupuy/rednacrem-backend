import { EventEmitter } from "node:events";
import http from "node:http";
import https from "node:https";

const bus = new EventEmitter();

const REALTIME_URL = process.env.REALTIME_INTERNAL_URL || "";
const REALTIME_SECRET = process.env.REALTIME_INTERNAL_SECRET || "";

function postToRealtime(event, payload) {
  return new Promise((resolve) => {
    if (!REALTIME_URL) return resolve();
    try {
      const body = JSON.stringify({ event, payload });
      const url = new URL("/internal/event", REALTIME_URL);
      const isHttps = url.protocol === "https:";
      const client = isHttps ? https : http;
      const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          "x-internal-secret": REALTIME_SECRET
        }
      };
      const req = client.request(options, () => resolve());
      req.on("error", () => resolve());
      req.write(body);
      req.end();
    } catch (_) {
      resolve();
    }
  });
}

export async function emitRealtime(event, payload) {
  bus.emit(event, payload);
  await postToRealtime(event, payload);
}

export function onRealtime(event, handler) {
  bus.on(event, handler);
}

export function offRealtime(event, handler) {
  bus.off(event, handler);
}
