import crypto from "node:crypto";
import https from "node:https";

function md5Hex(value) {
  return crypto.createHash("md5").update(String(value || "")).digest("hex");
}

function parseDigestChallenge(headerValue) {
  const source = String(headerValue || "");
  const pairs = [...source.matchAll(/([a-z0-9_]+)=(?:"([^"]*)"|([^,\s]+))/gi)];
  const parsed = {};
  for (const match of pairs) {
    parsed[String(match[1] || "").toLowerCase()] = match[2] ?? match[3] ?? "";
  }
  return parsed;
}

function buildDigestAuthorizationHeader({ username, password, method, url, challenge }) {
  const realm = challenge.realm || "";
  const nonce = challenge.nonce || "";
  const opaque = challenge.opaque || "";
  const algorithm = (challenge.algorithm || "MD5").toUpperCase();
  const qop = String(challenge.qop || "")
    .split(",")
    .map((item) => item.trim())
    .find((item) => item) || null;
  if (algorithm !== "MD5" || !realm || !nonce) {
    return null;
  }
  const uriUrl = new URL(url);
  const uri = `${uriUrl.pathname}${uriUrl.search}`;
  const ha1 = md5Hex(`${username}:${realm}:${password}`);
  const ha2 = md5Hex(`${String(method || "GET").toUpperCase()}:${uri}`);
  const nc = "00000001";
  const cnonce = crypto.randomBytes(8).toString("hex");
  const response = qop
    ? md5Hex(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
    : md5Hex(`${ha1}:${nonce}:${ha2}`);
  const parts = [
    `username="${username}"`,
    `realm="${realm}"`,
    `nonce="${nonce}"`,
    `uri="${uri}"`,
    `response="${response}"`,
    `algorithm=${algorithm}`
  ];
  if (opaque) parts.push(`opaque="${opaque}"`);
  if (qop) {
    parts.push(`qop=${qop}`);
    parts.push(`nc=${nc}`);
    parts.push(`cnonce="${cnonce}"`);
  }
  return `Digest ${parts.join(", ")}`;
}

function createGatewayResponse(statusCode, headers, bodyBuffer) {
  const normalizedHeaders = new Map(
    Object.entries(headers || {}).map(([key, value]) => [String(key).toLowerCase(), value])
  );
  const bodyText = Buffer.isBuffer(bodyBuffer)
    ? bodyBuffer.toString("utf8")
    : String(bodyBuffer || "");

  return {
    status: Number(statusCode) || 500,
    ok: Number(statusCode) >= 200 && Number(statusCode) < 300,
    headers: {
      get(name) {
        return normalizedHeaders.get(String(name || "").toLowerCase()) ?? null;
      },
      entries() {
        return normalizedHeaders.entries();
      }
    },
    async text() {
      return bodyText;
    },
    async json() {
      return JSON.parse(bodyText);
    }
  };
}

function gatewayRequest(url, { method = "GET", headers = {}, body }) {
  const gatewayAgent = new https.Agent({ rejectUnauthorized: false });
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method, headers, agent: gatewayAgent }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        resolve(createGatewayResponse(response.statusCode, response.headers, Buffer.concat(chunks)));
      });
    });
    request.on("error", reject);
    if (body !== undefined && body !== null) {
      request.write(body);
    }
    request.end();
  });
}

async function fetchWithGatewayAuth(url, { method = "GET", headers = {}, body, username, password }) {
  const requestHeaders = { ...headers };
  const basicToken = Buffer.from(`${username || ""}:${password || ""}`).toString("base64");
  let response = await gatewayRequest(url, {
    method,
    headers: {
      ...requestHeaders,
      Authorization: `Basic ${basicToken}`
    },
    body
  });
  if (response.status !== 401) {
    return response;
  }
  const challengeHeader = response.headers.get("www-authenticate") || "";
  if (!/digest/i.test(challengeHeader)) {
    return response;
  }
  const digestHeader = buildDigestAuthorizationHeader({
    username,
    password,
    method,
    url,
    challenge: parseDigestChallenge(challengeHeader)
  });
  if (!digestHeader) {
    return response;
  }
  return gatewayRequest(url, {
    method,
    headers: {
      ...requestHeaders,
      Authorization: digestHeader
    },
    body
  });
}

const host = process.env.SMS_GATEWAY_HOST || "165.232.128.228";
const port = Number(process.env.SMS_GATEWAY_PORT || "28443");
const username = process.env.SMS_GATEWAY_USERNAME || "";
const password = process.env.SMS_GATEWAY_PASSWORD || "";
const phone = process.env.SMS_TEST_PHONE || "092900743";
const message = process.env.SMS_TEST_MESSAGE || "Prueba local antes de deploy";

if (!username || !password) {
  console.error("Missing SMS_GATEWAY_USERNAME or SMS_GATEWAY_PASSWORD");
  process.exit(1);
}

const url = `https://${host}:${port}/api/send_sms`;
const payload = {
  text: message,
  param: [{ number: phone }],
  encoding: "gsm-7bit",
  request_status_report: true
};

console.log("Sending test SMS...");
console.log(JSON.stringify({ url, phone, message, payload }, null, 2));

const response = await fetchWithGatewayAuth(url, {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify(payload),
  username,
  password
});

const bodyText = await response.text();

console.log("Status:", response.status);
console.log("OK:", response.ok);
console.log("Headers:", Object.fromEntries(response.headers.entries()));
console.log("Body:", bodyText);
