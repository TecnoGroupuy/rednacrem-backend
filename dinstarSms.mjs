import https from "node:https";
import crypto from "node:crypto";

function md5(str) {
  return crypto.createHash("md5").update(str).digest("hex");
}

function rawRequest(options, body) {
  return new Promise((resolve, reject) => {
    const request = https.request(options, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("end", () => {
        resolve({
          statusCode: response.statusCode,
          headers: response.headers,
          body: Buffer.concat(chunks).toString("utf8")
        });
      });
    });
    request.on("error", reject);
    if (body) request.write(body);
    request.end();
  });
}

function parseDigestHeader(header) {
  const result = {};
  const regex = /(\w+)=(?:"([^"]*)"|([^\s,]+))/g;
  let match;
  while ((match = regex.exec(header)) !== null) {
    result[match[1]] = match[2] !== undefined ? match[2] : match[3];
  }
  return result;
}

function buildDigestAuthHeader({ user, pass, method, uri, digestParams, cnonce, nc }) {
  const { realm, nonce, qop, opaque } = digestParams;
  const ha1 = md5(`${user}:${realm}:${pass}`);
  const ha2 = md5(`${method}:${uri}`);
  let response;
  let authHeader;

  if (qop) {
    const ncStr = nc.toString(16).padStart(8, "0");
    response = md5(`${ha1}:${nonce}:${ncStr}:${cnonce}:${qop}:${ha2}`);
    authHeader = `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", qop=${qop}, nc=${ncStr}, cnonce="${cnonce}", response="${response}"`;
  } else {
    response = md5(`${ha1}:${nonce}:${ha2}`);
    authHeader = `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"`;
  }

  if (opaque) authHeader += `, opaque="${opaque}"`;
  return authHeader;
}

function safeJsonParse(str) {
  try {
    return JSON.parse(str);
  } catch {
    return { raw: str };
  }
}

async function digestPost({ host, port, path, user, pass, bodyObj }) {
  const body = JSON.stringify(bodyObj);
  const baseOptions = {
    host,
    port,
    path,
    method: "POST",
    rejectUnauthorized: false,
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body)
    }
  };

  const first = await rawRequest(baseOptions, body);
  if (first.statusCode !== 401) {
    return { statusCode: first.statusCode, body: safeJsonParse(first.body) };
  }

  const wwwAuth = first.headers["www-authenticate"];
  if (!wwwAuth) {
    throw new Error("Dinstar devolvio 401 sin header WWW-Authenticate; no se puede continuar con Digest auth");
  }

  const digestParams = parseDigestHeader(wwwAuth);
  const cnonce = crypto.randomBytes(8).toString("hex");
  const authHeader = buildDigestAuthHeader({
    user,
    pass,
    method: "POST",
    uri: path,
    digestParams,
    cnonce,
    nc: 1
  });

  const second = await rawRequest(
    {
      ...baseOptions,
      headers: {
        ...baseOptions.headers,
        Authorization: authHeader
      }
    },
    body
  );

  return { statusCode: second.statusCode, body: safeJsonParse(second.body) };
}

export async function dinstarSendSmsApi(connection, number, text, userId, portIndex = 0, encoding = "unicode") {
  const { host, port, username, password } = connection;

  const bodyObj = {
    text,
    port: [portIndex],
    param: [{ number, user_id: userId }],
    encoding
  };

  const { statusCode, body } = await digestPost({
    host,
    port,
    path: "/api/send_sms",
    user: username,
    pass: password,
    bodyObj
  });

  const errorCode = body?.error_code;
  const success = errorCode === 202;

  return {
    success,
    errorCode,
    taskId: body?.task_id ?? null,
    smsInQueue: body?.sms_in_queue ?? null,
    raw: body,
    httpStatusCode: statusCode
  };
}

export async function dinstarTestConnectionApi(connection) {
  const { host, port, username, password } = connection;

  const { statusCode, body } = await digestPost({
    host,
    port,
    path: "/api/get_status",
    user: username,
    pass: password,
    bodyObj: ["performance"]
  });

  return {
    ok: statusCode === 200 && !!body?.performance,
    statusCode,
    raw: body
  };
}
