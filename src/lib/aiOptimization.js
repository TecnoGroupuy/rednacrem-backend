function normalizeText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function stableStringify(value) {
  if (value === null || value === undefined) {
    return String(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

export function dedupePromptSections(sections = []) {
  const seen = new Set();
  const compacted = [];

  for (const section of sections) {
    const normalized = normalizeText(section);

    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    compacted.push(normalized);
  }

  return compacted;
}

export function trimPromptExamples(examples = [], limit = 1) {
  return dedupePromptSections(examples).slice(0, Math.max(0, limit));
}

export function buildStructuredPrompt({
  task,
  context = [],
  examples = [],
  requestedFields = [],
  extraRules = [],
} = {}) {
  const normalizedTask = normalizeText(task);
  const compactContext = dedupePromptSections(context);
  const compactExamples = trimPromptExamples(examples, examples.length);
  const compactFields = dedupePromptSections(requestedFields);
  const compactRules = dedupePromptSections(extraRules);
  const lines = [];

  if (normalizedTask) {
    lines.push(`Task: ${normalizedTask}`);
  }

  if (compactContext.length > 0) {
    lines.push("Context:");
    for (const item of compactContext) {
      lines.push(`- ${item}`);
    }
  }

  if (compactExamples.length > 0) {
    lines.push("Examples:");
    for (const item of compactExamples) {
      lines.push(`- ${item}`);
    }
  }

  if (compactFields.length > 0) {
    lines.push(`Return JSON with fields: ${compactFields.join(", ")}`);
  }

  lines.push("Keep the answer concise and avoid repeating the context.");

  if (compactRules.length > 0) {
    lines.push("Rules:");
    for (const item of compactRules) {
      lines.push(`- ${item}`);
    }
  }

  return lines.join("\n");
}

export function buildChatCompletionPayload({
  model,
  task,
  context = [],
  examples = [],
  requestedFields = [],
  extraRules = [],
  maxTokens = 300,
  responseFormat,
  temperature = 0.2,
} = {}) {
  return {
    model,
    messages: [
      {
        role: "system",
        content: "Responde de forma breve, estructurada y sin repetir contexto.",
      },
      {
        role: "user",
        content: buildStructuredPrompt({
          task,
          context,
          examples,
          requestedFields,
          extraRules,
        }),
      },
    ],
    max_tokens: maxTokens,
    temperature,
    ...(responseFormat ? { response_format: responseFormat } : {}),
  };
}

export function createExpiringMemoCache({
  ttlMs = 60_000,
  maxEntries = 200,
  now = () => Date.now(),
} = {}) {
  const entries = new Map();
  const inflight = new Map();
  let hits = 0;
  let misses = 0;

  function isExpired(entry) {
    return !entry || entry.expiresAt <= now();
  }

  function evictExpired() {
    for (const [key, entry] of entries.entries()) {
      if (isExpired(entry)) {
        entries.delete(key);
      }
    }
  }

  function evictOverflow() {
    while (entries.size > maxEntries) {
      const oldestKey = entries.keys().next().value;
      entries.delete(oldestKey);
    }
  }

  function get(key) {
    const entry = entries.get(key);

    if (isExpired(entry)) {
      entries.delete(key);
      misses += 1;
      return null;
    }

    hits += 1;
    return entry.value;
  }

  function set(key, value, customTtlMs = ttlMs) {
    evictExpired();

    entries.set(key, {
      value,
      expiresAt: now() + customTtlMs,
    });

    evictOverflow();
    return value;
  }

  async function getOrCompute(key, compute, options = {}) {
    const cached = get(key);
    if (cached !== null) {
      return cached;
    }

    if (inflight.has(key)) {
      return inflight.get(key);
    }

    const task = (async () => {
      const value = await compute();
      set(key, value, options.ttlMs);
      return value;
    })();

    inflight.set(key, task);

    try {
      return await task;
    } finally {
      inflight.delete(key);
    }
  }

  return {
    get,
    set,
    delete(key) {
      entries.delete(key);
      inflight.delete(key);
    },
    clear() {
      entries.clear();
      inflight.clear();
      hits = 0;
      misses = 0;
    },
    stats() {
      evictExpired();
      return {
        size: entries.size,
        inflight: inflight.size,
        hits,
        misses,
      };
    },
    buildKey(parts) {
      return stableStringify(parts);
    },
    getOrCompute,
  };
}

export function createUsageAuditLogger({ log = console.info } = {}) {
  return function logUsage({
    route,
    feature,
    model,
    promptTokens = 0,
    completionTokens = 0,
    totalTokens,
    cached = false,
    status = "ok",
  } = {}) {
    const computedTotal = totalTokens ?? promptTokens + completionTokens;

    log("OPENAI_USAGE", {
      route: normalizeText(route) || "unknown",
      feature: normalizeText(feature) || "unknown",
      model: normalizeText(model) || "unknown",
      promptTokens,
      completionTokens,
      totalTokens: computedTotal,
      cached,
      status,
      timestamp: new Date().toISOString(),
    });
  };
}
