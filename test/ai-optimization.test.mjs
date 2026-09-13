import test from "node:test";
import assert from "node:assert/strict";
import {
  buildChatCompletionPayload,
  buildStructuredPrompt,
  createExpiringMemoCache,
  createUsageAuditLogger,
  dedupePromptSections,
  trimPromptExamples,
} from "../src/lib/aiOptimization.js";

test("dedupePromptSections removes empty and repeated context", () => {
  assert.deepEqual(
    dedupePromptSections(["  Cliente premium  ", "", "Cliente premium", "Modulo ventas"]),
    ["Cliente premium", "Modulo ventas"],
  );
});

test("trimPromptExamples keeps only the requested number of unique examples", () => {
  assert.deepEqual(
    trimPromptExamples(["ejemplo 1", "ejemplo 1", "ejemplo 2"], 1),
    ["ejemplo 1"],
  );
});

test("buildStructuredPrompt groups fields into one structured request", () => {
  const prompt = buildStructuredPrompt({
    task: "Genera contenido para el cliente",
    context: ["Cliente premium", "Cliente premium", "Modulo onboarding"],
    requestedFields: ["titulo", "descripcion", "pasos"],
    extraRules: ["No inventes datos"],
  });

  assert.match(prompt, /Task: Genera contenido para el cliente/);
  assert.match(prompt, /Return JSON with fields: titulo, descripcion, pasos/);
  assert.equal(prompt.includes("Cliente premium\n- Cliente premium"), false);
});

test("buildChatCompletionPayload limits output and includes response format", () => {
  const payload = buildChatCompletionPayload({
    model: "gpt-5-mini",
    task: "Resume el cliente",
    context: ["Empresa industrial"],
    requestedFields: ["summary"],
    maxTokens: 120,
    responseFormat: { type: "json_object" },
  });

  assert.equal(payload.model, "gpt-5-mini");
  assert.equal(payload.max_tokens, 120);
  assert.deepEqual(payload.response_format, { type: "json_object" });
  assert.equal(payload.messages.length, 2);
});

test("createExpiringMemoCache reuses cached values and deduplicates inflight work", async () => {
  let currentTime = 1_000;
  let calls = 0;

  const cache = createExpiringMemoCache({
    ttlMs: 500,
    now: () => currentTime,
  });

  const key = cache.buildKey({ clientId: 10, module: "summary" });

  const [first, second] = await Promise.all([
    cache.getOrCompute(key, async () => {
      calls += 1;
      return { text: "cached summary" };
    }),
    cache.getOrCompute(key, async () => {
      calls += 1;
      return { text: "should not run" };
    }),
  ]);

  assert.deepEqual(first, { text: "cached summary" });
  assert.deepEqual(second, { text: "cached summary" });
  assert.equal(calls, 1);

  const third = await cache.getOrCompute(key, async () => {
    calls += 1;
    return { text: "should stay cached" };
  });

  assert.deepEqual(third, { text: "cached summary" });
  assert.equal(cache.stats().hits, 1);

  currentTime += 600;

  const fourth = await cache.getOrCompute(key, async () => {
    calls += 1;
    return { text: "refreshed summary" };
  });

  assert.deepEqual(fourth, { text: "refreshed summary" });
  assert.equal(calls, 2);
});

test("createUsageAuditLogger emits token usage logs", () => {
  const entries = [];
  const logger = createUsageAuditLogger({
    log: (...args) => entries.push(args),
  });

  logger({
    route: "/ai/client-summary",
    feature: "client-summary",
    model: "gpt-5-mini",
    promptTokens: 120,
    completionTokens: 40,
    cached: true,
  });

  assert.equal(entries.length, 1);
  assert.equal(entries[0][0], "OPENAI_USAGE");
  assert.equal(entries[0][1].totalTokens, 160);
  assert.equal(entries[0][1].cached, true);
});
