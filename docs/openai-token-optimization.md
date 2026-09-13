# OpenAI token optimization

Este backend todavia no tiene una integracion activa con OpenAI, pero ya cuenta con utilidades reutilizables en `src/lib/aiOptimization.js` para reducir consumo cuando se agregue.

## Que incluye

- Compactacion de prompt: elimina contexto repetido y ejemplos duplicados.
- Batching de salida: permite pedir `titulo + descripcion + pasos` en un solo JSON estructurado.
- Limite de salida: arma payloads con `max_tokens` y `response_format`.
- Cache TTL en memoria: reutiliza respuestas costosas por clave.
- Deduplicacion inflight: si entran dos requests iguales al mismo tiempo, se hace una sola llamada al modelo.
- Auditoria de uso: deja logs por ruta, feature, modelo y tokens.

## Uso sugerido

```js
import OpenAI from "openai";
import {
  buildChatCompletionPayload,
  createExpiringMemoCache,
  createUsageAuditLogger,
} from "../lib/aiOptimization.js";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const cache = createExpiringMemoCache({ ttlMs: 5 * 60_000 });
const logUsage = createUsageAuditLogger();

export async function getClientSummary(clientId, sourceData) {
  const key = cache.buildKey({ feature: "client-summary", clientId, sourceData });

  return cache.getOrCompute(key, async () => {
    const payload = buildChatCompletionPayload({
      model: "gpt-5-mini",
      task: "Resume el cliente para el ejecutivo comercial",
      context: [
        `Cliente: ${sourceData.name}`,
        `Segmento: ${sourceData.segment}`,
        `Notas: ${sourceData.notes}`,
      ],
      requestedFields: ["title", "summary", "next_steps"],
      extraRules: ["No repitas datos ya presentes en el CRM"],
      maxTokens: 180,
      responseFormat: { type: "json_object" },
    });

    const response = await openai.chat.completions.create(payload);
    const usage = response.usage || {};

    logUsage({
      route: "/ai/client-summary",
      feature: "client-summary",
      model: payload.model,
      promptTokens: usage.prompt_tokens || 0,
      completionTokens: usage.completion_tokens || 0,
      cached: false,
    });

    return response.choices[0]?.message?.content || "";
  });
}
```

## Prioridad recomendada

1. Identificar las rutas con mas `totalTokens` usando el logger.
2. Aplicar `createExpiringMemoCache` en resúmenes y salidas que cambian poco.
3. Convertir varias llamadas chicas en una sola salida JSON estructurada.
4. Reducir cualquier polling automatico que hoy rehaga requests equivalentes.
