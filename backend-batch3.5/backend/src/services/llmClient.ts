import { fetchWithTimeout, TimeoutError } from "../utils/http";

export interface LlmCompletionRequest {
  system: string;
  user: string;
}

export interface LlmProvider {
  complete(request: LlmCompletionRequest): Promise<string>;
}

export class LlmUnavailableError extends Error {
  constructor(message = "LLM provider is unavailable.") {
    super(message);
    this.name = "LlmUnavailableError";
  }
}

/**
 * Anthropic Messages-compatible client. API key stays server-side and
 * is never written to logs.
 */
export function createAnthropicProvider(options: {
  apiKey: string;
  apiUrl: string;
  model: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}): LlmProvider {
  const timeoutMs = options.timeoutMs ?? 15000;
  const fetchImpl = options.fetchImpl ?? fetch;

  return {
    async complete(request: LlmCompletionRequest): Promise<string> {
      const res = await fetchWithTimeout(
        options.apiUrl,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-api-key": options.apiKey,
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify({
            model: options.model,
            max_tokens: 800,
            system: request.system,
            messages: [{ role: "user", content: request.user }],
          }),
        },
        timeoutMs,
        fetchImpl
      );

      if (!res.ok) {
        throw new LlmUnavailableError(`LLM HTTP ${res.status}`);
      }

      const body = (await res.json()) as {
        content?: { type?: string; text?: string }[];
      };
      const text = body.content?.find((c) => c.type === "text")?.text;
      if (!text) throw new LlmUnavailableError("LLM returned no text content.");
      return text;
    },
  };
}

export function createGeminiProvider(options: {
  apiKey: string;
  model: string;
  apiBaseUrl?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}): LlmProvider {
  const timeoutMs = options.timeoutMs ?? 15000;
  const fetchImpl = options.fetchImpl ?? fetch;
  const baseUrl = options.apiBaseUrl ?? "https://generativelanguage.googleapis.com/v1beta/models";

  return {
    async complete(request: LlmCompletionRequest): Promise<string> {
      const url = `${baseUrl}/${encodeURIComponent(options.model)}:generateContent?key=${encodeURIComponent(options.apiKey)}`;
      const res = await fetchWithTimeout(
        url,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: request.system }] },
            contents: [{ role: "user", parts: [{ text: request.user }] }],
            // Ask Gemini to reply with a bare JSON body (supported by the
            // v1beta generateContent API) so we don't depend solely on
            // parseLlmSemanticJson's markdown-fence stripping to recover
            // valid JSON from a prose or fenced-code-block reply.
            generationConfig: { responseMimeType: "application/json" },
          }),
        },
        timeoutMs,
        fetchImpl
      );

      // TEMPORARY SAFE DIAGNOSTIC — status code only, never the request/
      // response body, never the API key. Remove once Gemini responses
      // are confirmed reliably AVAILABLE.
      console.error(`[ai-debug] Gemini HTTP status: ${res.status}`);

      if (!res.ok) {
        // Gemini error bodies are Google's own structured diagnostic text
        // about the request (e.g. "API key not valid", "quota exceeded",
        // "model not found") — never the caller's email content — so a
        // short bounded excerpt is safe to surface here.
        let safeDetail = "";
        try {
          const errBody = (await res.json()) as { error?: { message?: string; status?: string } };
          safeDetail = errBody.error?.message?.slice(0, 200) ?? "";
        } catch {
          // Body wasn't JSON — nothing more to safely extract.
        }
        console.error(`[ai-debug] Gemini error detail: ${safeDetail || "(no structured error body)"}`);
        throw new LlmUnavailableError(`LLM HTTP ${res.status}${safeDetail ? `: ${safeDetail}` : ""}`);
      }

      const body = (await res.json()) as {
        candidates?: { content?: { parts?: { text?: string }[] }; finishReason?: string }[];
        promptFeedback?: { blockReason?: string };
      };
      const text = body.candidates?.[0]?.content?.parts?.find((p) => p.text)?.text;
      if (!text) {
        // Safe to log: finishReason/blockReason are Gemini's own enum
        // labels (e.g. "SAFETY", "MAX_TOKENS", "RECITATION"), never
        // content.
        const finishReason = body.candidates?.[0]?.finishReason;
        const blockReason = body.promptFeedback?.blockReason;
        console.error(
          `[ai-debug] Gemini returned no usable text — finishReason: ${finishReason ?? "none"}, blockReason: ${blockReason ?? "none"}`
        );
        throw new LlmUnavailableError("LLM returned no text content.");
      }
      return text;
    },
  };
}

// Provider selection is entirely configuration-driven — LLM_PROVIDER
// picks the wire format/client, LLM_API_KEY/LLM_MODEL/LLM_API_URL
// configure it. No secrets or model names are hardcoded here beyond
// the pre-existing Anthropic default, which is unchanged so behavior
// with LLM_PROVIDER unset is identical to before this change (Batch
// 4/5C/6 all keep working as-is). Gemini has no hardcoded model
// default on purpose: guessing a specific Gemini model name risks
// shipping one that's already outdated by the time this runs — set
// LLM_MODEL explicitly (e.g. "gemini-2.5-flash") when using Gemini.
export function llmProviderFromEnv(): LlmProvider | null {
  const apiKey = process.env.LLM_API_KEY?.trim();
  if (!apiKey) {
    console.error("[ai-debug] provider initialized: false (no LLM_API_KEY configured)");
    return null;
  }

  const provider = (process.env.LLM_PROVIDER?.trim().toLowerCase() || "anthropic");
  const timeoutMs = Number(process.env.LLM_TIMEOUT_MS ?? 15000);

  if (provider === "gemini") {
    const model = process.env.LLM_MODEL?.trim();
    if (!model) {
      console.error("[ai-debug] provider initialized: false (LLM_PROVIDER=gemini but LLM_MODEL is not set)");
      return null; // no safe default — require an explicit, current model name
    }
    console.error(`[ai-debug] provider initialized: true | provider: gemini | model: ${model}`);
    return createGeminiProvider({
      apiKey,
      model,
      apiBaseUrl: process.env.LLM_API_URL?.trim() || undefined,
      timeoutMs,
    });
  }

  const model = process.env.LLM_MODEL?.trim() || "claude-haiku-4-5-20251001";
  console.error(`[ai-debug] provider initialized: true | provider: anthropic | model: ${model}`);
  return createAnthropicProvider({
    apiKey,
    apiUrl: process.env.LLM_API_URL?.trim() || "https://api.anthropic.com/v1/messages",
    model,
    timeoutMs,
  });
}

export { TimeoutError };
