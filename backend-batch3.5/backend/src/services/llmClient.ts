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
          }),
        },
        timeoutMs,
        fetchImpl
      );

      if (!res.ok) {
        throw new LlmUnavailableError(`LLM HTTP ${res.status}`);
      }

      const body = (await res.json()) as {
        candidates?: { content?: { parts?: { text?: string }[] } }[];
      };
      const text = body.candidates?.[0]?.content?.parts?.find((p) => p.text)?.text;
      if (!text) throw new LlmUnavailableError("LLM returned no text content.");
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
  if (!apiKey) return null;

  const provider = (process.env.LLM_PROVIDER?.trim().toLowerCase() || "anthropic");
  const timeoutMs = Number(process.env.LLM_TIMEOUT_MS ?? 15000);

  if (provider === "gemini") {
    const model = process.env.LLM_MODEL?.trim();
    if (!model) return null; // no safe default — require an explicit, current model name
    return createGeminiProvider({
      apiKey,
      model,
      apiBaseUrl: process.env.LLM_API_URL?.trim() || undefined,
      timeoutMs,
    });
  }

  return createAnthropicProvider({
    apiKey,
    apiUrl: process.env.LLM_API_URL?.trim() || "https://api.anthropic.com/v1/messages",
    model: process.env.LLM_MODEL?.trim() || "claude-haiku-4-5-20251001",
    timeoutMs,
  });
}

export { TimeoutError };
