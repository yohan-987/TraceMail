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

export function llmProviderFromEnv(): LlmProvider | null {
  const apiKey = process.env.LLM_API_KEY?.trim();
  if (!apiKey) return null;
  return createAnthropicProvider({
    apiKey,
    apiUrl: process.env.LLM_API_URL?.trim() || "https://api.anthropic.com/v1/messages",
    model: process.env.LLM_MODEL?.trim() || "claude-haiku-4-5-20251001",
    timeoutMs: Number(process.env.LLM_TIMEOUT_MS ?? 15000),
  });
}

export { TimeoutError };
