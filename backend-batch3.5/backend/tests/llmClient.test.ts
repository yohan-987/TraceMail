import { test } from "node:test";
import assert from "node:assert/strict";
import { createGeminiProvider, llmProviderFromEnv } from "../src/services/llmClient";

function withEnv(vars: Record<string, string | undefined>, fn: () => void | Promise<void>) {
  const previous: Record<string, string | undefined> = {};
  for (const key of Object.keys(vars)) previous[key] = process.env[key];
  for (const [key, value] of Object.entries(vars)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  return Promise.resolve(fn()).finally(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

function fakeFetch(status: number, body: unknown): typeof fetch {
  return (async () =>
    ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    }) as Response) as typeof fetch;
}

test("llmProviderFromEnv returns null when no API key is configured", async () => {
  await withEnv({ LLM_API_KEY: undefined, LLM_PROVIDER: undefined }, () => {
    assert.equal(llmProviderFromEnv(), null);
  });
});

test("llmProviderFromEnv defaults to the Anthropic provider when LLM_PROVIDER is unset (preserves prior behavior)", async () => {
  await withEnv(
    { LLM_API_KEY: "test-key", LLM_PROVIDER: undefined, LLM_MODEL: undefined, LLM_API_URL: undefined },
    () => {
      const provider = llmProviderFromEnv();
      assert.ok(provider, "a provider must be returned when an API key is present");
    }
  );
});

test("llmProviderFromEnv requires an explicit LLM_MODEL for Gemini (no hardcoded/guessed model default)", async () => {
  await withEnv(
    { LLM_API_KEY: "test-key", LLM_PROVIDER: "gemini", LLM_MODEL: undefined },
    () => {
      assert.equal(llmProviderFromEnv(), null);
    }
  );
});

test("llmProviderFromEnv builds a Gemini provider once LLM_PROVIDER and LLM_MODEL are both configured", async () => {
  await withEnv(
    { LLM_API_KEY: "test-key", LLM_PROVIDER: "gemini", LLM_MODEL: "gemini-2.5-flash" },
    () => {
      const provider = llmProviderFromEnv();
      assert.ok(provider);
    }
  );
});

test("llmProviderFromEnv is case-insensitive for LLM_PROVIDER", async () => {
  await withEnv(
    { LLM_API_KEY: "test-key", LLM_PROVIDER: "GEMINI", LLM_MODEL: "gemini-2.5-flash" },
    () => {
      assert.ok(llmProviderFromEnv());
    }
  );
});

test("createGeminiProvider sends the API key as a query param and system+user as Gemini contents, and parses candidates[0].content.parts[].text", async () => {
  let capturedUrl = "";
  let capturedBody: any = null;
  const fetchImpl = (async (url: string, init: RequestInit) => {
    capturedUrl = url;
    capturedBody = JSON.parse(init.body as string);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        candidates: [{ content: { parts: [{ text: '{"summary":"test"}' }] } }],
      }),
    } as Response;
  }) as typeof fetch;

  const provider = createGeminiProvider({
    apiKey: "secret-key",
    model: "gemini-2.5-flash",
    fetchImpl,
  });

  const text = await provider.complete({ system: "sys-prompt", user: "user-payload" });

  assert.equal(text, '{"summary":"test"}');
  assert.ok(capturedUrl.includes("gemini-2.5-flash:generateContent"));
  assert.ok(capturedUrl.includes("key=secret-key"));
  assert.equal(capturedBody.systemInstruction.parts[0].text, "sys-prompt");
  assert.equal(capturedBody.contents[0].parts[0].text, "user-payload");
});

test("createGeminiProvider throws LlmUnavailableError on a non-2xx response", async () => {
  const provider = createGeminiProvider({
    apiKey: "secret-key",
    model: "gemini-2.5-flash",
    fetchImpl: fakeFetch(500, {}),
  });
  await assert.rejects(() => provider.complete({ system: "s", user: "u" }));
});

test("createGeminiProvider throws when the response has no usable text", async () => {
  const provider = createGeminiProvider({
    apiKey: "secret-key",
    model: "gemini-2.5-flash",
    fetchImpl: fakeFetch(200, { candidates: [] }),
  });
  await assert.rejects(() => provider.complete({ system: "s", user: "u" }));
});

test("createGeminiProvider respects an overridden apiBaseUrl without hardcoding it", async () => {
  let capturedUrl = "";
  const fetchImpl = (async (url: string) => {
    capturedUrl = url;
    return { ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text: "ok" }] } }] }) } as Response;
  }) as typeof fetch;

  const provider = createGeminiProvider({
    apiKey: "k",
    model: "gemini-2.5-flash",
    apiBaseUrl: "https://custom-proxy.example.com/models",
    fetchImpl,
  });
  await provider.complete({ system: "s", user: "u" });
  assert.ok(capturedUrl.startsWith("https://custom-proxy.example.com/models/"));
});
