import { test } from "node:test";
import assert from "node:assert/strict";
import { assessAi, buildLlmUserPayload, unavailableAi } from "../src/analyzers/aiAssessment";
import type {
  AuthenticationAnalysis,
  HeaderAnalysis,
  MLAssessment,
  ParsedEmail,
  URLAnalysis,
  CanonicalUrlIndicator,
} from "../src/schemas/types";
import type { LlmProvider } from "../src/services/llmClient";

// Prompt 6 regression tests: the LLM/Gemini reasoning fix. Since no LLM
// API is reachable in this sandboxed, network-disabled environment,
// these tests exercise OUR handling of LLM output (payload
// construction, schema validation, groundedness-based evidence
// strength gating) against a mocked LlmProvider returning canned JSON
// for each scenario — they do NOT verify a real model's actual
// reasoning quality, which cannot be checked here. That distinction is
// deliberate and stated, not glossed over.

function baseParsed(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: "ai-test",
    subject: "Subject",
    from: [{ displayName: "Sender", email: "sender@example.com", localPart: "sender", domain: "example.com" }],
    to: [], cc: [], bcc: [], replyTo: [], returnPath: [],
    date: null, messageId: "<a@example.com>",
    headers: { normalized: {}, raw: [] },
    body: { text: "body", html: null },
    attachments: [],
    ...overrides,
  } as ParsedEmail;
}

const headerAnalysis = { emailId: "t", status: "AVAILABLE", anomalies: [], receivedChain: [] } as unknown as HeaderAnalysis;
const authentication = {
  emailId: "t",
  spf: { result: "pass", raw: null },
  dkim: { result: "pass", raw: null },
  dmarc: { result: "pass", policy: null, raw: null },
} as AuthenticationAnalysis;
const urlAnalysis = { emailId: "t", urls: [] } as unknown as URLAnalysis;
const mlAssessment = { emailId: "t", status: "UNAVAILABLE", classification: null, probability: null } as unknown as MLAssessment;

function mockProvider(jsonOutput: object): LlmProvider {
  return {
    async complete() {
      return JSON.stringify(jsonOutput);
    },
  };
}

function scenarioOutput(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    phishingIntent: 0,
    credentialHarvesting: 0,
    financialFraud: 0,
    impersonation: 0,
    socialEngineering: 0,
    concernLevel: "none",
    topReasons: [],
    benignExplanation: null,
    confidence: "medium",
    attackType: "None",
    summary: "summary",
    recommendedActions: [],
    ...overrides,
  };
}

async function run(jsonOutput: object, canonicalUrlIndicators?: CanonicalUrlIndicator[]) {
  return assessAi({
    emailId: "ai-test",
    parsed: baseParsed(),
    headerAnalysis,
    authentication,
    urlAnalysis,
    mlAssessment,
    canonicalUrlIndicators,
    provider: mockProvider(jsonOutput),
  });
}

// A. Legitimate HoYoverse/Genshin-style anniversary mail: an LLM that
// (wrongly) reads high stylistic suspicion from URL/Message-ID
// structure alone must be tagged WEAK, not strong.
test("A: legitimate anniversary mail — high phishingIntent/impersonation with NO credential/financial claim is capped as weak evidence", async () => {
  const { aiAssessment, evidence } = await run(
    scenarioOutput({ phishingIntent: 0.9, impersonation: 0.8, socialEngineering: 0.7, concernLevel: "high" })
  );
  assert.equal(aiAssessment.status, "AVAILABLE");
  assert.ok((aiAssessment.aiContentScore ?? 0) >= 40, "test setup should cross the evidence gate");
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].strength, "weak", "stylistic-only concern must not count as strong evidence");
});

// B. Fake Genshin-style phishing mail: real credential harvesting ->
// strong evidence, detection preserved.
test("B: fake anniversary phishing mail with real credential harvesting is tagged strong", async () => {
  const { evidence } = await run(
    scenarioOutput({
      phishingIntent: 0.8,
      credentialHarvesting: 0.9,
      impersonation: 0.7,
      concernLevel: "high",
    })
  );
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].strength, "strong");
});

// C. Ordinary newsletter: no concern, no evidence at all.
test("C: ordinary newsletter with no concerning signals produces no AI evidence", async () => {
  const { aiAssessment, evidence } = await run(scenarioOutput());
  assert.equal(evidence.length, 0);
  assert.equal(aiAssessment.concernLevel, "none");
});

// D. Credential-harvesting email (financial-fraud variant): grounded
// via financialFraud instead of credentialHarvesting.
test("D: financial-fraud claim also grounds the evidence as strong", async () => {
  const { evidence } = await run(scenarioOutput({ phishingIntent: 0.9, financialFraud: 0.8, concernLevel: "high" }));
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].strength, "strong");
});

// E. Suspicious infrastructure + benign-looking text: this analyzer
// only ever receives content/header evidence, never infrastructure —
// confirms it does not fabricate concern it has no basis for.
test("E: benign content text produces low/no AI concern regardless of what infrastructure evidence might exist elsewhere", async () => {
  const { aiAssessment, evidence } = await run(scenarioOutput({ concernLevel: "none" }));
  assert.equal(evidence.length, 0);
  assert.equal(aiAssessment.confidence, "medium");
});

// F. Benign infrastructure + dangerous social-engineering text: a
// genuine credential ask must still be flagged strong even though this
// analyzer has no visibility into (and is not suppressed by) infra.
test("F: dangerous social-engineering/credential-request text is still flagged strong, independent of infrastructure", async () => {
  const { evidence } = await run(
    scenarioOutput({ phishingIntent: 0.8, socialEngineering: 0.8, credentialHarvesting: 0.85, concernLevel: "high" })
  );
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].strength, "strong");
});

test("buildLlmUserPayload uses canonical host-grouped indicators when provided, not raw near-duplicate URLs", () => {
  const canonical: CanonicalUrlIndicator[] = [
    { hostname: "click.mail.brand.example", occurrenceCount: 60, sampleUrls: ["https://click.mail.brand.example/a"] },
  ];
  const payload = JSON.parse(
    buildLlmUserPayload({ parsed: baseParsed(), headerAnalysis, authentication, urlAnalysis, mlAssessment, canonicalUrlIndicators: canonical })
  );
  assert.equal(payload.urls.length, 1, "60 near-duplicate links to one host must appear as ONE entry in the LLM payload");
  assert.equal(payload.urls[0].occurrenceCount, 60);
  assert.equal(payload.urls[0].host, "click.mail.brand.example");
});

test("buildLlmUserPayload falls back to per-URL entries when no canonical indicators are supplied", () => {
  const rawUrlAnalysis = { emailId: "t", urls: [{ url: "https://a.example.com/x", domain: "a.example.com" }] } as unknown as URLAnalysis;
  const payload = JSON.parse(
    buildLlmUserPayload({ parsed: baseParsed(), headerAnalysis, authentication, urlAnalysis: rawUrlAnalysis, mlAssessment })
  );
  assert.equal(payload.urls.length, 1);
  assert.equal(payload.urls[0].host, "a.example.com");
});

test("Prompt 11 fix: a pre-Prompt-6-style mock LLM response (no concernLevel/topReasons/benignExplanation/confidence) still produces an AVAILABLE assessment, not UNAVAILABLE", async () => {
  const preExistingMockResponse = {
    phishingIntent: 0.1,
    credentialHarvesting: 0,
    financialFraud: 0,
    impersonation: 0.1,
    socialEngineering: 0.1,
    attackType: "None",
    summary: "Appears to be routine marketing email.",
    recommendedActions: [],
  };
  const { aiAssessment, evidence } = await run(preExistingMockResponse);
  assert.equal(
    aiAssessment.status,
    "AVAILABLE",
    "a pre-Prompt-6 mock/response missing the new qualitative fields must not degrade the whole assessment to UNAVAILABLE"
  );
  assert.equal(aiAssessment.concernLevel, null, "missing field reported honestly as null, never fabricated");
  assert.deepEqual(aiAssessment.topReasons, []);
  assert.equal(evidence.length, 0, "test setup's scores are all low, so no evidence gate crossed -- unrelated to this fix");
});

test("no provider configured still returns a structurally valid unavailable assessment with the new fields present", () => {
  const result = unavailableAi("t");
  assert.equal(result.concernLevel, null);
  assert.deepEqual(result.topReasons, []);
  assert.equal(result.confidence, null);
});
