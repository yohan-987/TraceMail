import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLlmSemanticJson, aiContentScore } from "../src/schemas/llmOutput";
import { assessAi, buildLlmUserPayload, unavailableAi } from "../src/analyzers/aiAssessment";
import { TimeoutError, LlmUnavailableError, type LlmProvider } from "../src/services/llmClient";
import type {
  AuthenticationAnalysis,
  HeaderAnalysis,
  MLAssessment,
  ParsedEmail,
  URLAnalysis,
} from "../src/schemas/types";

const parsedEmail: ParsedEmail = {
  emailId: "EMAIL-AI",
  subject: "Verify account",
  from: [{ displayName: "PayPal", email: "a@b.com", localPart: "a", domain: "b.com" }],
  to: [],
  cc: [],
  bcc: [],
  replyTo: [{ displayName: null, email: "x@gmail.com", localPart: "x", domain: "gmail.com" }],
  returnPath: [],
  date: null,
  messageId: null,
  headers: { normalized: {}, raw: [] },
  body: { text: "Please verify your account.", html: null },
  attachments: [],
};

const headerAnalysis: HeaderAnalysis = {
  emailId: "EMAIL-AI",
  anomalies: [
    {
      type: "spf_fail",
      severity: "high",
      weight: 25,
      message: "SPF failed.",
      evidence: {},
      category: "technical",
      provenance: "DETERMINISTIC_ANALYSIS",
    },
  ],
  receivedChain: [],
  status: "SUSPICIOUS",
};

const authentication: AuthenticationAnalysis = {
  emailId: "EMAIL-AI",
  spf: { result: "fail", raw: "spf=fail" },
  dkim: { result: "fail", raw: "dkim=fail" },
  dmarc: { result: "fail", policy: "reject", raw: "dmarc=fail" },
};

const urlAnalysis: URLAnalysis = {
  emailId: "EMAIL-AI",
  urls: [
    {
      url: "http://example.com/login",
      hostname: "example.com",
      domain: "example.com",
      isHttps: false,
      urlLength: 24,
      subdomainLength: 0,
      pathLength: 6,
      queryLength: 0,
      hasIpHost: false,
      hasAtSymbol: false,
      hasEncodedCharacters: false,
      hasMultipleSubdomains: false,
      isShortened: false,
      riskNotes: [],
    },
  ],
};

const mlAssessment: MLAssessment = {
  emailId: "EMAIL-AI",
  model: "tfidf-logistic-v1",
  modelVersion: "1.0",
  classification: "phishing",
  probability: 0.9,
  status: "AVAILABLE",
};

function baseArgs(provider: LlmProvider | null) {
  return {
    emailId: "EMAIL-AI",
    parsed: parsedEmail,
    headerAnalysis,
    authentication,
    urlAnalysis,
    mlAssessment,
    provider,
  };
}

test("valid structured LLM JSON is accepted and scored", async () => {
  const payload = {
    phishingIntent: 0.94,
    credentialHarvesting: 0.82,
    financialFraud: 0.12,
    impersonation: 0.89,
    socialEngineering: 0.93,
    attackType: "phishing",
    summary: "Credential harvesting impersonation.",
    recommendedActions: ["Do not click the link"],
  };
  const provider: LlmProvider = {
    complete: async () => JSON.stringify(payload),
  };
  const { aiAssessment, evidence } = await assessAi(baseArgs(provider));
  assert.equal(aiAssessment.status, "AVAILABLE");
  assert.equal(aiAssessment.phishingIntent, 0.94);
  assert.equal(aiAssessment.aiContentScore, aiContentScore(payload));
  assert.equal(aiAssessment.provenance, "AI_INTERPRETATION");
  assert.ok(evidence.length >= 1);
  assert.equal(evidence[0].provenance, "AI_INTERPRETATION");
});

test("malformed LLM output is UNAVAILABLE and does not fabricate scores", async () => {
  const provider: LlmProvider = { complete: async () => "not json at all" };
  const { aiAssessment, evidence } = await assessAi(baseArgs(provider));
  assert.equal(aiAssessment.status, "UNAVAILABLE");
  assert.equal(aiAssessment.phishingIntent, null);
  assert.equal(evidence.length, 0);
});

test("out-of-range probabilities are rejected", () => {
  assert.throws(() =>
    parseLlmSemanticJson(
      JSON.stringify({
        phishingIntent: 1.5,
        credentialHarvesting: 0.1,
        financialFraud: 0.1,
        impersonation: 0.1,
        socialEngineering: 0.1,
        attackType: "phishing",
        summary: "x",
        recommendedActions: [],
      })
    )
  );
});

test("timeout is ERROR", async () => {
  const provider: LlmProvider = {
    complete: async () => {
      throw new TimeoutError();
    },
  };
  const { aiAssessment } = await assessAi(baseArgs(provider));
  assert.equal(aiAssessment.status, "ERROR");
});

test("unavailable provider stays UNAVAILABLE", async () => {
  const { aiAssessment } = await assessAi(baseArgs(null));
  assert.equal(aiAssessment.status, "UNAVAILABLE");
  const { aiAssessment: failed } = await assessAi(
    baseArgs({
      complete: async () => {
        throw new LlmUnavailableError();
      },
    })
  );
  assert.equal(failed.status, "UNAVAILABLE");
});

test("LLM payload does not include GeoIP/ASN/ISP/reputation fields", () => {
  const payload = buildLlmUserPayload({
    parsed: parsedEmail,
    headerAnalysis,
    authentication,
    urlAnalysis,
    mlAssessment,
  });
  const parsed = JSON.parse(payload) as Record<string, unknown>;
  assert.equal("asn" in parsed, false);
  assert.equal("geoip" in parsed, false);
  assert.equal("isp" in parsed, false);
  assert.equal("blacklist" in parsed, false);
  assert.ok(payload.includes("Verify account"));
  assert.ok(payload.includes("spf_fail"));
});

test("unavailableAi helper has no invented intent scores", () => {
  const a = unavailableAi("EMAIL-X");
  assert.equal(a.summary, null);
  assert.equal(a.phishingIntent, null);
});
