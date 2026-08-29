import type {
  AIAssessment,
  AuthenticationAnalysis,
  HeaderAnalysis,
  MLAssessment,
  ParsedEmail,
  RiskEvidenceItem,
  URLAnalysis,
} from "../schemas/types";
import { ZodError } from "zod";
import { aiContentScore, parseLlmSemanticJson } from "../schemas/llmOutput";
import { LlmUnavailableError, TimeoutError, type LlmProvider } from "../services/llmClient";

const SYSTEM_PROMPT = `You are a phishing-analysis assistant. Interpret ONLY the evidence JSON the user supplies.
Return a single JSON object with keys:
phishingIntent, credentialHarvesting, financialFraud, impersonation, socialEngineering (each a number 0-1),
attackType (string), summary (string), recommendedActions (array of strings).
Do NOT invent IP reputation, domain reputation, GeoIP, ASN, ISP, hosting, DNS, WHOIS, blacklist matches, infrastructure relationships, or attacker identity.
If a fact is not in the supplied evidence, do not claim it.
Scores must be in 0-1.`;

function clipBody(text: string, max = 4000): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}\n[truncated]`;
}

export function buildLlmUserPayload(input: {
  parsed: ParsedEmail;
  headerAnalysis: HeaderAnalysis;
  authentication: AuthenticationAnalysis;
  urlAnalysis: URLAnalysis;
  mlAssessment: MLAssessment;
}): string {
  const from = input.parsed.from[0];
  const replyTo = input.parsed.replyTo[0];
  return JSON.stringify(
    {
      subject: input.parsed.subject,
      from: { displayName: from?.displayName ?? null, email: from?.email ?? null },
      replyTo: { displayName: replyTo?.displayName ?? null, email: replyTo?.email ?? null },
      bodyText: clipBody(input.parsed.body.text ?? ""),
      technicalEvidence: input.headerAnalysis.anomalies.slice(0, 12).map((a) => ({
        type: a.type,
        message: a.message,
        category: a.category,
      })),
      authentication: {
        spf: input.authentication.spf.result,
        dkim: input.authentication.dkim.result,
        dmarc: input.authentication.dmarc.result,
      },
      urls: input.urlAnalysis.urls.slice(0, 10).map((u) => u.url),
      domains: [...new Set(input.urlAnalysis.urls.map((u) => u.domain))].slice(0, 10),
      ml: {
        status: input.mlAssessment.status,
        classification: input.mlAssessment.classification,
        probability: input.mlAssessment.probability,
      },
    },
    null,
    2
  );
}

export function unavailableAi(emailId: string, status: AIAssessment["status"] = "UNAVAILABLE"): AIAssessment {
  return {
    emailId,
    status,
    phishingIntent: null,
    credentialHarvesting: null,
    financialFraud: null,
    impersonation: null,
    socialEngineering: null,
    malwareDelivery: null,
    attackType: null,
    summary: null,
    recommendedActions: [],
    aiContentScore: null,
    provenance: "AI_INTERPRETATION",
  };
}

export async function assessAi(options: {
  emailId: string;
  parsed: ParsedEmail;
  headerAnalysis: HeaderAnalysis;
  authentication: AuthenticationAnalysis;
  urlAnalysis: URLAnalysis;
  mlAssessment: MLAssessment;
  provider: LlmProvider | null;
}): Promise<{ aiAssessment: AIAssessment; evidence: RiskEvidenceItem[] }> {
  const { emailId, provider } = options;
  if (!provider) {
    return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
  }

  try {
    const raw = await provider.complete({
      system: SYSTEM_PROMPT,
      user: buildLlmUserPayload(options),
    });

    // TEMPORARY SAFE DIAGNOSTIC — length and a structural shape check
    // only, never the actual response text (the model's summary can
    // echo fragments of the email, so treat it the same as email
    // content for logging purposes).
    console.error(
      `[ai-debug] LLM raw response length: ${raw.length} | starts with '{': ${raw.trim().startsWith("{")}`
    );

    const parsed = parseLlmSemanticJson(raw);
    console.error("[ai-debug] JSON parse + schema validation: OK");
    const score = aiContentScore(parsed);
    const aiAssessment: AIAssessment = {
      emailId,
      status: "AVAILABLE",
      phishingIntent: parsed.phishingIntent,
      credentialHarvesting: parsed.credentialHarvesting,
      financialFraud: parsed.financialFraud,
      impersonation: parsed.impersonation,
      socialEngineering: parsed.socialEngineering,
      malwareDelivery: null,
      attackType: parsed.attackType,
      summary: parsed.summary,
      recommendedActions: parsed.recommendedActions,
      aiContentScore: score,
      provenance: "AI_INTERPRETATION",
    };

    const evidence: RiskEvidenceItem[] = [];
    if (score >= 40) {
      evidence.push({
        type: "ai_semantic_phishing",
        severity: score >= 70 ? "high" : "medium",
        weight: Math.min(30, Math.round(score * 0.3)),
        message: `LLM semantic analysis produced an AI content score of ${score} (interpretive, not observed fact).`,
        evidence: {
          attackType: parsed.attackType,
          aiContentScore: score,
          phishingIntent: parsed.phishingIntent,
        },
        category: "content",
        provenance: "AI_INTERPRETATION",
      });
    }

    return { aiAssessment, evidence };
  } catch (err) {
    // TEMPORARY SAFE DIAGNOSTIC — error type/name and a bounded,
    // content-free message only. Zod issue messages describe schema
    // shape problems (e.g. "phishingIntent: Expected number, received
    // string"), never email content, so a truncated summary is safe.
    if (err instanceof TimeoutError) {
      console.error("[ai-debug] assessAi failed at: provider.complete() — request timed out");
      return { aiAssessment: unavailableAi(emailId, "ERROR"), evidence: [] };
    }
    if (err instanceof LlmUnavailableError) {
      console.error(`[ai-debug] assessAi failed at: provider.complete() — ${err.message}`);
      return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
    }
    if (err instanceof SyntaxError) {
      console.error(`[ai-debug] assessAi failed at: JSON.parse() — ${err.message}`);
      return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
    }
    if (err instanceof ZodError) {
      const issues = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ").slice(0, 300);
      console.error(`[ai-debug] assessAi failed at: schema validation — ${issues}`);
      return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
    }
    console.error(
      `[ai-debug] assessAi failed at: unexpected error — ${err instanceof Error ? err.constructor.name + ": " + err.message : String(err)}`
    );
    return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
  }
}
