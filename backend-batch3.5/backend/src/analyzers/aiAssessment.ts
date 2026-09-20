import type {
  AIAssessment,
  AuthenticationAnalysis,
  CanonicalUrlIndicator,
  HeaderAnalysis,
  MLAssessment,
  ParsedEmail,
  RiskEvidenceItem,
  URLAnalysis,
} from "../schemas/types";
import { ZodError } from "zod";
import { aiContentScore, isGroundedConcern, parseLlmSemanticJson } from "../schemas/llmOutput";
import { LlmUnavailableError, TimeoutError, type LlmProvider } from "../services/llmClient";

/**
 * Prompt 6 (docs/audit/PHASE1-AUDIT.md, Finding 8). Architectural rule
 * restated here because it governs everything below: the deterministic
 * backend (riskEngine.ts) remains authoritative for overall score,
 * level, and classification. This model provides a SEPARATE semantic/
 * content assessment ("Semantic Content Assessment" in the UI) that
 * can contribute bounded evidence to the `content` risk category (see
 * isGroundedConcern() and the strength gating below) but never sets or
 * overrides canonical score/level/classification directly -- nothing
 * in this file writes to those fields, and nothing downstream reads
 * AIAssessment as a competing "overall status."
 */
const SYSTEM_PROMPT = `You are a phishing-analysis assistant producing a SEMANTIC CONTENT ASSESSMENT — a secondary, supporting signal. You are NOT the authoritative verdict: a separate deterministic system computes the email's overall risk score and classification from independent evidence, and your output does not override it.

Interpret ONLY the evidence JSON the user supplies. Do not invent IP reputation, domain reputation, GeoIP, ASN, ISP, hosting, DNS, WHOIS, blacklist matches, infrastructure relationships, or attacker identity. If a fact is not in the supplied evidence, do not claim it.

The "urls" field is already deduplicated and grouped by destination host (each entry is one host plus how many links pointed to it) — treat repeated links to the same host as ONE observation, never as multiple independent findings, and never restate it once per link.

None of the following are, by themselves, proof of phishing, credential harvesting, financial fraud, or account compromise — they are common in entirely legitimate bulk/marketing/forwarded email:
- percent-encoded URL characters
- multiple subdomains
- general URL complexity or length
- tracking parameters / marketing redirect links
- a Message-ID domain that differs from the sender domain
- the message being forwarded
- the email being promotional or containing marketing language

Do not infer credential harvesting when none is present in the evidence. Do not infer financial fraud when none is present. Do not infer account compromise without supporting evidence beyond promotional content or URL structure. Do not conclude phishing merely because an email is promotional.

For every reason you give, distinguish the OBSERVATION (what is factually present in the evidence) from its SECURITY SIGNIFICANCE (whether that observation actually indicates malicious intent) — a reason that is only an observation with no established significance is not a top reason.

At the same time, do not under-call a genuinely malicious promotional-style email: if the evidence shows an actual credential request, a financial request, or infrastructure indicators pointing to a harvesting/fraud destination, reflect that plainly and at high concern regardless of how promotional the surrounding language is.

Return a single JSON object with keys:
phishingIntent, credentialHarvesting, financialFraud, impersonation, socialEngineering (each a number 0-1, reflecting only what the evidence actually supports),
concernLevel ("none" | "low" | "medium" | "high"),
topReasons (array of up to 5 short strings, each an observation plus its security significance, consolidated — not one entry per link or per near-duplicate finding),
benignExplanation (string or null — a plausible non-malicious explanation for the observations, when one applies; null when none does; never fabricated to appear balanced),
confidence ("low" | "medium" | "high"),
attackType (string),
summary (string),
recommendedActions (array of strings).
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
  /** Canonical, host-grouped URL indicators (Prompt 4's
   *  IOCSet.canonicalUrlIndicators). Sending these instead of a raw,
   *  near-duplicate-heavy URL list is what makes the "already
   *  deduplicated and grouped" instruction in SYSTEM_PROMPT true rather
   *  than aspirational — the model is structurally unable to see 90
   *  near-identical tracking links, only "1 host, 90 occurrences". */
  canonicalUrlIndicators?: CanonicalUrlIndicator[];
}): string {
  const from = input.parsed.from[0];
  const replyTo = input.parsed.replyTo[0];
  const urls = input.canonicalUrlIndicators?.length
    ? input.canonicalUrlIndicators
        .slice(0, 10)
        .map((g) => ({ host: g.hostname, occurrenceCount: g.occurrenceCount, sampleUrls: g.sampleUrls }))
    : input.urlAnalysis.urls.slice(0, 10).map((u) => ({ host: u.domain, occurrenceCount: 1, sampleUrls: [u.url] }));

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
      // Already deduplicated and grouped by destination host — see
      // SYSTEM_PROMPT's instruction and the canonicalUrlIndicators doc
      // comment above.
      urls,
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
    concernLevel: null,
    topReasons: [],
    benignExplanation: null,
    confidence: null,
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
  canonicalUrlIndicators?: CanonicalUrlIndicator[];
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

    const parsed = parseLlmSemanticJson(raw);
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
      concernLevel: parsed.concernLevel ?? null,
      topReasons: parsed.topReasons ?? [],
      benignExplanation: parsed.benignExplanation ?? null,
      confidence: parsed.confidence ?? null,
      attackType: parsed.attackType,
      summary: parsed.summary,
      recommendedActions: parsed.recommendedActions,
      aiContentScore: score,
      provenance: "AI_INTERPRETATION",
    };

    const evidence: RiskEvidenceItem[] = [];
    if (score >= 40) {
      // Groundedness gate (schemas/llmOutput.ts's isGroundedConcern,
      // docs/audit/PHASE1-AUDIT.md Finding 8 / Prompt 6 requirements 1
      // and 8): a high score built only from phishingIntent/
      // impersonation/socialEngineering — exactly what percent-encoded
      // URLs, subdomains, a Message-ID mismatch, or forwarding can
      // inflate — is tagged "weak" (capped by riskEngine.ts's weak-only
      // ceiling, and on its own insufficient for classify()'s
      // "suspicious" fallback). A score grounded in an actual
      // credential- or financial-fraud claim is tagged "strong" and can
      // appropriately drive detection, preserving requirement 8's fake
      // anniversary/reward + credential-request case.
      const grounded = isGroundedConcern(parsed);
      evidence.push({
        type: "ai_semantic_phishing",
        severity: score >= 70 ? "high" : "medium",
        weight: Math.min(30, Math.round(score * 0.3)),
        message: `Semantic Content Assessment: AI content score ${score} (concern level: ${parsed.concernLevel ?? "unspecified"}; interpretive, not observed fact).`,
        evidence: {
          attackType: parsed.attackType,
          aiContentScore: score,
          concernLevel: parsed.concernLevel ?? null,
          topReasons: parsed.topReasons ?? [],
          grounded,
        },
        category: "content",
        provenance: "AI_INTERPRETATION",
        strength: grounded ? "strong" : "weak",
      });
    }

    return { aiAssessment, evidence };
  } catch (err) {
    // Structured, operationally-useful failure log (Prompt 10: keep
    // structured forensic/operational logs, remove only debug noise —
    // the success-path logging this function used to emit on every
    // call was removed for exactly that reason, this is not). Content
    // is deliberately bounded to error type/name and a short,
    // content-free message: Zod issue messages describe schema shape
    // problems only (e.g. "phishingIntent: Expected number, received
    // string"), never email content, so this is safe to log even
    // though the email itself may contain sensitive material.
    if (err instanceof TimeoutError) {
      console.error("[ai-assessment] assessAi failed at: provider.complete() — request timed out");
      return { aiAssessment: unavailableAi(emailId, "ERROR"), evidence: [] };
    }
    if (err instanceof LlmUnavailableError) {
      console.error(`[ai-assessment] assessAi failed at: provider.complete() — ${err.message}`);
      return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
    }
    if (err instanceof SyntaxError) {
      console.error(`[ai-assessment] assessAi failed at: JSON.parse() — ${err.message}`);
      return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
    }
    if (err instanceof ZodError) {
      const issues = err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ").slice(0, 300);
      console.error(`[ai-assessment] assessAi failed at: schema validation — ${issues}`);
      return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
    }
    console.error(
      `[ai-assessment] assessAi failed at: unexpected error — ${err instanceof Error ? err.constructor.name + ": " + err.message : String(err)}`
    );
    return { aiAssessment: unavailableAi(emailId, "UNAVAILABLE"), evidence: [] };
  }
}
