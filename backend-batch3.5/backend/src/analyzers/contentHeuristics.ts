import type { ParsedEmail, RiskEvidenceItem } from "../schemas/types";

// Deterministic keyword-based content signals. Batch 4 adds ML/LLM
// content evidence separately; this analyzer stays rule-only.
// Counting distinct matched keywords per category (not raw occurrences)
// avoids a single repeated word inflating the signal.
const KEYWORDS: Record<string, string[]> = {
  urgency: [
    "urgent",
    "immediately",
    "asap",
    "right away",
    "as soon as possible",
    "act now",
    "time sensitive",
    "expires",
    "expiring",
  ],
  credential_request: [
    "verify your account",
    "verify account",
    "confirm your identity",
    "confirm identity",
    "your password",
    "log in to",
    "sign in to confirm",
    "username and password",
  ],
  financial_request: [
    "wire transfer",
    "wire the funds",
    "process this payment",
    "bank account",
    "routing number",
    "gift card",
    "invoice attached",
    "make a payment",
  ],
  call_to_action: [
    "click here",
    "click the link",
    "download the attachment",
    "open the attachment",
    "verify now",
    "update now",
    "confirm now",
  ],
};

const CATEGORY_META: Record<
  keyof typeof KEYWORDS,
  { type: string; severity: "low" | "medium" | "high"; weight: number; label: string; strength: "weak" | "strong" }
> = {
  // Ordinary urgency/call-to-action copy is common in entirely
  // legitimate marketing and transactional mail on its own — weak.
  // Credential/financial requests specifically ask for something a
  // legitimate bulk sender essentially never asks for by email — strong.
  // See docs/audit/PHASE1-AUDIT.md, Finding 3.
  urgency: { type: "urgency_language", severity: "low", weight: 15, label: "urgency", strength: "weak" },
  credential_request: {
    type: "credential_request_language",
    severity: "high",
    weight: 25,
    label: "credential-request",
    strength: "strong",
  },
  financial_request: {
    type: "financial_request_language",
    severity: "high",
    weight: 25,
    label: "financial-request",
    strength: "strong",
  },
  call_to_action: {
    type: "call_to_action_language",
    severity: "medium",
    weight: 15,
    label: "call-to-action",
    strength: "weak",
  },
};

function matchedKeywords(text: string, keywords: string[]): string[] {
  return keywords.filter((kw) => text.includes(kw));
}

export interface ContentFeatureCounts {
  urgency: number;
  credential_request: number;
  financial_request: number;
  call_to_action: number;
}

export interface ContentHeuristicsResult {
  featureCounts: ContentFeatureCounts;
  evidence: RiskEvidenceItem[];
}

function stripHtmlTags(html: string): string {
  return html.replace(/<[^>]*>/g, " ");
}

/**
 * Deterministic keyword-based content signals. Each matched category
 * produces one evidence item (not one per keyword) — the risk engine
 * combines these with everything else via its non-additive aggregation,
 * so a single email mentioning "urgent" three times isn't scored
 * differently than one mentioning it once.
 */
export function analyzeContent(parsed: ParsedEmail): ContentHeuristicsResult {
  const subject = (parsed.subject ?? "").toLowerCase();
  const text = (parsed.body.text ?? "").toLowerCase();
  const html = parsed.body.html ? stripHtmlTags(parsed.body.html).toLowerCase() : "";
  const combined = `${subject}\n${text}\n${html}`;

  const featureCounts: ContentFeatureCounts = {
    urgency: 0,
    credential_request: 0,
    financial_request: 0,
    call_to_action: 0,
  };
  const evidence: RiskEvidenceItem[] = [];

  for (const key of Object.keys(featureCounts) as (keyof ContentFeatureCounts)[]) {
    const matched = matchedKeywords(combined, KEYWORDS[key]);
    featureCounts[key] = matched.length;
    if (matched.length > 0) {
      const meta = CATEGORY_META[key];
      evidence.push({
        type: meta.type,
        severity: meta.severity,
        weight: meta.weight,
        message: `Email content contains ${meta.label} language (matched: ${matched.slice(0, 3).join(", ")}${
          matched.length > 3 ? ", ..." : ""
        }).`,
        evidence: { matchedKeywords: matched },
        category: "content",
        provenance: "DETERMINISTIC_ANALYSIS",
        strength: meta.strength,
      });
    }
  }

  return { featureCounts, evidence };
}
