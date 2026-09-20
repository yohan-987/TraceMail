import { z } from "zod";

const unitInterval = z.number().min(0).max(1);

/**
 * Prompt 6: added concernLevel/topReasons/benignExplanation/confidence
 * as explicit, structured fields so the model reports a qualitative
 * "Semantic Content Assessment" (observation + significance + benign
 * counter-explanation + confidence) rather than only five raw 0-1
 * scores and a single free-text summary. The five intent scores and
 * aiContentScore()'s formula are UNCHANGED -- this is additive, not a
 * rescoring of the existing numeric model.
 *
 * Prompt 11 follow-up fix (discovered via a pre-existing test,
 * scan-batch4.test.ts, never visible in any repomix export this
 * project received): these four fields were originally REQUIRED,
 * which broke that test's mocked LLM response -- written before
 * Prompt 6 existed, so it naturally omits fields that didn't exist
 * yet. A schema this strict silently degraded a working AI assessment
 * to fully UNAVAILABLE the moment any caller (real model included, if
 * it ever omits one of these) didn't supply every new field. Made
 * optional with safe, honest fallbacks in parseLlmSemanticJson()
 * below -- "we don't know" (undefined/none/empty), never a fabricated
 * value -- so an older or partial response degrades gracefully to
 * "no qualitative read available" instead of failing validation
 * entirely and discarding the five numeric scores it DID provide.
 */
export const llmSemanticSchema = z.object({
  phishingIntent: unitInterval,
  credentialHarvesting: unitInterval,
  financialFraud: unitInterval,
  impersonation: unitInterval,
  socialEngineering: unitInterval,
  concernLevel: z.enum(["none", "low", "medium", "high"]).optional(),
  // Each entry should be one OBSERVATION plus its security significance
  // (e.g. "Multiple tracking links to one marketing domain -- common in
  // legitimate bulk email, not independently suspicious"), not a raw
  // repetition of supplied evidence. Capped at 5: this is meant to be a
  // consolidated top-reasons list, not an itemized re-statement of
  // everything in the evidence JSON.
  topReasons: z.array(z.string().min(1).max(240)).max(5).optional(),
  // Null when no benign explanation plausibly applies -- never required
  // to be non-null, so the model isn't pressured into manufacturing a
  // false-balance excuse for a genuinely malicious email.
  benignExplanation: z.string().max(500).nullable().optional(),
  confidence: z.enum(["low", "medium", "high"]).optional(),
  attackType: z.string().min(1).max(80),
  summary: z.string().min(1).max(2000),
  recommendedActions: z.array(z.string().max(300)).max(12),
});

export type LlmSemanticOutput = z.infer<typeof llmSemanticSchema>;

export function parseLlmSemanticJson(raw: string): LlmSemanticOutput {
  const trimmed = raw.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const jsonText = fenced ? fenced[1].trim() : trimmed;
  const parsed: unknown = JSON.parse(jsonText);
  return llmSemanticSchema.parse(parsed);
}

/** UNCHANGED formula (Prompt 6 does not alter the numeric model). */
export function aiContentScore(output: LlmSemanticOutput): number {
  return Math.round(
    100 *
      (0.3 * output.phishingIntent +
        0.2 * output.credentialHarvesting +
        0.2 * output.financialFraud +
        0.2 * output.impersonation +
        0.1 * output.socialEngineering)
  );
}

/**
 * Groundedness gate (docs/audit/PHASE1-AUDIT.md, Finding 8; Prompt 6,
 * requirements 1 and 8): decides whether the LLM's semantic read is
 * treated as `strength: "strong"` evidence (see riskEngine.ts's
 * weak-only category ceiling) or `"weak"`.
 *
 * A HIGH phishingIntent/impersonation/socialEngineering score alone is
 * NOT enough to count as strong -- those are exactly the scores an LLM
 * can inflate purely from percent-encoded URLs, multiple subdomains,
 * a Message-ID mismatch, or forwarding, none of which are standalone
 * proof of phishing (requirement 1). Grounding requires the model to
 * assert a SPECIFIC, falsifiable claim -- credential harvesting or
 * financial fraud -- at a real level, which is what actually
 * distinguishes "this asks for your password" from "this looks like
 * marketing with unusual link formatting."
 *
 * This is deliberately conservative in the same direction as
 * requirement 8: a fake anniversary/reward email that ACTUALLY asks
 * for credentials still clears this gate (credentialHarvesting will be
 * high), so real malicious promotional phishing is not suppressed --
 * only the false-positive path (stylistic suspicion with no concrete
 * credential/financial ask) is kept weak.
 */
const GROUNDED_THRESHOLD = 0.5;

export function isGroundedConcern(output: LlmSemanticOutput): boolean {
  return output.credentialHarvesting >= GROUNDED_THRESHOLD || output.financialFraud >= GROUNDED_THRESHOLD;
}
