import { analyzeContent } from "../analyzers/contentHeuristics";
import type { ParsedEmail } from "../schemas/types";

/**
 * ML upgrade — leakage fix (see docs/ml/AUDIT.md, "Finding 1").
 *
 * Root cause: the original LABELED_EMAILS rows carried hand-authored
 * `urlCount` / `urgency` / `credentialRequest` / `financialRequest`
 * numbers that were set by whoever wrote the example, not computed from
 * its text. Auditing them against the real production feature extractor
 * (`analyzeContent()` in contentHeuristics.ts) showed 23 of 81 rows
 * (~28%) disagreed with what the deployed pipeline would actually
 * compute for that same text — and the hand-set numbers were *never*
 * non-zero for a "ham" row and *never* zero for a "phish" row, i.e. they
 * were a near-perfect proxy for the label itself, constructed by the
 * dataset author rather than measured.
 *
 * A model trained on that combination learns to trust a feature that
 * behaves nothing like it will at inference time, where these same
 * fields are populated by keyword/regex heuristics run over real text
 * and are noisy. That mismatch is not classic train/test leakage (train
 * and test are still disjoint), but it is the same failure in effect:
 * the benchmarked score reflects a shortcut that will not survive
 * contact with real email.
 *
 * The fix: compute these four fields the same way for every training
 * row as the production path does, via `analyzeContent()` for the three
 * language-based counts, and a documented regex stand-in for URL count.
 *
 * Limitation, stated plainly: the real production URL count does not
 * live in this snapshot (it is produced by the URL/domain analyzer,
 * which was not included in the 19-file ML handoff). `countUrlsHeuristic`
 * below is a simple, documented regex counter used ONLY to keep training
 * features internally consistent with each other; it is not a claim
 * about what the production URL/domain analyzer does.
 */
export function countUrlsHeuristic(text: string): number {
  const matches = text.match(/https?:\/\/\S+/gi);
  return matches ? matches.length : 0;
}

export interface DerivedStructuredFeatures {
  urlCount: number;
  urgency: number;
  credentialRequest: number;
  financialRequest: number;
}

/**
 * Derives the four structured ML features from raw subject/body text
 * using the exact same content-heuristics function the production
 * pipeline calls (see mlClassifier.ts `mlInputFromEmail`), so training
 * data and inference data are computed the same way.
 */
export function deriveStructuredFeatures(subject: string, body: string): DerivedStructuredFeatures {
  // analyzeContent() only reads `.subject` and `.body.{text,html}` off a
  // ParsedEmail — the other fields aren't relevant for training-time
  // feature derivation, so a minimal shape is cast rather than fabricating
  // realistic header/attachment data that would never be read.
  const minimalParsedEmail = {
    subject,
    body: { text: body, html: null },
  } as unknown as ParsedEmail;
  const { featureCounts } = analyzeContent(minimalParsedEmail);

  return {
    urlCount: countUrlsHeuristic(`${subject}\n${body}`),
    urgency: featureCounts.urgency,
    credentialRequest: featureCounts.credential_request,
    financialRequest: featureCounts.financial_request,
  };
}
