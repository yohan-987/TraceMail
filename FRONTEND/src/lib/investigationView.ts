/**
 * Prompt 12 — AI Investigation UI redesign: presentation-only helpers.
 *
 * Kept in a dependency-free module (no React, no project imports, only
 * erasable TypeScript syntax) so it can be unit-tested directly with
 * `node --test` and so the page component stays purely declarative.
 *
 * NOTHING in here computes, re-weights or re-classifies risk. Every
 * number that reaches the screen is a backend value passed through
 * clamping/rounding for display, or a selection between backend values
 * (see resolveRiskDimensions). The plain-English explanation builders
 * only describe values that are actually on screen and never assert more
 * than the underlying evidence supports.
 */

// ---------------------------------------------------------------------
// Availability / number formatting
// ---------------------------------------------------------------------

export type AvailabilityStatus = 'Available' | 'Unavailable' | 'Inconclusive';

export function normalizeAvailability(value: unknown): AvailabilityStatus {
  const normalized = String(value ?? '').toLowerCase();
  switch (normalized) {
    case 'available':
    case 'success':
    case 'ok':
      return 'Available';
    case 'inconclusive':
      return 'Inconclusive';
    default:
      return 'Unavailable';
  }
}

/** A backend 0-100 score for display: finite numbers only, clamped and rounded. */
export function asScore(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return Math.round(Math.max(0, Math.min(100, value)));
}

/** A backend 0-1 fraction as a whole percentage (0-100), or null. */
export function fractionToPercent(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return Math.round(Math.max(0, Math.min(1, value)) * 100);
}

/** Backend normally uses 0-1 probability; 0-100 values are tolerated
 *  without changing their meaning (unchanged Prompt 9/10 behaviour). */
export function probabilityToPercent(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  const pct = value <= 1 ? value * 100 : value;
  return Math.round(Math.max(0, Math.min(100, pct)));
}

export function percentLabel(pct: number | null): string {
  return pct === null ? 'UNAVAILABLE' : `${pct}%`;
}

/** SNAKE_CASE archetype -> Title Case ("ANONYMIZED_INFRASTRUCTURE" -> "Anonymized Infrastructure"). */
export function archetypeLabel(value: string): string {
  return value
    .toLowerCase()
    .split('_')
    .map((word) => (word ? word.charAt(0).toUpperCase() + word.slice(1) : word))
    .join(' ');
}

/** Expands the backend's internal model slug into the human-readable
 *  family name; falls back to the raw slug for anything unrecognised so
 *  it never silently mislabels an unknown model (Prompt 10 behaviour). */
export function formatModelName(slug: string | null | undefined): string {
  if (!slug) return 'UNAVAILABLE';
  const known: Record<string, string> = {
    'tfidf-logistic-v1': 'TF-IDF + Logistic Regression',
  };
  return known[slug] ?? slug;
}

/** "2026-09-20T07:56:39.000Z" -> "2026-09-20 07:56:39 (UTC)". Unparseable input is returned untouched. */
export function formatUtcTimestamp(value: unknown): string | null {
  if (typeof value !== 'string' || value.trim() === '') return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return `${parsed.toISOString().slice(0, 19).replace('T', ' ')} (UTC)`;
}

// ---------------------------------------------------------------------
// Risk level presentation
// ---------------------------------------------------------------------

export type LevelTone = 'low' | 'moderate' | 'high' | 'critical' | 'unknown';

export function levelTone(level: unknown): LevelTone {
  switch (String(level ?? '').toUpperCase()) {
    case 'LOW':
      return 'low';
    case 'MODERATE':
    case 'MEDIUM':
      return 'moderate';
    case 'HIGH':
      return 'high';
    case 'CRITICAL':
      return 'critical';
    default:
      return 'unknown';
  }
}

// ---------------------------------------------------------------------
// Risk categories and the three risk dimensions
// ---------------------------------------------------------------------

export const CATEGORY_ORDER = ['technical', 'identity', 'urlDomain', 'content', 'infrastructure'] as const;

export const CATEGORY_LABELS: Record<string, string> = {
  technical: 'Technical Integrity',
  identity: 'Identity Consistency',
  urlDomain: 'URL / Domain Risk',
  content: 'Content / Social Engineering',
  infrastructure: 'Infrastructure Risk',
};

/** Same grouping the page has used since Prompt 9: purely a display
 *  grouping of the five existing categories. */
export const TECHNICAL_CATEGORY_KEYS = ['technical', 'identity', 'urlDomain', 'infrastructure'] as const;
export const CONTENT_CATEGORY_KEYS = ['content'] as const;

export interface CategoryScoreEntry {
  score?: number | null;
  status?: string;
  evidence?: Array<{ message?: string }>;
}
export type CategoryScores = Record<string, CategoryScoreEntry | null | undefined>;

const UNUSABLE_CATEGORY_STATUSES = new Set(['UNAVAILABLE', 'ERROR', 'NOT_APPLICABLE', 'INSUFFICIENT_EVIDENCE']);

/** The category's score if — and only if — the backend produced a usable
 *  one. A missing/unavailable category is NEVER treated as 0 ("missing
 *  evidence is not the same as safe evidence"). */
export function usableCategoryScore(entry: CategoryScoreEntry | null | undefined): number | null {
  if (!entry) return null;
  const status = String(entry.status ?? '').toUpperCase();
  if (UNUSABLE_CATEGORY_STATUSES.has(status)) return null;
  return asScore(entry.score);
}

/** Ordered list of category keys to render: the five canonical ones
 *  first, then any additional keys the backend may have added. */
export function orderedCategoryKeys(categoryScores: CategoryScores | null | undefined): string[] {
  const present = categoryScores ? Object.keys(categoryScores) : [];
  const extras = present.filter((k) => !(CATEGORY_ORDER as readonly string[]).includes(k));
  return [...CATEGORY_ORDER, ...extras];
}

export type DimensionKey = 'overall' | 'forensic' | 'content';

export interface RiskDimension {
  key: DimensionKey;
  label: string;
  /** 0-100 or null when no reliable value exists (rendered UNAVAILABLE). */
  value: number | null;
  /** One short line saying where the number comes from. */
  basis: string;
}

export interface ResolvedRiskDimensions {
  overall: RiskDimension;
  forensic: RiskDimension;
  content: RiskDimension;
  /** Label of the technical-family category the forensic value was taken from (null if unavailable). */
  forensicDriver: string | null;
  /** How many of the technical-family categories had a usable score. */
  forensicCategoriesUsed: number;
  forensicCategoriesTotal: number;
}

/**
 * The backend's public risk object exposes the overall score plus five
 * per-category scores; it does not expose separate "forensic" and
 * "content" totals. The three dimensions are therefore taken from those
 * existing values with a SELECTION, not a new calculation:
 *
 *  - Overall   = risk.score                      (the authoritative verdict)
 *  - Forensic  = highest usable score among the four technical-family
 *                categories (technical, identity, urlDomain,
 *                infrastructure) — the strongest technical signal, which
 *                by construction cannot understate the worst one
 *  - Content   = the content category score
 *
 * If the backend later exposes dedicated fields, replace the bodies of
 * the two `forensic`/`content` branches here — nothing else needs to
 * change.
 */
export function resolveRiskDimensions(risk: {
  score?: unknown;
  categoryScores?: CategoryScores | null;
} | null | undefined): ResolvedRiskDimensions {
  const categoryScores = risk?.categoryScores ?? null;

  let forensicValue: number | null = null;
  let forensicDriver: string | null = null;
  let used = 0;
  for (const key of TECHNICAL_CATEGORY_KEYS) {
    const score = usableCategoryScore(categoryScores?.[key]);
    if (score === null) continue;
    used += 1;
    if (forensicValue === null || score > forensicValue) {
      forensicValue = score;
      forensicDriver = CATEGORY_LABELS[key] ?? key;
    }
  }

  const contentValue = usableCategoryScore(categoryScores?.[CONTENT_CATEGORY_KEYS[0]]);

  return {
    overall: {
      key: 'overall',
      label: 'Overall Risk',
      value: asScore(risk?.score),
      basis: 'Final deterministic risk engine score',
    },
    forensic: {
      key: 'forensic',
      label: 'Forensic / Technical',
      value: forensicValue,
      basis:
        forensicValue === null
          ? 'No technical category returned a usable score'
          : `Highest of ${used}/${TECHNICAL_CATEGORY_KEYS.length} technical categories`,
    },
    content: {
      key: 'content',
      label: 'Content / Semantic',
      value: contentValue,
      basis: 'Content / Social Engineering category score',
    },
    forensicDriver,
    forensicCategoriesUsed: used,
    forensicCategoriesTotal: TECHNICAL_CATEGORY_KEYS.length,
  };
}

// ---------------------------------------------------------------------
// Radar geometry (presentational only)
// ---------------------------------------------------------------------

export interface RadarPoint {
  x: number;
  y: number;
}

/** Axis order and angles (SVG coordinates, y grows downward):
 *  Overall = top, Content = bottom-right, Forensic = bottom-left. */
export const RADAR_AXES: Array<{ key: DimensionKey; angleDeg: number }> = [
  { key: 'overall', angleDeg: -90 },
  { key: 'content', angleDeg: 30 },
  { key: 'forensic', angleDeg: 150 },
];

export function radarPoint(
  cx: number,
  cy: number,
  radius: number,
  angleDeg: number,
  value: number
): RadarPoint {
  const clamped = Math.max(0, Math.min(100, value));
  const r = (clamped / 100) * radius;
  const rad = (angleDeg * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

export function pointsAttr(points: RadarPoint[]): string {
  return points.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
}

// ---------------------------------------------------------------------
// Grouping repeated observations
// ---------------------------------------------------------------------

/** Groups identical (trimmed, case-insensitive) messages, preserving
 *  first-seen order, so repeated observations render once with a count. */
export function groupRepeated(messages: unknown[]): Array<{ message: string; count: number }> {
  const order: string[] = [];
  const byKey = new Map<string, { message: string; count: number }>();
  for (const raw of messages) {
    const message = typeof raw === 'string' ? raw.trim() : '';
    if (!message) continue;
    const key = message.toLowerCase();
    const existing = byKey.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      byKey.set(key, { message, count: 1 });
      order.push(key);
    }
  }
  return order.map((k) => byKey.get(k)!);
}

// ---------------------------------------------------------------------
// Authentication tone
// ---------------------------------------------------------------------

export type AuthTone = 'good' | 'bad' | 'neutral';

/** Only an explicit PASS is "good"; only an explicit FAIL/SOFTFAIL is
 *  "bad". Anything else (none / unknown / neutral / temperror / ...) is
 *  neutral — an unchecked or missing result must never look like success. */
export function authTone(result: string): AuthTone {
  const r = result.toLowerCase();
  if (r === 'pass') return 'good';
  if (r === 'fail' || r === 'softfail') return 'bad';
  return 'neutral';
}

// ---------------------------------------------------------------------
// Plain-English explanations
//
// Each builder returns an array of short paragraphs. They describe the
// values that are on screen and stay deliberately conservative.
// ---------------------------------------------------------------------

export function explainRiskEngine(input: {
  score: number | null;
  level: string;
  confidencePct: number | null;
  coveragePct: number | null;
  categoryScores: CategoryScores | null | undefined;
}): string[] {
  const { score, level, confidencePct, coveragePct, categoryScores } = input;
  const out: string[] = [
    "These scores summarize the technical and behavioral evidence found in the email. The overall score is the deterministic risk engine's final assessment; each category score shows how strongly that type of evidence points toward risk.",
  ];

  const tone = levelTone(level);
  if (score === null) {
    out.push(
      'No overall score was produced because there was not enough reliable evidence. Missing evidence is not treated as safe evidence.'
    );
  } else if (tone === 'low') {
    out.push(
      `A score of ${score}/100 (${level}) means the available evidence does not strongly indicate a threat. It is not a guarantee that the email is safe.`
    );
  } else if (tone === 'moderate') {
    out.push(
      `A score of ${score}/100 (${level}) means some risk signals were found that deserve a closer look, but they are not conclusive on their own.`
    );
  } else if (tone === 'high') {
    out.push(`A score of ${score}/100 (${level}) means multiple or strong risk signals were found in the evidence.`);
  } else if (tone === 'critical') {
    out.push(
      `A score of ${score}/100 (${level}) means strong risk signals were found; this email should be treated as a priority.`
    );
  } else {
    out.push(`A score of ${score}/100 was returned without a recognized risk level.`);
  }

  const parts: string[] = [];
  if (confidencePct !== null) {
    parts.push(
      `Confidence (${confidencePct}%) reflects how well independent categories corroborate each other; it is not the probability that the email is malicious.`
    );
  }
  if (coveragePct !== null) {
    parts.push(
      coveragePct >= 100
        ? `Evidence coverage (${coveragePct}%) means all five categories had usable evidence.`
        : `Evidence coverage (${coveragePct}%) means only part of the evidence could be assessed; categories without evidence are not counted as safe.`
    );
  }
  if (parts.length) out.push(parts.join(' '));

  if (categoryScores) {
    let top: { label: string; score: number } | null = null;
    let anyUsable = false;
    for (const key of orderedCategoryKeys(categoryScores)) {
      const s = usableCategoryScore(categoryScores[key]);
      if (s === null) continue;
      anyUsable = true;
      if (top === null || s > top.score) top = { label: CATEGORY_LABELS[key] ?? key, score: s };
    }
    if (anyUsable && top) {
      out.push(
        top.score > 0
          ? `The highest category score here is ${top.label} (${top.score}).`
          : 'None of the assessed categories showed elevated risk.'
      );
    }
  }
  return out;
}

export function explainRiskDimensions(dims: ResolvedRiskDimensions): string[] {
  const out: string[] = [
    'This view separates the investigation into three dimensions. Overall risk is the final deterministic assessment, forensic risk reflects technical and infrastructure evidence, and content risk reflects suspicious language or social-engineering signals.',
  ];

  const missing = [dims.overall, dims.forensic, dims.content].filter((d) => d.value === null);
  for (const d of missing) {
    out.push(`${d.label} is UNAVAILABLE: no reliable assessment was returned for this dimension.`);
  }

  const f = dims.forensic.value;
  const c = dims.content.value;
  if (f !== null && c !== null) {
    if (f === 0 && c === 0) {
      out.push('Neither the forensic nor the content dimension shows elevated risk.');
    } else if (f > c) {
      out.push(
        `Forensic risk (${f}) is higher than content risk (${c}), so the stronger signal comes from technical evidence${
          dims.forensicDriver ? `, mainly ${dims.forensicDriver}` : ''
        } rather than the wording of the message.`
      );
    } else if (c > f) {
      out.push(
        `Content risk (${c}) is higher than forensic risk (${f}), so the stronger signal comes from the wording of the message rather than its technical evidence.`
      );
    } else {
      out.push(`Forensic and content risk are equal (${f}).`);
    }
    out.push(
      'A message can be technically clean while still having concerning content, or vice versa. The overall score is calculated by the risk engine, so it does not have to equal either of the other two.'
    );
  } else if (f !== null && dims.forensicCategoriesUsed < dims.forensicCategoriesTotal) {
    out.push(
      `Forensic risk is based on ${dims.forensicCategoriesUsed} of ${dims.forensicCategoriesTotal} technical categories, because the others had no usable evidence.`
    );
  }
  return out;
}

const ARCHETYPE_MEANING: Record<string, string> = {
  SPOOFED_DOMAIN:
    'The evidence resembles a message sent under a forged or look-alike sender domain, rather than from the genuine domain.',
  COMPROMISED_ACCOUNT:
    'The evidence resembles a message sent from a genuine account that may be under someone else\u2019s control.',
  ANONYMIZED_INFRASTRUCTURE:
    'The evidence suggests the sending infrastructure may be masked, for example behind anonymizing or proxy services. Masking on its own is not proof of malicious intent.',
  DIRECT_MALICIOUS_INFRASTRUCTURE:
    'The evidence links the message to infrastructure that appears to be set up for malicious use.',
  INCONCLUSIVE:
    'The available evidence does not clearly match any single attack pattern. INCONCLUSIVE is an honest result when evidence is thin or mixed; it does not mean the email is safe or malicious.',
};

export function explainArchetype(input: {
  archetype: string | null;
  confidence: string | null;
  compromiseTier: string | null;
}): string[] {
  const { archetype, confidence, compromiseTier } = input;
  if (!archetype) {
    return [
      'No archetype assessment was returned for this email, so no attack pattern is being suggested. The rest of the investigation is unaffected.',
    ];
  }
  const out: string[] = [];
  const meaning = ARCHETYPE_MEANING[archetype];
  out.push(
    meaning ??
      `This label (${archetypeLabel(archetype)}) describes the attack pattern that best matches the available evidence.`
  );

  if (archetype === 'COMPROMISED_ACCOUNT' && compromiseTier) {
    const tier = compromiseTier.toUpperCase();
    if (tier === 'POSSIBLE') {
      out.push('The compromise level is POSSIBLE, which is the weaker, single-signal case.');
    } else if (tier === 'LIKELY') {
      out.push('The compromise level is LIKELY, which is stronger than a single uncorroborated signal.');
    }
  }

  const conf = (confidence ?? '').toLowerCase();
  if (conf === 'low') out.push('Confidence is LOW, meaning the supporting evidence is limited.');
  else if (conf === 'medium') out.push('Confidence is MEDIUM: there is some supporting evidence, but it is not conclusive.');
  else if (conf === 'high') out.push('Confidence is HIGH: several pieces of evidence point the same way.');

  out.push('This is an evidence-based pattern label. It does not prove who sent the email or who controlled the account.');
  return out;
}

export function explainMl(input: {
  status: AvailabilityStatus;
  classification: string | null;
  probabilityPct: number | null;
}): string[] {
  const out: string[] = [
    "The machine-learning model looks at patterns in the email's text and estimates whether the message resembles examples associated with phishing or legitimate mail. This probability is a model output and is not the final threat verdict.",
  ];
  if (input.status !== 'Available') {
    out.push(
      'No ML result was returned for this email, so no ML signal is shown here. The deterministic risk assessment is unaffected.'
    );
    return out;
  }
  if (input.classification && input.probabilityPct !== null) {
    out.push(
      `For this email the model output is "${input.classification}" with a model probability of ${input.probabilityPct}%.`
    );
  } else if (input.classification) {
    out.push(`For this email the model output is "${input.classification}".`);
  }
  out.push(
    'The overall risk score and classification come from the deterministic risk engine. If the model disagrees with that evidence, the deterministic result takes precedence.'
  );
  return out;
}

export function explainAi(input: { status: AvailabilityStatus }): string[] {
  const out: string[] = [
    "This is a secondary AI interpretation of the email's content. It helps explain possible intent or social-engineering patterns, but it does not replace the deterministic evidence-based risk assessment.",
  ];
  if (input.status === 'Available') {
    out.push(
      "The percentages are the AI's own estimates for each pattern, not measured facts, and the AI only reads the message content. If it disagrees with the deterministic evidence, the deterministic result is authoritative."
    );
  } else {
    out.push(
      'No AI interpretation is available for this email, so this section has nothing to interpret. The deterministic risk assessment is unaffected.'
    );
  }
  return out;
}

function explainAuthCheck(name: 'SPF' | 'DKIM' | 'DMARC', result: string): string {
  const r = result.toLowerCase();
  if (r === 'pass') {
    switch (name) {
      case 'SPF':
        return 'SPF PASS: the sending server is listed as authorized in the sender domain\u2019s DNS records.';
      case 'DKIM':
        return 'DKIM PASS: the message carries a valid cryptographic signature from the signing domain and was not altered after it was signed.';
      case 'DMARC':
        return 'DMARC PASS: the SPF or DKIM result also lined up with the domain shown in the From address.';
    }
  }
  if (r === 'fail' || r === 'softfail') {
    switch (name) {
      case 'SPF':
        return `SPF ${r.toUpperCase()}: the sending server was ${r === 'fail' ? 'not' : 'only weakly'} authorized by the sender domain\u2019s DNS records.`;
      case 'DKIM':
        return `DKIM ${r.toUpperCase()}: the signature was missing, invalid, or the message was modified after signing.`;
      case 'DMARC':
        return `DMARC ${r.toUpperCase()}: neither SPF nor DKIM lined up with the domain shown in the From address.`;
    }
  }
  return `${name} shows ${result.toUpperCase()}: no usable result was recorded for this check, which is not the same as passing.`;
}

export function explainTechnicalEvidence(input: {
  spf: string;
  dkim: string;
  dmarc: string;
  ipCount: number;
  domainCount: number;
}): string[] {
  const out: string[] = [
    'SPF, DKIM, and DMARC are email authentication checks that help show whether a message really came from the domain it claims to come from.',
    [
      explainAuthCheck('SPF', input.spf),
      explainAuthCheck('DKIM', input.dkim),
      explainAuthCheck('DMARC', input.dmarc),
    ].join(' '),
  ];
  if ([input.spf, input.dkim, input.dmarc].some((r) => r.toLowerCase() === 'pass')) {
    out.push(
      'A PASS only confirms that the technical check succeeded. It does not mean the sender is trustworthy or the content is safe, because a malicious sender can pass these checks for a domain they control.'
    );
  }
  out.push(
    `The message references ${input.ipCount} IP address${input.ipCount === 1 ? '' : 'es'} and ${input.domainCount} domain${
      input.domainCount === 1 ? '' : 's'
    }. A larger count is not a sign of risk by itself; these are simply the indicators extracted for review.`
  );
  return out;
}
