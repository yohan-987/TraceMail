// Prompt 12 — unit tests for the AI Investigation view logic.
// Run with:  npm test   (Node >= 22.6; uses the built-in test runner, no extra dependencies)
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  archetypeLabel,
  asScore,
  authTone,
  explainAi,
  explainArchetype,
  explainMl,
  explainRiskDimensions,
  explainRiskEngine,
  explainTechnicalEvidence,
  formatModelName,
  formatUtcTimestamp,
  fractionToPercent,
  groupRepeated,
  levelTone,
  normalizeAvailability,
  orderedCategoryKeys,
  pointsAttr,
  probabilityToPercent,
  radarPoint,
  resolveRiskDimensions,
  usableCategoryScore,
  type CategoryScores,
} from '../src/lib/investigationView.ts';

// The exact numbers from the reference screenshot (low-risk forwarded promo email).
const LOW_RISK_CATEGORIES: CategoryScores = {
  technical: { score: 0, status: 'AVAILABLE' },
  identity: { score: 10, status: 'AVAILABLE' },
  urlDomain: { score: 15, status: 'AVAILABLE' },
  content: { score: 0, status: 'AVAILABLE' },
  infrastructure: { score: 20, status: 'AVAILABLE' },
};

const BAD_TOKENS = /undefined|NaN|\[object|null/;

function allText(paragraphs: string[]): string {
  return paragraphs.join(' ');
}

// ---------------------------------------------------------------- formatting

test('asScore: finite numbers are clamped and rounded; everything else is null', () => {
  assert.equal(asScore(8), 8);
  assert.equal(asScore(7.6), 8);
  assert.equal(asScore(-5), 0);
  assert.equal(asScore(250), 100);
  assert.equal(asScore(0), 0);
  for (const bad of [NaN, Infinity, -Infinity, '8', null, undefined, {}, []]) {
    assert.equal(asScore(bad), null, `asScore(${String(bad)})`);
  }
});

test('fractionToPercent / probabilityToPercent', () => {
  assert.equal(fractionToPercent(0.7), 70);
  assert.equal(fractionToPercent(1), 100);
  assert.equal(fractionToPercent(2), 100);
  assert.equal(fractionToPercent(NaN), null);
  assert.equal(fractionToPercent(undefined), null);
  assert.equal(probabilityToPercent(0.46), 46);
  assert.equal(probabilityToPercent(46), 46); // tolerated 0-100 input
  assert.equal(probabilityToPercent(1), 100);
  assert.equal(probabilityToPercent(150), 100);
  assert.equal(probabilityToPercent('0.4'), null);
});

test('normalizeAvailability treats anything unknown as Unavailable (never as available)', () => {
  assert.equal(normalizeAvailability('AVAILABLE'), 'Available');
  assert.equal(normalizeAvailability('ok'), 'Available');
  assert.equal(normalizeAvailability('Inconclusive'), 'Inconclusive');
  for (const v of ['ERROR', 'NOT_APPLICABLE', '', undefined, null, 'weird']) {
    assert.equal(normalizeAvailability(v), 'Unavailable', String(v));
  }
});

test('levelTone / archetypeLabel / formatModelName', () => {
  assert.equal(levelTone('low'), 'low');
  assert.equal(levelTone('MEDIUM'), 'moderate');
  assert.equal(levelTone('CRITICAL'), 'critical');
  assert.equal(levelTone('UNKNOWN'), 'unknown');
  assert.equal(levelTone(undefined), 'unknown');
  assert.equal(archetypeLabel('ANONYMIZED_INFRASTRUCTURE'), 'Anonymized Infrastructure');
  assert.equal(formatModelName('tfidf-logistic-v1'), 'TF-IDF + Logistic Regression');
  assert.equal(formatModelName('some-future-model'), 'some-future-model'); // never mislabelled
  assert.equal(formatModelName(null), 'UNAVAILABLE');
});

test('formatUtcTimestamp', () => {
  assert.equal(formatUtcTimestamp('2026-09-20T07:56:39.000Z'), '2026-09-20 07:56:39 (UTC)');
  assert.equal(formatUtcTimestamp('not a date'), 'not a date');
  assert.equal(formatUtcTimestamp(''), null);
  assert.equal(formatUtcTimestamp(undefined), null);
});

// ------------------------------------------------------------- 3D dimensions

test('resolveRiskDimensions: reference case -> overall 8, forensic 20 (Infrastructure), content 0', () => {
  const d = resolveRiskDimensions({ score: 8, categoryScores: LOW_RISK_CATEGORIES });
  assert.equal(d.overall.value, 8);
  assert.equal(d.forensic.value, 20);
  assert.equal(d.forensicDriver, 'Infrastructure Risk');
  assert.equal(d.forensicCategoriesUsed, 4);
  assert.equal(d.content.value, 0);
});

test('resolveRiskDimensions never invents values: missing/unavailable stay null, not 0', () => {
  const none = resolveRiskDimensions({ score: null, categoryScores: null });
  assert.equal(none.overall.value, null);
  assert.equal(none.forensic.value, null);
  assert.equal(none.content.value, null);
  assert.equal(none.forensicDriver, null);

  const partial = resolveRiskDimensions({
    score: 40,
    categoryScores: {
      technical: { score: 0, status: 'UNAVAILABLE' }, // a stored 0 on an unavailable category is NOT evidence of safety
      identity: { score: null, status: 'UNAVAILABLE' },
      urlDomain: { score: 30, status: 'AVAILABLE' },
      content: { score: 0, status: 'UNAVAILABLE' },
      infrastructure: { score: null, status: 'UNAVAILABLE' },
    },
  });
  assert.equal(partial.forensic.value, 30);
  assert.equal(partial.forensicCategoriesUsed, 1);
  assert.equal(partial.content.value, null);
  assert.match(partial.forensic.basis, /1\/4/);
});

test('resolveRiskDimensions is a selection of existing values (no blending)', () => {
  const d = resolveRiskDimensions({
    score: 55,
    categoryScores: {
      technical: { score: 10, status: 'AVAILABLE' },
      identity: { score: 20, status: 'AVAILABLE' },
      urlDomain: { score: 30, status: 'AVAILABLE' },
      content: { score: 90, status: 'AVAILABLE' },
      infrastructure: { score: 25, status: 'AVAILABLE' },
    },
  });
  assert.equal(d.forensic.value, 30); // max, not average / noisy-OR
  assert.equal(d.content.value, 90);
  assert.equal(d.overall.value, 55); // passed through untouched
});

test('usableCategoryScore / orderedCategoryKeys', () => {
  assert.equal(usableCategoryScore(undefined), null);
  assert.equal(usableCategoryScore({ score: 12, status: 'available' }), 12);
  assert.equal(usableCategoryScore({ score: 12 }), 12); // status absent, number present
  assert.equal(usableCategoryScore({ score: 12, status: 'INSUFFICIENT_EVIDENCE' }), null);
  assert.deepEqual(orderedCategoryKeys(null), ['technical', 'identity', 'urlDomain', 'content', 'infrastructure']);
  assert.deepEqual(orderedCategoryKeys({ zeta: { score: 1 } }).slice(-1), ['zeta']);
});

test('radarPoint geometry', () => {
  const top = radarPoint(170, 150, 96, -90, 100);
  assert.ok(Math.abs(top.x - 170) < 1e-9 && Math.abs(top.y - 54) < 1e-9);
  const centre = radarPoint(170, 150, 96, 30, 0);
  assert.deepEqual(centre, { x: 170, y: 150 });
  const clamped = radarPoint(170, 150, 96, -90, 500);
  assert.ok(Math.abs(clamped.y - 54) < 1e-9);
  assert.match(pointsAttr([top, centre]), /^170\.0,54\.0 170\.0,150\.0$/);
});

// ------------------------------------------------------------------- helpers

test('groupRepeated groups identical findings once, in first-seen order', () => {
  const g = groupRepeated(['A ', 'b', 'a', '', null, 42, 'B', 'c']);
  assert.deepEqual(g, [
    { message: 'A', count: 2 },
    { message: 'b', count: 2 },
    { message: 'c', count: 1 },
  ]);
});

test('authTone: only an explicit PASS is good; unknown/none never looks like success', () => {
  assert.equal(authTone('pass'), 'good');
  assert.equal(authTone('PASS'), 'good');
  assert.equal(authTone('fail'), 'bad');
  assert.equal(authTone('softfail'), 'bad');
  for (const v of ['unknown', 'none', 'neutral', 'temperror', '']) assert.equal(authTone(v), 'neutral', v);
});

// -------------------------------------------------------------- explanations

test('explainRiskEngine: low-risk reference case', () => {
  const text = allText(
    explainRiskEngine({ score: 8, level: 'LOW', confidencePct: 70, coveragePct: 100, categoryScores: LOW_RISK_CATEGORIES })
  );
  assert.match(text, /deterministic risk engine/);
  assert.match(text, /8\/100 \(LOW\)/);
  assert.match(text, /does not strongly indicate a threat/);
  assert.match(text, /not a guarantee that the email is safe/);
  assert.match(text, /Confidence \(70%\)/);
  assert.match(text, /not the probability that the email is malicious/);
  assert.match(text, /all five categories had usable evidence/);
  assert.match(text, /highest category score here is Infrastructure Risk \(20\)/);
  assert.doesNotMatch(text, BAD_TOKENS);
});

test('explainRiskEngine: no score, partial coverage, high risk', () => {
  const none = allText(explainRiskEngine({ score: null, level: 'UNKNOWN', confidencePct: null, coveragePct: null, categoryScores: null }));
  assert.match(none, /not enough reliable evidence/);
  assert.match(none, /Missing evidence is not treated as safe evidence/);
  assert.doesNotMatch(none, BAD_TOKENS);

  const partial = allText(explainRiskEngine({ score: 45, level: 'MODERATE', confidencePct: 50, coveragePct: 60, categoryScores: null }));
  assert.match(partial, /only part of the evidence could be assessed/);
  assert.match(partial, /not conclusive on their own/);

  const high = allText(explainRiskEngine({ score: 82, level: 'HIGH', confidencePct: 80, coveragePct: 100, categoryScores: null }));
  assert.match(high, /82\/100 \(HIGH\)/);
  assert.doesNotMatch(high, /does not strongly indicate a threat/);
});

test('explainRiskEngine: all-zero categories do not claim a top category', () => {
  const zero: CategoryScores = { technical: { score: 0, status: 'AVAILABLE' }, content: { score: 0, status: 'AVAILABLE' } };
  const text = allText(explainRiskEngine({ score: 0, level: 'LOW', confidencePct: 60, coveragePct: 40, categoryScores: zero }));
  assert.match(text, /None of the assessed categories showed elevated risk/);
});

test('explainRiskDimensions: values, comparison, and unavailable dimensions', () => {
  const ref = allText(explainRiskDimensions(resolveRiskDimensions({ score: 8, categoryScores: LOW_RISK_CATEGORIES })));
  assert.match(ref, /three dimensions/);
  assert.match(ref, /Forensic risk \(20\) is higher than content risk \(0\)/);
  assert.match(ref, /mainly Infrastructure Risk/);
  assert.match(ref, /technically clean while still having concerning content, or vice versa/);
  assert.match(ref, /does not have to equal either of the other two/);
  assert.doesNotMatch(ref, BAD_TOKENS);

  const contentHeavy = allText(
    explainRiskDimensions(
      resolveRiskDimensions({
        score: 60,
        categoryScores: { technical: { score: 0, status: 'AVAILABLE' }, content: { score: 85, status: 'AVAILABLE' } },
      })
    )
  );
  assert.match(contentHeavy, /Content risk \(85\) is higher than forensic risk \(0\)/);

  const missing = allText(explainRiskDimensions(resolveRiskDimensions({ score: null, categoryScores: null })));
  assert.match(missing, /Overall Risk is UNAVAILABLE: no reliable assessment was returned for this dimension\./);
  assert.match(missing, /Forensic \/ Technical is UNAVAILABLE/);
  assert.match(missing, /Content \/ Semantic is UNAVAILABLE/);
  assert.doesNotMatch(missing, BAD_TOKENS);

  const zeros = allText(
    explainRiskDimensions(
      resolveRiskDimensions({
        score: 0,
        categoryScores: { technical: { score: 0, status: 'AVAILABLE' }, content: { score: 0, status: 'AVAILABLE' } },
      })
    )
  );
  assert.match(zeros, /Neither the forensic nor the content dimension shows elevated risk/);
});

test('explainArchetype: specific wording per archetype, never implies attribution', () => {
  const inconclusive = allText(explainArchetype({ archetype: 'INCONCLUSIVE', confidence: 'LOW', compromiseTier: null }));
  assert.match(inconclusive, /does not clearly match any single attack pattern/);
  assert.match(inconclusive, /does not mean the email is safe or malicious/);
  assert.match(inconclusive, /Confidence is LOW/);
  assert.match(inconclusive, /does not prove who sent the email or who controlled the account/);

  const spoof = allText(explainArchetype({ archetype: 'SPOOFED_DOMAIN', confidence: 'medium', compromiseTier: null }));
  assert.match(spoof, /forged or look-alike sender domain/);
  assert.match(spoof, /Confidence is MEDIUM/);

  const comp = allText(explainArchetype({ archetype: 'COMPROMISED_ACCOUNT', confidence: 'low', compromiseTier: 'POSSIBLE' }));
  assert.match(comp, /may be under someone else/);
  assert.match(comp, /POSSIBLE, which is the weaker, single-signal case/);

  for (const a of ['ANONYMIZED_INFRASTRUCTURE', 'DIRECT_MALICIOUS_INFRASTRUCTURE']) {
    const t = allText(explainArchetype({ archetype: a, confidence: null, compromiseTier: null }));
    assert.match(t, /does not prove who sent the email/);
    assert.doesNotMatch(t, BAD_TOKENS);
  }

  const unknownArchetype = allText(explainArchetype({ archetype: 'BRAND_NEW_VALUE', confidence: null, compromiseTier: null }));
  assert.match(unknownArchetype, /Brand New Value/);

  const none = allText(explainArchetype({ archetype: null, confidence: null, compromiseTier: null }));
  assert.match(none, /No archetype assessment was returned/);
});

test('explainMl: clear that ML is not the verdict; adapts to availability', () => {
  const ok = allText(explainMl({ status: 'Available', classification: 'legitimate', probabilityPct: 46 }));
  assert.match(ok, /not the final threat verdict/);
  assert.match(ok, /"legitimate" with a model probability of 46%/);
  assert.match(ok, /deterministic result takes precedence/);
  assert.doesNotMatch(ok, BAD_TOKENS);

  const off = allText(explainMl({ status: 'Unavailable', classification: null, probabilityPct: null }));
  assert.match(off, /not the final threat verdict/);
  assert.match(off, /No ML result was returned/);
  assert.doesNotMatch(off, /model probability of/);
});

test('explainAi: secondary interpretation; adapts to availability', () => {
  const ok = allText(explainAi({ status: 'Available' }));
  assert.match(ok, /secondary AI interpretation/);
  assert.match(ok, /does not replace the deterministic evidence-based risk assessment/);
  assert.match(ok, /deterministic result is authoritative/);
  const off = allText(explainAi({ status: 'Unavailable' }));
  assert.match(off, /No AI interpretation is available/);
});

test('explainTechnicalEvidence: matches actual results and never over-claims', () => {
  const allPass = allText(explainTechnicalEvidence({ spf: 'pass', dkim: 'pass', dmarc: 'pass', ipCount: 1, domainCount: 3 }));
  assert.match(allPass, /SPF PASS/);
  assert.match(allPass, /DKIM PASS/);
  assert.match(allPass, /DMARC PASS/);
  assert.match(allPass, /does not mean the sender is trustworthy or the content is safe/);
  assert.match(allPass, /1 IP address and 3 domains/);
  assert.match(allPass, /not a sign of risk by itself/);

  const failing = allText(explainTechnicalEvidence({ spf: 'fail', dkim: 'softfail', dmarc: 'unknown', ipCount: 0, domainCount: 1 }));
  assert.match(failing, /SPF FAIL: the sending server was not authorized/);
  assert.match(failing, /DKIM SOFTFAIL/);
  assert.match(failing, /DMARC shows UNKNOWN: no usable result was recorded for this check, which is not the same as passing/);
  assert.doesNotMatch(failing, /does not mean the sender is trustworthy/); // no PASS -> no PASS caveat
  assert.match(failing, /0 IP addresses and 1 domain\./);
  assert.doesNotMatch(failing, BAD_TOKENS);

  const nothing = allText(explainTechnicalEvidence({ spf: 'unknown', dkim: 'unknown', dmarc: 'unknown', ipCount: 0, domainCount: 0 }));
  assert.doesNotMatch(nothing, /PASS:/);
});

test('no explanation builder ever emits undefined / NaN / null for degenerate input', () => {
  const dimsNone = resolveRiskDimensions(undefined);
  const outputs = [
    explainRiskEngine({ score: null, level: '', confidencePct: null, coveragePct: null, categoryScores: undefined }),
    explainRiskDimensions(dimsNone),
    explainArchetype({ archetype: null, confidence: null, compromiseTier: null }),
    explainMl({ status: 'Unavailable', classification: null, probabilityPct: null }),
    explainMl({ status: 'Available', classification: null, probabilityPct: null }),
    explainAi({ status: 'Inconclusive' }),
    explainTechnicalEvidence({ spf: '', dkim: '', dmarc: '', ipCount: 0, domainCount: 0 }),
  ];
  for (const o of outputs) assert.doesNotMatch(allText(o), BAD_TOKENS);
});
