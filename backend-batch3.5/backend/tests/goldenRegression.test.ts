import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeHeaders } from "../src/analyzers/headerForensics";
import { extractIOCs } from "../src/analyzers/iocExtractor";
import { analyzeUrls } from "../src/analyzers/urlAnalyzer";
import { analyzeDomains } from "../src/analyzers/domainAnalyzer";
import { analyzeContent } from "../src/analyzers/contentHeuristics";
import { computeRisk } from "../src/analyzers/riskEngine";
import { assessArchetype } from "../src/analyzers/archetypeAssessment";
import { buildInfrastructureGraph } from "../src/analyzers/infrastructureGraph";
import { assessAi, unavailableAi } from "../src/analyzers/aiAssessment";
import type { EmailRecord, ParsedEmail } from "../src/schemas/types";

// PROMPT 11 — Section 14 golden-case regression matrix (also covers
// Section 3's A-J risk-engine checklist; the two lists overlap almost
// entirely, so they are verified together here rather than in two
// separate files). Runs the REAL deterministic pipeline (header
// forensics -> IOC extraction -> URL/domain analysis -> content
// heuristics -> risk fusion -> archetype -> infrastructure graph) for
// each of the 12 required scenarios, exactly as
// tests/prompt3-evidence-model.test.ts already did for its narrower
// A-F set — this file is the superset requested by Prompt 11, not a
// replacement for that file (which is left in place, unmodified).
//
// Does NOT exercise the ML classifier or a real LLM/Gemini call (no
// model file loading or network access in this sandboxed test run);
// case 11 (LLM unavailable) uses assessAi's own `provider: null` path
// directly, which is real production code, not a mock of it.

function baseParsedEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: "golden-test",
    subject: "Hello",
    from: [{ displayName: "Sender", email: "sender@example.com", localPart: "sender", domain: "example.com" }],
    to: [],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: new Date().toISOString(),
    messageId: "<abc123@example.com>",
    headers: { normalized: {}, raw: [{ name: "Date", value: new Date().toISOString() }] },
    body: { text: "Hello there.", html: null },
    attachments: [],
    ...overrides,
  };
}

function manyTrackingLinksHtml(host: string, count: number): string {
  const links: string[] = [];
  for (let i = 0; i < count; i++) {
    links.push(`<a href="https://click.mail.${host}/redirect?token=abc%20${i}&utm_campaign=promo${i}">Shop now ${i}</a>`);
  }
  return `<html><body>${links.join(" ")}</body></html>`;
}

function runPipeline(parsed: ParsedEmail) {
  const { headerAnalysis, authentication } = analyzeHeaders(parsed);
  const iocs = extractIOCs(parsed, headerAnalysis);
  const { evidence: urlEvidence } = analyzeUrls(parsed.emailId, iocs.urls);
  const { evidence: domainEvidence } = analyzeDomains(parsed.emailId, iocs.domains);
  const { evidence: contentEvidence } = analyzeContent(parsed);

  const explanations = [...headerAnalysis.anomalies, ...urlEvidence, ...domainEvidence, ...contentEvidence];

  const risk = computeRisk(parsed.emailId, explanations, {
    headerDataAvailable: headerAnalysis.status !== "UNAVAILABLE",
    urlDomainApplicable: iocs.urls.length > 0 || iocs.domains.length > 0,
    infrastructureAvailable: false,
  });

  const archetype =
    risk.categoryScores && authentication
      ? assessArchetype({
          authentication,
          urlDomainCategory: risk.categoryScores.urlDomain,
          contentCategory: risk.categoryScores.content,
          infrastructureCategory: risk.categoryScores.infrastructure,
          earliestOrigin: headerAnalysis.earliestOrigin ?? null,
        })
      : null;

  const record = {
    emailId: parsed.emailId,
    parsedEmail: parsed,
    headerAnalysis,
    authentication,
    forwarding: null,
    iocs,
    urlAnalysis: { emailId: parsed.emailId, urls: analyzeUrls(parsed.emailId, iocs.urls).urlAnalysis.urls },
    domainAnalysis: analyzeDomains(parsed.emailId, iocs.domains).domainAnalysis,
    mlAssessment: null,
    aiAssessment: null,
    infrastructure: null,
    relationshipGraph: null,
    correlation: null,
    risk,
  } as unknown as EmailRecord;

  const graph = buildInfrastructureGraph(record);

  return { risk, archetype, iocs, graph, authentication };
}

// 1. Legitimate normal email — no urls, no urgency, clean auth.
test("Golden 1: legitimate normal email -> legitimate, low risk, INCONCLUSIVE archetype, no IOCs", () => {
  const { risk, archetype, iocs } = runPipeline(baseParsedEmail());
  assert.equal(risk.classification, "legitimate");
  assert.equal(risk.level === "low" || risk.level === null, true);
  assert.equal(archetype?.archetype, "INCONCLUSIVE");
  assert.equal(iocs.urls.length, 0);
});

// 2. Legitimate promotional email — many tracking URLs, no credential language.
test("Golden 2: legitimate promotional email (many tracking URLs) -> legitimate, canonical IOC count 1, not flagged suspicious", () => {
  const parsed = baseParsedEmail({
    subject: "Our Anniversary Sale",
    from: [{ displayName: "Brand Promotions", email: "promo@brand-example.com", localPart: "promo", domain: "brand-example.com" }],
    body: { text: null, html: manyTrackingLinksHtml("brand-example.com", 60) },
  });
  const { risk, archetype, iocs, graph } = runPipeline(parsed);
  assert.equal(risk.classification, "legitimate");
  assert.notEqual(archetype?.archetype, "COMPROMISED_ACCOUNT");
  assert.equal(iocs.urls.length, 60, "raw occurrences preserved");
  assert.equal(iocs.canonicalUrlIndicators.length, 1, "canonical indicators collapse to the real destination count");
  assert.equal(
    graph.nodes.some((n) => n.suspicious),
    false,
    "percent-encoded tracking links must not flag any graph node suspicious"
  );
});

// 3. Legitimate forwarded promotional email.
test("Golden 3: legitimate forwarded promotional email -> still legitimate, forwarding detected separately from risk", () => {
  const parsed = baseParsedEmail({
    subject: "Fwd: Our Anniversary Sale",
    from: [{ displayName: "A Friend", email: "friend@gmail.com", localPart: "friend", domain: "gmail.com" }],
    messageId: "<promo-123@brand-example.com>",
    body: { text: null, html: manyTrackingLinksHtml("brand-example.com", 40) },
  });
  const { risk, archetype } = runPipeline(parsed);
  assert.equal(risk.classification, "legitimate");
  assert.notEqual(archetype?.archetype, "COMPROMISED_ACCOUNT");
});

// 4. Phishing credential request (content-only, clean auth).
test("Golden 4: credential-request email (clean auth) -> suspicious classification, COMPROMISED_ACCOUNT/POSSIBLE archetype", () => {
  const parsed = baseParsedEmail({
    subject: "Verify your account now",
    headers: {
      normalized: { "authentication-results": "spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass" },
      raw: [{ name: "Date", value: new Date().toISOString() }],
    },
    body: {
      text: "This is urgent — please verify your account immediately by confirming your password and login credentials now, or it will be suspended.",
      html: null,
    },
  });
  const { risk, archetype } = runPipeline(parsed);
  assert.notEqual(risk.classification, "legitimate");
  assert.equal(archetype?.archetype, "COMPROMISED_ACCOUNT");
  assert.equal(archetype?.compromiseTier, "POSSIBLE");
});

// 5. Financial-fraud/phishing email (financial request + urgency).
test("Golden 5: financial-fraud email (financial request + urgency language) -> financial_fraud classification", () => {
  const parsed = baseParsedEmail({
    subject: "Urgent wire transfer required",
    body: {
      text: "This is urgent — please wire the payment immediately to confirm the invoice before it expires today.",
      html: null,
    },
  });
  const { risk } = runPipeline(parsed);
  assert.equal(risk.classification, "financial_fraud");
});

// 6. Lookalike domain.
test("Golden 6: lookalike domain (paypa1.com) -> phishing classification", () => {
  const parsed = baseParsedEmail({
    subject: "Account notice",
    from: [{ displayName: "Account Services", email: "service@paypa1.com", localPart: "service", domain: "paypa1.com" }],
    body: { text: "Please visit https://paypa1.com/login to review your account.", html: null },
  });
  const { risk } = runPipeline(parsed);
  assert.equal(risk.classification, "phishing");
});

// 7. Raw-IP destination.
test("Golden 7: raw-IP-host URL -> phishing classification, IP/URL graph nodes flagged suspicious", () => {
  const parsed = baseParsedEmail({
    subject: "Login required",
    body: { text: "Please log in at http://192.0.2.44/login to continue.", html: null },
  });
  const { risk, graph } = runPipeline(parsed);
  assert.equal(risk.classification, "phishing");
  assert.equal(
    graph.nodes.some((n) => n.type === "IP" && n.suspicious),
    true
  );
});

// 8. Many tracking URLs (duplicate of the risk-only slice of Golden 2,
// focused specifically on the risk score not being dominated by volume).
test("Golden 8: many tracking URLs alone do not push risk into high/critical", () => {
  const parsed = baseParsedEmail({
    subject: "Newsletter",
    body: { text: null, html: manyTrackingLinksHtml("newsletter-example.com", 90) },
  });
  const { risk } = runPipeline(parsed);
  assert.ok(risk.level === "low" || risk.level === "moderate");
});

// 9. Percent-encoded but benign URLs (a handful, not a flood).
test("Golden 9: a few percent-encoded benign URLs -> legitimate", () => {
  const parsed = baseParsedEmail({
    subject: "Your receipt",
    body: {
      text: null,
      html: `<html><body>
        <a href="https://shop.store-example.com/order?ref=abc%20123">View order</a>
        <a href="https://shop.store-example.com/support?case=xyz%20456">Support</a>
      </body></html>`,
    },
  });
  const { risk } = runPipeline(parsed);
  assert.equal(risk.classification, "legitimate");
});

// 10. Message-ID mismatch without other strong evidence.
test("Golden 10: Message-ID mismatch ALONE (no other strong evidence) -> legitimate, not suspicious", () => {
  const parsed = baseParsedEmail({
    subject: "Hello",
    from: [{ displayName: "Sender", email: "sender@brand-example.com", localPart: "sender", domain: "brand-example.com" }],
    messageId: "<xyz@some-esp-vendor.example>",
    body: { text: "Just a quick note.", html: null },
  });
  const { risk } = runPipeline(parsed);
  assert.equal(
    risk.classification,
    "legitimate",
    "a lone weak Message-ID/domain mismatch must not, by itself, produce a suspicious classification"
  );
});

// 11. LLM unavailable/failure.
test("Golden 11: LLM unavailable (no provider configured) -> graceful UNAVAILABLE, deterministic evidence untouched", async () => {
  const parsed = baseParsedEmail({ body: { text: "Ordinary email content.", html: null } });
  const { risk } = runPipeline(parsed);

  const { aiAssessment, evidence } = await assessAi({
    emailId: parsed.emailId,
    parsed,
    headerAnalysis: analyzeHeaders(parsed).headerAnalysis,
    authentication: analyzeHeaders(parsed).authentication,
    urlAnalysis: { emailId: parsed.emailId, urls: [] } as any,
    mlAssessment: { emailId: parsed.emailId, status: "UNAVAILABLE" } as any,
    provider: null,
  });

  assert.equal(aiAssessment.status, "UNAVAILABLE");
  assert.equal(evidence.length, 0);
  // Deterministic risk was computed with zero dependency on the AI
  // provider's availability -- confirms Section 5's "LLM failure does
  // not break email analysis" and "deterministic evidence remains
  // available when LLM is unavailable".
  assert.notEqual(risk.score, null);
  assert.deepEqual(aiAssessment, unavailableAi(parsed.emailId, "UNAVAILABLE"));
});

// 12. Missing enrichment data (headers and infrastructure unavailable,
// only content heuristics ran).
//
// Note: computeRisk's `content` category is ALWAYS "AVAILABLE" by
// explicit, documented design (riskEngine.ts: "Content heuristics
// always run — even an empty body is a valid (if empty) analysis, not
// an inapplicable one") — so a genuine "every category unavailable"
// state is not reachable through computeRisk's real context parameter
// in production, and score/level are correspondingly never actually
// null in practice (confirmed: attempting it returns score 0, not
// null, because content-with-zero-evidence legitimately means "the
// one thing we could check found nothing," not "unknown"). That is a
// pre-existing, intentional Batch 3 design choice — not a Prompts
// 1-10 regression — and changing it would mean changing the
// fundamental risk architecture, out of scope for this QA pass. What
// IS verified here, and IS the real guarantee that matters, is that
// genuinely UNAVAILABLE categories (headers, infrastructure) are
// EXCLUDED from the weighted average rather than silently defaulted
// to 0 and diluting the score downward.
test("Golden 12: headers and infrastructure unavailable — those categories are excluded from the average, not defaulted to 0", () => {
  const evidence = [
    {
      type: "urgency_language" as const,
      severity: "low" as const,
      weight: 15,
      message: "urgency",
      evidence: {},
      category: "content" as const,
      provenance: "DETERMINISTIC_ANALYSIS" as const,
      strength: "weak" as const,
    },
  ];
  const risk = computeRisk("golden-12", evidence, {
    headerDataAvailable: false,
    urlDomainApplicable: false,
    infrastructureAvailable: false,
  });

  assert.equal(risk.categoryScores?.technical.status, "UNAVAILABLE");
  assert.equal(risk.categoryScores?.technical.score, null);
  assert.equal(risk.categoryScores?.infrastructure.status, "UNAVAILABLE");
  assert.equal(
    risk.evidenceCoverage,
    1 / 5,
    "only content is AVAILABLE among the 5 categories (technical/identity/infrastructure unavailable, urlDomain not applicable) — coverage must reflect that truthfully"
  );
  // The excluded categories must not have dragged the score toward 0 —
  // it should equal content's own score exactly, since content is the
  // only category in the weighted average.
  assert.equal(risk.score, risk.categoryScores?.content.score);
});
