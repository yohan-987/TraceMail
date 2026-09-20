import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeHeaders } from "../src/analyzers/headerForensics";
import { extractIOCs } from "../src/analyzers/iocExtractor";
import { analyzeUrls } from "../src/analyzers/urlAnalyzer";
import { analyzeDomains } from "../src/analyzers/domainAnalyzer";
import { analyzeContent } from "../src/analyzers/contentHeuristics";
import { computeRisk } from "../src/analyzers/riskEngine";
import type { ParsedEmail } from "../src/schemas/types";

// Prompt 3 regression matrix (A-F), run against the REAL analyzers
// (headerForensics, iocExtractor, urlAnalyzer, domainAnalyzer,
// contentHeuristics, riskEngine) wired together the same way
// emailIngestPipeline.ts does, minus the ML classifier / AI semantic
// interpretation / infrastructure (GeoIP/DNS) stages — those need a
// loaded model / network access / an LLM provider respectively, none
// of which are available in this sandboxed, network-disabled test
// run, so this exercises the deterministic evidence pipeline only.
// That is the part Findings 1/2/3/4 actually changed.

function baseParsedEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: "test-email",
    subject: "Hello",
    from: [{ displayName: "Sender", email: "sender@example.com", localPart: "sender", domain: "example.com" }],
    to: [],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: new Date().toISOString(),
    messageId: "<abc123@example.com>",
    headers: {
      normalized: {},
      raw: [{ name: "Date", value: new Date().toISOString() }],
    },
    body: { text: "Hello there.", html: null },
    attachments: [],
    ...overrides,
  };
}

function computeRiskFor(parsed: ParsedEmail) {
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

  return { risk, authentication, iocs, explanations };
}

function manyTrackingLinksHtml(host: string, count: number): string {
  const links: string[] = [];
  for (let i = 0; i < count; i++) {
    links.push(
      `<a href="https://click.mail.${host}/redirect?token=abc%20${i}&utm_campaign=promo${i}">Shop now ${i}</a>`
    );
  }
  return `<html><body>${links.join(" ")}</body></html>`;
}

// A. Legitimate promotional email with many tracking URLs.
test("A: legitimate promotional email with many tracking URLs classifies as legitimate", () => {
  const parsed = baseParsedEmail({
    subject: "Our Anniversary Sale - Save Big!",
    from: [{ displayName: "Brand Promotions", email: "promo@brand-example.com", localPart: "promo", domain: "brand-example.com" }],
    messageId: "<promo-123@brand-example.com>",
    body: {
      text: null,
      html: manyTrackingLinksHtml("brand-example.com", 60),
    },
  });

  const { risk } = computeRiskFor(parsed);
  assert.equal(
    risk.classification,
    "legitimate",
    `expected legitimate for a clean promo email with many tracking links, got "${risk.classification}" (score=${risk.score})`
  );
});

// B. Legitimate forwarded promotional email.
test("B: legitimate forwarded promotional email (Message-ID domain mismatch) classifies as legitimate", () => {
  const parsed = baseParsedEmail({
    subject: "Fwd: Our Anniversary Sale - Save Big!",
    // Forwarded: From is the forwarding account, but Message-ID still
    // carries the original sender's domain -- a real, common, benign
    // artifact of forwarding, not evidence of phishing.
    from: [{ displayName: "A Friend", email: "friend@gmail.com", localPart: "friend", domain: "gmail.com" }],
    messageId: "<promo-123@brand-example.com>",
    body: {
      text: null,
      html: manyTrackingLinksHtml("brand-example.com", 40),
    },
  });

  const { risk } = computeRiskFor(parsed);
  assert.equal(
    risk.classification,
    "legitimate",
    `expected legitimate for a forwarded promo email, got "${risk.classification}" (score=${risk.score})`
  );
});

// C. Phishing email with credential harvesting.
test("C: phishing email with credential-harvesting language and SPF fail does NOT classify as legitimate", () => {
  const parsed = baseParsedEmail({
    subject: "Urgent: verify your account now",
    from: [{ displayName: "IT Support", email: "it-support@mailer.example", localPart: "it-support", domain: "mailer.example" }],
    headers: {
      normalized: { "authentication-results": "spf=fail smtp.mailfrom=mailer.example" },
      raw: [{ name: "Date", value: new Date().toISOString() }],
    },
    body: {
      text: "This is urgent. Please verify your account immediately by logging in to confirm your identity.",
      html: null,
    },
  });

  const { risk } = computeRiskFor(parsed);
  assert.notEqual(
    risk.classification,
    "legitimate",
    `expected a real phishing email (credential request + SPF fail) to NOT classify as legitimate, got "${risk.classification}" (score=${risk.score})`
  );
  assert.equal(risk.classification, "suspicious_authentication");
});

// D. Lookalike/malicious destination domain.
test("D: lookalike domain (paypa1.com mimicking paypal.com) classifies as phishing", () => {
  const parsed = baseParsedEmail({
    subject: "Your account",
    // Deliberately a generic display name (not "PayPal") so this
    // isolates the lookalike-DOMAIN path (classify()'s
    // possible_lookalike_domain branch) from display-name brand
    // impersonation, which is checked first in classify()'s priority
    // order and would otherwise correctly, but confusingly for this
    // test, win with "impersonation" instead.
    from: [{ displayName: "Account Services", email: "service@paypa1.com", localPart: "service", domain: "paypa1.com" }],
    body: {
      text: "Please visit https://paypa1.com/login to review your account.",
      html: null,
    },
  });

  const { risk } = computeRiskFor(parsed);
  assert.equal(risk.classification, "phishing");
});

// E. Many duplicate/near-duplicate URLs (Finding 1) should not, by
// themselves, push a clean email to a high/critical score.
test("E: many duplicate and near-duplicate URLs to one host do not push risk into high/critical", () => {
  const parsed = baseParsedEmail({
    subject: "Newsletter",
    body: {
      text: null,
      html: manyTrackingLinksHtml("newsletter-example.com", 90),
    },
  });

  const { risk } = computeRiskFor(parsed);
  assert.ok(risk.score !== null);
  assert.ok(
    risk.level === "low" || risk.level === "moderate",
    `expected low/moderate for a mail with only duplicate tracking links, got level="${risk.level}" (score=${risk.score})`
  );
});

// F. Encoded but benign URLs (a handful, not a flood) should not read
// as suspicious on their own.
test("F: a few percent-encoded but benign URLs do not classify as suspicious", () => {
  const parsed = baseParsedEmail({
    subject: "Your receipt",
    body: {
      text: null,
      html: `<html><body>
        <a href="https://shop.store-example.com/order?ref=abc%20123">View your order</a>
        <a href="https://shop.store-example.com/support?case=xyz%20456">Contact support</a>
      </body></html>`,
    },
  });

  const { risk } = computeRiskFor(parsed);
  assert.equal(
    risk.classification,
    "legitimate",
    `expected legitimate for a couple of encoded-but-benign links, got "${risk.classification}" (score=${risk.score})`
  );
});
