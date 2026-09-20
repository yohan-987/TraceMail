import { test } from "node:test";
import assert from "node:assert/strict";
import { extractIOCs, groupUrlsByHost } from "../src/analyzers/iocExtractor";
import type { ParsedEmail, HeaderAnalysis } from "../src/schemas/types";

// Regression tests for Prompt 4 (IOC duplication / evidence amplification).
//
// The underlying amplification bug itself (repeated near-duplicate URLs
// saturating the urlDomain risk category) was already fixed at the
// evidence-generation layer in urlAnalyzer.ts (docs/audit/PHASE1-AUDIT.md,
// Finding 1 — see tests/urlAnalyzer.test.ts). This file tests the
// complementary fix at the IOC/indicator layer requested by Prompt 4:
// IOCSet now exposes BOTH the raw, exact-string-deduplicated occurrence
// list (`urls`, unchanged, preserved for forensic completeness) AND a
// canonical, host-grouped indicator list (`canonicalUrlIndicators`) that
// answers "how many distinct destinations does this email actually
// point to" without discarding the raw occurrence count as metadata.

function minimalHeaderAnalysis(): HeaderAnalysis {
  return { emailId: "t", status: "AVAILABLE", anomalies: [], receivedChain: [] } as unknown as HeaderAnalysis;
}

function parsedEmailWithBody(html: string): ParsedEmail {
  return {
    emailId: "t",
    subject: "s",
    from: [],
    to: [],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: null,
    messageId: "<t@example.com>",
    headers: { normalized: {}, raw: [] },
    body: { text: null, html },
    attachments: [],
  } as unknown as ParsedEmail;
}

test("same exact URL repeated 10 times collapses to one raw entry and one canonical indicator (occurrenceCount 1)", () => {
  const links = Array(10).fill('<a href="https://example.com/page">link</a>').join(" ");
  const iocs = extractIOCs(parsedEmailWithBody(`<html><body>${links}</body></html>`), minimalHeaderAnalysis());

  assert.equal(iocs.urls.length, 1, "exact-duplicate URLs should already collapse in the raw list");
  assert.equal(iocs.canonicalUrlIndicators.length, 1);
  assert.equal(iocs.canonicalUrlIndicators[0].occurrenceCount, 1);
});

test("distinct URLs (different paths) on the same domain: raw entries preserved, ONE canonical indicator with occurrenceCount = N", () => {
  const html = `<html><body>
    <a href="https://shop.example.com/products/a">A</a>
    <a href="https://shop.example.com/products/b">B</a>
    <a href="https://shop.example.com/checkout">Checkout</a>
  </body></html>`;
  const iocs = extractIOCs(parsedEmailWithBody(html), minimalHeaderAnalysis());

  assert.equal(iocs.urls.length, 3, "three genuinely distinct paths must all be preserved raw");
  assert.equal(iocs.canonicalUrlIndicators.length, 1);
  assert.equal(iocs.canonicalUrlIndicators[0].hostname, "shop.example.com");
  assert.equal(iocs.canonicalUrlIndicators[0].occurrenceCount, 3);
});

test("many unique tracking-parameter URLs to one host: raw count stays high (forensic), canonical count is 1 (risk-relevant)", () => {
  const links = Array.from(
    { length: 60 },
    (_, i) => `<a href="https://click.mail.brand-example.com/redirect?token=${i}&utm=promo${i}">go</a>`
  ).join(" ");
  const iocs = extractIOCs(parsedEmailWithBody(`<html><body>${links}</body></html>`), minimalHeaderAnalysis());

  assert.equal(iocs.urls.length, 60, "raw forensic count must not be discarded");
  assert.equal(iocs.canonicalUrlIndicators.length, 1, "canonical count must reflect ONE real destination host");
  assert.equal(iocs.canonicalUrlIndicators[0].occurrenceCount, 60);
  assert.ok(
    iocs.canonicalUrlIndicators[0].sampleUrls.length <= 5,
    "sampleUrls must be capped for forensic display, not repeat all 60"
  );
});

test("genuinely different destinations (including a malicious-looking one) are NOT collapsed together", () => {
  const html = `<html><body>
    <a href="https://newsletter.example.com/track?x=1">Newsletter</a>
    <a href="https://newsletter.example.com/track?x=2">Newsletter 2</a>
    <a href="http://192.0.2.55/login.php">Suspicious</a>
    <a href="https://totally-different-brand.example/offer">Other brand</a>
  </body></html>`;
  const iocs = extractIOCs(parsedEmailWithBody(html), minimalHeaderAnalysis());

  assert.equal(iocs.canonicalUrlIndicators.length, 3, "three distinct hosts must remain three separate indicators");
  const hostnames = iocs.canonicalUrlIndicators.map((g) => g.hostname).sort();
  assert.deepEqual(hostnames, ["192.0.2.55", "newsletter.example.com", "totally-different-brand.example"]);
});

test("groupUrlsByHost is the single grouping function — deterministic and order-independent for the same input set", () => {
  const urls = [
    "https://a.example.com/1",
    "https://a.example.com/2",
    "https://b.example.com/1",
  ];
  const g1 = groupUrlsByHost(urls);
  const g2 = groupUrlsByHost([...urls].reverse());

  const asMap = (groups: typeof g1) => new Map(groups.map((g) => [g.hostname, g.occurrenceCount]));
  assert.deepEqual(asMap(g1), asMap(g2));
});
