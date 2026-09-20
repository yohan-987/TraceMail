import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeUrls } from "../src/analyzers/urlAnalyzer";

// Regression test for docs/audit/PHASE1-AUDIT.md, Finding 1.
//
// Real-world case: a legitimate promotional/marketing email with many
// unique tracking-parameter URLs to the SAME host (each with a
// different token, so exact-string dedupe in iocExtractor.ts does not
// collapse them). Before the fix, analyzeUrls() emitted one
// "suspicious_structure" evidence item PER URL, and the risk engine's
// noisy-OR combination saturated the urlDomain category to ~100 from
// nothing but repeated instances of one weak structural observation.

function manyTrackingUrls(host: string, count: number): string[] {
  const urls: string[] = [];
  for (let i = 0; i < count; i++) {
    // percent-encoded query value + a marketing subdomain structure
    // (sub1.sub2.host) so each trips hasEncodedCharacters/hasMultipleSubdomains.
    urls.push(`https://click.mail.${host}/redirect?token=abc%20${i}&utm=promo${i}`);
  }
  return urls;
}

test("many unique tracking URLs to one host produce ONE suspicious_structure evidence item, not one per URL", () => {
  const urls = manyTrackingUrls("example-brand.com", 90);
  const { evidence } = analyzeUrls("email-1", urls);

  const structuralItems = evidence.filter((e) => e.type === "suspicious_structure");
  assert.equal(
    structuralItems.length,
    1,
    `expected exactly one suspicious_structure evidence item for one host, got ${structuralItems.length}`
  );
  assert.equal(structuralItems[0].weight, 15, "weight must not scale with URL count");
  assert.equal((structuralItems[0].evidence as { count: number }).count, 90);
});

test("distinct hosts each still produce their own evidence item", () => {
  const urls = [...manyTrackingUrls("brand-a.com", 5), ...manyTrackingUrls("brand-b.com", 5)];
  const { evidence } = analyzeUrls("email-2", urls);

  const structuralItems = evidence.filter((e) => e.type === "suspicious_structure");
  assert.equal(structuralItems.length, 2, "two distinct hosts should produce two evidence items");
});

test("a single raw-IP-host link still produces raw_ip_host evidence (no regression on real signals)", () => {
  const { evidence } = analyzeUrls("email-3", ["http://192.0.2.10/login"]);
  const ipItems = evidence.filter((e) => e.type === "raw_ip_host");
  assert.equal(ipItems.length, 1);
  assert.equal(ipItems[0].weight, 30);
});
