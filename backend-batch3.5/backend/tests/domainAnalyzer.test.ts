import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeDomains } from "../src/analyzers/domainAnalyzer";

test("flags a close look-alike of a trusted domain", () => {
  const { evidence, domainAnalysis } = analyzeDomains("EMAIL-1", ["paypa1.com"]);
  const anomaly = evidence.find((e) => e.type === "possible_lookalike_domain");
  assert.ok(anomaly);
  assert.equal(anomaly?.severity, "high");
  assert.equal(anomaly?.weight, 35);
  assert.equal(domainAnalysis.domains[0].lookalikeOf, "paypal.com");
});

test("does not flag the real trusted domain itself", () => {
  const { evidence } = analyzeDomains("EMAIL-2", ["paypal.com"]);
  assert.equal(evidence.find((e) => e.type === "possible_lookalike_domain"), undefined);
});

test("does not flag a legitimate subdomain of a trusted domain", () => {
  const { evidence } = analyzeDomains("EMAIL-3", ["mail.paypal.com"]);
  assert.equal(evidence.find((e) => e.type === "possible_lookalike_domain"), undefined);
});

test("does not flag an unrelated, dissimilar domain", () => {
  const { evidence } = analyzeDomains("EMAIL-4", ["mycompany-internal.com"]);
  assert.equal(evidence.find((e) => e.type === "possible_lookalike_domain"), undefined);
});

test("computes structural fields: tld, subdomain, hyphen/digit counts, punycode", () => {
  const { domainAnalysis } = analyzeDomains("EMAIL-5", ["secure-login123.sub.example.com"]);
  const d = domainAnalysis.domains[0];
  assert.equal(d.tld, "com");
  assert.equal(d.subdomain, "secure-login123.sub");
  assert.ok(d.hyphenCount >= 1);
  assert.ok(d.digitCount >= 3);
  assert.equal(d.isPunycode, false);
});

test("detects punycode domains", () => {
  const { domainAnalysis } = analyzeDomains("EMAIL-6", ["xn--pple-43d.com"]);
  assert.equal(domainAnalysis.domains[0].isPunycode, true);
});
