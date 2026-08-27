import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeUrls } from "../src/analyzers/urlAnalyzer";

test("flags a raw IP host with high severity, weight 30", () => {
  const { urlAnalysis, evidence } = analyzeUrls("EMAIL-1", ["http://203.0.113.5/login"]);
  assert.equal(urlAnalysis.urls[0].hasIpHost, true);
  const anomaly = evidence.find((e) => e.type === "raw_ip_host");
  assert.ok(anomaly);
  assert.equal(anomaly?.severity, "high");
  assert.equal(anomaly?.weight, 30);
});

test("flags @ symbol, encoded chars, and multiple subdomains as suspicious_structure", () => {
  const { evidence } = analyzeUrls("EMAIL-2", [
    "http://legit.com@evil.com/path%20with%20encoding",
  ]);
  const anomaly = evidence.find((e) => e.type === "suspicious_structure");
  assert.ok(anomaly);
  assert.equal(anomaly?.weight, 15);
});

test("flags known shortener domains", () => {
  const { urlAnalysis, evidence } = analyzeUrls("EMAIL-3", ["https://bit.ly/3xyz"]);
  assert.equal(urlAnalysis.urls[0].isShortened, true);
  assert.ok(evidence.find((e) => e.type === "shortened_url"));
});

test("does not flag a normal, clean HTTPS URL", () => {
  const { evidence } = analyzeUrls("EMAIL-4", ["https://www.example.com/about"]);
  assert.equal(evidence.length, 0);
});

test("computes structural fields correctly (length, subdomain, path, query)", () => {
  const { urlAnalysis } = analyzeUrls("EMAIL-5", ["https://a.b.example.com/some/path?x=1&y=2"]);
  const u = urlAnalysis.urls[0];
  assert.equal(u.isHttps, true);
  assert.equal(u.hostname, "a.b.example.com");
  assert.equal(u.domain, "example.com");
  assert.ok(u.pathLength > 0);
  assert.ok(u.queryLength > 0);
  assert.equal(u.hasMultipleSubdomains, true); // "a.b" -> two subdomain labels
});

test("skips unparseable URLs rather than throwing", () => {
  const { urlAnalysis } = analyzeUrls("EMAIL-6", ["not a url at all"]);
  assert.equal(urlAnalysis.urls.length, 0);
});
