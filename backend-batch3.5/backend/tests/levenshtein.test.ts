import { test } from "node:test";
import assert from "node:assert/strict";
import { levenshteinDistance, normalizedSimilarity } from "../src/utils/levenshtein";

test("levenshteinDistance: identical strings is 0", () => {
  assert.equal(levenshteinDistance("paypal.com", "paypal.com"), 0);
});

test("levenshteinDistance: one substitution", () => {
  assert.equal(levenshteinDistance("paypal.com", "paypa1.com"), 1);
});

test("normalizedSimilarity: identical strings is 1", () => {
  assert.equal(normalizedSimilarity("google.com", "google.com"), 1);
});

test("normalizedSimilarity: close look-alike is high but not 1", () => {
  const sim = normalizedSimilarity("paypa1.com", "paypal.com");
  assert.ok(sim > 0.85 && sim < 1);
});

test("normalizedSimilarity: unrelated strings is low", () => {
  const sim = normalizedSimilarity("google.com", "totally-unrelated-site.net");
  assert.ok(sim < 0.4);
});
