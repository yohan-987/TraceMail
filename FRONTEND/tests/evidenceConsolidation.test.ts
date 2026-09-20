import { test } from "node:test";
import assert from "node:assert/strict";
import { consolidateTopEvidencePoints } from "../src/lib/evidenceConsolidation";

test("exact-duplicate messages between deterministic evidence and AI reasons are deduplicated", () => {
  const result = consolidateTopEvidencePoints(
    ["Message-ID domain differs from sender domain"],
    ["Message-ID domain differs from sender domain", "Additional AI reason"]
  );
  assert.deepEqual(result, ["Message-ID domain differs from sender domain", "Additional AI reason"]);
});

test("dedup is case-insensitive on trimmed text", () => {
  const result = consolidateTopEvidencePoints(["  Some Finding.  "], ["some finding."]);
  assert.equal(result.length, 1);
});

test("caps at 5 by default even with many distinct inputs", () => {
  const many = Array.from({ length: 10 }, (_, i) => `finding ${i}`);
  const result = consolidateTopEvidencePoints(many, []);
  assert.equal(result.length, 5);
});

test("respects a custom max", () => {
  const many = ["a", "b", "c", "d"];
  const result = consolidateTopEvidencePoints(many, [], 2);
  assert.equal(result.length, 2);
});

test("empty/blank entries are dropped, not counted as findings", () => {
  const result = consolidateTopEvidencePoints(["", "   ", "real finding"], [null as any, undefined as any]);
  assert.deepEqual(result, ["real finding"]);
});

test("preserves deterministic-first ordering (deterministic evidence before AI reasons)", () => {
  const result = consolidateTopEvidencePoints(["det-1", "det-2"], ["ai-1"]);
  assert.deepEqual(result, ["det-1", "det-2", "ai-1"]);
});

test("no inputs produces an empty list, not a placeholder", () => {
  assert.deepEqual(consolidateTopEvidencePoints([], []), []);
});
