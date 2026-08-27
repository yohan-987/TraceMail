import { test } from "node:test";
import assert from "node:assert/strict";
import { assertSafeFilename } from "../src/utils/filename";

test("accepts a normal, safe filename", () => {
  assert.doesNotThrow(() => assertSafeFilename("invoice.eml"));
});

test("rejects '..' path traversal sequences", () => {
  assert.throws(() => assertSafeFilename("../../etc/passwd.eml"), /UNSAFE_FILENAME|\.\./);
});

test("rejects filenames containing forward slashes", () => {
  assert.throws(() => assertSafeFilename("a/b.eml"));
});

test("rejects filenames containing backslashes", () => {
  assert.throws(() => assertSafeFilename("a\\b.eml"));
});

test("rejects filenames containing control characters", () => {
  assert.throws(() => assertSafeFilename("bad\x00name.eml"));
});

test("rejects an empty filename", () => {
  assert.throws(() => assertSafeFilename(""));
});

test("rejects an excessively long filename", () => {
  assert.throws(() => assertSafeFilename("a".repeat(300) + ".eml"));
});
