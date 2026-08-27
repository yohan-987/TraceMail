import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256 } from "../src/utils/hash";
import { generateEmailId, generateCaseId } from "../src/utils/ids";

test("sha256 is deterministic for identical bytes", () => {
  const a = sha256(Buffer.from("hello world"));
  const b = sha256(Buffer.from("hello world"));
  assert.equal(a, b);
});

test("sha256 differs for different bytes", () => {
  const a = sha256(Buffer.from("hello world"));
  const b = sha256(Buffer.from("hello world!"));
  assert.notEqual(a, b);
});

test("generateEmailId produces the EMAIL-YYYYMMDD-XXXXXX shape", () => {
  const id = generateEmailId();
  assert.match(id, /^EMAIL-\d{8}-[A-Z0-9]{6}$/);
});

test("generateCaseId produces the CASE-YYYYMMDD-XXXXXX shape", () => {
  const id = generateCaseId();
  assert.match(id, /^CASE-\d{8}-[A-Z0-9]{6}$/);
});

test("emailId and caseId generators don't collide in shape", () => {
  const emailId = generateEmailId();
  const caseId = generateCaseId();
  assert.notEqual(emailId.split("-")[0], caseId.split("-")[0]);
});
