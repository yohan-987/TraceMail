import { test } from "node:test";
import assert from "node:assert/strict";

// Must be set BEFORE app/upload module loads, since upload.ts reads
// MAX_UPLOAD_BYTES once at module import time. node:test runs each
// test file in its own process, so this doesn't leak into other files.
process.env.MAX_UPLOAD_BYTES = "1024"; // 1KB limit for this test only

test("POST /emails/scan rejects a file exceeding the configured max size", async () => {
  const { createApp } = await import("../src/app");
  const request = (await import("supertest")).default;
  const app = createApp();

  const oversized = Buffer.alloc(2048, "a"); // 2KB > 1KB limit
  const res = await request(app)
    .post("/api/v1/emails/scan")
    .attach("file", oversized, "big.eml");

  assert.equal(res.status, 413);
  assert.equal(res.body.error.code, "UPLOAD_ERROR");
});
