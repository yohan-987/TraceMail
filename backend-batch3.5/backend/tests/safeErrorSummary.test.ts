import { test } from "node:test";
import assert from "node:assert/strict";
import { safeErrorSummary } from "../src/utils/safeErrorSummary";

// Prompt 11, Section 9 (logging/privacy audit). Confirms the summary
// never surfaces a request config/headers field — specifically, that
// an Authorization bearer token embedded in a GaxiosError-shaped
// object's `.config.headers` is NOT present anywhere in the output —
// while still extracting genuinely useful diagnostic fields.

test("plain Error: extracts name and message", () => {
  const err = new Error("something failed");
  assert.equal(safeErrorSummary(err), "Error: something failed");
});

test("GaxiosError-shaped object with an embedded Authorization header: the token never appears in the summary", () => {
  const fakeGaxiosError = {
    name: "GaxiosError",
    message: "Request failed with status code 401",
    response: { status: 401, data: {} },
    // This is exactly the shape a real googleapis/gaxios error carries
    // — the full outgoing request config, including auth headers.
    config: {
      url: "https://gmail.googleapis.com/gmail/v1/users/me/history",
      headers: { Authorization: "Bearer ya29.a0ARW5m-super-secret-live-access-token" },
    },
  };
  const summary = safeErrorSummary(fakeGaxiosError);
  assert.equal(summary, "GaxiosError: Request failed with status code 401 (HTTP 401)");
  assert.doesNotMatch(summary, /ya29|Bearer|Authorization/i, "the access token must never appear in the log summary");
});

test("an error with no response/status: omits the HTTP suffix", () => {
  const err = { name: "TypeError", message: "fetch failed" };
  assert.equal(safeErrorSummary(err), "TypeError: fetch failed");
});

test("a non-object thrown value is stringified safely", () => {
  assert.equal(safeErrorSummary("plain string error"), "plain string error");
  assert.equal(safeErrorSummary(42), "42");
});
