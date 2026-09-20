/**
 * Prompt 11 (Section 9, logging/privacy audit). Extracted from
 * gmailClient.ts into its own dependency-free module — gmailClient.ts
 * imports the real `googleapis` package, which isn't installed in
 * every environment this test suite runs in, so a pure helper with no
 * reason to live there was moved out specifically so it stays directly
 * unit-testable.
 *
 * googleapis (and other axios/gaxios-based HTTP clients) throw error
 * objects that carry the full request config as an enumerable
 * property — including any `Authorization: Bearer <token>` header a
 * client attached to the request. Logging such an error directly
 * (`console.error(msg, err)`) prints the whole object, config
 * included, which can put a live credential into server logs. This
 * extracts only what's actually useful for diagnosis — error name,
 * message, and HTTP status if present — and deliberately never reads
 * `.config`/`.request`/headers off the error at all.
 */
export function safeErrorSummary(err: unknown): string {
  if (err && typeof err === "object") {
    const name = "name" in err ? String((err as { name?: unknown }).name) : "Error";
    const message = "message" in err ? String((err as { message?: unknown }).message) : String(err);
    const status =
      "response" in err &&
      err.response &&
      typeof err.response === "object" &&
      "status" in err.response
        ? (err.response as { status?: unknown }).status
        : undefined;
    return status !== undefined ? `${name}: ${message} (HTTP ${status})` : `${name}: ${message}`;
  }
  return String(err);
}
