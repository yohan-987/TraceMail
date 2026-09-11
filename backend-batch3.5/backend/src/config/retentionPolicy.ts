// Batch 6 — a real, configured retention value, not a sentence in a
// document (see the platform reference doc, §8: "a config field, not
// a sentence in a document"). Serving this at GET
// /api/v1/compliance/retention-policy is the requirement for this
// batch; actually purging original.eml files on a schedule once they
// pass rawEvidenceRetentionDays is explicitly out of scope here.
export const RETENTION_POLICY = {
  rawEvidenceRetentionDays: 90,
  description:
    "Raw evidence (.eml files) retained for 90 days from ingestion, then purged. " +
    "The SHA-256 hash and generated forensic report are retained indefinitely for audit purposes.",
};
