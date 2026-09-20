# SIH26106 — Phase 1 Forensic Audit
Regression case: legitimate Genshin Impact / HoYoverse 6th-anniversary
promotional email, forwarded from another Gmail account, misclassified
as SUSPICIOUS / LIKELY COMPROMISED ACCOUNT.

No code changed in this phase. Findings only.

---

## Finding 1 — CONFIRMED BUG: URL evidence is generated per-URL-instance, not per-unique-signal, and compounds without bound

**A. File/path:** `backend-batch3.5/backend/src/analyzers/urlAnalyzer.ts` (function `analyzeUrls`), fed by `backend-batch3.5/backend/src/analyzers/iocExtractor.ts` (function `extractIOCs`) via `backend-batch3.5/backend/src/services/emailIngestPipeline.ts` line 61.

**B. Exact function/component:** `extractIOCs()`'s `urls` dedupe is exact-string only (`dedupe([...extractUrls(...)])`, iocExtractor.ts:56-61). `analyzeUrls()` then emits one `suspicious_structure` (weight 15), `raw_ip_host` (weight 30), or `shortened_url` (weight 10) evidence item **per surviving URL**, with no grouping by hostname/domain and no cap.

**C. Current behavior:** A promotional email with ~90 tracking links to the same domain, each with a unique query-string token (`?utm_source=...&token=...`), survives exact-string dedupe as ~90 distinct "URLs." Each one independently trips `hasEncodedCharacters` and/or `hasMultipleSubdomains` and produces its own `suspicious_structure` evidence item. `riskEngine.ts`'s `combineEvidence()` (noisy-OR: `1 - Π(1 - w/100)`) then multiplies ~90 survival factors of 0.85, which converges to a combined `urlDomain` category score of 100 almost immediately (`0.85^13 ≈ 0.12`, so even ~13 duplicate hits already saturate the category) — this is exactly the reported `URL/domain risk: 100`.

**D. Why it is wrong or risky:** Noisy-OR is a sound way to combine *independent, qualitatively different* signals (SPF fail + DKIM fail + DMARC fail). It is the wrong tool for *the same weak structural observation repeated across near-duplicate instances of one underlying link* — those are not independent evidence, they're one observation multiplied by "how many tracking parameters did the mail-merge tool generate." The result is that raw send volume/marketing-link count, not maliciousness, drives the score to the maximum band. This is also visible in the UI: the near-identical `"A link has a suspicious structure (percent-encoded characters, multiple subdomains)."` message repeated ~90 times that you observed is this same evidence list rendered one row per URL — not an LLM artifact.

**E. Minimal safe fix:** Two independent, complementary changes:
   1. In `iocExtractor.ts`, additionally group URLs by `(hostname, meaningful-path)` — or at minimum by hostname — for the purposes of *evidence generation* (the full IOC list can and should still be preserved for display/forensics). `analyzeUrls` should emit at most one evidence item per (finding-type, hostname) pair, with the count of affected links folded into the evidence's `evidence` payload/message ("14 links to this host carry this structural pattern") rather than 14 separate weighted items.
   2. In `riskEngine.ts`, evidence items of the *same type* within a category should not each get an independent noisy-OR slot — either pre-aggregate same-type items into one representative item (taking the max weight, not the product of survivals) before calling `combineEvidence`, or cap the number of same-type items that participate per category. `contentHeuristics.ts` already follows this correct pattern (one evidence item per matched *category*, never per keyword occurrence) — `urlAnalyzer.ts` should be brought in line with it.

**F. Regression test needed:** A synthetic email with 50+ unique tracking-parameter URLs on one benign host (percent-encoded, multi-subdomain) should NOT push `urlDomain` category score anywhere near "high"/100 — it should score close to what one or two such links would score.

---

## Finding 2 — CONFIRMED BUG: default classification for any non-"low" score is "suspicious," even when every contributing signal is individually weak

**A. File/path:** `backend-batch3.5/backend/src/analyzers/riskEngine.ts`

**B. Exact function/component:** `classify()`, final fallback line: `return level === "low" ? "legitimate" : "suspicious";`

**C. Current behavior:** Once Finding 1 inflates `urlDomain` to 100 and `content` sits around ~36 from ordinary marketing language (urgency/call-to-action keywords), the coverage-weighted final score lands at 32 → `moderate` band. None of the specific evidence types checked earlier in `classify()` (`display_name_*_impersonation`, `possible_lookalike_domain`, `raw_ip_host`, `financial_request_language` + `urgency`/`reply_to_mismatch`, `spf/dkim/dmarc_fail`) are present — so the function falls through to the catch-all, and any `moderate`/`high`/`critical` level becomes `"suspicious"` by default, regardless of *why* the level isn't "low."

**D. Why it is wrong or risky:** This makes the fallback branch effectively "guilty until proven low-risk" rather than "low-risk until specific evidence says otherwise" — the opposite of the system's own stated design principle (missing/weak evidence should never be defaulted toward an alarming conclusion). Combined with Finding 1, weak/duplicated structural evidence alone is enough to cross into `moderate` and get the `suspicious` label with no genuinely suspicious *type* of evidence present at all.

**E. Minimal safe fix:** Do not treat "no specific bad-evidence-type matched" the same as "moderate risk of something." Two safe options, either works and both can be done together:
   1. Track *which* evidence types actually contributed to a non-"low" score, and only fall through to `"suspicious"` when the surviving `moderate+` score is substantially driven by evidence categorized above a "weak" severity/type-list (see Finding 3's WEAK/STRONGER split) rather than by any evidence at all.
   2. Independently of Finding 1's URL fix, this fallback should not be reached purely off `urlDomain`/`content` scores composed entirely of low-severity, structural-only evidence — require at least one `medium`+ severity item outside of `urlDomain`/`content`'s weakest types, or a `high` severity item anywhere, before defaulting away from `legitimate`.

**F. Regression test needed:** An evidence list containing only `low`-severity, structural-only items (e.g. several `suspicious_structure`/`urgency_language`) that happens to land in the `moderate` score band should classify as `legitimate` or a new `"low_confidence_suspicious"`/similar band, not the same `"suspicious"` label used for a message with an actual `spf_fail`+`dkim_fail`.

---

## Finding 3 — CONFIRMED BUG / DESIGN WEAKNESS: weak contextual signals and strong malicious evidence are not distinguished anywhere in the scoring model

**A. File/path:** `backend-batch3.5/backend/src/analyzers/urlAnalyzer.ts`, `headerForensics.ts` (`checkMessageId`), `contentHeuristics.ts`

**B. Exact function/component:** `analyzeOneUrl`/`analyzeUrls` (percent-encoding, multiple subdomains, all folded into one `suspicious_structure` type), `checkMessageId` (Message-ID/From domain mismatch), `KEYWORDS`/`CATEGORY_META` (urgency, call-to-action).

**C. Current behavior:** All of these are legitimate *weak, contextual* signals (per your own Prompt 3 framing) but nothing in the current model marks them as weaker-in-kind than, say, `possible_lookalike_domain` or `spf_fail`/`dkim_fail`/`dmarc_fail`. They all just contribute a `weight` number into the same noisy-OR pool per category, so enough of them stacking up (as in Finding 1) reaches the same numeric territory a genuinely strong signal would reach alone.

**D. Why it is wrong or risky:** Percent-encoding, multiple subdomains, and Message-ID/From mismatches are extremely common in completely legitimate bulk/marketing mail (ESP tracking links, third-party send infrastructure). Treating them as equivalent-in-kind to reputation-confirmed-malicious or lookalike-domain evidence is precisely the "URL complexity mistaken for maliciousness" failure mode named in your prompt.

**E. Minimal safe fix:** Introduce an explicit `evidenceStrength: "weak" | "strong"` (or reuse/extend `severity`) tag already present on `RiskEvidenceItem`, and change `combineEvidence`/`computeCategoryResult` to cap the maximum category contribution attributable to `weak`-only evidence (e.g. `weak` evidence alone cannot push a category score past ~40, only `strong` evidence can cross into `high`/`critical` territory). This is additive to Finding 1's per-instance fix, not a replacement for it.

**F. Regression test needed:** Category score ceiling test — an arbitrarily large pile of `weak`-tagged evidence in one category must not exceed the defined weak-only ceiling.

---

## Finding 4 — LIKELY BUG: `COMPROMISED_ACCOUNT` archetype can fire from ordinary marketing language alone

**A. File/path:** `backend-batch3.5/backend/src/analyzers/archetypeAssessment.ts`

**B. Exact function/component:** `assessArchetype()`, branch 4 (`COMPROMISED_ACCOUNT`): fires when auth is clean-pass, `contentCategory.score > CONTENT_MODERATE_THRESHOLD (25)`, and no lookalike/cloud/known-suspicious flags are present.

**C. Current behavior:** A clean-passing promotional email whose body happens to contain 2+ of the (very common) urgency/call-to-action keyword categories from `contentHeuristics.ts` (e.g. "expires," "click here") clears the 25-point content threshold on ordinary marketing copy alone, and — since nothing else in the email trips the other three archetype branches — gets confidently labeled `LIKELY COMPROMISED ACCOUNT`, with the top two matched keyword evidence messages presented as "basis."

**D. Why it is wrong or risky:** "Compromised legitimate account sending social-engineering content" is a strong, specific claim. Reaching it from nothing but two matched marketing keyword categories is a false positive with a confident, specific label attached — worse for analyst trust than a vaguer `INCONCLUSIVE`.

**E. Minimal safe fix:** Raise `CONTENT_MODERATE_THRESHOLD` for this specific branch and/or require the content evidence to include at least one `credential_request_language` or `financial_request_language` hit (the two `severity: "high"` content categories) rather than being satisfiable by `urgency`/`call_to_action` alone (both `low`/`medium` severity). This is a one-line tightening of the existing branch 4 condition, not a rewrite.

**F. Regression test needed:** Clean-auth email with only `urgency_language` + `call_to_action_language` evidence (no credential/financial-request language, no lookalike/infra flags) → archetype must be `INCONCLUSIVE`, not `COMPROMISED_ACCOUNT`.

---

## Finding 5 — DESIGN WEAKNESS (documented, out of P0 scope per your Prompt 2 instructions): forwarded mail is not specially handled

**A. File/path:** No file — capability does not exist anywhere in `emailParser.ts`, `headerForensics.ts`, or `gmailClient.ts`.

**B. Exact function/component:** N/A.

**C. Current behavior:** There is no parsing of "---------- Forwarded message ---------" body markers, no `Resent-*` header handling, and no concept of "original sender" distinct from the immediate `From:`. A forwarded email is analyzed exactly as if the forwarding account authored it.

**D. Why it is wrong or risky:** This is a real gap, but per your Prompt 2 instructions (do not touch anything beyond canonical-risk/Overview-status this round) and the project's own previously-recorded scope decisions, forwarding-aware analysis was never built for this MVP — it is a known, pre-existing limitation, not a regression. I'm flagging it because your prompt asked specifically about "forwarded mail analyzed as if the forwarder were the original sender," and the honest answer is: yes, that's current behavior, by omission rather than defect.

**E. Minimal safe fix:** Out of scope for P0/P1 here — would need explicit scoping (Q&A-deferred-scope list already exists in project memory; this belongs there if not already).

**F. Regression test needed:** N/A for this phase.

---

## Finding 6 — NOT ACTUALLY A BUG (already fixed, kept for the record): stale cached summary vs. detail-view risk level

**A. File/path:** `backend-batch3.5/backend/src/services/emailStore.ts`

**B. Exact function/component:** `readSummary()` / `toEmailSummary()`, and `applyConsistencyOverride()` in `evidenceConsistency.ts`.

**C. Current behavior:** `readSummary()` explicitly recomputes `toEmailSummary()` live from `parsed.json` on every read (the code comment documents this was a prior bug, already root-caused and fixed: the list view previously trusted a `summary.json` snapshot written before the live consistency override ran). `applyConsistencyOverride` is shared between the list-row projection and the detail route (`routes/emails.ts`), specifically to prevent exactly the two-different-views divergence your prompt asks about.

**D/E/F:** N/A — this requirement (Prompt 2, #5) already appears to be satisfied in the current snapshot. Worth a regression test anyway to keep it that way (see P1 table below).

---

## Finding 7 — UI-ONLY BUG, UNVERIFIABLE IN THIS REPO SNAPSHOT: frontend Overview status rendering

**A. File/path:** Unknown — **the frontend source directory (`frontend/src/**`) was not included in this repomix export**, only `frontend/package.json`. I cannot audit the "frontend derives status independently" or "Overview showing SAFE" behavior without it.

**B–F:** Cannot be completed this phase. This needs a repomix that includes `frontend/src/**` (at minimum the Overview/status-rendering component and whatever enum-mapping utility it uses) before Prompt 2's requirement #3/#8 can be implemented or verified. Backend canonical values (`record.risk.classification`/`level` after `applyConsistencyOverride`) are confirmed correct and stable (score 32 → `moderate`, classification `suspicious`) — if the UI is showing "SAFE" for this record, the bug is entirely on the frontend's own mapping logic, not a value coming from the backend.

---

## Finding 8 — DESIGN WEAKNESS: LLM was not shown to corrupt canonical risk in this case, but the mechanism is fragile

**A. File/path:** `backend-batch3.5/backend/src/analyzers/aiAssessment.ts`, `schemas/llmOutput.ts` (`aiContentScore`)

**B. Exact function/component:** `assessAi()`'s `ai_semantic_phishing` evidence injection, gated on `aiContentScore(parsed) >= 40`.

**C. Current behavior:** For the reported LLM output (phishingIntent 0.5, impersonation 0.5, socialEngineering 0.4, others 0), `aiContentScore` computes to 29, below the 40-point gate — so in this specific case the LLM's (arguably hallucinated — nothing in the supplied evidence actually supports 50% "impersonation") read did **not** get injected into canonical `content` category evidence, and did not move the canonical score. The `"suspicious"` classification and `moderate` level displayed alongside the AI panel both come from the deterministic risk engine (Findings 1/2), not from the LLM.

**D. Why it is wrong or risky:** This is good design *when it works*, but it's a single hardcoded threshold away from directly contaminating canonical score with an ungrounded LLM read, and the LLM is already producing a not-really-justified 50% "impersonation" figure for a message where no impersonation evidence was supplied to it (no lookalike domain, no display-name brand match). That's a prompt/grounding quality issue worth tightening even though it isn't the cause of today's regression.

**E. Minimal safe fix (P1, not P0):** Tighten `SYSTEM_PROMPT` in `aiAssessment.ts` to require the model to ground each non-zero score in a specific field of the supplied evidence JSON, and/or lower `impersonation`'s weight in `aiContentScore` if it keeps drifting up without grounding evidence for it, since the fix belongs in Prompt 3's evidence-semantics work, not Prompt 2's canonical-risk work.

**F. Regression test needed:** Given the exact evidence JSON for this email, a stubbed LLM response should not be allowed to cross the 40-point `aiContentScore` gate without at least one field pointing at real supplied evidence — this needs a prompt-level test (harder to automate; flag as manual/LLM-eval test, not a unit test).

---

## Prioritized table

| Pri | Finding | One-line fix scope |
|---|---|---|
| **P0** | 1 — per-URL evidence compounding | Group URL evidence by host, cap same-type noisy-OR contribution |
| **P0** | 2 — default-to-"suspicious" fallback | Don't default non-"low" scores to "suspicious" absent a real strong-type signal |
| **P0** | 4 — COMPROMISED_ACCOUNT from marketing keywords | Require high-severity content evidence (credential/financial), not just urgency/CTA |
| **P1** | 3 — no weak/strong evidence distinction | Add `evidenceStrength` tag + weak-only score ceiling (this is Prompt 3's main body of work) |
| **P1** | 6 — stale summary vs detail (already fixed) | Add regression test to lock in existing fix |
| **P1** | 8 — LLM impersonation score not grounded | Tighten LLM system prompt / grounding requirement |
| **P2** | 7 — frontend Overview status | **Blocked**: need `frontend/src/**` in a follow-up repomix before this can be audited or fixed |
| **P2** | 5 — no forwarded-mail handling | Explicitly out of scope per your Prompt 2 instructions; log as known limitation only |

---

## What I need from you before Prompt 2/3 implementation
1. Confirmation to proceed with Findings 1, 2, 4 as P0 (these are the three that actually produced the wrong score/classification/archetype in your regression case).
2. If you want Finding 7 (frontend Overview) fixed in this pass, I'll need a repomix that includes `frontend/src/**` — right now I have zero visibility into that code.
