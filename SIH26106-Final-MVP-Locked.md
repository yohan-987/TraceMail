# SIH 26106 — Complete Technical Reference
## AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

**This is the definitive reference document, not a new scope iteration.** Every feature below is either already built and verified, or scoped and scheduled under the locked Tier 1 / Tier 2 build plan. No item here is new — this document exists to hold everything already decided in one place: what the system does, how it's built, and why each design choice was made the way it was.

---

## 1. Positioning

> Most phishing detectors produce a score. This platform produces an investigation — evidence collected across five independent categories, fused without double-counting correlated signals, traced to a candidate origin and likely archetype, correlated against a relationship graph, and explained by an LLM that is structurally forbidden from inventing facts it wasn't given.

Built for a 7-8 day solo, AI-assisted build (Claude for judgment-heavy and security-sensitive work; a local model for fully-specified, mechanical work — see §9).

---

## 2. Non-Negotiable Design Principles

These constraints apply to every feature in this document without exception:

1. **`emailId` is the primary identity.** `caseId` is optional grouping metadata, never a gate — nothing requires a case to exist before an email can be analyzed.
2. **Missing evidence is always `UNAVAILABLE` / `NOT_APPLICABLE`** — never silently treated as 0 or "safe." A category that couldn't be evaluated must say so, not default to a clean result.
3. **Geolocation and infrastructure findings are "probable," never attacker identity.** The system traces infrastructure, not people.
4. **ML output, deterministic rules, external intelligence, and LLM interpretation stay visually distinguishable at every layer** — a user should always be able to tell which kind of evidence they're looking at.
5. **The LLM explains and narrates evidence — it never invents evidence.** Enforced by an explicit anti-fabrication system prompt (§5.9).
6. **The original `.eml` is preserved byte-for-byte.** Every finding traces back to it via SHA-256, computed before any parsing occurs.
7. **Suspicious URLs are never auto-fetched; attachments are never executed.** The system analyzes, it does not interact with attacker-controlled content.
8. **Any single failed integration degrades gracefully.** One dead external API never breaks the pipeline or silently passes an email as benign.
9. **Every claim in this document that says "Built" must survive being clicked on by someone who didn't write it.** This principle exists because it was violated once (an earlier Cases page implementation claimed to be real-data-backed while running on mock data) — it does not get violated again. The status table in §3 is the enforcement mechanism.

---

## 3. Feature Status — What's Built vs. What's Being Added

| Feature | Status | Tier |
|---|---|---|
| NLP (TF-IDF + trained Logistic Regression) | ✅ Built | — |
| Content heuristics (urgency/credential/financial/BEC) | ✅ Built | — |
| Header forensics + authentication-result parsing | ✅ Built | — |
| Display-name / brand impersonation detection | ✅ Built | — |
| URL/domain structural rules + dual look-alike detection | ✅ Built | — |
| GeoIP + static suspicious IP/ASN/cloud-VPS lists | ✅ Built | — |
| Risk fusion engine (noisy-OR, coverage-aware) | ✅ Built | — |
| Campaign correlation engine (backend) | ✅ Built | — |
| LLM interpretation layer (evidence-grounded, anti-fabrication) | ✅ Built | — |
| Report generation + recommendations engine | ✅ Built | — |
| Relationship graph (backend + endpoint) | ✅ Built, frontend not yet wired | 1 |
| DNS/MX intelligence | ✅ Built | — |
| .eml upload ingestion | ✅ Built | — |
| Gmail OAuth + polling ingestion | ⬜ Adding | 1 |
| Cases page real-data wiring | 🔴 Currently broken — mock data | 1 |
| Campaign correlation → Cases UI | 🔴 Currently broken — hardcoded UNAVAILABLE | 1 |
| `recommendedActions` field wiring | 🔴 Currently broken — reads wrong field | 1 |
| WHOIS / domain-age | 🟡 Stubbed — schema + UI exist, lookup returns null | 1 |
| Earliest reliable sending node | ⬜ Adding | 1 |
| Attack archetype (4-way classification) | ⬜ Adding | 1 |
| Access control (single-analyst login gate) | ⬜ Adding | 1 |
| Retention policy (configured value) | ⬜ Adding | 1 |
| Access log | ⬜ Adding | 1 |
| Compliance reference line in report | ⬜ Adding | 1 |
| Explainability panel (LR coefficient breakdown) | ⬜ Adding if time remains | 2 |
| Threat narrative (deterministic template) | ⬜ Adding if time remains | 2 |
| PII redaction toggle on report export | ⬜ Adding if time remains | 2 |
| Adversarial + clean demo email curation | ⬜ Adding if time remains | 2 |
| Evidence Consistency Engine | Deferred — Q&A only, see §10 | — |
| IOC pivoting / first-last-seen / attack timeline | Deferred — Q&A only, see §10 | — |
| Analyst verdict/feedback loop | Deferred — Q&A only, see §10 | — |
| Live evidence-accumulation reveal (UI) | Deferred — Q&A only, see §10 | — |
| SQLite migration | Deferred — Q&A only, see §10 | — |
| Botnet / open-relay correlation | Deferred — Q&A only, see §10 | — |
| AbuseIPDB (tertiary threat intel) | Deferred — Q&A only, see §10 | — |

**Tier 1 is mandatory.** Tier 2 ships only if Tier 1 is complete with days to spare, and is cut without exception if not started by Day 6.

---

## 4. System Architecture

```text
                         ┌──────────────────────────┐
                         │       DATA SOURCES       │
                         ├──────────────────────────┤
                         │ .eml upload               │
                         │ Gmail API (OAuth, polling)│
                         │ GeoIP · DNS · WHOIS       │
                         │ Static TOR/VPN/ASN lists  │
                         └────────────┬─────────────┘
                                      ▼
                         ┌──────────────────────────┐
                         │      INGESTION LAYER     │
                         │  MIME/EML parser          │
                         │  SHA-256 evidence hash     │
                         │  Flat-file store + raw     │
                         │   .eml files preserved     │
                         └────────────┬─────────────┘
                                      ▼
                 ┌────────────────────────────────────────┐
                 │          EMAIL FORENSICS ENGINE        │
                 └────────────────────────────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          ▼                           ▼                           ▼
┌───────────────────┐      ┌────────────────────┐      ┌────────────────────┐
│   NLP ENGINE      │      │ HEADER FORENSICS   │      │  URL/DOMAIN RULES │
│ TF-IDF + LR        │      │ Auth-result parse  │      │ Structural rules  │
│ Content heuristics:│      │ Received-chain      │      │ Dual look-alike   │
│  urgency/credential/│     │ Earliest reliable   │      │  detection        │
│  financial/BEC      │      │  node               │      │ WHOIS/domain-age  │
│                     │      │ Reply-To/Return-    │      │                    │
│                     │      │  Path mismatch      │      │                    │
│                     │      │ Brand/authority      │      │                    │
│                     │      │  impersonation       │      │                    │
└─────────┬──────────┘      └─────────┬──────────┘      └─────────┬──────────┘
          │                           │                            │
          └────────────┬──────────────┴─────────────┬──────────────┘
                        ▼                            ▼
             ┌────────────────────┐        ┌────────────────────────┐
             │ INFRASTRUCTURE     │        │  ATTACK ARCHETYPE       │
             │ INTELLIGENCE       │        │  4-way evidence-based   │
             │ GeoIP · DNS ·      │        │  classification         │
             │ static suspicious  │        └───────────┬─────────────┘
             │ IP/ASN lists       │                     │
             └──────────┬─────────┘                     │
                        └──────────────┬─────────────────┘
                                       ▼
                       ┌─────────────────────────────┐
                       │   RELATIONSHIP GRAPH        │
                       │   Cytoscape-ready nodes/edges│
                       └──────────────┬───────────────┘
                                      ▼
                       ┌─────────────────────────────┐
                       │  CAMPAIGN CORRELATION       │
                       │  Noisy-OR shared-signal      │
                       │  matching across all stored  │
                       │  emails                      │
                       └──────────────┬───────────────┘
                                      ▼
                       ┌─────────────────────────────┐
                       │   RISK FUSION ENGINE        │
                       │   Noisy-OR within category   │
                       │   Coverage-aware weighted avg│
                       │   across categories          │
                       └──────────────┬───────────────┘
                                      ▼
                       ┌─────────────────────────────┐
                       │  FINAL THREAT ASSESSMENT    │
                       │  score · band · confidence · │
                       │  coverage · archetype         │
                       └──────────────┬───────────────┘
                          ┌───────────┴────────────┐
                          ▼                        ▼
                 ┌─────────────────┐      ┌─────────────────────┐
                 │ LLM INTERPRETER │      │ RECOMMENDATIONS +     │
                 │ Anti-fabrication │      │ REPORT BUILDER        │
                 │  system prompt   │      │ + Chain-of-Custody    │
                 │                  │      │  (report hash + source│
                 │                  │      │  hash pinned together)│
                 └────────┬─────────┘      └──────────┬────────────┘
                          └──────────────┬─────────────┘
                                         ▼
                       ┌──────────────────────────────┐
                       │       ANALYST FRONTEND        │
                       │  Overview · Forensics ·        │
                       │  Infrastructure · Graph ·      │
                       │  Cases · Reports                │
                       │  Access control + PII redaction │
                       └──────────────────────────────┘
```

**Design note — why the graph feeds correlation, not the reverse:** the relationship graph is built from IOCs extracted earlier in the pipeline; campaign correlation then queries across all stored emails using those same IOCs plus additional similarity signals (sender/subject). Building the graph first means correlation results can reference concrete graph nodes rather than recomputing indicator extraction a second time.

---

## 5. End-to-End Workflow

```text
 1. Email enters system             .eml upload OR Gmail polling
 2. Evidence preserved               SHA-256 hash; original .eml untouched
 3. Email parsed                     mailparser → structured fields
 4. Header forensics run             Auth-result parsing, Received-chain,
                                       Reply-To/Return-Path checks,
                                       brand/authority impersonation
 5. Earliest reliable node found     Walk chain oldest→newest, first
                                       public hop = candidate origin
 6. IOC extraction                   IPs, URLs, domains, attachment hashes
 7. URL/domain analysis              Structural rules + dual look-alike +
                                       WHOIS/domain-age
 8. NLP analysis run                 TF-IDF+LR + content heuristics
                                       (urgency/credential/financial/BEC)
 9. Infrastructure enrichment        GeoIP, DNS, static suspicious lists
10. Attack archetype assessed        4-way decision table over evidence
                                       already collected
11. Relationship graph built         Node/edge structure from IOCs
12. Campaign correlation run         Noisy-OR shared-signal matching
                                       against all stored emails
13. Risk fusion                      Noisy-OR within category, coverage-
                                       aware weighted average across
                                       categories
14. LLM interpretation                Structured evidence → validated JSON;
                                       forbidden from inventing facts
15. Recommendations generated         Derived from risk + archetype +
                                       correlation
16. Investigator reviews              Overview → Forensics → Indicators →
                                       Infrastructure → Graph → Cases → AI
17. Forensic report generated         Structured JSON, report SHA-256 +
                                       source SHA-256 pinned together
18. Access logged                     Who viewed which emailId, when
```

Every stage that can fail reports its own status explicitly — no stage's failure is ever interpreted as "clean." This is enforced in the actual risk-engine code, not just stated as a principle.

---

## 6. Core Features, Algorithms & Design Rationale

### 6.1 Ingestion — `.eml` Upload + Gmail Polling

**What:** Accepts raw `.eml` files directly, and polls a connected Gmail inbox on an interval for new mail.

**How:**
- SHA-256 computed over raw bytes immediately on receipt, before any parsing. Original stored immutably; `emailId` assigned.
- Gmail: OAuth2 (`googleapis` package, read-only `gmail.readonly` scope, app kept in Google's Testing publishing status — no verification review needed with a registered test user). A `pollInbox()` function lists new messages since the last processed `historyId` (Gmail's incremental sync cursor, persisted to disk so restarts don't re-ingest everything), fetches each as raw RFC 2822 MIME, and feeds it through the **exact same parser** the `.eml` upload path uses — a Gmail-sourced email produces an identical record shape to an uploaded one, so nothing downstream needs to know or care which source it came from.

**Why polling, not push (Pub/Sub):** push notifications require standing up Cloud Pub/Sub infrastructure and a webhook — real engineering cost with meaningful external-dependency risk inside a 7-8 day window. Polling delivers the same "not manual-upload-only, near-real-time" story at a fraction of the setup risk, and this tradeoff is stated plainly in the pitch rather than hidden.

**Why hash before parse, not after:** if parsing later turns out to be buggy, the hash still proves what arrived — independent of any bug in the system's own code. This is the actual mechanism behind every later chain-of-custody claim, not just a phrase.

---

### 6.2 Header Forensics

**What:** Authentication-result parsing, Received-chain reconstruction, identity-mismatch checks, brand/authority impersonation detection.

**Logic:**
- Parses `Authentication-Results` (falling back to `Received-SPF` when absent) for `spf=`, `dkim=`, `dmarc=`, and `p=` (policy) tokens.
- Reply-To vs. `From`-domain mismatch is weighted **higher** than Return-Path mismatch, because legitimate bulk-mail systems commonly differ on Return-Path alone as normal, non-suspicious behavior — treating them equally would produce false positives on ordinary marketing/transactional mail.
- Display name is checked against a trusted-brand list and a separate authority-keyword list (CEO, Finance Dept, etc.) — flags impersonation when a referenced brand or authority role doesn't match the sending domain.

**Why "authentication-result forensics," not "SPF/DKIM/DMARC verification":** the system reads conclusions the receiving mail server already computed cryptographically — it does not re-implement SPF/DKIM/DMARC's cryptographic verification itself. This distinction is stated explicitly in all documentation and the pitch because it's the exact kind of claim that collapses under one direct technical question if overstated.

---

### 6.3 Earliest Reliable Sending Node

```text
function findEarliestReliableOrigin(receivedChain):
  for hop in receivedChain reversed (oldest → newest):
    if hop.fromIpClassification == "PUBLIC":
      return { candidateOrigin: hop.fromIp, hopIndex: hop.hop,
               basis: "earliest_reliable_public_hop" }
  return { candidateOrigin: null, basis: "no_reliable_public_hop_found" }
```

**Output fields:** `claimedOrigin` (what the newest/topmost header asserts, no reliability judgment applied), `earliestReliableOrigin` (the algorithm's result), `relayHops[]`, `routingAnomalies[]` (flags unexpected private-after-public transitions in the chain), `confidence`.

**Why:** the problem statement explicitly names "identification of the earliest reliable sending node" as a requirement. This operationalizes it directly instead of leaving "Received-chain reconstruction" as a vague gesture toward it.

**Why labeled "Candidate Origin," never "Attacker Location":** origin infrastructure and attacker identity are not the same claim. An attacker who controls their own outbound mail server can insert fake `Received` headers before a message ever leaves their infrastructure — this algorithm identifies the earliest **reliable** public hop from what's present in the chain, not a cryptographically verified point of origin. Conflating "candidate origin" with "attacker location" is exactly the kind of overclaim that fails under cross-examination, so the two are kept linguistically and structurally separate everywhere in the system.

---

### 6.4 NLP Engine

**What:** Two independent, separately-scored layers.
- **Classical layer:** TF-IDF vectorization + a trained Logistic Regression model, serialized and loaded from disk. Evidence is only emitted above a 0.6 phishing-probability threshold, to avoid noisy low-confidence flags.
- **Content heuristic layer (separate, deterministic):** urgency language, credential-request language, financial-request/BEC language — scored independently of the ML model, fully explainable without any inference call.

**Why two separate layers instead of one model:** the classical layer is fast, deterministic, and independently explainable — it directly answers "is this just an LLM wrapper?" with "no, here's a model whose coefficients you can inspect" (see Tier 2 explainability panel, §7.1). The LLM layer (§6.9) is strictly additive semantic depth on top of this, never the sole classifier.

---

### 6.5 URL / Domain Analysis

**What:** Structural heuristics (HTTPS presence, IP-literal host, subdomain count, punycode) plus dual look-alike detection plus WHOIS/domain-age.

**Look-alike algorithm:** normalized Levenshtein similarity run in **two modes** — full-string comparison and prefix comparison — against a trusted-domain list. Running both modes matters because they catch different attack patterns: full-string comparison catches short character substitutions ("paypa1.com"), while prefix comparison catches brand-plus-suffix typosquats ("paypal-secure-login.com") that a full-string comparison would score as dissimilar overall.

**WHOIS algorithm:**
```text
for each enriched domain:
  result = whoisLookup(domain)
  registrar = result.registrar ?? null
  domainAgeDays = result.creationDate
      ? daysBetween(result.creationDate, now)
      : null
```
Domains younger than roughly 30-60 days are scored as a risk signal in the URL/domain category.

**Why WHOIS is worth finishing, not skipping:** newly-registered domains are one of the single most judge-recognizable phishing indicators, directly answers a PS-named requirement (registrar/registration intelligence), and the schema/UI already exist — only the lookup call was missing.

**Critical handling — redaction:** many domains, especially newly-registered ones (exactly the population this signal targets), use privacy/proxy WHOIS redaction that hides or inconsistently returns the creation date. If the WHOIS response is redacted, `domainAgeDays` must be set to `null` and treated as `UNAVAILABLE` per Principle 2 — **never defaulted to 0 or silently read as "not new."** A wrong default here would produce a false negative on exactly the domains the signal exists to catch, so this case is tested explicitly against a real redacted domain before demo day, not assumed to work from testing against clean domains alone.

---

### 6.6 Infrastructure Intelligence

**What:** GeoIP, DNS/domain intelligence, static suspicious IP/ASN/cloud-VPS/TOR-VPN lists.

**Priority order:**
```text
1. GeoIP                    (primary, always attempted for public IPs)
2. Static suspicious lists  (local — never fails due to network issues)
3. DNS/domain intelligence
```

**Why static lists sit ahead of any external API in this priority order:** they never fail due to network issues or rate limits, so the Infrastructure category can always report `AVAILABLE` from local data alone, regardless of whether any third-party service is reachable at demo time. This matches how every external dependency in the system is treated — one dead integration should never collapse a whole evidence category.

**Why not build botnet/open-relay correlation:** botnet C2 correlation needs a live threat feed with no realistic accessible free source at hackathon scope; open-relay detection means actively probing a third-party mail server's relay behavior — a materially different and legally murkier activity than passive analysis. The intent behind this PS line is folded honestly into the anonymized-infrastructure archetype language (§6.7) instead of claimed as a separately built feature.

---

### 6.7 Attack Archetype Assessment

```text
SPOOFED_DOMAIN                    auth fails AND look-alike/raw-IP-host present
COMPROMISED_ACCOUNT                auth passes AND content/behavioral anomalies
                                    present AND no infra/domain red flags
ANONYMIZED_INFRASTRUCTURE          candidate origin matches TOR/VPN/hosting markers
DIRECT_MALICIOUS_INFRASTRUCTURE    candidate origin matches known-suspicious
                                    IP/ASN AND auth fails
INCONCLUSIVE                       coverage too low, or signals conflict without
                                    a clear majority
```
Evaluated in this exact order — first match wins, because some conditions could otherwise overlap (e.g. an email could satisfy both a suspicious-IP match and a look-alike-domain match; the more specific/severe archetype should win the tie).

**Why:** directly answers the PS's line on flagging "whether the email likely originated from a compromised account, spoofed domain, anonymized infrastructure, or direct malicious actor environment" — built entirely from evidence already collected elsewhere in the pipeline, at near-zero marginal engineering cost.

**Why `INCONCLUSIVE` is a real, intended outcome, not a fallback failure:** forcing every email into one of the four positive archetypes when evidence is thin would misrepresent confidence the system doesn't actually have. An honest "we don't have enough evidence to classify this" is a correct answer, and is presented with neutral, non-alarming styling rather than being treated as worse than the other four outcomes.

**Presented as:** *"Likely Archetype: `<value>` — evidence-based, not confirmed attacker identity."*

---

### 6.8 Relationship Graph + Campaign Correlation

**What:** A node/edge graph (`EMAIL`, `EMAIL_ADDRESS`, `DOMAIN`, `URL`, `IP`, `ASN`, `GEOLOCATION`) rendered via Cytoscape.js, backed by a campaign correlation engine.

**Correlation confidence formula:**
```text
confidence = 1 - Π(1 - weight_i)   over each matched signal type
```
Signal types: shared domain, URL, IP, attachment hash, infrastructure, sender-domain similarity, subject similarity — **each contributes at most once**, regardless of how many matching values it produces, so one strong overlapping fact doesn't get inflated by counting it multiple ways.

**Why noisy-OR here, not additive:** identical reasoning to risk fusion (§6.9) — correlated signals (a shared domain and shared sender-similarity often co-occur as the same underlying fact) shouldn't be double-counted as independent proof.

**Why the relationship graph is the highest-leverage single addition in this build:** the backend module and API endpoint already exist and work correctly — the only missing piece is a frontend call and a rendering library. This is real, working intelligence currently returning data nobody can see, at a fraction of the engineering cost of anything else on the build list.

---

### 6.9 Risk Fusion Engine

**Within-category combination (noisy-OR):**
```text
combined = 1 - Π(1 - weight_i / 100)
```
Deliberately not additive: SPF/DKIM/DMARC failures, for example, are often correlated symptoms of one underlying misalignment — summing their weights would double-count a single underlying fact. Noisy-OR means marginal evidence contributes less as more accumulates, which is the correct shape for overlapping, non-independent evidence rather than truly independent evidence.

**Across-category combination (coverage-aware weighted average):**
```text
Technical Integrity     25%
Identity Consistency    20%
URL/Domain Risk         20%
Content/Social Eng.     20%
Infrastructure Risk     15%
```
Categories marked `UNAVAILABLE`/`NOT_APPLICABLE` are excluded entirely — their weight redistributes proportionally among the categories that are available, and is **never treated as 0.**

**Confidence:** a corroboration-count model — `0.4 base + 0.15 per additional category with actual scored evidence`, capped at 0.95. This is explicitly **not** a calibrated statistical probability, and is documented as such rather than implied to be one.

**UI surfacing:**
```text
THREAT SCORE       81 / 100
RISK BAND          HIGH
EVIDENCE COVERAGE  87%
CONFIDENCE         0.84
```

**Why surface coverage and confidence alongside the score, not just the score alone:** a bare number invites the obvious follow-up question "how sure are you, really?" Showing coverage and confidence answers that before it's asked, and demonstrates that the fusion logic is honest about the limits of its own evidence.

---

### 6.10 LLM Interpretation Layer

**What:** Interprets subject, body, sender/Reply-To, and selected technical evidence into structured JSON — phishing intent, credential harvesting, financial fraud, impersonation, social engineering, attack type, summary, recommended actions.

**Guardrail:** the system prompt explicitly forbids the model from inventing IP reputation, GeoIP, WHOIS, DNS, blacklist matches, infrastructure relationships, or attacker identity — it may only interpret evidence it is actually given.

**Why this is the single most load-bearing design decision for the system's credibility:** an LLM given unrestricted latitude to "explain phishing risk" will hallucinate infrastructure facts under pressure — especially in a live demo, where a judge's follow-up question is exactly the kind of pressure that surfaces this failure mode. Constraining the model to interpretation-only, given the same evidence a human analyst sees, keeps every explanation traceable back to something real and independently verifiable.

---

### 6.11 Report Generation & Chain of Custody

**What:** A structured forensic report assembled server-side from stored analysis results, plus a SHA-256 of the report content pinned together with the source email's own hash at generation time.

**Why hash the report itself, not just the source email:** these are two independent integrity claims, not one. Hashing only the source email proves the original wasn't altered since ingestion; hashing the report separately additionally proves the report hasn't been altered *since it was generated* — either claim alone leaves a gap the other closes.

**Why browser print-to-PDF, not a server-side PDF engine:** avoids an entire dependency and its failure modes for a hackathon-scale deliverable — the browser already renders this reliably, at zero additional engineering or operational cost.

---

## 7. Tier 2 — Differentiation Layer (Only If Time Remains)

None of this is new intelligence — all of it reuses computation the system already performs, only surfacing it differently.

### 7.1 Explainability Panel
```text
contribution_i = coefficient_i × feature_value_i
```
The trained Logistic Regression model already has coefficients. Sorting by absolute contribution and rendering the top 5-8 as a bar chart (red = toward phishing, green = toward legitimate) costs zero new inference — it's presentation of numbers the model already produced, next to the NLP score.

### 7.2 Threat Narrative
A deterministic template assembling already-computed facts into a numbered sequence (origin → authentication → identity mismatch → content signals → URL match → infrastructure overlap → campaign membership → overall risk band). The LLM only rewrites this for readability — it does not generate the sequence itself. This is a formatting function over existing data, not a new subsystem, and it does the work of assembling the full evidence story so a judge doesn't have to do it mentally themselves.

### 7.3 PII Redaction Toggle
A checkbox on the Reports page (default: on) that masks a recipient's local-part on export (`j***@company.com`, domain preserved) via a small pure function, scoped only to the report-export view — every other page continues showing the unredacted address.

### 7.4 Demo Email Curation
One adversarial email — clean SPF/DKIM/DMARC, but malicious content/URL/infrastructure — proving the fusion engine catches what a single-layer detector would miss. One legitimate email that correctly does **not** get flagged, proving the system doesn't over-flag. This is content curation, not code — an hour or two total, and it's the single most persuasive demo moment available for the cost.

---

## 8. Privacy, Legal & Compliance Safeguards

The PS names this as its own key component; a judge checking for it needs to find something real, not silence.

- **Access control:** a single-analyst login/session gate (not multi-role RBAC) — proof that "who can view a case" was implemented, not skipped.
- **Retention policy:** a real, configured value (e.g. raw evidence retained 90 days, then the original `.eml` purged while the hash and report remain for audit) — a config field, not a sentence in a document.
- **Access log:** a simple table recording who viewed which `emailId`, when.
- **Compliance reference:** one explicit line in the generated report referencing IT Act 2000 / DPDP Act 2023 alignment.
- **PII redaction** (Tier 2, §7.3).

**Why minimal, not sophisticated:** none of this requires deep security engineering to stop scoring zero on this PS component — it requires existing and being demonstrable.

---

## 9. Tech Stack — What & Why

| Layer | Tool | Why this, specifically |
|---|---|---|
| Frontend | React + TypeScript, Tailwind, Cytoscape.js | Existing codebase convention; Cytoscape chosen because the backend graph endpoint already emits a Cytoscape-ready node/edge shape |
| Backend | Node.js + TypeScript + Express | Single language across frontend/backend reduces context-switching for a solo build |
| Email parsing | `mailparser` | Mature, handles MIME edge cases so a custom parser doesn't have to |
| Gmail ingestion | `googleapis` (Gmail API), OAuth2 Testing mode | Testing mode avoids Google's app-verification review, which isn't feasible on this timeline |
| ML | Custom TF-IDF + Logistic Regression | Deliberately explainable (see §6.4, §7.1) — a black-box model would forfeit the "not just an LLM wrapper" argument |
| Look-alike detection | Custom normalized-Levenshtein | Two-mode (full-string + prefix) comparison needed a custom implementation to control exactly how similarity is scored (§6.5) |
| WHOIS | Node WHOIS lookup library | No paid API key required |
| GeoIP / DNS | Free-tier GeoIP API, DNS resolution | Zero cost, sufficient accuracy for demo-scale evidence |
| LLM | Server-side API call, validated structured JSON output | Structured output + a system prompt is the only way to enforce the anti-fabrication guardrail in §6.10 |
| Storage | Flat JSON files + raw `.eml` on disk | Sufficient at demo scale; migration to SQLite is correctly sequenced after all demo-facing features (§10) — a judge notices a missing live feature far more readily than flat-file latency at small scale |
| Reports | Browser print-to-PDF | Avoids a server-side PDF dependency entirely (§6.11) |
| Local coding assistance | Qwen2.5-Coder-7B-Instruct (Q4_K_M, via Ollama) | Handles fully-specified, low-ambiguity implementation tasks (WHOIS completion, earliest-node translation, retention config, access log, compliance text) to conserve Claude's token budget for security-sensitive and judgment-heavy work (Gmail OAuth, archetype logic, access control, Cases page fix) |

---

## 10. Explicitly Deferred — Stated Plainly in Q&A, Not Built This Cycle

| Item | Why deferred |
|---|---|
| Evidence Consistency Engine | Genuinely new subsystem (reads fused categories, produces an agree/conflict verdict) — real design value, but not a recombination of existing evidence the way Tier 1 items are |
| IOC Pivoting / First-Last-Seen / Attack Timeline | Needs efficient cross-email query patterns the current flat-file store doesn't support well; correctly sequenced after a storage migration that isn't happening this cycle |
| Analyst Verdict / Feedback Loop | A new data-capture subsystem, not a recombination of existing evidence |
| Live evidence-accumulation reveal | Requires new streaming/staged-response logic, not just a read of existing state |
| SQLite migration | Real bottleneck in the flat-file store's full-directory-scan pattern, but demo-facing features correctly take priority for the time available |
| Gmail push (Pub/Sub) | Stated plainly: *"Detection runs on a polling cycle today; a production deployment would sit this behind Gmail push or a mail-flow hook for true pre-delivery interception — what's being demonstrated is the detection and forensic engine underneath, which is what actually needed building for this evaluation."* |
| Botnet / open-relay correlation | No realistic accessible live threat feed; open-relay probing is active third-party interaction, legally murkier than passive analysis. Folded into anonymized-infrastructure archetype language instead. |
| AbuseIPDB | Lowest marginal value of anything considered — cut first if time is short even within Tier 2 |

---

## 11. Demo Script

```text
Upload/receive email (live or via Gmail) → score with confidence +
   coverage shown
→ [Tier 2, if built] explainability panel (top contributing features)
→ header/auth-result forensics → earliest reliable origin
→ WHOIS domain age flagged → archetype assessment
→ relationship graph (real nodes/edges)
→ related campaign shown on Cases page
→ [Tier 2, if built] threat narrative
→ LLM explanation + recommended actions
→ forensic report generated, chain-of-custody logged
→ access control + retention policy shown briefly

Then: run the adversarial email — clean SPF/DKIM/DMARC, but malicious
   content/URL/infrastructure — show the fusion engine catch what a
   single-layer detector would miss.
Then: run one legitimate email to prove the system doesn't over-flag.
Close: state the real-time (polling, not push) framing plainly,
   before a judge has to ask.
```

---

## 12. Pitch Positioning

> "Most phishing detectors give you a score. Ours shows you exactly why — five independent evidence categories, fused without double-counting correlated signals, traced to a candidate origin and archetype, correlated against a relationship graph you can inspect, and explained by an LLM that's structurally forbidden from inventing facts it wasn't given. Every claim on this screen is something you can click on."

---

## 13. The One Rule

**No further scope expansion.** If a new idea occurs during the build, it goes into §10 as Q&A material, not into the build queue. This document's job is to be the thing that gets built against, not revised further.
