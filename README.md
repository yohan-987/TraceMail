# TraceMail

**AI-assisted email threat detection and forensic investigation platform.**
Built for the Smart India Hackathon (problem statement SIH26106).

TraceMail takes a suspicious email (an uploaded `.eml` file, or a message picked up from a connected Gmail inbox), preserves it as hashed evidence, runs it through a stack of independent analyzers, fuses their findings into an explainable risk verdict, and gives an analyst a workspace to investigate it: sender infrastructure on a map and graph, extracted indicators, related emails, and a print-ready forensic report.

## Features

**Ingestion**
- Upload `.eml` files (up to ~25 MB by default), optionally grouped under a `caseId`.
- Optional Gmail polling: a connected account is checked on an interval (default 45 s) and every new message goes through the same pipeline as an upload.
- Every email is stored as evidence with a SHA-256 hash; a configurable retention policy is exposed through the API.

**Analysis**
- **Header forensics:** SPF / DKIM / DMARC results, forwarding analysis, Reply-To and display-name mismatches.
- **URL and domain analysis:** lookalike domains, raw-IP hosts, WHOIS and DNS intelligence.
- **Content heuristics:** urgency, credential-request and financial-request language.
- **IOC extraction:** URLs, domains, IPs and other indicators pulled out of the message.
- **GeoIP and infrastructure mapping:** sender and hop infrastructure shown on a Leaflet map and a Cytoscape graph.
- **ML content classifier:** TF-IDF + logistic regression, implemented from scratch in TypeScript, with a per-term explanation of why it scored a message the way it did.
- **Optional LLM assessment:** Anthropic or Gemini. Off by default; the scan works fine without it.
- **Correlation:** finds related emails across everything stored so far.

**Risk engine**
- Evidence is grouped into categories (technical, identity, URL/domain, infrastructure, content) and combined with a noisy-OR rather than a flat sum, so correlated signals like SPF, DKIM and DMARC failing together are not double-counted.
- Categories made up only of weak evidence are capped, so a pile of innocuous signals cannot reach "high" or "critical" on volume alone.
- Output is a level (`low`, `moderate`, `high`, `critical`), a classification, the supporting evidence, and recommended actions.

**Analyst workspace (frontend)**
- Pages: Overview, Cases, Scanner, Investigation, Indicators, Infrastructure, Forensics, AI Investigation, Reports, and Login.
- Forensic reports are structured JSON rendered in the browser; export to PDF with the browser's Print dialog (no server-side PDF generation).
- Viewing an email's record is written to an access log.

## Architecture

```
TraceMail/
├── FRONTEND/                    React 18 + Vite + TypeScript + Tailwind
│                                (Leaflet, Cytoscape, React Router)
├── backend-batch3.5/backend/    Express 4 + TypeScript API
│   ├── src/analyzers/           header, URL, domain, content, IOC, risk engine, report builder
│   ├── src/ml/                  TF-IDF, logistic regression, training and benchmark code
│   ├── src/services/            ingest pipeline, Gmail, GeoIP, DNS, LLM, storage
│   ├── src/routes/              auth, emails, gmail, compliance, health
│   ├── models/                  trained model (tfidf-logistic-v1) and its metrics
│   ├── ml-transformer/          optional Python transformer pipeline (not benchmarked)
│   ├── docs/ml/AUDIT.md         ML audit, benchmark and model selection
│   └── tests/                   backend test suite
└── .eml samples/                sample emails for trying the scanner
```

The frontend talks to the backend over `/api/v1`. In development, Vite proxies `/api` to `http://localhost:4000`.

## Getting started

### Prerequisites

- Node.js 20 or newer and npm
- Python 3.10+ is only needed for the optional transformer pipeline

### 1. Backend

```bash
cd backend-batch3.5/backend
npm install
cp .env.example .env
```

Login is a single analyst account configured through environment variables. Generate a password hash and add the credentials to `.env`:

```bash
npm run hash:password -- "your-chosen-password"
```

```env
ANALYST_USERNAME=analyst
ANALYST_PASSWORD_HASH=<paste the hash printed above>
SESSION_SECRET=<a long random string>
```

`.env.example` does not list these three, so add them yourself. Without `ANALYST_USERNAME` and `ANALYST_PASSWORD_HASH`, login always fails.

Then start the API:

```bash
npm run dev        # http://localhost:4000
```

### 2. Frontend

```bash
cd FRONTEND
npm install
npm run dev        # http://localhost:5173
```

Sign in with the analyst credentials, open **Scanner**, and upload one of the files from `.eml samples/`.

## Configuration

All backend settings are environment variables, loaded from `backend-batch3.5/backend/.env`.

| Variable | Purpose | Default |
| --- | --- | --- |
| `PORT` | API port | `4000` |
| `ANALYST_USERNAME` | Analyst login name | none (required) |
| `ANALYST_PASSWORD_HASH` | Hash from `npm run hash:password` | none (required) |
| `SESSION_SECRET` | Session signing secret | an insecure dev value; always set your own |
| `CORS_ORIGINS` | Comma-separated allowed origins | reflects any origin (fine for local dev) |
| `MAX_UPLOAD_BYTES` | Upload size limit | `26214400` (~25 MB) |
| `LLM_PROVIDER` | `anthropic` or `gemini` | `anthropic` |
| `LLM_API_KEY` | Enables the AI assessment when set | empty (AI assessment unavailable) |
| `LLM_MODEL` / `LLM_API_URL` / `LLM_TIMEOUT_MS` | LLM model, endpoint and timeout | see `.env.example` |
| `GEOIP_API_URL` / `GEOIP_TIMEOUT_MS` | GeoIP provider | `http://ip-api.com/json`, `5000` |
| `DNS_INTEL_ENABLED` / `DNS_TIMEOUT_MS` | DNS intelligence (`0` disables) | `1`, `2000` |
| `ML_MODEL_PATH` | Override the bundled model file | bundled `models/tfidf-logistic-v1.json` |
| `GMAIL_CLIENT_ID` / `GMAIL_CLIENT_SECRET` / `GMAIL_REFRESH_TOKEN` | Enable Gmail polling | unset (polling disabled) |
| `GMAIL_POLL_INTERVAL_SECONDS` | Gmail poll interval | `45` |
| `EMAIL_DATA_DIR` | Where evidence is stored | `backend-batch3.5/backend/data/emails` |
| `ACCESS_LOG_PATH` | Access log file | `backend-batch3.5/backend/data/access-log.json` |

Every optional provider (LLM, GeoIP, DNS, Gmail) degrades gracefully: if one is unavailable or unconfigured, the scan still completes and that layer is marked unavailable.

### Enabling Gmail polling (optional)

1. In Google Cloud Console, create a project, enable the Gmail API, configure the OAuth consent screen in Testing mode and add the inbox you want to monitor as a test user.
2. Create an OAuth client of type **Desktop app** and put its ID and secret in `.env` as `GMAIL_CLIENT_ID` and `GMAIL_CLIENT_SECRET`.
3. Run `npm run get:gmail-token`, approve access in the browser, and paste the printed value into `.env` as `GMAIL_REFRESH_TOKEN`.
4. Restart the backend. `GET /api/v1/gmail/status` reports the polling state.

Keep your OAuth credentials out of version control (`Oauth/` and the polling cursor file are already git-ignored).

## API

All routes are under `/api/v1`. Everything except `/health` and the `/auth` routes requires a logged-in session.

| Method | Route | Description |
| --- | --- | --- |
| `GET` | `/health` | Health check (public) |
| `POST` | `/auth/login` | Log in with the analyst credentials |
| `POST` | `/auth/logout` | End the session |
| `GET` | `/auth/me` | Current session state |
| `POST` | `/emails/scan` | Upload an `.eml` (multipart field `file`, optional `caseId`) |
| `GET` | `/emails` | List stored emails with summary scores |
| `GET` | `/emails/:emailId` | Full stored record, including risk, ML, AI and recommendations |
| `GET` | `/emails/:emailId/graph` | Infrastructure graph for the email |
| `GET` | `/emails/:emailId/related` | Correlated emails |
| `GET` | `/emails/:emailId/access-log` | Who viewed this record and when |
| `GET` | `/emails/:emailId/report` | Structured forensic report |
| `GET` | `/gmail/status` | Gmail polling status |
| `GET` | `/compliance/retention-policy` | Configured evidence retention policy |

## The ML model, honestly

The bundled classifier (`tfidf-logistic-v1`, model version 2.0) is a TF-IDF + logistic regression model trained on a hand-written dataset of 81 examples (40 phishing, 41 legitimate), using a seeded 70/15/15 split.

| Split | Precision | Recall | F1 |
| --- | --- | --- | --- |
| Test (13 examples) | 1.00 | 0.83 | 0.91 |

Treat these numbers as illustrative, not as production evidence: the test set is 13 emails, the data is synthetic, and the output is an uncalibrated score, not a real-world probability. The model contributes one category (content) to the overall verdict; it does not decide alone.

`backend-batch3.5/backend/docs/ml/AUDIT.md` documents a data-leakage issue found and fixed in the original dataset, the benchmark, and why the classical model was kept. A DistilBERT fine-tuning pipeline lives in `ml-transformer/`, but it has **not been run or benchmarked**, so no transformer results are claimed.

Retrain the classical model with:

```bash
cd backend-batch3.5/backend
npm run train:ml
```

## Development

```bash
# Backend (from backend-batch3.5/backend)
npm test               # full test suite
npm run typecheck
npm run build && npm start

# Frontend (from FRONTEND)
npm test
npm run typecheck
npm run lint
npm run build
```

## Known limitations

- **Single analyst:** one account from environment variables. No multi-user support, roles, or password reset.
- **In-memory sessions:** the session store is process memory, so restarting the server logs everyone out, and it is not suitable for multiple instances.
- **File-based storage:** evidence lives on local disk, not in a database.
- **Retention is configuration only:** the 90-day raw-evidence retention policy is served by the API, but automatic purging is not implemented.
- **Small ML dataset:** see above.

## Evidence handling

Emails you scan may be real phishing messages with live malicious links or attachments. Handle the original `.eml` files with care, and avoid opening them in a mail client on a machine you care about.
