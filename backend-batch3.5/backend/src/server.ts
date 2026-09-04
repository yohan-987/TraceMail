import "dotenv/config";
import { createApp } from "./app";
import { startGmailPolling } from "./services/gmailClient";

const PORT = Number(process.env.PORT ?? 4000);
const app = createApp();

app.listen(PORT, () => {
  console.log(`SIH26106 backend listening on http://localhost:${PORT}`);
});

// Batch 1 — Gmail polling. No-ops with a log line when GMAIL_CLIENT_ID /
// GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN aren't set, so the server
// still runs normally with just .eml upload when Gmail isn't configured.
startGmailPolling();
