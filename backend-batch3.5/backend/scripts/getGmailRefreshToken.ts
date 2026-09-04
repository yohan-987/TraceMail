/**
 * One-time developer utility — mints a Gmail OAuth refresh token.
 *
 * NOT part of the running server. Nothing in src/ imports this file, and
 * it is never invoked by server.ts, gmailClient.ts, or any request path.
 * Run it by hand, once — or again if a token is ever revoked or expires:
 *
 *   npm run get:gmail-token
 *
 * Prerequisites (do this in Google Cloud Console first):
 *   1. Create/select a project, enable the Gmail API.
 *   2. Configure the OAuth consent screen in Testing mode, and add the
 *      Gmail account you'll poll as a test user.
 *   3. Create an OAuth client of type "Desktop app."
 *   4. Put its client ID / secret in .env as GMAIL_CLIENT_ID and
 *      GMAIL_CLIENT_SECRET (this script reads them the same way the rest
 *      of the backend does — via "dotenv/config").
 *
 * This script then prints a consent URL, tries to open it in your default
 * browser, and once you approve access, prints the refresh token to paste
 * into .env as GMAIL_REFRESH_TOKEN.
 *
 * Why a local loopback redirect instead of a pasted code: Google
 * deprecated the out-of-band (urn:ietf:wg:oauth:2.0:oob) redirect for
 * OAuth clients created after Feb 2022 — pasting a code shown on a Google
 * page is no longer a flow new clients support. The supported flow for a
 * "Desktop app" client today is a loopback redirect
 * (http://localhost:<port>), so this script briefly starts a local server
 * on that port for the sole purpose of catching the ?code= query param
 * Google appends when it redirects back, then shuts the server down
 * immediately. No new dependency needed — child_process, http, and url
 * are all Node built-ins.
 */
import "dotenv/config";
import { createServer } from "node:http";
import { URL } from "node:url";
import { exec } from "node:child_process";
import { google } from "googleapis";

const PORT = 53682; // arbitrary fixed local port, only bound during this script's run
const REDIRECT_URI = `http://localhost:${PORT}`;
const SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"];

async function main(): Promise<void> {
  const clientId = process.env.GMAIL_CLIENT_ID;
  const clientSecret = process.env.GMAIL_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.error(
      "GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET must be set in .env before running this script."
    );
    process.exitCode = 1;
    return;
  }

  const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret, REDIRECT_URI);

  // access_type=offline + prompt=consent are both required to reliably
  // get a refresh_token back — Google omits it if this account already
  // granted consent once before without prompt=consent forcing a fresh
  // grant screen.
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
  });

  console.log("\n1. Open this URL and approve access with the test-user Gmail account:\n");
  console.log(authUrl);
  console.log(
    `\n2. Waiting for the browser to redirect back to ${REDIRECT_URI} ...\n   (leave this running — it exits on its own once that happens)\n`
  );

  tryOpenBrowser(authUrl);

  const code = await waitForAuthorizationCode();
  const { tokens } = await oAuth2Client.getToken(code);

  if (!tokens.refresh_token) {
    console.error(
      "\nGoogle did not return a refresh_token. This usually means this account\n" +
        "already granted consent to this app previously. Revoke access at\n" +
        "https://myaccount.google.com/permissions and run this script again.\n"
    );
    process.exitCode = 1;
    return;
  }

  console.log("\nRefresh token (paste into .env as GMAIL_REFRESH_TOKEN):\n");
  console.log(tokens.refresh_token);
  console.log("");
}

/** Best-effort only — this is a convenience, never a hard dependency. If
 *  it fails silently, the URL already printed above is the real fallback
 *  path, so no error handling beyond "don't crash" belongs here. */
function tryOpenBrowser(url: string): void {
  const opener =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
  try {
    exec(`${opener} "${url}"`);
  } catch {
    // Ignore — printed URL above is sufficient.
  }
}

/** Starts a throwaway local server for exactly as long as it takes to
 *  catch Google's redirect and read the ?code= query param off it, then
 *  shuts itself down. */
function waitForAuthorizationCode(): Promise<string> {
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      if (!req.url) return;

      const url = new URL(req.url, REDIRECT_URI);
      const code = url.searchParams.get("code");
      const error = url.searchParams.get("error");

      if (error) {
        res.end("Authorization failed — check the terminal, then close this tab.");
        server.close();
        reject(new Error(`Google returned an error: ${error}`));
        return;
      }

      if (!code) {
        res.end("No authorization code on this request — close this tab.");
        return;
      }

      res.end("Authorization complete — you can close this tab and return to the terminal.");
      server.close();
      resolve(code);
    });

    server.listen(PORT);
  });
}

main().catch((err) => {
  console.error("\n[getGmailRefreshToken] failed:", err);
  process.exitCode = 1;
});
