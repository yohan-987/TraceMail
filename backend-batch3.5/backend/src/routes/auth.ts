import { Router, Request, Response, NextFunction } from "express";
import { Errors } from "../utils/apiError";
import { verifyPassword } from "../utils/password";

export const authRouter = Router();

// POST /api/v1/auth/login
// Batch 5: single hardcoded analyst credential set via env vars.
// Intentionally minimal — no multi-user support, no password reset,
// no JWT. See ANALYST_USERNAME / ANALYST_PASSWORD_HASH.
authRouter.post("/auth/login", (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, password } = req.body ?? {};
    const expectedUsername = process.env.ANALYST_USERNAME;
    const expectedHash = process.env.ANALYST_PASSWORD_HASH;

    if (!expectedUsername || !expectedHash) {
      // Misconfigured server — not the client's fault, but still never
      // leak which env var is missing.
      throw Errors.invalidCredentials();
    }

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username !== expectedUsername ||
      !verifyPassword(password, expectedHash)
    ) {
      throw Errors.invalidCredentials();
    }

    req.session.authenticated = true;
    req.session.username = username;

    return res.status(200).json({ authenticated: true, username });
  } catch (err) {
    return next(err);
  }
});

// POST /api/v1/auth/logout
authRouter.post("/auth/logout", (req: Request, res: Response, next: NextFunction) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    return res.status(200).json({ authenticated: false, username: null });
  });
});

// GET /api/v1/auth/me
authRouter.get("/auth/me", (req: Request, res: Response) => {
  if (req.session?.authenticated) {
    return res.status(200).json({
      authenticated: true,
      username: req.session.username ?? null,
    });
  }
  return res.status(200).json({ authenticated: false, username: null });
});
