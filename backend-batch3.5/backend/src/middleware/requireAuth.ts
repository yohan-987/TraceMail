import { Request, Response, NextFunction } from "express";
import { Errors } from "../utils/apiError";

// Batch 5: minimal single-analyst session gate. Not RBAC, not
// multi-user — a real, working boundary that demonstrates the PS's
// privacy/access-control requirement rather than leaving it absent.
//
// express-session's default SessionData doesn't know about our two
// custom fields — without this augmentation, req.session.authenticated
// and req.session.username don't typecheck at all (this was missing
// from the first attempt at this batch and would have failed to build).
declare module "express-session" {
  interface SessionData {
    authenticated?: boolean;
    username?: string;
  }
}

export function requireAuth(req: Request, _res: Response, next: NextFunction) {
  if (req.session?.authenticated) {
    return next();
  }
  return next(Errors.unauthorized());
}
