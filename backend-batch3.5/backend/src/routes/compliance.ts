import { Router, Request, Response } from "express";
import { requireAuth } from "../middleware/requireAuth";
import { RETENTION_POLICY } from "../config/retentionPolicy";

export const complianceRouter = Router();

// Batch 6 — gated behind requireAuth, matching gmail.ts's own established
// precedent for this codebase: "analyst-facing, not a public health
// check like /health, belongs behind the same gate as emailsRouter."
// Retention policy is analyst/compliance-facing tooling content, not a
// public disclosure page, so it follows that same norm rather than
// /health's unauthenticated pattern. Flagging this as a judgment call,
// not something the task spec stated either way.
complianceRouter.use(requireAuth);

// GET /api/v1/compliance/retention-policy — serves the configured
// retention policy so the frontend can display it without hardcoding
// the same values in two places. Does not implement actual
// purge-on-schedule logic — out of scope for this batch.
complianceRouter.get("/compliance/retention-policy", (_req: Request, res: Response) => {
  res.status(200).json(RETENTION_POLICY);
});
