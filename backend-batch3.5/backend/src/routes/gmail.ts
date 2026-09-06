import { Router, Request, Response } from "express";
import { requireAuth } from "../middleware/requireAuth";
import { getGmailStatus } from "../services/gmailClient";

export const gmailRouter = Router();

// Batch 5: this router was left unauthenticated by the first attempt at
// this batch — /gmail/status is analyst-facing, not a public health
// check like /health, so it belongs behind the same gate as emailsRouter.
gmailRouter.use(requireAuth);

// GET /api/v1/gmail/status — lets the frontend show a "Live Gmail:
// connected / not configured" indicator without knowing anything about
// polling internals, OAuth, or cursors.
gmailRouter.get("/gmail/status", (_req: Request, res: Response) => {
  res.status(200).json(getGmailStatus());
});
