import { Router, Request, Response } from "express";
import { getGmailStatus } from "../services/gmailClient";

export const gmailRouter = Router();

// GET /api/v1/gmail/status — lets the frontend show a "Live Gmail:
// connected / not configured" indicator without knowing anything about
// polling internals, OAuth, or cursors.
gmailRouter.get("/gmail/status", (_req: Request, res: Response) => {
  res.status(200).json(getGmailStatus());
});
