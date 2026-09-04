import { Router, Request, Response, NextFunction } from "express";
import { uploadEml } from "../utils/upload";
import { assertSafeFilename } from "../utils/filename";
import { Errors } from "../utils/apiError";
import { buildInfrastructureGraph } from "../analyzers/infrastructureGraph";
import { correlateEmail } from "../analyzers/correlation";
import { generateRecommendations } from "../analyzers/recommendations";
import { buildForensicReport } from "../analyzers/reportBuilder";
import { ingestEmailBuffer } from "../services/emailIngestPipeline";
import {
  getEmailRecord,
  listEmailSummaries,
  listAllEmailRecords,
  toPublicEmailRecord,
} from "../services/emailStore";
import { applyEmailListQuery, parseEmailListQuery } from "../services/emailQuery";
import type { ScanAcceptedResponse } from "../schemas/types";

export const emailsRouter = Router();

// Batch 7 hardening: validate the :emailId route param once, for every
// route that declares it, instead of letting each handler pass the raw
// value straight to storage. safeId() in emailStore.ts already strips
// anything unsafe before touching the filesystem, so this isn't a
// traversal fix — it's about failing a malformed ID cleanly with a 400
// (rather than silently mangling it into an unrelated lookup that
// 404s) and keeping obviously-invalid raw input out of error messages.
const EMAIL_ID_PATTERN = /^[A-Za-z0-9-]{1,100}$/;
emailsRouter.param("emailId", (req: Request, res: Response, next: NextFunction, value: string) => {
  if (!EMAIL_ID_PATTERN.test(value)) {
    return next(Errors.invalidEmailId());
  }
  return next();
});

// POST /api/v1/emails/scan
// Batch 1: validates upload, preserves the original .eml untouched,
// hashes evidence, parses it, and persists the full EmailRecord.
// Batch 2: header/authentication forensics now run here too.
// Batch 3: IOC extraction, URL/domain analysis, content heuristics, and
// the deterministic risk engine now run here too.
// Batch 4: ML, LLM, GeoIP, and DNS enrichment run here as optional
// layers. Missing providers must not fail the scan.
// Batch 1 (Gmail): the actual hash -> parse -> analyze -> persist chain
// now lives in services/emailIngestPipeline.ts, shared with Gmail
// polling — this handler only does upload-specific validation and
// shapes the response.
emailsRouter.post(
  "/emails/scan",
  uploadEml.single("file"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const file = req.file;
      if (!file) throw Errors.missingFile();
      if (file.buffer.length === 0) throw Errors.emptyFile();

      assertSafeFilename(file.originalname);

      // Optional caseId for grouping — never required.
      const caseId =
        typeof req.body?.caseId === "string" && req.body.caseId.trim() !== ""
          ? req.body.caseId.trim()
          : null;

      const record = await ingestEmailBuffer({
        buffer: file.buffer,
        filename: file.originalname,
        caseId,
        source: "upload",
      });

      const response: ScanAcceptedResponse = {
        emailId: record.emailId,
        caseId: record.caseId,
        filename: record.evidence.filename,
        sha256: record.evidence.sha256,
        fileSize: record.evidence.fileSizeBytes,
        status: "accepted",
        warnings: record.warnings,
      };

      return res.status(201).json(response);
    } catch (err) {
      return next(err);
    }
  }
);

// GET /api/v1/emails — lightweight table rows, independent of any case.
// Reads stored summary metadata only; never re-runs ML/LLM/GeoIP/DNS.
emailsRouter.get("/emails", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const q = parseEmailListQuery(req.query as Record<string, string | string[] | undefined>);
    const summaries = await listEmailSummaries();
    return res.status(200).json(applyEmailListQuery(summaries, q));
  } catch (err) {
    return next(err);
  }
});

// GET /api/v1/emails/:emailId — stored full investigation for one email.
// Does not re-run expensive analyzers; returns persisted Batch 1–4 data.
// Batch 5C: also attaches advisory `recommendations`, derived from the
// stored risk/domain/infrastructure results plus a fresh (cheap, O(n))
// Batch 5B correlation check — never executed actions, never re-runs
// ML/LLM/GeoIP/DNS.
emailsRouter.get(
  "/emails/:emailId",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const record = await getEmailRecord(req.params.emailId);
      if (!record) throw Errors.emailNotFound(req.params.emailId);
      const allRecords = await listAllEmailRecords();
      const relatedEmails = correlateEmail(record, allRecords);
      const recommendations = generateRecommendations(record, relatedEmails);
      return res.status(200).json({
        ...toPublicEmailRecord(record),
        recommendations,
      });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /api/v1/emails/:emailId/graph — derived Cytoscape-ready graph for
// one stored email. Pure projection of EmailRecord; does not re-run
// parsers, ML, LLM, GeoIP, or DNS, and does not persist a second dataset.
emailsRouter.get(
  "/emails/:emailId/graph",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const record = await getEmailRecord(req.params.emailId);
      if (!record) throw Errors.emailNotFound(req.params.emailId);
      return res.status(200).json({
        emailId: record.emailId,
        graph: buildInfrastructureGraph(record),
      });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /api/v1/emails/:emailId/related — Batch 5B: evidence-based related-
// email / campaign correlation for one stored email. Reuses stored
// analysis only (candidate generation via inverted indexes, then scoring
// just the candidates) — never re-runs parsers, ML, LLM, GeoIP, or DNS,
// and never a full O(n²) pairwise comparison.
emailsRouter.get(
  "/emails/:emailId/related",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const record = await getEmailRecord(req.params.emailId);
      if (!record) throw Errors.emailNotFound(req.params.emailId);
      const allRecords = await listAllEmailRecords();
      return res.status(200).json(correlateEmail(record, allRecords));
    } catch (err) {
      return next(err);
    }
  }
);

// GET /api/v1/emails/:emailId/report — Batch 6: print-friendly, structured
// forensic report. Built entirely from the stored EmailRecord (plus a
// fresh, cheap Batch 5B correlation check) — never re-runs parsers, ML,
// LLM, GeoIP, or DNS. No PDF is generated server-side; the frontend uses
// the browser's Print → Save as PDF against this structured content.
emailsRouter.get(
  "/emails/:emailId/report",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const record = await getEmailRecord(req.params.emailId);
      if (!record) throw Errors.emailNotFound(req.params.emailId);
      const allRecords = await listAllEmailRecords();
      const relatedEmails = correlateEmail(record, allRecords);
      return res.status(200).json(buildForensicReport(record, relatedEmails));
    } catch (err) {
      return next(err);
    }
  }
);
