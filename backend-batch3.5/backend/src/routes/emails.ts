import { Router, Request, Response, NextFunction } from "express";
import { uploadEml } from "../utils/upload";
import { sha256 } from "../utils/hash";
import { generateEmailId } from "../utils/ids";
import { assertSafeFilename } from "../utils/filename";
import { Errors } from "../utils/apiError";
import { parseEmlBuffer } from "../analyzers/emailParser";
import { analyzeHeaders } from "../analyzers/headerForensics";
import { extractIOCs } from "../analyzers/iocExtractor";
import { analyzeUrls } from "../analyzers/urlAnalyzer";
import { analyzeDomains } from "../analyzers/domainAnalyzer";
import { analyzeContent } from "../analyzers/contentHeuristics";
import { computeRisk } from "../analyzers/riskEngine";
import { assessMl, getDefaultPredictor, mlInputFromEmail } from "../analyzers/mlClassifier";
import { assessAi } from "../analyzers/aiAssessment";
import { analyzeInfrastructure } from "../analyzers/infrastructure";
import { geoIpProviderFromEnv } from "../services/geoipClient";
import { dnsProviderFromEnv } from "../services/dnsClient";
import { llmProviderFromEnv } from "../services/llmClient";
import {
  saveOriginalEml,
  saveEmailRecord,
  getEmailRecord,
  listEmailSummaries,
  toPublicEmailRecord,
} from "../services/emailStore";
import { applyEmailListQuery, parseEmailListQuery } from "../services/emailQuery";
import type { EmailRecord, ScanAcceptedResponse } from "../schemas/types";

export const emailsRouter = Router();

// POST /api/v1/emails/scan
// Batch 1: validates upload, preserves the original .eml untouched,
// hashes evidence, parses it, and persists the full EmailRecord.
// Batch 2: header/authentication forensics now run here too.
// Batch 3: IOC extraction, URL/domain analysis, content heuristics, and
// the deterministic risk engine now run here too.
// Batch 4: ML, LLM, GeoIP, and DNS enrichment run here as optional
// layers. Missing providers must not fail the scan.
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

      // Hash the exact uploaded bytes BEFORE anything else touches them.
      const evidenceHash = sha256(file.buffer);
      const emailId = generateEmailId();

      // Preserve the original evidence untouched on disk.
      const storagePath = await saveOriginalEml(emailId, file.buffer);

      // Parse — never throws; malformed input degrades to warnings on
      // an otherwise-empty ParsedEmail rather than aborting the scan.
      const { parsed, warnings } = await parseEmlBuffer(emailId, file.buffer);

      // Batch 2: header/authentication forensics run on the parsed
      // structure — no re-parsing of the raw email needed.
      const { headerAnalysis, authentication } = analyzeHeaders(parsed);

      // Batch 3: IOCs reuse headerAnalysis's already-parsed Received
      // chain IPs rather than re-deriving them.
      const iocs = extractIOCs(parsed, headerAnalysis);
      const { urlAnalysis, evidence: urlEvidence } = analyzeUrls(emailId, iocs.urls);
      const { domainAnalysis, evidence: domainEvidence } = analyzeDomains(emailId, iocs.domains);
      const { evidence: contentEvidence, featureCounts } = analyzeContent(parsed);

      const predictor = await getDefaultPredictor();
      const { mlAssessment, evidence: mlEvidence } = assessMl({
        emailId,
        input: mlInputFromEmail(parsed, iocs.urls.length, featureCounts),
        predictor,
      });

      const [infraResult, aiResult] = await Promise.all([
        analyzeInfrastructure({
          emailId,
          headerAnalysis,
          iocs,
          geoIp: geoIpProviderFromEnv(),
          dns: dnsProviderFromEnv(),
        }),
        assessAi({
          emailId,
          parsed,
          headerAnalysis,
          authentication,
          urlAnalysis,
          mlAssessment,
          provider: llmProviderFromEnv(),
        }),
      ]);

      // Every RiskEvidenceItem across all analyzers feeds the risk
      // engine, which combines them per-category with a non-additive
      // aggregation (see riskEngine.ts) — never a blind sum, so
      // correlated signals like SPF/DKIM/DMARC don't double-count.
      // ML/AI items are additional content evidence; they do not replace
      // deterministic findings.
      const explanations = [
        ...headerAnalysis.anomalies,
        ...urlEvidence,
        ...domainEvidence,
        ...contentEvidence,
        ...mlEvidence,
        ...aiResult.evidence,
        ...infraResult.evidence,
      ];
      // Availability context: only the caller knows whether an empty
      // category means "checked, found nothing" vs "nothing to check" —
      // see RiskComputationContext in riskEngine.ts.
      const infrastructureStatus = infraResult.infrastructure.status;
      const risk = computeRisk(emailId, explanations, {
        headerDataAvailable: headerAnalysis.status !== "UNAVAILABLE",
        urlDomainApplicable: iocs.urls.length > 0 || iocs.domains.length > 0,
        infrastructureAvailable: infrastructureStatus === "AVAILABLE",
        infrastructureStatus,
      });

      const record: EmailRecord = {
        emailId,
        caseId,
        evidence: {
          filename: file.originalname,
          sha256: evidenceHash,
          fileSizeBytes: file.buffer.length,
          createdAt: new Date().toISOString(),
          storagePath,
        },
        parsedEmail: parsed,
        headerAnalysis,
        authentication,
        iocs,
        urlAnalysis,
        domainAnalysis,
        risk,
        aiAssessment: aiResult.aiAssessment,
        infrastructure: infraResult.infrastructure,
        report: null,
        explanations,
        warnings,
        mlAssessment,
        intelligenceAssessment: {
          emailId,
          status: infraResult.infrastructure.status,
        },
      };

      await saveEmailRecord(record);

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
emailsRouter.get(
  "/emails/:emailId",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const record = await getEmailRecord(req.params.emailId);
      if (!record) throw Errors.emailNotFound(req.params.emailId);
      return res.status(200).json(toPublicEmailRecord(record));
    } catch (err) {
      return next(err);
    }
  }
);

// GET /api/v1/emails/:emailId/report — placeholder until Batch 6.
emailsRouter.get(
  "/emails/:emailId/report",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const record = await getEmailRecord(req.params.emailId);
      if (!record) throw Errors.emailNotFound(req.params.emailId);
      if (!record.report) throw Errors.reportNotAvailable(req.params.emailId);
      return res.status(200).json(record.report);
    } catch (err) {
      return next(err);
    }
  }
);
