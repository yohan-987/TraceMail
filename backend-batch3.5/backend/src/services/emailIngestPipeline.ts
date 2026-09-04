import { sha256 } from "../utils/hash";
import { generateEmailId } from "../utils/ids";
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
import { geoIpProviderFromEnv } from "./geoipClient";
import { dnsProviderFromEnv } from "./dnsClient";
import { llmProviderFromEnv } from "./llmClient";
import { saveOriginalEml, saveEmailRecord } from "./emailStore";
import type { EmailRecord } from "../schemas/types";

export interface IngestEmailInput {
  /** Raw bytes, exactly as they'll be hashed and preserved. */
  buffer: Buffer;
  /** Display filename — the actual upload's originalname, or a
   *  synthesized name for non-upload sources (e.g. `gmail-<id>.eml`). */
  filename: string;
  caseId: string | null;
  /** Where these bytes came from. Purely descriptive metadata — every
   *  source produces an identical EmailRecord shape; nothing downstream
   *  branches on this. */
  source: "upload" | "gmail";
  /** Gmail message ID, when source is "gmail" — lets a future dedupe
   *  or re-poll check trace a stored record back to its Gmail message. */
  sourceMessageId?: string;
}

/**
 * The single ingestion pipeline every source (manual .eml upload, Gmail
 * polling, and any future source) must go through: hash the exact bytes
 * before anything touches them, preserve the original untouched, parse,
 * run every analyzer, fuse risk, persist. Extracted out of
 * routes/emails.ts (Batch 1 Gmail work) so a Gmail-sourced email is
 * guaranteed to produce the same EmailRecord shape as an uploaded one —
 * there is no second, parallel implementation of this pipeline anywhere.
 */
export async function ingestEmailBuffer(input: IngestEmailInput): Promise<EmailRecord> {
  const { buffer, filename, caseId, source, sourceMessageId } = input;

  // Hash the exact bytes BEFORE anything else touches them.
  const evidenceHash = sha256(buffer);
  const emailId = generateEmailId();

  // Preserve the original evidence untouched on disk.
  const storagePath = await saveOriginalEml(emailId, buffer);

  // Parse — never throws; malformed input degrades to warnings on an
  // otherwise-empty ParsedEmail rather than aborting ingestion.
  const { parsed, warnings } = await parseEmlBuffer(emailId, buffer);

  const { headerAnalysis, authentication } = analyzeHeaders(parsed);

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

  const explanations = [
    ...headerAnalysis.anomalies,
    ...urlEvidence,
    ...domainEvidence,
    ...contentEvidence,
    ...mlEvidence,
    ...aiResult.evidence,
    ...infraResult.evidence,
  ];

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
      filename,
      sha256: evidenceHash,
      fileSizeBytes: buffer.length,
      createdAt: new Date().toISOString(),
      storagePath,
      source,
      ...(sourceMessageId ? { sourceMessageId } : {}),
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
  return record;
}
