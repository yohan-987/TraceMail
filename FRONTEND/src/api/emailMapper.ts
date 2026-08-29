import type { ApiEmailSummary, ApiEmailDetail } from './api';
import type { ScannedEmail, EmailStatus } from '@/data/mockData';

// Accepts EITHER shape GET /api/v1/emails can return:
//  - ApiEmailSummary: the flat lightweight list-row projection from
//    GET /api/v1/emails (sender/subject/threatScore/riskLevel at the
//    top level).
//  - ApiEmailDetail: the full per-email record from
//    GET /api/v1/emails/:emailId (nested under risk/mlAssessment/
//    aiAssessment/email, plus Batch 5C's `recommendations`).
// Root cause of the historical "Cannot read properties of undefined
// (reading 'split')" crash: this mapper used to assume every caller
// passed the flat summary shape and called `apiEmail.sender.split('@')`
// unguarded. ScannerPage.tsx (and anywhere else that calls getEmail())
// passes the full detail shape, which has no top-level `sender` at
// all — so `.sender` was `undefined` and `.split()` threw. Every field
// below is now derived through a safe fallback chain across both
// shapes instead of assuming one.
// getEmail()'s return type is intentionally left as the implicit `any`
// from response.json() (unchanged from before this fix) so this type
// change stays scoped to the mapper and doesn't ripple into unrelated
// callers (e.g. ForensicsPage.tsx has its own local BackendEmailDetail
// shape). Both ApiEmailSummary and ApiEmailDetail fields are optional
// here — a real caller only ever has ONE of the two shapes, never both.
type ApiEmailAny = Partial<ApiEmailSummary> & Partial<ApiEmailDetail> & { emailId: string };

export function mapApiEmailToUiEmail(apiEmail: ApiEmailAny): ScannedEmail {
  const detailFrom = apiEmail.email?.from?.[0];
  const detailTo = apiEmail.email?.to?.[0];

  const sender = apiEmail.sender ?? detailFrom?.email ?? '';
  const subject = apiEmail.subject ?? apiEmail.email?.subject ?? '';
  const recipient = apiEmail.recipient ?? detailTo?.email ?? '';
  const date = apiEmail.date ?? apiEmail.email?.date ?? '';

  const threatScore = apiEmail.threatScore ?? apiEmail.risk?.score ?? 0;
  const classification = apiEmail.classification ?? apiEmail.risk?.classification ?? 'Unknown';
  const riskLevel = apiEmail.riskLevel ?? apiEmail.risk?.level ?? 'UNKNOWN';

  // Normalize the backend status to exactly match your UI's 4 strict types
  const rawStatus = (apiEmail.status || riskLevel || '').toLowerCase();
  let uiStatus: EmailStatus = 'safe';

  if (rawStatus === 'critical' || rawStatus === 'malicious') uiStatus = 'malicious';
  else if (rawStatus === 'high' || rawStatus === 'suspicious') uiStatus = 'suspicious';
  else if (rawStatus === 'inconclusive') uiStatus = 'inconclusive';

  const authResult = (r?: string): 'pass' | 'fail' | 'none' =>
    r === 'pass' || r === 'fail' ? r : 'none';

  return {
    id: apiEmail.emailId,
    caseId: apiEmail.caseId || '', // Prevents the null crash
    subject,
    sender,
    senderName: sender ? sender.split('@')[0] : '',
    senderDomain: apiEmail.senderDomain || (sender ? sender.split('@')[1] || '' : ''),
    recipient,
    date,
    size: 'N/A', // Placeholder for list view
    threatScore,
    status: uiStatus,
    classification,
    riskLevel,

    // Only present when the full per-email detail was fetched — the
    // list summary doesn't carry authentication/explanations at all.
    threatSummary: apiEmail.aiAssessment?.summary || 'Data loaded from summary API.',
    spf: authResult(apiEmail.authentication?.spf?.result),
    dkim: authResult(apiEmail.authentication?.dkim?.result),
    dmarc: authResult(apiEmail.authentication?.dmarc?.result),
    authenticationSummary: '',
    whyFlagged: (apiEmail.explanations ?? []).map((e) => e.message),
    senderAnomalies: [],
    headers: {},
    receivedChain: [],
    indicators: [],
    infraNodes: [],
    infraEdges: [],
    geoData: [],
    reportSections: [],

    // Batch 4/5C fields — only ever populated from the full detail
    // shape; left undefined (not defaulted) when unavailable, so the UI
    // can distinguish "not fetched" from "fetched, genuinely unavailable".
    mlProbability: apiEmail.mlAssessment?.probability,
    mlStatus: apiEmail.mlAssessment?.status,
    aiSummary: apiEmail.aiAssessment?.summary,
    aiStatus: apiEmail.aiAssessment?.status,
    attackType: apiEmail.aiAssessment?.attackType,
    recommendedActions: apiEmail.recommendations,
  };
}