import type { ApiRecommendation } from '@/api/api';

// The real-data type for a single email as rendered across the app's
// list/preview surfaces (Cases, Overview, Scanner, the Investigation
// shell, global search, notifications). This shape used to live in
// data/mockData.ts alongside a hardcoded seed array — that array (and
// mockCases/ForensicCase/getTriageStats/getEmailById, none of which
// were used anywhere outside that file) are gone. This is exactly the
// shape api/emailMapper.ts already produces from the real backend, so
// nothing about the type itself changed — only where it lives.

export type EmailStatus = 'safe' | 'suspicious' | 'malicious' | 'inconclusive';

// indicators/infraNodes/infraEdges/geoData are always populated as
// empty arrays by emailMapper.ts today — the real, per-category detail
// lives on the richer types each deep page fetches directly instead
// (ForensicsPage/IndicatorsPage/InfrastructurePage each have their own
// local API-backed shapes). These four field types are kept here under
// their own names — not reused from @/types/infrastructure, which
// has its own real, actively-rendered InfraNode/InfraEdge/MappedGeoEntry
// with slightly different shapes (e.g. an 'unknown' status) — purely so
// ScannedEmail's shape doesn't change out from under any consumer, and
// so the two never collide if ever imported into the same file.
export interface EmailThreatIndicator {
  id: string;
  type: 'IP' | 'Domain' | 'URL' | 'Hash' | 'Email';
  value: string;
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  source: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
}

export interface EmailInfraNode {
  id: string;
  label: string;
  type: 'ip' | 'domain' | 'server' | 'sender';
  x: number;
  y: number;
  status: 'malicious' | 'suspicious' | 'clean';
}

export interface EmailInfraEdge {
  from: string;
  to: string;
  label: string;
}

export interface EmailGeoEntry {
  ip: string;
  country: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  asn: string;
  flag: string;
}

export interface ReceivedHop {
  hop: number;
  from: string;
  by: string;
  timestamp: string;
  delay: string;
}

export interface ScannedEmail {
  id: string;
  caseId: string;
  subject: string;
  sender: string;
  senderName: string;
  senderDomain: string;
  recipient: string;
  date: string;
  size: string;
  threatScore: number;
  status: EmailStatus;
  classification: string;
  riskLevel: string;
  threatSummary: string;
  spf: 'pass' | 'fail' | 'none';
  dkim: 'pass' | 'fail' | 'none';
  dmarc: 'pass' | 'fail' | 'none';
  authenticationSummary: string;
  whyFlagged: string[];
  senderAnomalies: string[];
  headers: Record<string, string>;
  receivedChain: ReceivedHop[];
  indicators: EmailThreatIndicator[];
  infraNodes: EmailInfraNode[];
  infraEdges: EmailInfraEdge[];
  geoData: EmailGeoEntry[];
  reportSections: { title: string; content: string }[];
  // Optional — only populated when the source API response was the full
  // per-email detail (GET /api/v1/emails/:emailId), never the lightweight
  // list summary. Absent (not faked) rather than defaulted, so the UI can
  // tell "not checked yet" apart from "checked, genuinely unavailable".
  mlProbability?: number | null;
  mlStatus?: string;
  aiSummary?: string | null;
  aiStatus?: string;
  attackType?: string | null;
  // Real backend recommendations (routes/emails.ts's `recommendations`
  // field) — reuses api.ts's own ApiRecommendation directly rather than
  // a separate mock-era duplicate of the same shape.
  recommendedActions?: ApiRecommendation[];
}
