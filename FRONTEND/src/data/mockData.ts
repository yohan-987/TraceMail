export interface ThreatIndicator {
  id: string;
  type: 'IP' | 'Domain' | 'URL' | 'Hash' | 'Email';
  value: string;
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  source: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
}

export interface ForensicCase {
  id: string;
  caseId: string;
  title: string;
  status: 'open' | 'closed' | 'pending' | 'escalated';
  priority: 'critical' | 'high' | 'medium' | 'low';
  dateOpened: string;
  dateClosed?: string;
  analyst: string;
  threatType: string;
  score: number;
  description: string;
}

export interface InfraNode {
  id: string;
  label: string;
  type: 'ip' | 'domain' | 'server' | 'sender';
  x: number;
  y: number;
  status: 'malicious' | 'suspicious' | 'clean';
}

export interface InfraEdge {
  from: string;
  to: string;
  label: string;
}

export interface GeoEntry {
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

export type EmailStatus = 'safe' | 'suspicious' | 'malicious' | 'inconclusive';

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
  indicators: ThreatIndicator[];
  infraNodes: InfraNode[];
  infraEdges: InfraEdge[];
  geoData: GeoEntry[];
  reportSections: { title: string; content: string }[];
}

const emptyInfraNodes: InfraNode[] = [];
const emptyInfraEdges: InfraEdge[] = [];
const emptyGeo: GeoEntry[] = [];
const emptyIndicators: ThreatIndicator[] = [];
const emptyWhyFlagged: string[] = [];
const emptyAnomalies: string[] = [];

const safeHeaders: Record<string, string> = {
  'Return-Path': '<noreply@google.com>',
  'Received-1': 'from mail-io1.google.com (209.85.167.41) by mx1.company.com',
  'From': 'Google Docs <docs@google.com>',
  'To': 'user@company.com',
  'Date': 'Fri, 22 Aug 2026 14:32:11 +0000',
  'Message-ID': '<CAO8c2x9Qw@mail-io1.google.com>',
  'X-Mailer': 'Google SMTP',
  'MIME-Version': '1.0',
  'Content-Type': 'text/html; charset=UTF-8',
};

export const mockEmails: ScannedEmail[] = [
  {
    id: 'EML-2026-0847',
    caseId: 'CASE-2026-0847',
    subject: 'Urgent: Account Security Verification Required',
    sender: 'security@acc0unt-verify.net',
    senderName: 'Account Security Team',
    senderDomain: 'acc0unt-verify.net',
    recipient: 'j.morrison@company.com',
    date: '2026-08-23 09:14:22 UTC',
    size: '42.3 KB',
    threatScore: 81,
    status: 'malicious',
    classification: 'Phishing',
    riskLevel: 'HIGH RISK',
    threatSummary: 'Credential phishing attempt impersonating internal security team. Sender domain is a lookalike, authentication failed across all protocols, and the message contains links to known phishing infrastructure.',
    spf: 'fail',
    dkim: 'none',
    dmarc: 'fail',
    authenticationSummary: 'Sender authentication failed across all protocols. SPF return is unauthorized.',
    whyFlagged: [
      'Sender domain "acc0unt-verify.net" is a lookalike of the legitimate "account-verify.com"',
      'SPF authentication failed — sending IP 185.220.101.34 is not authorized for this domain',
      'Email contains 3 suspicious URLs redirecting through URL shortener to credential harvest page',
      'Reply-to address differs from sender address and points to a free email provider',
      'Content urgency language ("Immediate action required") detected — common phishing tactic',
    ],
    senderAnomalies: [
      'Display name impersonates internal security team',
      'From domain is a lookalike of account-verify.com',
      'Reply-to address uses free email provider (protonmail.com)',
      'Return-Path differs from From address',
      'X-Mailer indicates PHPMailer 5.2.9 — commonly used in phishing kits',
    ],
    headers: {
      'Return-Path': '<noreply@acc0unt-verify.net>',
      'Received-1': 'from mail.acc0unt-verify.net (185.220.101.34) by mx1.company.com',
      'Received-2': 'from localhost (127.0.0.1) by mail.acc0unt-verify.net',
      'From': 'Account Security Team <security@acc0unt-verify.net>',
      'To': 'j.morrison@company.com',
      'Date': 'Sat, 23 Aug 2026 09:14:22 +0000',
      'Subject': 'Urgent: Account Security Verification Required',
      'Message-ID': '<a4f8c2e1@acc0unt-verify.net>',
      'X-Mailer': 'PHPMailer 5.2.9',
      'Reply-To': 'security.verification@protonmail.com',
      'MIME-Version': '1.0',
      'Content-Type': 'text/html; charset=UTF-8',
    },
    receivedChain: [
      { hop: 1, from: 'mail.acc0unt-verify.net (185.220.101.34)', by: 'mx1.company.com', timestamp: '09:14:22 UTC', delay: '0s' },
      { hop: 2, from: 'localhost (127.0.0.1)', by: 'mail.acc0unt-verify.net', timestamp: '09:14:20 UTC', delay: '2s' },
      { hop: 3, from: 'unknown (10.0.0.1)', by: 'localhost', timestamp: '09:14:18 UTC', delay: '2s' },
    ],
    indicators: [
      { id: 'IOC-001', type: 'IP', value: '185.220.101.34', reputation: 'malicious', source: 'Tor Exit Node DB', firstSeen: '2026-08-20', lastSeen: '2026-08-23', tags: ['TOR', 'Botnet', 'Credential Harvesting'] },
      { id: 'IOC-002', type: 'Domain', value: 'acc0unt-verify.net', reputation: 'malicious', source: 'Threat Intel Feed', firstSeen: '2026-08-19', lastSeen: '2026-08-23', tags: ['Lookalike', 'Phishing', 'Newly Registered'] },
      { id: 'IOC-003', type: 'URL', value: 'https://bit.ly/3xYz-account-verify', reputation: 'malicious', source: 'URL Scanner', firstSeen: '2026-08-23', lastSeen: '2026-08-23', tags: ['Shortener', 'Redirect', 'Credential Theft'] },
      { id: 'IOC-004', type: 'Email', value: 'security.verification@protonmail.com', reputation: 'suspicious', source: 'Reply-To Analysis', firstSeen: '2026-08-23', lastSeen: '2026-08-23', tags: ['Free Email', 'Reply-To Mismatch'] },
      { id: 'IOC-005', type: 'Hash', value: 'a4f8c2e1b3d5e7f9a1c3e5d7f9b1c3e5', reputation: 'suspicious', source: 'Attachment Analysis', firstSeen: '2026-08-23', lastSeen: '2026-08-23', tags: ['PHPMailer', 'Known Phishing Kit'] },
      { id: 'IOC-006', type: 'IP', value: '104.21.45.89', reputation: 'suspicious', source: 'CDN Analysis', firstSeen: '2026-08-21', lastSeen: '2026-08-23', tags: ['Cloudflare', 'Hosted Phishing'] },
      { id: 'IOC-007', type: 'Domain', value: 'account-verify.com', reputation: 'clean', source: 'Legitimate Domain DB', firstSeen: '2019-03-14', lastSeen: '2026-08-23', tags: ['Legitimate', 'Lookalike Target'] },
    ],
    infraNodes: [
      { id: 'n1', label: '185.220.101.34', type: 'ip', x: 50, y: 20, status: 'malicious' },
      { id: 'n2', label: 'acc0unt-verify.net', type: 'domain', x: 25, y: 45, status: 'malicious' },
      { id: 'n3', label: 'mail.acc0unt-verify.net', type: 'server', x: 75, y: 45, status: 'suspicious' },
      { id: 'n4', label: 'security@acc0unt-verify.net', type: 'sender', x: 50, y: 70, status: 'malicious' },
      { id: 'n5', label: 'bit.ly/3xYz', type: 'domain', x: 15, y: 75, status: 'suspicious' },
      { id: 'n6', label: '104.21.45.89', type: 'ip', x: 85, y: 75, status: 'suspicious' },
    ],
    infraEdges: [
      { from: 'n1', to: 'n3', label: 'hosts' },
      { from: 'n3', to: 'n2', label: 'resolves' },
      { from: 'n2', to: 'n4', label: 'sends as' },
      { from: 'n4', to: 'n5', label: 'links to' },
      { from: 'n5', to: 'n6', label: 'redirects' },
      { from: 'n1', to: 'n6', label: 'ASN shared' },
    ],
    geoData: [
      { ip: '185.220.101.34', country: 'Russia', city: 'Moscow', lat: 55.75, lon: 37.62, isp: 'Tor Exit Node', asn: 'AS59723', flag: 'RU' },
      { ip: '104.21.45.89', country: 'United States', city: 'San Francisco', lat: 37.77, lon: -122.41, isp: 'Cloudflare', asn: 'AS13335', flag: 'US' },
      { ip: '10.0.0.1', country: 'Unknown', city: 'Private Network', lat: 0, lon: 0, isp: 'Internal', asn: 'N/A', flag: '--' },
    ],
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'This report details the forensic analysis of email EML-2026-0847, received on 2026-08-23 at 09:14:22 UTC. The email was identified as a phishing attempt with a threat score of 81/100. The sender impersonated an internal security team using the lookalike domain "acc0unt-verify.net". Authentication checks (SPF, DKIM, DMARC) all failed. The email contained links to a credential harvesting page hosted behind a URL shortener.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Sender IP 185.220.101.34 is a known Tor exit node. The domain "acc0unt-verify.net" was registered 4 days prior to the email being sent, a strong indicator of malicious intent. The reply-to address differs from the sender address, a common tactic for credential harvesting. The email body contains 3 URLs, all redirecting through bit.ly to a phishing page.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'IP: 185.220.101.34 (Tor Exit Node, Malicious)\nDomain: acc0unt-verify.net (Lookalike, Malicious)\nURL: https://bit.ly/3xYz-account-verify (Phishing Redirect)\nEmail: security.verification@protonmail.com (Reply-To Mismatch)\nHash: a4f8c2e1b3d5e7f9a1c3e5d7f9b1c3e5 (PHPMailer 5.2.9)' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: FAIL — Sending IP not authorized for domain.\nDKIM: NONE — No DKIM signature present.\nDMARC: FAIL — Both SPF and DKIM failed; no alignment possible.\nRecommendation: Reject all emails from acc0unt-verify.net at the gateway.' },
      { title: 'RECOMMENDATIONS', content: '1. Block sender domain acc0unt-verify.net at email gateway.\n2. Add IP 185.220.101.34 to firewall blocklist.\n3. Notify all users who received this email — advise password reset if credentials were entered.\n4. Monitor for additional emails from lookalike domains.\n5. Update phishing awareness training with this example.' },
    ],
  },
  {
    id: 'EML-2026-0831',
    caseId: 'CASE-2026-0831',
    subject: 'Re: Updated Wire Transfer Instructions — Action Today',
    sender: 'ceo@company-corp.com',
    senderName: 'Sarah K. Whitfield (CEO)',
    senderDomain: 'company-corp.com',
    recipient: 'finance@company.com',
    date: '2026-08-20 11:42:08 UTC',
    size: '18.7 KB',
    threatScore: 94,
    status: 'malicious',
    classification: 'BEC / Wire Fraud',
    riskLevel: 'CRITICAL',
    threatSummary: 'Business Email Compromise impersonating the CEO. Domain "company-corp.com" is a lookalike of the legitimate "company.com". Email requests urgent wire transfer to a new account, a hallmark of BEC attacks.',
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    authenticationSummary: 'All authentication checks failed. Sender domain is a lookalike not owned by the organization.',
    whyFlagged: [
      'Sender domain "company-corp.com" is a lookalike of legitimate "company.com"',
      'Email requests urgent wire transfer to a previously unknown bank account',
      'CEO display name and title used to pressure recipient into bypassing verification procedures',
      'SPF, DKIM, and DMARC all failed — sender is not authorized',
      'Language patterns match known BEC templates (urgency, confidentiality, authority)',
    ],
    senderAnomalies: [
      'Display name matches real CEO but domain differs',
      'Domain registered 2 weeks ago — newly created for this campaign',
      'No prior communication history with this sender address',
      'Reply-to address redirects to external free email provider',
    ],
    headers: {
      'Return-Path': '<ceo@company-corp.com>',
      'Received-1': 'from mail.company-corp.com (45.133.1.22) by mx1.company.com',
      'From': 'Sarah K. Whitfield (CEO) <ceo@company-corp.com>',
      'To': 'finance@company.com',
      'Date': 'Wed, 20 Aug 2026 11:42:08 +0000',
      'Subject': 'Re: Updated Wire Transfer Instructions — Action Today',
      'Message-ID': '<be928f4a@company-corp.com>',
      'X-Mailer': 'RoundCube Webmail 1.4.13',
      'Reply-To': 'sarah.whitfield.exec@yandex.com',
      'MIME-Version': '1.0',
      'Content-Type': 'text/plain; charset=UTF-8',
    },
    receivedChain: [
      { hop: 1, from: 'mail.company-corp.com (45.133.1.22)', by: 'mx1.company.com', timestamp: '11:42:08 UTC', delay: '0s' },
      { hop: 2, from: 'webmail.company-corp.com (45.133.1.22)', by: 'mail.company-corp.com', timestamp: '11:42:05 UTC', delay: '3s' },
    ],
    indicators: [
      { id: 'IOC-101', type: 'IP', value: '45.133.1.22', reputation: 'malicious', source: 'BEC Threat Feed', firstSeen: '2026-08-18', lastSeen: '2026-08-20', tags: ['BEC', 'Lookalike Domain'] },
      { id: 'IOC-102', type: 'Domain', value: 'company-corp.com', reputation: 'malicious', source: 'Domain Registration DB', firstSeen: '2026-08-06', lastSeen: '2026-08-20', tags: ['Lookalike', 'Newly Registered', 'BEC'] },
      { id: 'IOC-103', type: 'Email', value: 'sarah.whitfield.exec@yandex.com', reputation: 'suspicious', source: 'Reply-To Analysis', firstSeen: '2026-08-20', lastSeen: '2026-08-20', tags: ['Free Email', 'Reply-To Mismatch', 'Executive Impersonation'] },
    ],
    infraNodes: [
      { id: 'n1', label: '45.133.1.22', type: 'ip', x: 50, y: 25, status: 'malicious' },
      { id: 'n2', label: 'company-corp.com', type: 'domain', x: 30, y: 50, status: 'malicious' },
      { id: 'n3', label: 'mail.company-corp.com', type: 'server', x: 70, y: 50, status: 'malicious' },
      { id: 'n4', label: 'ceo@company-corp.com', type: 'sender', x: 50, y: 75, status: 'malicious' },
    ],
    infraEdges: [
      { from: 'n1', to: 'n3', label: 'hosts' },
      { from: 'n3', to: 'n2', label: 'resolves' },
      { from: 'n2', to: 'n4', label: 'sends as' },
    ],
    geoData: [
      { ip: '45.133.1.22', country: 'Nigeria', city: 'Lagos', lat: 6.52, lon: 3.38, isp: 'Spectranet', asn: 'AS37371', flag: 'NG' },
    ],
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Business Email Compromise (BEC) attack impersonating CEO Sarah K. Whitfield. Sender used lookalike domain "company-corp.com" to request urgent wire transfer to a fraudulent account. Threat score: 94/100. This represents a critical financial fraud attempt.' },
      { title: 'TECHNICAL ANALYSIS', content: 'The sender domain "company-corp.com" was registered on 2026-08-06, only 14 days before the email was sent. The sending IP 45.133.1.22 is located in Lagos, Nigeria. All authentication protocols failed. The reply-to address redirects to a Yandex free email account.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'IP: 45.133.1.22 (BEC Source, Malicious)\nDomain: company-corp.com (Lookalike, Malicious)\nEmail: sarah.whitfield.exec@yandex.com (Reply-To Mismatch)' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: FAIL\nDKIM: FAIL\nDMARC: FAIL\nAll authentication mechanisms failed. Sender domain is not affiliated with the organization.' },
      { title: 'RECOMMENDATIONS', content: '1. Immediately alert finance team of fraudulent wire request.\n2. Block domain company-corp.com at gateway.\n3. Verify CEO communication through secondary channel.\n4. Review recent wire transfers for unauthorized activity.\n5. Report to FBI IC3 and financial institution.' },
    ],
  },
  {
    id: 'EML-2026-0802',
    caseId: 'CASE-2026-0802',
    subject: 'Invoice #INV-4471 — Payment Overdue',
    sender: 'billing@global-supp1iers.com',
    senderName: 'Global Suppliers Billing',
    senderDomain: 'global-supp1iers.com',
    recipient: 'accounts@company.com',
    date: '2026-08-15 07:22:41 UTC',
    size: '156.4 KB',
    threatScore: 73,
    status: 'malicious',
    classification: 'Malware',
    riskLevel: 'HIGH RISK',
    threatSummary: 'Email contains a macro-enabled Word document disguised as an invoice. The document attempts to download and execute a remote payload from a known C2 server. Domain uses homoglyph attack (1 instead of l).',
    spf: 'fail',
    dkim: 'none',
    dmarc: 'fail',
    authenticationSummary: 'Authentication failed. Domain uses homoglyph characters to impersonate legitimate supplier.',
    whyFlagged: [
      'Domain "global-supp1iers.com" uses homoglyph (digit 1 replacing letter l) to impersonate "global-suppliers.com"',
      'Attachment "INV-4471.docm" contains macro code that downloads remote payload',
      'Attachment hash matches known malware family (Emotet variant)',
      'Sending IP is on multiple blocklists for malware distribution',
      'SPF and DMARC authentication failed',
    ],
    senderAnomalies: [
      'Domain uses homoglyph characters — digit "1" instead of letter "l"',
      'Attachment extension .docm indicates macro-enabled document',
      'No prior invoice history from this sender',
    ],
    headers: {
      'Return-Path': '<billing@global-supp1iers.com>',
      'Received-1': 'from mx2.global-supp1iers.com (193.27.14.88) by mx1.company.com',
      'From': 'Global Suppliers Billing <billing@global-supp1iers.com>',
      'To': 'accounts@company.com',
      'Date': 'Fri, 15 Aug 2026 07:22:41 +0000',
      'Subject': 'Invoice #INV-4471 — Payment Overdue',
      'Message-ID': '<inv4471@global-supp1iers.com>',
      'X-Mailer': 'Exim 4.92',
      'MIME-Version': '1.0',
      'Content-Type': 'multipart/mixed; boundary="boundary123"',
    },
    receivedChain: [
      { hop: 1, from: 'mx2.global-supp1iers.com (193.27.14.88)', by: 'mx1.company.com', timestamp: '07:22:41 UTC', delay: '0s' },
      { hop: 2, from: 'internal-relay (10.5.2.1)', by: 'mx2.global-supp1iers.com', timestamp: '07:22:38 UTC', delay: '3s' },
    ],
    indicators: [
      { id: 'IOC-201', type: 'IP', value: '193.27.14.88', reputation: 'malicious', source: 'Malware Blocklist', firstSeen: '2026-08-10', lastSeen: '2026-08-15', tags: ['Malware', 'C2', 'Emotet'] },
      { id: 'IOC-202', type: 'Domain', value: 'global-supp1iers.com', reputation: 'malicious', source: 'Homoglyph Detection', firstSeen: '2026-08-08', lastSeen: '2026-08-15', tags: ['Homoglyph', 'Malware', 'Invoice Lure'] },
      { id: 'IOC-203', type: 'Hash', value: 'e7b3a9f2c4d6e8a1b3c5d7e9f1a3b5c7', reputation: 'malicious', source: 'Attachment Analysis', firstSeen: '2026-08-15', lastSeen: '2026-08-15', tags: ['Emotet', 'Macro Malware', '.docm'] },
      { id: 'IOC-204', type: 'URL', value: 'http://193.27.14.88/payload.php', reputation: 'malicious', source: 'Sandbox Analysis', firstSeen: '2026-08-15', lastSeen: '2026-08-15', tags: ['C2', 'Payload Download'] },
    ],
    infraNodes: [
      { id: 'n1', label: '193.27.14.88', type: 'ip', x: 50, y: 20, status: 'malicious' },
      { id: 'n2', label: 'global-supp1iers.com', type: 'domain', x: 30, y: 50, status: 'malicious' },
      { id: 'n3', label: 'billing@global-supp1iers.com', type: 'sender', x: 70, y: 50, status: 'malicious' },
      { id: 'n4', label: 'INV-4471.docm', type: 'domain', x: 50, y: 75, status: 'malicious' },
    ],
    infraEdges: [
      { from: 'n1', to: 'n2', label: 'hosts' },
      { from: 'n2', to: 'n3', label: 'sends as' },
      { from: 'n3', to: 'n4', label: 'attaches' },
      { from: 'n4', to: 'n1', label: 'C2 beacon' },
    ],
    geoData: [
      { ip: '193.27.14.88', country: 'Romania', city: 'Bucharest', lat: 44.43, lon: 26.10, isp: 'M247 Europe', asn: 'AS9009', flag: 'RO' },
    ],
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Malware delivery email disguised as overdue invoice. Contains macro-enabled Word document (Emotet variant). Threat score: 73/100. Sending domain uses homoglyph attack.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Attachment "INV-4471.docm" contains VBA macros that download payload from C2 server at 193.27.14.88. Hash matches known Emotet variant. Domain uses digit "1" in place of letter "l".' },
      { title: 'INDICATORS OF COMPROMISE', content: 'IP: 193.27.14.88 (C2 Server, Malicious)\nDomain: global-supp1iers.com (Homoglyph, Malicious)\nHash: e7b3a9f2c4d6e8a1b3c5d7e9f1a3b5c7 (Emotet)\nURL: http://193.27.14.88/payload.php (C2)' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: FAIL\nDKIM: NONE\nDMARC: FAIL' },
      { title: 'RECOMMENDATIONS', content: '1. Quarantine all emails from global-supp1iers.com.\n2. Block IP 193.27.14.88 at perimeter.\n3. Update endpoint AV signatures for Emotet variant.\n4. Verify no users opened the attachment.\n5. Notify legitimate supplier of impersonation.' },
    ],
  },
  {
    id: 'EML-2026-0791',
    caseId: 'CASE-2026-0791',
    subject: 'Updated Banking Details — Please Update Records',
    sender: 'vendor-payments@staplebiz.net',
    senderName: 'Staple Business Solutions',
    senderDomain: 'staplebiz.net',
    recipient: 'accounts@company.com',
    date: '2026-08-12 13:55:17 UTC',
    size: '24.1 KB',
    threatScore: 67,
    status: 'suspicious',
    classification: 'Vendor Fraud',
    riskLevel: 'MODERATE RISK',
    threatSummary: 'Email appears to come from a known vendor requesting banking detail update. Domain is similar but not identical to the vendor\'s legitimate domain. No urgent language, but the request pattern matches vendor fraud tactics.',
    spf: 'pass',
    dkim: 'none',
    dmarc: 'fail',
    authenticationSummary: 'SPF passed but DMARC failed due to domain misalignment. DKIM signature absent. Domain is similar to but not the same as the known vendor domain.',
    whyFlagged: [
      'Domain "staplebiz.net" is similar to known vendor "staple-biz.com" but not identical',
      'Email requests banking detail update — common vendor fraud pattern',
      'DKIM signature absent, DMARC alignment failed despite SPF pass',
      'No prior payment-change requests from this specific domain',
    ],
    senderAnomalies: [
      'Domain similar to known vendor but uses different TLD and no hyphen',
      'No DKIM signature — legitimate vendor emails typically include DKIM',
    ],
    headers: {
      'Return-Path': '<vendor-payments@staplebiz.net>',
      'Received-1': 'from mail.staplebiz.net (198.51.100.42) by mx1.company.com',
      'From': 'Staple Business Solutions <vendor-payments@staplebiz.net>',
      'To': 'accounts@company.com',
      'Date': 'Tue, 12 Aug 2026 13:55:17 +0000',
      'Subject': 'Updated Banking Details — Please Update Records',
      'Message-ID': '<vp0192@staplebiz.net>',
      'X-Mailer': 'Postfix 3.5',
      'MIME-Version': '1.0',
      'Content-Type': 'text/html; charset=UTF-8',
    },
    receivedChain: [
      { hop: 1, from: 'mail.staplebiz.net (198.51.100.42)', by: 'mx1.company.com', timestamp: '13:55:17 UTC', delay: '0s' },
    ],
    indicators: [
      { id: 'IOC-301', type: 'Domain', value: 'staplebiz.net', reputation: 'suspicious', source: 'Vendor Domain Analysis', firstSeen: '2026-08-11', lastSeen: '2026-08-12', tags: ['Vendor Impersonation', 'Banking Change'] },
      { id: 'IOC-302', type: 'IP', value: '198.51.100.42', reputation: 'unknown', source: 'IP Reputation', firstSeen: '2026-08-12', lastSeen: '2026-08-12', tags: ['New IP', 'No History'] },
    ],
    infraNodes: [
      { id: 'n1', label: '198.51.100.42', type: 'ip', x: 50, y: 30, status: 'suspicious' },
      { id: 'n2', label: 'staplebiz.net', type: 'domain', x: 50, y: 60, status: 'suspicious' },
      { id: 'n3', label: 'vendor-payments@staplebiz.net', type: 'sender', x: 50, y: 85, status: 'suspicious' },
    ],
    infraEdges: [
      { from: 'n1', to: 'n2', label: 'hosts' },
      { from: 'n2', to: 'n3', label: 'sends as' },
    ],
    geoData: [
      { ip: '198.51.100.42', country: 'United States', city: 'Phoenix', lat: 33.45, lon: -112.07, isp: 'Hostinger International', asn: 'AS47583', flag: 'US' },
    ],
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Suspicious vendor impersonation email requesting banking detail update. Domain is similar to known vendor but not identical. Threat score: 67/100. Requires manual verification with vendor.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Domain "staplebiz.net" differs from known vendor domain "staple-biz.com" (different TLD, no hyphen). SPF passed but DMARC failed due to alignment mismatch. No DKIM present.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'Domain: staplebiz.net (Vendor Impersonation, Suspicious)\nIP: 198.51.100.42 (Unknown Reputation)' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: PASS\nDKIM: NONE\nDMARC: FAIL (alignment mismatch)' },
      { title: 'RECOMMENDATIONS', content: '1. Verify banking change request with vendor via phone.\n2. Do not update banking details until verified.\n3. Flag domain staplebiz.net for monitoring.\n4. Check if other employees received similar requests.' },
    ],
  },
  {
    id: 'EML-2026-0756',
    caseId: 'CASE-2026-0756',
    subject: 'Parking Invoice — Scan to Pay',
    sender: 'noreply@park-invoice.io',
    senderName: 'City Parking Services',
    senderDomain: 'park-invoice.io',
    recipient: 'd.reyes@company.com',
    date: '2026-08-05 16:08:33 UTC',
    size: '88.2 KB',
    threatScore: 58,
    status: 'suspicious',
    classification: 'Quishing',
    riskLevel: 'MODERATE RISK',
    threatSummary: 'Email contains a QR code that redirects to a credential harvesting page. QR code phishing ("quishing") bypasses traditional URL scanners by encoding the destination inside an image.',
    spf: 'fail',
    dkim: 'none',
    dmarc: 'fail',
    authenticationSummary: 'All authentication checks failed. Domain is newly registered with no legitimate parking service association.',
    whyFlagged: [
      'Email contains QR code that resolves to credential harvesting page',
      'Domain "park-invoice.io" is newly registered (3 days old)',
      'No legitimate parking service uses this domain',
      'SPF and DMARC authentication failed',
      'QR code destination URL not visible in email body — bypasses URL scanners',
    ],
    senderAnomalies: [
      'Domain has no association with any legitimate parking authority',
      'QR code used instead of clickable links to evade URL scanning',
    ],
    headers: {
      'Return-Path': '<noreply@park-invoice.io>',
      'Received-1': 'from mail.park-invoice.io (91.243.59.12) by mx1.company.com',
      'From': 'City Parking Services <noreply@park-invoice.io>',
      'To': 'd.reyes@company.com',
      'Date': 'Tue, 05 Aug 2026 16:08:33 +0000',
      'Subject': 'Parking Invoice — Scan to Pay',
      'Message-ID': '<park0042@park-invoice.io>',
      'X-Mailer': 'Custom SMTP Client',
      'MIME-Version': '1.0',
      'Content-Type': 'text/html; charset=UTF-8',
    },
    receivedChain: [
      { hop: 1, from: 'mail.park-invoice.io (91.243.59.12)', by: 'mx1.company.com', timestamp: '16:08:33 UTC', delay: '0s' },
    ],
    indicators: [
      { id: 'IOC-401', type: 'Domain', value: 'park-invoice.io', reputation: 'suspicious', source: 'Newly Registered Domain', firstSeen: '2026-08-02', lastSeen: '2026-08-05', tags: ['Quishing', 'Newly Registered', 'QR Phishing'] },
      { id: 'IOC-402', type: 'IP', value: '91.243.59.12', reputation: 'suspicious', source: 'IP Reputation', firstSeen: '2026-08-03', lastSeen: '2026-08-05', tags: ['Bulletproof Hosting'] },
    ],
    infraNodes: [
      { id: 'n1', label: '91.243.59.12', type: 'ip', x: 50, y: 30, status: 'suspicious' },
      { id: 'n2', label: 'park-invoice.io', type: 'domain', x: 50, y: 60, status: 'suspicious' },
      { id: 'n3', label: 'QR Code → harvest.page', type: 'domain', x: 50, y: 85, status: 'malicious' },
    ],
    infraEdges: [
      { from: 'n1', to: 'n2', label: 'hosts' },
      { from: 'n2', to: 'n3', label: 'QR redirects' },
    ],
    geoData: [
      { ip: '91.243.59.12', country: 'Bulgaria', city: 'Sofia', lat: 42.70, lon: 23.32, isp: 'Net1 Ltd', asn: 'AS43561', flag: 'BG' },
    ],
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'QR code phishing ("quishing") email disguised as parking invoice. QR code in email body redirects to credential harvesting page. Threat score: 58/100.' },
      { title: 'TECHNICAL ANALYSIS', content: 'QR code encodes URL to credential harvest page hosted at 91.243.59.12. Domain registered 3 days prior. QR codes bypass traditional URL scanners.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'Domain: park-invoice.io (Newly Registered, Suspicious)\nIP: 91.243.59.12 (Bulletproof Hosting)' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: FAIL\nDKIM: NONE\nDMARC: FAIL' },
      { title: 'RECOMMENDATIONS', content: '1. Block domain park-invoice.io at gateway.\n2. Deploy QR code scanning in email security stack.\n3. Warn users about scanning QR codes from emails.\n4. Check if user scanned the QR code.' },
    ],
  },
  {
    id: 'EML-2026-0729',
    caseId: 'CASE-2026-0729',
    subject: 'Re: Confidential — Acquisition Discussion',
    sender: 'cfo@financia1-partners.com',
    senderName: 'Robert Chen (CFO, Financial Partners)',
    senderDomain: 'financia1-partners.com',
    recipient: 'exec@company.com',
    date: '2026-08-08 10:15:44 UTC',
    size: '12.3 KB',
    threatScore: 88,
    status: 'malicious',
    classification: 'Executive Impersonation',
    riskLevel: 'CRITICAL',
    threatSummary: 'Executive impersonation targeting company executives. Sender impersonates a CFO from a known partner firm using a homoglyph domain. Email references confidential acquisition discussions to elicit response.',
    spf: 'fail',
    dkim: 'none',
    dmarc: 'fail',
    authenticationSummary: 'All authentication checks failed. Domain uses homoglyph (digit 1 replacing letter l) to impersonate legitimate partner firm.',
    whyFlagged: [
      'Domain "financia1-partners.com" uses homoglyph (1 for l) to impersonate "financial-partners.com"',
      'Sender impersonates CFO of known partner firm — no prior email from this address',
      'Subject references confidential acquisition — social engineering for sensitive information',
      'SPF, DKIM, and DMARC all failed',
      'Email contains no links or attachments — pure social engineering for response',
    ],
    senderAnomalies: [
      'Domain uses homoglyph — digit "1" instead of letter "l"',
      'Display name matches real CFO but email address differs',
      'No prior communication from this address',
      'Text-only email with no links — designed to start a conversation',
    ],
    headers: {
      'Return-Path': '<cfo@financia1-partners.com>',
      'Received-1': 'from mail.financia1-partners.com (77.247.108.55) by mx1.company.com',
      'From': 'Robert Chen (CFO, Financial Partners) <cfo@financia1-partners.com>',
      'To': 'exec@company.com',
      'Date': 'Sat, 08 Aug 2026 10:15:44 +0000',
      'Subject': 'Re: Confidential — Acquisition Discussion',
      'Message-ID': '<cf0291@financia1-partners.com>',
      'X-Mailer': 'Mailgun',
      'MIME-Version': '1.0',
      'Content-Type': 'text/plain; charset=UTF-8',
    },
    receivedChain: [
      { hop: 1, from: 'mail.financia1-partners.com (77.247.108.55)', by: 'mx1.company.com', timestamp: '10:15:44 UTC', delay: '0s' },
    ],
    indicators: [
      { id: 'IOC-501', type: 'IP', value: '77.247.108.55', reputation: 'malicious', source: 'BEC Threat Feed', firstSeen: '2026-08-07', lastSeen: '2026-08-08', tags: ['Executive Impersonation', 'Homoglyph'] },
      { id: 'IOC-502', type: 'Domain', value: 'financia1-partners.com', reputation: 'malicious', source: 'Homoglyph Detection', firstSeen: '2026-08-05', lastSeen: '2026-08-08', tags: ['Homoglyph', 'Executive Impersonation', 'Newly Registered'] },
    ],
    infraNodes: [
      { id: 'n1', label: '77.247.108.55', type: 'ip', x: 50, y: 25, status: 'malicious' },
      { id: 'n2', label: 'financia1-partners.com', type: 'domain', x: 50, y: 55, status: 'malicious' },
      { id: 'n3', label: 'cfo@financia1-partners.com', type: 'sender', x: 50, y: 80, status: 'malicious' },
    ],
    infraEdges: [
      { from: 'n1', to: 'n2', label: 'hosts' },
      { from: 'n2', to: 'n3', label: 'sends as' },
    ],
    geoData: [
      { ip: '77.247.108.55', country: 'Netherlands', city: 'Amsterdam', lat: 52.37, lon: 4.90, isp: 'Telia Network Services', asn: 'AS1299', flag: 'NL' },
    ],
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Executive impersonation attack targeting company executives. Sender impersonates CFO of partner firm using homoglyph domain. Email references confidential acquisition to elicit sensitive response. Threat score: 88/100.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Domain "financia1-partners.com" uses digit "1" in place of letter "l". Text-only email with no links or attachments — designed as conversation starter for social engineering. Sending IP located in Amsterdam.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'IP: 77.247.108.55 (Malicious)\nDomain: financia1-partners.com (Homoglyph, Malicious)' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: FAIL\nDKIM: NONE\nDMARC: FAIL' },
      { title: 'RECOMMENDATIONS', content: '1. Alert executive team of impersonation attempt.\n2. Verify with partner firm CFO via phone.\n3. Block domain financia1-partners.com.\n4. Monitor for follow-up emails if any response was sent.' },
    ],
  },
  {
    id: 'EML-2026-0742',
    caseId: '',
    subject: 'Weekly Engineering Newsletter — Issue #142',
    sender: 'newsletter@engineering.company.com',
    senderName: 'Engineering Team',
    senderDomain: 'engineering.company.com',
    recipient: 'engineering@company.com',
    date: '2026-08-19 08:00:00 UTC',
    size: '34.2 KB',
    threatScore: 5,
    status: 'safe',
    classification: 'Internal Newsletter',
    riskLevel: 'SAFE',
    threatSummary: 'Internal engineering newsletter from a verified internal domain. All authentication checks passed. No suspicious links, attachments, or indicators detected.',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    authenticationSummary: 'All authentication checks passed. Sender is an internal domain with valid DKIM signature.',
    whyFlagged: emptyWhyFlagged,
    senderAnomalies: emptyAnomalies,
    headers: {
      'Return-Path': '<newsletter@engineering.company.com>',
      'Received-1': 'from mail.engineering.company.com (10.0.1.5) by mx1.company.com',
      'From': 'Engineering Team <newsletter@engineering.company.com>',
      'To': 'engineering@company.com',
      'Date': 'Mon, 19 Aug 2026 08:00:00 +0000',
      'Subject': 'Weekly Engineering Newsletter — Issue #142',
      'Message-ID': '<newsletter-142@engineering.company.com>',
      'X-Mailer': 'Amazon SES',
      'DKIM-Signature': 'v=1; a=rsa-sha256; d=engineering.company.com; s=hskey',
      'MIME-Version': '1.0',
      'Content-Type': 'text/html; charset=UTF-8',
    },
    receivedChain: [
      { hop: 1, from: 'mail.engineering.company.com (10.0.1.5)', by: 'mx1.company.com', timestamp: '08:00:00 UTC', delay: '0s' },
    ],
    indicators: emptyIndicators,
    infraNodes: emptyInfraNodes,
    infraEdges: emptyInfraEdges,
    geoData: emptyGeo,
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Internal engineering newsletter from verified sender. All authentication checks passed (SPF, DKIM, DMARC). No threats detected. Threat score: 5/100.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Email sent from internal domain "engineering.company.com" with valid DKIM signature. Content is a standard HTML newsletter with internal links only.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'No indicators of compromise detected.' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: PASS\nDKIM: PASS\nDMARC: PASS\nAll authentication mechanisms passed.' },
      { title: 'RECOMMENDATIONS', content: 'No action required. Email is legitimate.' },
    ],
  },
  {
    id: 'EML-2026-0738',
    caseId: '',
    subject: 'Google Docs: New document shared with you',
    sender: 'docs@google.com',
    senderName: 'Google Docs',
    senderDomain: 'google.com',
    recipient: 'j.morrison@company.com',
    date: '2026-08-22 14:32:11 UTC',
    size: '21.5 KB',
    threatScore: 3,
    status: 'safe',
    classification: 'Document Share',
    riskLevel: 'SAFE',
    threatSummary: 'Legitimate Google Docs sharing notification. All authentication checks passed. Link points to a genuine Google Docs URL. No indicators of compromise.',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    authenticationSummary: 'All authentication checks passed. DKIM signature valid for google.com.',
    whyFlagged: emptyWhyFlagged,
    senderAnomalies: emptyAnomalies,
    headers: safeHeaders,
    receivedChain: [
      { hop: 1, from: 'mail-io1.google.com (209.85.167.41)', by: 'mx1.company.com', timestamp: '14:32:11 UTC', delay: '0s' },
    ],
    indicators: emptyIndicators,
    infraNodes: emptyInfraNodes,
    infraEdges: emptyInfraEdges,
    geoData: emptyGeo,
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Legitimate Google Docs sharing notification. All authentication passed. No threats detected. Threat score: 3/100.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Email from google.com with valid DKIM signature. Link points to legitimate docs.google.com URL.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'No indicators of compromise detected.' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: PASS\nDKIM: PASS\nDMARC: PASS' },
      { title: 'RECOMMENDATIONS', content: 'No action required. Email is legitimate.' },
    ],
  },
  {
    id: 'EML-2026-0721',
    caseId: '',
    subject: 'Your Amazon Order #114-9928374 has shipped',
    sender: 'auto-confirm@amazon.com',
    senderName: 'Amazon.com',
    senderDomain: 'amazon.com',
    recipient: 'd.reyes@company.com',
    date: '2026-08-21 19:44:02 UTC',
    size: '45.8 KB',
    threatScore: 2,
    status: 'safe',
    classification: 'Order Confirmation',
    riskLevel: 'SAFE',
    threatSummary: 'Legitimate Amazon order confirmation email. All authentication checks passed. Tracking links point to genuine Amazon domains.',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    authenticationSummary: 'All authentication checks passed. DKIM signature valid for amazon.com.',
    whyFlagged: emptyWhyFlagged,
    senderAnomalies: emptyAnomalies,
    headers: {
      'Return-Path': '<auto-confirm@amazon.com>',
      'Received-1': 'from smtp-out.amazon.com (54.240.27.12) by mx1.company.com',
      'From': 'Amazon.com <auto-confirm@amazon.com>',
      'To': 'd.reyes@company.com',
      'Date': 'Fri, 21 Aug 2026 19:44:02 +0000',
      'Subject': 'Your Amazon Order #114-9928374 has shipped',
      'Message-ID': '<amz-confirm-1149928374@amazon.com>',
      'X-Mailer': 'Amazon SES',
      'DKIM-Signature': 'v=1; a=rsa-sha256; d=amazon.com; s=awskey',
      'MIME-Version': '1.0',
      'Content-Type': 'text/html; charset=UTF-8',
    },
    receivedChain: [
      { hop: 1, from: 'smtp-out.amazon.com (54.240.27.12)', by: 'mx1.company.com', timestamp: '19:44:02 UTC', delay: '0s' },
    ],
    indicators: emptyIndicators,
    infraNodes: emptyInfraNodes,
    infraEdges: emptyInfraEdges,
    geoData: emptyGeo,
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Legitimate Amazon shipping confirmation. All authentication passed. No threats detected. Threat score: 2/100.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Email from amazon.com with valid DKIM. Tracking links point to legitimate Amazon domains.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'No indicators of compromise detected.' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: PASS\nDKIM: PASS\nDMARC: PASS' },
      { title: 'RECOMMENDATIONS', content: 'No action required. Email is legitimate.' },
    ],
  },
  {
    id: 'EML-2026-0733',
    caseId: '',
    subject: 'Meeting Notes — Q3 Strategy Review',
    sender: 'a.sullivan@business-consulting.org',
    senderName: 'Aidan Sullivan',
    senderDomain: 'business-consulting.org',
    recipient: 'exec@company.com',
    date: '2026-08-17 11:18:55 UTC',
    size: '67.3 KB',
    threatScore: 35,
    status: 'inconclusive',
    classification: 'Inconclusive',
    riskLevel: 'LOW RISK',
    threatSummary: 'Email from an unknown sender with no prior communication history. Authentication partially passed (SPF pass, DKIM none, DMARC fail). Contains a .pdf attachment that could not be fully analyzed. No clear threat indicators, but insufficient data to classify as safe.',
    spf: 'pass',
    dkim: 'none',
    dmarc: 'fail',
    authenticationSummary: 'SPF passed but DKIM absent and DMARC failed due to alignment issues. Sender domain is legitimate but has no prior history with the organization.',
    whyFlagged: [
      'No prior communication history with this sender',
      'DKIM signature absent — cannot cryptographically verify sender',
      'PDF attachment could not be fully analyzed in sandbox',
      'DMARC alignment failed despite SPF pass',
    ],
    senderAnomalies: [
      'No prior email history with this sender address',
      'DKIM absent despite sender domain being established',
    ],
    headers: {
      'Return-Path': '<a.sullivan@business-consulting.org>',
      'Received-1': 'from mail.business-consulting.org (64.252.30.18) by mx1.company.com',
      'From': 'Aidan Sullivan <a.sullivan@business-consulting.org>',
      'To': 'exec@company.com',
      'Date': 'Mon, 17 Aug 2026 11:18:55 +0000',
      'Subject': 'Meeting Notes — Q3 Strategy Review',
      'Message-ID': '<mn0382@business-consulting.org>',
      'X-Mailer': 'Microsoft Outlook 16.0',
      'MIME-Version': '1.0',
      'Content-Type': 'multipart/mixed; boundary="boundary456"',
    },
    receivedChain: [
      { hop: 1, from: 'mail.business-consulting.org (64.252.30.18)', by: 'mx1.company.com', timestamp: '11:18:55 UTC', delay: '0s' },
    ],
    indicators: [
      { id: 'IOC-601', type: 'Hash', value: 'b2c4e6f8a1d3b5c7e9f1a3b5c7d9e1f3', reputation: 'unknown', source: 'Attachment Analysis', firstSeen: '2026-08-17', lastSeen: '2026-08-17', tags: ['PDF', 'Inconclusive'] },
    ],
    infraNodes: [
      { id: 'n1', label: '64.252.30.18', type: 'ip', x: 50, y: 40, status: 'clean' },
      { id: 'n2', label: 'business-consulting.org', type: 'domain', x: 50, y: 70, status: 'clean' },
    ],
    infraEdges: [
      { from: 'n1', to: 'n2', label: 'hosts' },
    ],
    geoData: [
      { ip: '64.252.30.18', country: 'United Kingdom', city: 'London', lat: 51.51, lon: -0.13, isp: 'Gamma Telecom', asn: 'AS31655', flag: 'GB' },
    ],
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Email from unknown sender with inconclusive threat assessment. SPF passed but DKIM absent and DMARC failed. PDF attachment could not be fully analyzed. Threat score: 35/100. Requires manual review.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Sender domain "business-consulting.org" appears legitimate (registered 2018) but has no prior email history with the organization. DKIM absent. PDF attachment returned inconclusive from sandbox analysis — may contain embedded content that requires manual inspection.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'Hash: b2c4e6f8a1d3b5c7e9f1a3b5c7d9e1f3 (PDF, Inconclusive)' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: PASS\nDKIM: NONE\nDMARC: FAIL (alignment mismatch)\nPartial authentication — cannot fully verify sender.' },
      { title: 'RECOMMENDATIONS', content: '1. Manually inspect PDF attachment in isolated environment.\n2. Verify sender identity through out-of-band channel.\n3. Do not open attachment until verified.\n4. Monitor sender domain for future communications.' },
    ],
  },
  {
    id: 'EML-2026-0715',
    caseId: '',
    subject: 'Security Alert: New sign-in from Chrome on Windows',
    sender: 'no-reply@accounts.google.com',
    senderName: 'Google Security',
    senderDomain: 'accounts.google.com',
    recipient: 'j.morrison@company.com',
    date: '2026-08-21 22:07:33 UTC',
    size: '28.4 KB',
    threatScore: 22,
    status: 'suspicious',
    classification: 'Security Alert (Unverified)',
    riskLevel: 'LOW RISK',
    threatSummary: 'Appears to be a Google security alert about a new sign-in. Authentication passed but the sign-in location (unexpected geo) and timestamp pattern are atypical. Could be legitimate or a sophisticated phishing attempt using a spoofed Google notification template.',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    authenticationSummary: 'All authentication checks passed. However, the sign-in event details do not match the user\'s known activity patterns.',
    whyFlagged: [
      'Sign-in location (Istanbul, Turkey) does not match user\'s typical locations',
      'Sign-in time (02:07 local) is outside user\'s typical activity hours',
      'Email template closely matches Google\'s legitimate security alert format — possible template abuse',
      'Despite passing authentication, behavioral analysis flags this as anomalous',
    ],
    senderAnomalies: [
      'Sign-in geo-location mismatch with user profile',
      'Unusual sign-in time pattern',
    ],
    headers: {
      'Return-Path': '<no-reply@accounts.google.com>',
      'Received-1': 'from mail-vc1.google.com (209.85.220.41) by mx1.company.com',
      'From': 'Google Security <no-reply@accounts.google.com>',
      'To': 'j.morrison@company.com',
      'Date': 'Fri, 21 Aug 2026 22:07:33 +0000',
      'Subject': 'Security Alert: New sign-in from Chrome on Windows',
      'Message-ID': '<sec-alert-99281@accounts.google.com>',
      'X-Mailer': 'Google SMTP',
      'DKIM-Signature': 'v=1; a=rsa-sha256; d=accounts.google.com; s=gmailkey',
      'MIME-Version': '1.0',
      'Content-Type': 'text/html; charset=UTF-8',
    },
    receivedChain: [
      { hop: 1, from: 'mail-vc1.google.com (209.85.220.41)', by: 'mx1.company.com', timestamp: '22:07:33 UTC', delay: '0s' },
    ],
    indicators: [
      { id: 'IOC-701', type: 'IP', value: '88.230.12.45', reputation: 'suspicious', source: 'Behavioral Analysis', firstSeen: '2026-08-21', lastSeen: '2026-08-21', tags: ['Geo Anomaly', 'Unusual Login'] },
    ],
    infraNodes: emptyInfraNodes,
    infraEdges: emptyInfraEdges,
    geoData: [
      { ip: '88.230.12.45', country: 'Turkey', city: 'Istanbul', lat: 41.01, lon: 28.98, isp: 'Turk Telekom', asn: 'AS47331', flag: 'TR' },
    ],
    reportSections: [
      { title: 'EXECUTIVE SUMMARY', content: 'Security alert notification that passed authentication but was flagged by behavioral analysis. Sign-in from unexpected location (Istanbul) at unusual hours. Threat score: 22/100. Requires user confirmation.' },
      { title: 'TECHNICAL ANALYSIS', content: 'Email authentication fully passed (SPF, DKIM, DMARC). The alert itself appears to be a genuine Google notification about a real sign-in event. However, the sign-in geo-location and timing are anomalous for this user.' },
      { title: 'INDICATORS OF COMPROMISE', content: 'IP: 88.230.12.45 (Geo Anomaly, Suspicious)' },
      { title: 'AUTHENTICATION FINDINGS', content: 'SPF: PASS\nDKIM: PASS\nDMARC: PASS\nEmail is authenticated — the security alert itself is genuine. The flagged activity is the sign-in event it describes.' },
      { title: 'RECOMMENDATIONS', content: '1. Confirm with user whether the sign-in was legitimate.\n2. If not, initiate password reset and revoke sessions.\n3. Enable additional verification for the account.\n4. Monitor for further anomalous sign-ins.' },
    ],
  },
];

export function getEmailById(id: string): ScannedEmail | undefined {
  return mockEmails.find((e) => e.id === id);
}

export function getTriageStats() {
  return {
    total: mockEmails.length,
    safe: mockEmails.filter((e) => e.status === 'safe').length,
    suspicious: mockEmails.filter((e) => e.status === 'suspicious').length,
    malicious: mockEmails.filter((e) => e.status === 'malicious').length,
    inconclusive: mockEmails.filter((e) => e.status === 'inconclusive').length,
  };
}

export const mockCases: ForensicCase[] = [
  { id: '1', caseId: 'CASE-2026-0847', title: 'Credential Harvesting Campaign via Lookalike Domain', status: 'open', priority: 'critical', dateOpened: '2026-08-23', analyst: 'M. Chen', threatType: 'Phishing', score: 81, description: 'Targeted phishing email impersonating internal security team. Sender domain is lookalike of legitimate service.' },
  { id: '2', caseId: 'CASE-2026-0831', title: 'Business Email Compromise — Wire Transfer Request', status: 'escalated', priority: 'critical', dateOpened: '2026-08-20', analyst: 'J. Patel', threatType: 'BEC', score: 94, description: 'Executive impersonation attempt requesting urgent wire transfer to fraudulent account.' },
  { id: '3', caseId: 'CASE-2026-0802', title: 'Malware Attachment — Invoice Themed Lure', status: 'closed', priority: 'high', dateOpened: '2026-08-15', dateClosed: '2026-08-18', analyst: 'S. Okoye', threatType: 'Malware', score: 73, description: 'Macro-enabled document disguised as invoice. C2 beaconing to known malicious infrastructure.' },
  { id: '4', caseId: 'CASE-2026-0791', title: 'Spoofed Vendor Payment Redirect', status: 'pending', priority: 'high', dateOpened: '2026-08-12', analyst: 'M. Chen', threatType: 'Vendor Fraud', score: 67, description: 'Email appearing to be from known vendor requesting payment method update.' },
  { id: '5', caseId: 'CASE-2026-0756', title: 'QR Code Phishing — Parking Invoice', status: 'closed', priority: 'medium', dateOpened: '2026-08-05', dateClosed: '2026-08-09', analyst: 'L. Ramirez', threatType: 'Quishing', score: 58, description: 'Email containing malicious QR code redirecting to credential harvest page.' },
];
