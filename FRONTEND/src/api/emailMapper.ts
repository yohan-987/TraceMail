import type { ApiEmailSummary } from './api';
import type { ScannedEmail, EmailStatus } from '@/data/mockData';

export function mapApiEmailToUiEmail(apiEmail: ApiEmailSummary): ScannedEmail {
  // Normalize the backend status to exactly match your UI's 4 strict types
  const rawStatus = (apiEmail.status || apiEmail.riskLevel || '').toLowerCase();
  let uiStatus: EmailStatus = 'safe';
  
  if (rawStatus === 'critical' || rawStatus === 'malicious') uiStatus = 'malicious';
  else if (rawStatus === 'high' || rawStatus === 'suspicious') uiStatus = 'suspicious';
  else if (rawStatus === 'inconclusive') uiStatus = 'inconclusive';

  return {
    id: apiEmail.emailId,
    caseId: apiEmail.caseId || '', // Prevents the null crash
    subject: apiEmail.subject,
    sender: apiEmail.sender,
    senderName: apiEmail.sender.split('@')[0], // Fallback if backend doesn't send name
    senderDomain: apiEmail.senderDomain || apiEmail.sender.split('@')[1] || '',
    recipient: apiEmail.recipient,
    date: apiEmail.date,
    size: 'N/A', // Placeholder for list view
    threatScore: apiEmail.threatScore,
    status: uiStatus,
    classification: apiEmail.classification || 'Unknown',
    riskLevel: apiEmail.riskLevel || 'UNKNOWN',
    
    // Fill the rest with safe empty defaults for the Overview table. 
    // The actual details will be fetched later when the user clicks "Inspect".
    threatSummary: 'Data loaded from summary API.',
    spf: 'none',
    dkim: 'none',
    dmarc: 'none',
    authenticationSummary: '',
    whyFlagged: [],
    senderAnomalies: [],
    headers: {},
    receivedChain: [],
    indicators: [],
    infraNodes: [],
    infraEdges: [],
    geoData: [],
    reportSections: []
  };
}