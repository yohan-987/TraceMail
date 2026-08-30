import { useState, useEffect, useMemo } from 'react';
import { useLocation } from 'react-router-dom';
import { Network, MapPin, Server, Globe, Link2, Zap, Eye, Sparkles, Radar, AlertTriangle, ShieldQuestion } from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import { InvestigationWorkspace, PreviewField, PreviewInvestigateButton } from '@/components/InvestigationWorkspace';
import { cn } from '@/lib/utils';
import { getEmail as fetchEmailDetails, getRelatedEmails, type ApiRelatedEmails } from '@/api/api';

// --- TYPES ---
export interface InfraNode {
  id: string;
  type: 'ip' | 'domain' | 'server' | 'sender';
  label: string;
  status: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  x: number;
  y: number;
}

export interface InfraEdge {
  from: string;
  to: string;
  label: string;
}

export interface MappedGeoEntry {
  ip: string;
  country: string;
  region?: string;
  city: string;
  lat: number;
  lon: number;
  flag: string;
  isp: string;
  asn: string;
  organization?: string;
  hosting?: string;
}

const nodeIcons: Record<string, typeof Server> = {
  ip: Server,
  domain: Globe,
  server: Network,
  sender: Link2,
};

const statusColors: Record<string, string> = {
  malicious: 'text-accent-500 border-accent-700/30 bg-accent-700/10',
  suspicious: 'text-amber-500 border-amber-700/20 bg-amber-700/10',
  clean: 'text-emerald-500 border-emerald-700/20 bg-emerald-700/10',
  unknown: 'text-ink-400 border-base-500/30 bg-base-800/50',
};

function geoValue(raw: string | undefined | null): string {
  if (!raw || raw.toLowerCase() === 'unknown') return 'INCONCLUSIVE';
  return raw;
}

function intelStatus(geo: MappedGeoEntry, nodes: InfraNode[]): string | null {
  const match = nodes.find((n) => n.type === 'ip' && n.label === geo.ip);
  if (!match) return null;
  switch (match.status) {
    case 'malicious': return 'Malicious';
    case 'suspicious': return 'Suspicious';
    case 'clean': return 'Verified';
    default: return 'Unknown';
  }
}

function intelColor(label: string | null): string {
  if (label === 'Malicious') return 'text-accent-400';
  if (label === 'Suspicious') return 'text-amber-400';
  if (label === 'Verified') return 'text-emerald-400';
  return 'text-ink-500';
}

function mapDetailedApiToInfrastructure(apiData: any) {
  const geoData: MappedGeoEntry[] = [];
  const infraNodes: InfraNode[] = [];
  const infraEdges: InfraEdge[] = []; // Kept empty until Batch 5A provides real relationships

  const ipIntel = apiData?.infrastructure?.ipIntelligence || [];
  const senderDomain = apiData?.parsedEmail?.from?.[0]?.domain || 'Unknown Domain';

  // Plot the core Sender Domain node with an honest 'unknown' status (no fake score inheritance)
  infraNodes.push({
    id: 'domain-node',
    type: 'domain',
    label: senderDomain,
    status: 'unknown',
    x: 50,
    y: 20
  });

  // Map IP Intelligence into GeoData and Graph Nodes without fabricating speculative edges
  ipIntel.forEach((ipObj: any, index: number) => {
    geoData.push({
      ip: ipObj.ip,
      country: ipObj.country || 'Unknown',
      region: ipObj.region || 'Unknown',
      city: ipObj.city || 'Unknown',
      lat: ipObj.latitude ?? 0,
      lon: ipObj.longitude ?? 0,
      flag: ipObj.country?.substring(0, 2)?.toUpperCase() || '??',
      isp: ipObj.isp || 'Unknown',
      asn: ipObj.asn || 'Unknown',
      organization: ipObj.organization,
      hosting: ipObj.hosting
    });

    const ipNodeId = `ip-node-${index}`;
    infraNodes.push({
      id: ipNodeId,
      type: 'ip',
      label: ipObj.ip,
      status: 'unknown',
      x: 20 + ((index % 3) * 30),
      y: 70 + (Math.floor(index / 3) * 15)
    });
  });

  return { geoData, infraNodes, infraEdges };
}

export function InfrastructurePage() {
  const location = useLocation();
  const { setLastViewed, availableEmails, getEmail } = useActiveCase();
  
  const [infrastructureSelectedEmailId, setInfrastructureSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );

  const [activeEmailData, setActiveEmailData] = useState<any | null>(null);
  const [mappedInfra, setMappedInfra] = useState<{ geoData: MappedGeoEntry[], infraNodes: InfraNode[], infraEdges: InfraEdge[] }>({
    geoData: [], infraNodes: [], infraEdges: []
  });
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);
  const [detailsError, setDetailsError] = useState<string | null>(null);
  // Batch 5B — real campaign/correlation data, fetched separately from
  // the detail record so a failure here never blocks the rest of the
  // infrastructure view.
  const [relatedEmails, setRelatedEmails] = useState<ApiRelatedEmails | null>(null);

  useEffect(() => {
    if (!infrastructureSelectedEmailId) {
      setActiveEmailData(null);
      setMappedInfra({ geoData: [], infraNodes: [], infraEdges: [] });
      setRelatedEmails(null);
      return;
    }

    let cancelled = false;
    setIsLoadingDetails(true);
    setDetailsError(null);

    fetchEmailDetails(infrastructureSelectedEmailId)
      .then((data) => {
        if (!cancelled) {
          setActiveEmailData(data);
          setMappedInfra(mapDetailedApiToInfrastructure(data));
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setDetailsError(err instanceof Error ? err.message : 'Failed to load infrastructure');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIsLoadingDetails(false);
        }
      });

    getRelatedEmails(infrastructureSelectedEmailId)
      .then((data) => {
        if (!cancelled) setRelatedEmails(data);
      })
      .catch(() => {
        if (!cancelled) setRelatedEmails(null);
      });

    return () => {
      cancelled = true;
    };
  }, [infrastructureSelectedEmailId]);

  const handleInvestigate = (emailId: string) => {
    setInfrastructureSelectedEmailId(emailId);
    setLastViewed(emailId);
  };

  const { geoData, infraNodes, infraEdges } = mappedInfra;
  
  const candidateGeo = geoData.filter((g) => !(g.lat === 0 && g.lon === 0));
  const unresolvedGeo = geoData.filter((g) => g.lat === 0 && g.lon === 0);

  // Use the real, already-fetched lightweight record from availableEmails —
  // never a fabricated stub — so InvestigationShell/CaseSelector always
  // receive a complete ScannedEmail (or null, which they render safely).
  const headerEmailContext = activeEmailData ? getEmail(activeEmailData.emailId) : null;

  return (
    <InvestigationShell
      breadcrumb="Infrastructure"
      title="Infrastructure Analysis"
      subtitle={activeEmailData ? `Relationships, geolocation, and probable infrastructure · ${activeEmailData.emailId}` : undefined}
      hideCaseSelector={!activeEmailData}
      selectedEmail={headerEmailContext}
      availableEmails={availableEmails}
      onSelectEmail={(id) => { setInfrastructureSelectedEmailId(id); setLastViewed(id); }}
      onClearEmail={() => setInfrastructureSelectedEmailId(null)}
      investigationNav={activeEmailData ? { emailId: activeEmailData.emailId, activeSection: 'infrastructure' } : undefined}
    >
      {isLoadingDetails ? (
        <div className="flex items-center justify-center h-[500px] w-full text-ink-400 font-mono text-sm animate-pulse">
          Mapping infrastructure...
        </div>
      ) : detailsError ? (
        <div className="flex items-center justify-center h-[500px] w-full text-accent-500 font-mono text-sm">
          Error: {detailsError}
        </div>
      ) : !activeEmailData ? (
        <InvestigationWorkspace onInvestigate={(e: any) => handleInvestigate(e.id)} renderPreview={renderInfrastructurePreview} />
      ) : (
        <div key={activeEmailData.emailId} className="animate-fade-in">
          <div className="flex items-center gap-2.5 px-4 py-2.5 rounded-lg bg-amber-900/10 border border-amber-700/25 mb-5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
            <span className="text-[11px] text-amber-200/90">
              <strong className="font-bold">Infrastructure location ≠ attacker identity.</strong> Geolocation reflects the observed network path, not who sent the email.
            </span>
          </div>

          <div className="grid grid-cols-12 gap-5">
            <Card className="col-span-7 p-5">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Network className="w-3.5 h-3.5 text-accent-500" />
                  <SectionLabel>Infrastructure Relationships</SectionLabel>
                </div>
                <Badge variant="neutral">{infraNodes.length} nodes · {infraEdges.length} edges</Badge>
              </div>
              {infraNodes.length > 0 ? (
                <RelationshipGraph nodes={infraNodes} edges={infraEdges} />
              ) : (
                <div className="h-80 flex items-center justify-center text-[12px] text-ink-600">
                  No infrastructure relationship data available
                </div>
              )}
              <Divider className="my-4" />
              <div className="grid grid-cols-3 gap-3">
                <LegendItem color="bg-accent-600" label="Malicious" />
                <LegendItem color="bg-amber-500" label="Suspicious" />
                <LegendItem color="bg-emerald-500" label="Clean" />
              </div>
            </Card>

            <Card className="col-span-5 p-5">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <MapPin className="w-3.5 h-3.5 text-accent-500" />
                  <SectionLabel>Geolocation Map</SectionLabel>
                </div>
              </div>
              {candidateGeo.length > 0 ? (
                <GeoMap points={candidateGeo} nodes={infraNodes} />
              ) : (
                <div className="h-48 flex items-center justify-center text-[12px] text-ink-600">
                  No resolvable coordinates for this email
                </div>
              )}
              <p className="text-[9px] text-ink-700 mt-2 italic">
                Approximate coordinate plot — not a precise basemap.
                {unresolvedGeo.length > 0 && ` ${unresolvedGeo.length} candidate IP(s) excluded — no resolvable coordinates.`}
              </p>
            </Card>
          </div>

          <Card className="mt-5 p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-accent-500" />
                <SectionLabel>PROBABLE INFRASTRUCTURE</SectionLabel>
              </div>
              <div className="flex items-center gap-3 text-[9px] uppercase tracking-wider text-ink-600">
                <span className="flex items-center gap-1"><Eye className="w-2.5 h-2.5 text-ink-500" /> Observed</span>
                <span className="flex items-center gap-1"><Radar className="w-2.5 h-2.5 text-sky-400" /> External Intel</span>
                <span className="flex items-center gap-1"><Sparkles className="w-2.5 h-2.5 text-amber-500" /> Inferred</span>
              </div>
            </div>
            {geoData.length > 0 ? (
              <div className="grid grid-cols-3 gap-4">
                {geoData.map((geo) => (
                  <CandidateIpCard key={geo.ip} geo={geo} status={intelStatus(geo, infraNodes)} />
                ))}
              </div>
            ) : (
              <div className="text-[12px] text-ink-600 text-center py-8">No candidate source IPs identified</div>
            )}
          </Card>

          {/* Batch 5B — real correlation data, never fabricated relationships. */}
          <Card className="mt-5 p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Radar className="w-3.5 h-3.5 text-sky-400" />
                <SectionLabel>Likely Related Campaign</SectionLabel>
              </div>
              {relatedEmails?.campaignId && (
                <Badge variant="neutral">{Math.round(relatedEmails.confidence * 100)}% confidence</Badge>
              )}
            </div>
            {relatedEmails && relatedEmails.relatedEmailIds.length > 0 ? (
              <div className="grid grid-cols-4 gap-3">
                <div className="panel-2 p-3">
                  <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">Campaign ID</div>
                  <div className="mono text-[12px] text-ink-200">{relatedEmails.campaignId}</div>
                </div>
                <div className="panel-2 p-3">
                  <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">Related Emails</div>
                  <div className="text-[12px] text-ink-200">{relatedEmails.relatedEmailIds.length}</div>
                </div>
                <div className="panel-2 p-3">
                  <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">Shared Indicators</div>
                  <div className="text-[12px] text-ink-200">{relatedEmails.sharedIndicators.length}</div>
                </div>
                <div className="panel-2 p-3">
                  <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">Shared Infrastructure</div>
                  <div className="text-[12px] text-ink-200">{relatedEmails.sharedInfrastructure.length}</div>
                </div>
              </div>
            ) : (
              <div className="text-[12px] text-ink-600 text-center py-4">No related emails or campaign correlation found</div>
            )}
          </Card>
        </div>
      )}
    </InvestigationShell>
  );
}

function CandidateIpCard({ geo, status }: { geo: MappedGeoEntry; status: string | null }) {
  return (
    <div className="panel-2 p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="flex items-center justify-center w-8 h-6 rounded bg-base-600/50 border border-base-500/30">
            <span className="text-[9px] font-bold text-ink-400 mono">{geo.flag}</span>
          </div>
          <span className="mono text-[12px] font-semibold text-ink-200">{geo.ip}</span>
        </div>
        <span className={cn('text-[9px] font-bold uppercase tracking-wider', intelColor(status))}>
          {status ?? 'UNAVAILABLE'}
        </span>
      </div>
      <div className="space-y-2">
        <MiniField label="Country" value={geoValue(geo.country)} provenance="intel" />
        <MiniField label="Region" value={geoValue(geo.region)} provenance="intel" />
        <MiniField label="City" value={geoValue(geo.city)} provenance="intel" />
        <MiniField label="ISP" value={geoValue(geo.isp)} provenance="intel" />
        <MiniField label="ASN" value={geoValue(geo.asn)} provenance="intel" />
        <MiniField label="Hosting / Org" value={geoValue(geo.hosting || geo.organization)} provenance="intel" />
        <MiniField label="Observed In" value="Received chain / header IP" provenance="observed" />
      </div>
    </div>
  );
}

function MiniField({ label, value, provenance }: { label: string; value: string | null; provenance: 'observed' | 'intel' | 'inferred' }) {
  const ProvenanceIcon = provenance === 'observed' ? Eye : provenance === 'intel' ? Radar : Sparkles;
  const isUnavailable = value === null || value === 'INCONCLUSIVE';
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-ink-600 font-semibold shrink-0">
        <ProvenanceIcon className="w-2.5 h-2.5 opacity-60" /> {label}
      </span>
      {isUnavailable ? (
        <span className="text-[10px] text-ink-600 italic flex items-center gap-1">
          <ShieldQuestion className="w-2.5 h-2.5" /> UNAVAILABLE
        </span>
      ) : (
        <span className="mono text-[11px] text-ink-300 truncate">{value}</span>
      )}
    </div>
  );
}

function GeoMap({ points, nodes }: { points: MappedGeoEntry[]; nodes: InfraNode[] }) {
  const toX = (lon: number) => ((lon + 180) / 360) * 360;
  const toY = (lat: number) => ((90 - lat) / 180) * 180;

  return (
    <div className="relative w-full h-48 bg-base-950/40 rounded-lg border border-base-500/15 overflow-hidden">
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 360 180" preserveAspectRatio="xMidYMid meet">
        <line x1="0" y1="90" x2="360" y2="90" stroke="rgba(115,115,115,0.15)" strokeWidth="0.5" />
        <line x1="180" y1="0" x2="180" y2="180" stroke="rgba(115,115,115,0.15)" strokeWidth="0.5" />
        {Array.from({ length: 7 }, (_, i) => (i + 1) * 45).map((x) => (
          <line key={`v${x}`} x1={x} y1="0" x2={x} y2="180" stroke="rgba(115,115,115,0.06)" strokeWidth="0.5" />
        ))}
        {Array.from({ length: 3 }, (_, i) => (i + 1) * 45).map((y) => (
          <line key={`h${y}`} x1="0" y1={y} x2="360" y2={y} stroke="rgba(115,115,115,0.06)" strokeWidth="0.5" />
        ))}

        {points.map((geo) => {
          const match = nodes.find((n) => n.type === 'ip' && n.label === geo.ip);
          const color = match?.status === 'malicious' ? '#dc2626' : match?.status === 'suspicious' ? '#f59e0b' : match?.status === 'clean' ? '#10b981' : '#737373';
          const cx = toX(geo.lon);
          const cy = toY(geo.lat);
          return (
            <g key={geo.ip}>
              <circle cx={cx} cy={cy} r="4" fill={color} opacity="0.25" />
              <circle cx={cx} cy={cy} r="2" fill={color} />
              <text x={cx} y={cy - 5} fill="rgba(229,229,229,0.65)" fontSize="5" textAnchor="middle" className="mono">
                {geo.flag}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function RelationshipGraph({ nodes, edges }: { nodes: InfraNode[]; edges: InfraEdge[] }) {
  return (
    <div className="relative w-full h-80 bg-base-950/40 rounded-lg border border-base-500/15 overflow-hidden">
      <div className="absolute inset-0 bg-grid-subtle bg-grid-sm opacity-50" />

      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        {edges.map((edge, i) => {
          const from = nodes.find((n) => n.id === edge.from);
          const to = nodes.find((n) => n.id === edge.to);
          if (!from || !to) return null;
          return (
            <g key={i}>
              <line
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke="rgba(208,0,0,0.15)"
                strokeWidth="0.2"
                strokeDasharray="0.5 0.5"
              />
              <text
                x={(from.x + to.x) / 2}
                y={(from.y + to.y) / 2 - 0.5}
                fill="rgba(115,115,115,0.6)"
                fontSize="1.5"
                textAnchor="middle"
                className="mono"
              >
                {edge.label}
              </text>
            </g>
          );
        })}
      </svg>

      {nodes.map((node) => {
        const Icon = nodeIcons[node.type];
        return (
          <div
            key={node.id}
            className="absolute -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${node.x}%`, top: `${node.y}%` }}
          >
            <div
              className={cn(
                'flex items-center justify-center w-10 h-10 rounded-lg border transition-all',
                statusColors[node.status]
              )}
              style={{
                boxShadow:
                  node.status === 'malicious'
                    ? '0 0 12px -2px rgba(208,0,0,0.3)'
                    : node.status === 'suspicious'
                    ? '0 0 8px -2px rgba(245,158,11,0.2)'
                    : 'none',
              }}
            >
              <Icon className="w-4 h-4" />
            </div>
            <div className="absolute top-full left-1/2 -translate-x-1/2 mt-1 whitespace-nowrap">
              <span className="mono text-[9px] text-ink-500">{node.label}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={cn('w-2 h-2 rounded-full', color)} />
      <span className="text-[10px] font-medium text-ink-500 uppercase tracking-wider">{label}</span>
    </div>
  );
}

function renderInfrastructurePreview(email: any, onInvestigate: () => void) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>Probable Infrastructure</SectionLabel>
        <Badge variant="neutral">Extraction Pending</Badge>
      </div>

      <div className="min-w-0 mb-4">
        <div className="text-[13px] font-semibold text-ink-100 leading-snug truncate">
          {email.subject || 'No Subject'}
        </div>
        <div className="mono text-[10px] text-ink-500 mt-1">
          {email.caseId || email.id}
        </div>
      </div>

      <Card className="flex flex-col items-center justify-center py-12 border-dashed border-base-500/30 bg-base-900/30 mb-5">
        <Network className="w-8 h-8 text-ink-600 mb-3" />
        <div className="text-[12px] font-semibold text-ink-300 mb-1">
          Infrastructure Not Mapped
        </div>
        <div className="text-[11px] text-ink-500 text-center max-w-[200px] leading-relaxed">
          Open the full investigation to parse IP geolocation and relationship graphs.
        </div>
      </Card>

      <PreviewInvestigateButton label="Map Infrastructure" onClick={onInvestigate} />
    </div>
  );
}