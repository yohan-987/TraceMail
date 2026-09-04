import { useState, useEffect, useMemo, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import cytoscape from 'cytoscape';
import { Network, MapPin, Server, Globe, Link2, Zap, Eye, Sparkles, Radar, AlertTriangle, ShieldQuestion } from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import { InvestigationWorkspace, PreviewField, PreviewInvestigateButton } from '@/components/InvestigationWorkspace';
import { cn } from '@/lib/utils';
import {
  getEmail as fetchEmailDetails,
  getRelatedEmails,
  getEmailGraph,
  type ApiRelatedEmails,
  type ApiInfrastructureGraph,
  type ApiInfrastructureGraphNode,
  type ApiInfrastructureGraphNodeType,
} from '@/api/api';
import { InfrastructureMap } from '@/components/InfrastructureMap';
import { type InfraNode, type InfraEdge, type MappedGeoEntry, geoValue } from '@/types/infrastructure';

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

// Relationship-graph node styling by type. Reuses this codebase's existing
// palette (the ink/sky/amber/violet/cyan/emerald tones already used in
// ProvenanceTag.tsx and this file's own statusColors/LegendItem) — no new
// arbitrary colors. `status` on every InfrastructureGraphNode is always
// "AVAILABLE" (see backend analyzers/infrastructureGraph.ts), so it carries
// no risk signal to color by; coloring by node TYPE is the only meaningful
// axis here. Where two related types share a hue (IP/ASN, ORGANIZATION/
// GEOLOCATION), the shape differs so they stay visually distinct — and
// deliberately never accent/red, since a node's category is not itself a
// threat signal (see this page's own "location ≠ attacker identity" note).
const graphNodeStyle: Record<ApiInfrastructureGraphNodeType, { color: string; shape: string }> = {
  EMAIL: { color: '#e5e5e5', shape: 'ellipse' },
  EMAIL_ADDRESS: { color: '#0ea5e9', shape: 'ellipse' },
  DOMAIN: { color: '#f59e0b', shape: 'round-rectangle' },
  URL: { color: '#8b5cf6', shape: 'round-rectangle' },
  IP: { color: '#06b6d4', shape: 'diamond' },
  ASN: { color: '#06b6d4', shape: 'hexagon' },
  ORGANIZATION: { color: '#10b981', shape: 'rectangle' },
  GEOLOCATION: { color: '#10b981', shape: 'star' },
};

const graphLegend: { type: ApiInfrastructureGraphNodeType; label: string; swatch: string }[] = [
  { type: 'EMAIL', label: 'Email', swatch: 'bg-ink-200' },
  { type: 'EMAIL_ADDRESS', label: 'Email Address', swatch: 'bg-sky-500' },
  { type: 'DOMAIN', label: 'Domain', swatch: 'bg-amber-500' },
  { type: 'URL', label: 'URL', swatch: 'bg-violet-500' },
  { type: 'IP', label: 'IP', swatch: 'bg-cyan-500' },
  { type: 'ASN', label: 'ASN', swatch: 'bg-cyan-500' },
  { type: 'ORGANIZATION', label: 'Organization', swatch: 'bg-emerald-500' },
  { type: 'GEOLOCATION', label: 'Geolocation', swatch: 'bg-emerald-500' },
];

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

function isValidCoordinate(lat: unknown, lon: unknown): lat is number {
  return (
    typeof lat === 'number' &&
    Number.isFinite(lat) &&
    lat >= -90 &&
    lat <= 90 &&
    typeof lon === 'number' &&
    Number.isFinite(lon) &&
    lon >= -180 &&
    lon <= 180
  );
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

  // Map IP Intelligence into GeoData and Graph Nodes without fabricating speculative edges.
  // Coordinates: the backend record uses `latitude`/`longitude` (see GeoIpRecord /
  // InfrastructureAssessment.ipIntelligence[] in schemas/types.ts) — NOT `lat`/`lon`.
  // Reading `.lat`/`.lon` (as this previously did) always reads undefined and
  // silently defaults to (0, 0) via `|| 0`, which the map then filters out as
  // "unresolved" — that's why real coordinate data never rendered a marker,
  // even once the backend supplied a valid latitude/longitude. Every candidate
  // is validated (finite, in-range) before being treated as resolvable; an
  // invalid/missing coordinate is stored as `null`, never coerced to 0.
  ipIntel.forEach((ipObj: any, index: number) => {
    const hasCoords = isValidCoordinate(ipObj?.latitude, ipObj?.longitude);

    geoData.push({
      ip: ipObj.ip,
      country: ipObj.country || 'Unknown',
      region: ipObj.region || 'Unknown',
      city: ipObj.city || 'Unknown',
      lat: hasCoords ? ipObj.latitude : null,
      lon: hasCoords ? ipObj.longitude : null,
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
  // Frontend F2 — real Cytoscape-ready relationship graph, fetched the
  // same way: independently of the detail record, so one dead call never
  // blocks the map or the rest of this page.
  const [emailGraph, setEmailGraph] = useState<ApiInfrastructureGraph | null>(null);

  useEffect(() => {
    if (!infrastructureSelectedEmailId) {
      setActiveEmailData(null);
      setMappedInfra({ geoData: [], infraNodes: [], infraEdges: [] });
      setRelatedEmails(null);
      setEmailGraph(null);
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

    getEmailGraph(infrastructureSelectedEmailId)
      .then((data) => {
        if (!cancelled) setEmailGraph(data);
      })
      .catch(() => {
        if (!cancelled) setEmailGraph(null);
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
  
  const candidateGeo = geoData.filter((g) => g.lat !== null && g.lon !== null);
  const unresolvedGeo = geoData.filter((g) => g.lat === null || g.lon === null);

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
                  <SectionLabel>Probable Infrastructure Map</SectionLabel>
                </div>
                <span className="text-[9px] font-semibold uppercase tracking-wider text-sky-400 flex items-center gap-1">
                  <Radar className="w-2.5 h-2.5" /> External Intel
                </span>
              </div>
              <InfrastructureMap points={candidateGeo} nodes={infraNodes} />
              <p className="text-[9px] text-ink-700 mt-2 italic">
                Map tiles &copy;{' '}
                <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer" className="underline hover:text-ink-500">
                  OpenStreetMap
                </a>{' '}
                contributors. Marker positions reflect GeoIP-resolved network infrastructure, not attacker identity.
                {unresolvedGeo.length > 0 && ` ${unresolvedGeo.length} candidate IP(s) excluded — no resolvable coordinates.`}
              </p>
            </Card>

          </div>

          {/* Frontend F2 — real Cytoscape-backed relationship graph from
              GET /emails/:emailId/graph. Additive: the existing
              "Infrastructure Relationships" placeholder card above (fed by
              mapDetailedApiToInfrastructure, edges always []) and the GeoIP
              map are both untouched. */}
          <Card className="mt-5 p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Network className="w-3.5 h-3.5 text-accent-500" />
                <SectionLabel>Relationship Graph</SectionLabel>
              </div>
              {emailGraph && emailGraph.nodes.length > 0 && (
                <Badge variant="neutral">{emailGraph.nodes.length} nodes &middot; {emailGraph.edges.length} edges</Badge>
              )}
            </div>
            {emailGraph && emailGraph.nodes.length > 0 ? (
              <>
                <RelationshipGraphCanvas graph={emailGraph} />
                <Divider className="my-4" />
                <div className="grid grid-cols-4 gap-2.5">
                  {graphLegend.map((item) => (
                    <LegendItem key={item.type} color={item.swatch} label={item.label} />
                  ))}
                </div>
              </>
            ) : (
              <div className="h-80 flex items-center justify-center text-[12px] text-ink-600">
                No relationship graph data available
              </div>
            )}
          </Card>

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

// Frontend F2 — real Cytoscape-backed relationship graph, fed by
// GET /emails/:emailId/graph. Display only: no editing, no dragging
// persistence, no export. Re-initializes (and destroys the previous
// instance) whenever `graph` changes, so navigating between emails never
// leaks Cytoscape instances.
function RelationshipGraphCanvas({ graph }: { graph: ApiInfrastructureGraph }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<ApiInfrastructureGraphNode | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const elements = [
      ...graph.nodes.map((node) => ({
        data: { id: node.id, label: node.label, type: node.type },
      })),
      ...graph.edges.map((edge, i) => ({
        // Edge ids just need to be unique for Cytoscape — the same
        // source|relationship|target can't collide since the backend
        // already de-dupes edges (see infrastructureGraph.ts's addEdge),
        // but the index keeps this safe regardless.
        data: {
          id: `edge-${i}-${edge.source}-${edge.target}`,
          source: edge.source,
          target: edge.target,
          label: edge.relationship,
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        ...(Object.keys(graphNodeStyle) as ApiInfrastructureGraphNodeType[]).map((type) => ({
          selector: `node[type = "${type}"]`,
          style: {
            'background-color': graphNodeStyle[type].color,
            shape: graphNodeStyle[type].shape,
            width: type === 'EMAIL' ? 42 : 26,
            height: type === 'EMAIL' ? 42 : 26,
            label: 'data(label)',
            'font-size': 8,
            color: '#a3a3a3',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-max-width': '90px',
            'text-wrap': 'ellipsis',
            'border-width': 1,
            'border-color': 'rgba(255,255,255,0.15)',
          },
        })),
        {
          selector: 'node:selected',
          style: { 'border-width': 2, 'border-color': '#ffffff' },
        },
        {
          selector: 'edge',
          style: {
            width: 1,
            'line-color': 'rgba(163,163,163,0.35)',
            'target-arrow-color': 'rgba(163,163,163,0.35)',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.6,
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 6,
            color: '#737373',
            'text-rotation': 'autorotate',
            'text-background-color': '#0a0a0a',
            'text-background-opacity': 0.6,
            'text-background-padding': '2px',
          },
        },
      ] as cytoscape.Stylesheet[],
      layout: { name: 'cose', animate: false, padding: 24 } as cytoscape.LayoutOptions,
      minZoom: 0.3,
      maxZoom: 2.5,
      wheelSensitivity: 0.25,
    });

    cy.on('tap', 'node', (evt) => {
      const nodeId = evt.target.id();
      setSelectedNode(graph.nodes.find((n) => n.id === nodeId) ?? null);
    });

    // Tapping empty canvas clears the selection.
    cy.on('tap', (evt) => {
      if (evt.target === cy) setSelectedNode(null);
    });

    return () => {
      cy.destroy();
    };
  }, [graph]);

  return (
    <div className="grid grid-cols-12 gap-4">
      <div
        ref={containerRef}
        className="col-span-8 h-96 rounded-lg border border-base-500/20 bg-base-950/40"
      />
      <div className="col-span-4">
        <div className="panel-2 p-3 h-96 overflow-y-auto scrollbar-thin">
          <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-2">
            {selectedNode ? 'Selected Node' : 'Node Details'}
          </div>
          {selectedNode ? (
            <div className="space-y-2">
              <PreviewField label="Type" value={selectedNode.type} />
              <PreviewField label="Label" value={selectedNode.label} mono />
              {selectedNode.status && <PreviewField label="Status" value={selectedNode.status} />}
              {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                <div>
                  <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mt-3 mb-1">
                    Metadata
                  </div>
                  <pre className="mono text-[10px] text-ink-400 whitespace-pre-wrap break-words leading-relaxed">
                    {JSON.stringify(selectedNode.metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <p className="text-[11px] text-ink-600 leading-relaxed">
              Click any node for its type, label, and metadata. Nodes represent emails, addresses,
              domains, URLs, IPs, ASNs, organizations, and geolocations derived from this email's
              stored analysis — edges show how they're connected.
            </p>
          )}
        </div>
      </div>
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