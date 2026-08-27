import { useState, useMemo } from 'react';
import { useLocation } from 'react-router-dom';
import { Network, MapPin, Server, Globe, Link2, Zap, Eye, Sparkles, Radar, AlertTriangle, ShieldQuestion } from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import { InvestigationWorkspace, PreviewField, PreviewInvestigateButton } from '@/components/InvestigationWorkspace';
import type { InfraNode, InfraEdge, GeoEntry, ScannedEmail } from '@/data/mockData';
import { cn } from '@/lib/utils';

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
};

/** Renders the doc's literal "unknown" placeholder as INCONCLUSIVE — the data
 *  exists but the upstream lookup couldn't resolve it, which is exactly what
 *  that label means, rather than showing a vague raw string. */
function geoValue(raw: string): string {
  if (!raw || raw.toLowerCase() === 'unknown') return 'INCONCLUSIVE';
  return raw;
}

/**
 * "Intelligence status" for a candidate IP is derived from the existing
 * infraNode record for that same IP (already a real classification in the
 * shared dataset) — not invented. If no matching node exists, it's
 * genuinely UNAVAILABLE rather than guessed at.
 */
function intelStatus(geo: GeoEntry, nodes: InfraNode[]): string | null {
  const match = nodes.find((n) => n.type === 'ip' && n.label === geo.ip);
  if (!match) return null;
  switch (match.status) {
    case 'malicious': return 'Malicious';
    case 'suspicious': return 'Suspicious';
    case 'clean': return 'Verified';
  }
}

function intelColor(label: string | null): string {
  if (label === 'Malicious') return 'text-accent-400';
  if (label === 'Suspicious') return 'text-amber-400';
  if (label === 'Verified') return 'text-emerald-400';
  return 'text-ink-500';
}

export function InfrastructurePage() {
  // Locally-owned selection — this page's own `infrastructureSelectedEmailId`.
  const location = useLocation();
  const { getEmail, setLastViewed, availableEmails } = useActiveCase();
  const [infrastructureSelectedEmailId, setInfrastructureSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );

  const activeEmail = useMemo(() => getEmail(infrastructureSelectedEmailId), [getEmail, infrastructureSelectedEmailId]);

  const handleInvestigate = (email: ScannedEmail) => {
    setInfrastructureSelectedEmailId(email.id);
    setLastViewed(email.id);
  };

  const nodes = activeEmail?.infraNodes ?? [];
  const edges = activeEmail?.infraEdges ?? [];
  // Only IPs with an actual coordinate are "candidates" for the map/geo view —
  // a 0,0 lat/lon in this dataset means "no location resolved," not the coast
  // of Africa, so it's excluded rather than plotted as if it were real.
  const geoData = activeEmail?.geoData ?? [];
  const candidateGeo = geoData.filter((g) => !(g.lat === 0 && g.lon === 0));
  const unresolvedGeo = geoData.filter((g) => g.lat === 0 && g.lon === 0);

  return (
    <InvestigationShell
      breadcrumb="Infrastructure"
      title="Infrastructure Analysis"
      subtitle={activeEmail ? `Relationships, geolocation, and probable infrastructure · ${activeEmail.id}` : undefined}
      hideCaseSelector={!activeEmail}
      selectedEmail={activeEmail}
      availableEmails={availableEmails}
      onSelectEmail={(id) => { setInfrastructureSelectedEmailId(id); setLastViewed(id); }}
      onClearEmail={() => setInfrastructureSelectedEmailId(null)}
      investigationNav={activeEmail ? { emailId: activeEmail.id, activeSection: 'infrastructure' } : undefined}
    >
      {!activeEmail ? (
        <InvestigationWorkspace onInvestigate={handleInvestigate} renderPreview={renderInfrastructurePreview} />
      ) : (
        <div key={activeEmail.id} className="animate-fade-in">
          {/* Doc-required disclaimer — infrastructure location is not attacker identity */}
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
                <Badge variant="neutral">{nodes.length} nodes · {edges.length} edges</Badge>
              </div>
              {nodes.length > 0 ? (
                <RelationshipGraph nodes={nodes} edges={edges} />
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
                <GeoMap points={candidateGeo} nodes={nodes} />
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

          {/* Candidate source IPs — full detail, with evidence provenance */}
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
                  <CandidateIpCard key={geo.ip} geo={geo} status={intelStatus(geo, nodes)} />
                ))}
              </div>
            ) : (
              <div className="text-[12px] text-ink-600 text-center py-8">No candidate source IPs identified</div>
            )}
          </Card>
        </div>
      )}
    </InvestigationShell>
  );
}

function CandidateIpCard({ geo, status }: { geo: GeoEntry; status: string | null }) {
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
        <MiniField label="Region" value={null} provenance="intel" />
        <MiniField label="City" value={geoValue(geo.city)} provenance="intel" />
        <MiniField label="ISP" value={geo.isp} provenance="intel" />
        <MiniField label="ASN" value={geo.asn} provenance="intel" />
        <MiniField label="Hosting / Org" value={null} provenance="intel" />
        <MiniField label="Location Confidence" value={null} provenance="intel" />
        <MiniField label="Observed In" value="Received chain / header IP" provenance="observed" />
      </div>
    </div>
  );
}

function MiniField({ label, value, provenance }: { label: string; value: string | null; provenance: 'observed' | 'intel' | 'inferred' }) {
  const ProvenanceIcon = provenance === 'observed' ? Eye : provenance === 'intel' ? Radar : Sparkles;
  const isUnavailable = value === null;
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
        <span className={cn('mono text-[11px] text-ink-300 truncate', value === 'INCONCLUSIVE' && 'text-ink-500 italic')}>{value}</span>
      )}
    </div>
  );
}

function GeoMap({ points, nodes }: { points: GeoEntry[]; nodes: InfraNode[] }) {
  // Simple equirectangular plot: lon -180..180 → x 0..360, lat 90..-90 → y 0..180.
  const toX = (lon: number) => ((lon + 180) / 360) * 360;
  const toY = (lat: number) => ((90 - lat) / 180) * 180;

  return (
    <div className="relative w-full h-48 bg-base-950/40 rounded-lg border border-base-500/15 overflow-hidden">
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 360 180" preserveAspectRatio="xMidYMid meet">
        {/* Reference grid */}
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
          const color = match?.status === 'malicious' ? '#dc2626' : match?.status === 'suspicious' ? '#f59e0b' : '#10b981';
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

/**
 * Infrastructure-only single-click preview — candidate IP count + top
 * candidate's full geo/intel field set, per the doc. Uses "PROBABLE
 * INFRASTRUCTURE" framing, never "attacker location." Fields the mock
 * dataset doesn't carry (region, hosting type, location confidence) render
 * as UNAVAILABLE rather than a guess.
 */
function renderInfrastructurePreview(email: ScannedEmail, onInvestigate: () => void) {
  const nodes = email.infraNodes ?? [];
  const geoData = email.geoData ?? [];
  const candidates = geoData.filter((g) => !(g.lat === 0 && g.lon === 0));
  const top = candidates[0] ?? geoData[0] ?? null;
  const topStatus = top ? intelStatus(top, nodes) : null;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>Probable Infrastructure</SectionLabel>
        <Badge variant="neutral">{geoData.length} candidate IPs</Badge>
      </div>

      <div className="min-w-0 mb-4">
        <div className="text-[13px] font-semibold text-ink-100 leading-snug truncate">{email.subject}</div>
        <div className="mono text-[10px] text-ink-500 mt-1">{email.caseId || email.id}</div>
      </div>

      {top ? (
        <>
          <div className="flex items-center gap-2.5 mb-4">
            <div className="flex items-center justify-center w-8 h-6 rounded bg-base-600/50 border border-base-500/30 shrink-0">
              <span className="text-[9px] font-bold text-ink-400 mono">{top.flag}</span>
            </div>
            <span className="mono text-[13px] text-ink-100">{top.ip}</span>
            <span className={cn('ml-auto text-[9px] font-bold uppercase tracking-wider', intelColor(topStatus))}>
              {topStatus ?? 'UNAVAILABLE'}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2.5 mb-4">
            <PreviewField label="Country" value={geoValue(top.country)} />
            <PreviewField label="Region" value="UNAVAILABLE" />
            <PreviewField label="City" value={geoValue(top.city)} />
            <PreviewField label="ISP" value={top.isp} mono />
            <PreviewField label="ASN" value={top.asn} mono />
            <PreviewField label="Hosting Type" value="UNAVAILABLE" />
            <PreviewField label="Location Confidence" value="UNAVAILABLE" />
            <PreviewField label="Intelligence Status" value={topStatus ?? 'UNAVAILABLE'} />
          </div>

          {candidates.length > 1 && (
            <>
              <SectionLabel className="block mb-2">Other Candidate IPs</SectionLabel>
              <div className="space-y-1 mb-5">
                {candidates.slice(1).map((g) => (
                  <div key={g.ip} className="mono text-[10px] text-ink-500 panel-2 px-2 py-1.5">{g.ip}</div>
                ))}
              </div>
            </>
          )}
        </>
      ) : (
        <div className="text-[11px] text-ink-600 mb-5">No candidate IPs resolved for this email</div>
      )}

      <PreviewInvestigateButton label="View Infrastructure Map" onClick={onInvestigate} />
    </div>
  );
}
