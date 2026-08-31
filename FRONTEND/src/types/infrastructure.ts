// Shared between InfrastructurePage.tsx and InfrastructureMap.tsx so
// neither has to import the other (avoids a page <-> component
// circular import).

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
  /** null = no resolvable coordinate for this record — never defaulted to 0. */
  lat: number | null;
  lon: number | null;
  flag: string;
  isp: string;
  asn: string;
  organization?: string;
  hosting?: string;
}

export function geoValue(raw: string | undefined | null): string {
  if (!raw || raw.toLowerCase() === 'unknown') return 'INCONCLUSIVE';
  return raw;
}
