import { useEffect, useMemo, useRef } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import L from 'leaflet';
import { MapPin, ShieldQuestion } from 'lucide-react';
import type { InfraNode, MappedGeoEntry } from '@/types/infrastructure';
import { geoValue } from '@/types/infrastructure';

/**
 * Interactive geolocation map for probable infrastructure (candidate
 * source IPs), backed by Leaflet + OpenStreetMap tiles. Replaces the
 * old approximate SVG plot.
 *
 * This ONLY plots points already validated upstream in
 * InfrastructurePage.mapDetailedApiToInfrastructure — finite lat/lon,
 * lat in [-90,90], lon in [-180,180]. It never fabricates or defaults
 * a coordinate; a record without a valid latitude/longitude never
 * reaches this component (see the `points` filtering in
 * InfrastructurePage — candidateGeo only).
 */

const STATUS_COLOR: Record<string, string> = {
  malicious: '#dc2626',
  suspicious: '#f59e0b',
  clean: '#10b981',
  unknown: '#a3a3a3',
};

function markerIcon(color: string): L.DivIcon {
  // A hand-rolled DivIcon (no external PNG asset) — avoids the classic
  // Leaflet-under-a-bundler broken default-marker-icon-path problem
  // entirely, and lets the marker color reflect the same
  // malicious/suspicious/clean/unknown convention used everywhere
  // else in the app (RelationshipGraph, statusColors, etc).
  return L.divIcon({
    className: '',
    html: `
      <div style="
        width: 16px; height: 16px; border-radius: 50%;
        background: ${color};
        border: 2px solid rgba(255,255,255,0.85);
        box-shadow: 0 0 0 4px ${color}33, 0 1px 4px rgba(0,0,0,0.5);
      "></div>
    `,
    iconSize: [16, 16],
    iconAnchor: [8, 8],
    popupAnchor: [0, -8],
  });
}

/** Fits the map to all valid points (or centers on the single point) whenever
 *  the point set changes — never a hard-coded geographic center. */
function FitToPoints({ points }: { points: Array<{ lat: number; lon: number }> }) {
  const map = useMap();

  useEffect(() => {
    // Guards against Leaflet initializing into a zero-size container
    // (e.g. if this tab wasn't visible yet on first mount).
    map.invalidateSize();

    if (points.length === 0) return;

    if (points.length === 1) {
      map.setView([points[0].lat, points[0].lon], 6);
      return;
    }

    const bounds = L.latLngBounds(points.map((p) => [p.lat, p.lon] as [number, number]));
    map.fitBounds(bounds, { padding: [32, 32], maxZoom: 8 });
  }, [map, points]);

  return null;
}

export function InfrastructureMap({
  points,
  nodes,
}: {
  points: MappedGeoEntry[];
  nodes: InfraNode[];
}) {
  // Re-validated defensively at render time too (not just at mapping
  // time) so one malformed record can never crash the map — it's
  // simply excluded, same as any other unresolved entry.
  const validPoints = useMemo(
    () =>
      points.filter(
        (p): p is MappedGeoEntry & { lat: number; lon: number } =>
          typeof p.lat === 'number' &&
          Number.isFinite(p.lat) &&
          typeof p.lon === 'number' &&
          Number.isFinite(p.lon)
      ),
    [points]
  );

  // Stable icon instances per status — avoids rebuilding a DivIcon on
  // every render.
  const icons = useRef<Record<string, L.DivIcon>>({});
  for (const status of Object.keys(STATUS_COLOR)) {
    if (!icons.current[status]) {
      icons.current[status] = markerIcon(STATUS_COLOR[status]);
    }
  }

  if (validPoints.length === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center gap-2 rounded-lg border border-base-500/15 bg-base-950/40">
        <ShieldQuestion className="w-5 h-5 text-ink-600" />
        <span className="text-[11px] font-semibold uppercase tracking-wider text-ink-600">
          Location Unavailable
        </span>
        <span className="text-[10px] text-ink-700 max-w-[220px] text-center leading-relaxed">
          No candidate IP for this email resolved to a valid coordinate.
        </span>
      </div>
    );
  }

  return (
    <div className="h-64 rounded-lg overflow-hidden border border-base-500/15 relative z-0">
      <MapContainer
        center={[validPoints[0].lat, validPoints[0].lon]}
        zoom={4}
        scrollWheelZoom
        style={{ height: '100%', width: '100%', background: '#0a0a0a' }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        <FitToPoints points={validPoints} />

        {validPoints.map((geo) => {
          const match = nodes.find((n) => n.type === 'ip' && n.label === geo.ip);
          const status = match?.status ?? 'unknown';
          return (
            <Marker key={geo.ip} position={[geo.lat, geo.lon]} icon={icons.current[status]}>
              <Popup>
                <div style={{ fontFamily: 'inherit', fontSize: '12px', lineHeight: 1.5, minWidth: 180 }}>
                  <div style={{ fontWeight: 700, marginBottom: 4 }}>{geo.ip}</div>
                  <PopupRow label="Country" value={geoValue(geo.country)} />
                  <PopupRow label="Region" value={geoValue(geo.region)} />
                  <PopupRow label="City" value={geoValue(geo.city)} />
                  <PopupRow label="Latitude" value={geo.lat.toFixed(4)} />
                  <PopupRow label="Longitude" value={geo.lon.toFixed(4)} />
                  <PopupRow label="ISP" value={geoValue(geo.isp)} />
                  <PopupRow label="ASN" value={geoValue(geo.asn)} />
                  <PopupRow label="Org / Hosting" value={geoValue(geo.hosting || geo.organization)} />
                  <div style={{ marginTop: 6, fontSize: 10, color: '#888', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <MapPin size={10} /> Probable infrastructure — not attacker identity
                  </div>
                </div>
              </Popup>
            </Marker>
          );
        })}
      </MapContainer>
    </div>
  );
}

function PopupRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
      <span style={{ color: '#888' }}>{label}</span>
      <span style={{ fontWeight: 500 }}>{value}</span>
    </div>
  );
}
