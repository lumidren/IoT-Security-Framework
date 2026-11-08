'use client';

import * as React from 'react';
import Link from 'next/link';
import {
  Map as MapLibreMap,
  Marker,
  NavigationControl,
  setWorkerUrl,
  type GeoJSONSource,
  type MapGeoJSONFeature,
} from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';
import { ExternalLinkIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { KeyValueList } from '@/components/shared/key-value';
import { ErrorState } from '@/components/shared/states';
import {
  AssuranceBadge,
  CertStatusBadge,
  ConnectionIndicator,
  DEVICE_STATE_COLOR,
  DeviceStateBadge,
} from '@/components/shared/status-badges';
import { TimeAgo } from '@/components/shared/time';
import { MAP_HEIGHT_CLASS } from '@/lib/constants';
import { FALLBACK_MAP_STYLE } from '@/components/overview/map-style';
import { useDevice, useFleetSummary } from '@/lib/api/hooks';
import { DEVICE_STATES, type DeviceState, type FleetMapPoint } from '@/lib/api/schemas';
import { publicEnv } from '@/lib/env';
import { titleCase } from '@/lib/utils';

const SOURCE_ID = 'devices';

/**
 * Same-origin copy of the MapLibre worker (see scripts/copy-maplibre-worker.mjs).
 * MapLibre resolves its worker next to its own module URL, which does not exist
 * once Next.js bundles the library, so the URL is set explicitly.
 */
const MAPLIBRE_WORKER_URL = '/maplibre/maplibre-gl-worker.mjs';
let workerUrlConfigured = false;

function configureWorkerUrl(): void {
  if (workerUrlConfigured) return;
  setWorkerUrl(new URL(MAPLIBRE_WORKER_URL, window.location.origin).href);
  workerUrlConfigured = true;
}

function toGeoJson(points: FleetMapPoint[]): GeoJSON.FeatureCollection<GeoJSON.Point> {
  return {
    type: 'FeatureCollection',
    features: points.map((p) => ({
      type: 'Feature',
      geometry: { type: 'Point', coordinates: [p.lon, p.lat] },
      properties: { device_id: p.device_id, state: p.state, open_alerts: p.open_alerts },
    })),
  };
}

function clusterMarkerElement(props: Record<string, unknown>, onClick: () => void): HTMLElement {
  const count = Number(props['point_count'] ?? 0);
  const counts = DEVICE_STATES.map((state) => Number(props[state] ?? 0));
  const total = counts.reduce((a, b) => a + b, 0) || 1;
  const size = count >= 50 ? 56 : count >= 10 ? 48 : 40;
  const r = size / 2;
  const stroke = 6;
  const radius = r - stroke / 2;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const segments = counts
    .map((value, index) => {
      if (value === 0) return '';
      const length = (value / total) * circumference;
      const state = DEVICE_STATES[index] ?? 'active';
      const seg = `<circle r="${radius}" cx="${r}" cy="${r}" fill="none" stroke="${DEVICE_STATE_COLOR[state]}" stroke-width="${stroke}" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${r} ${r})"/>`;
      offset += length;
      return seg;
    })
    .join('');
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'fleet-marker fleet-marker-cluster';
  button.style.cssText = `width:${size}px;height:${size}px;border:0;padding:0;background:transparent;cursor:pointer;border-radius:9999px;`;
  const summary = DEVICE_STATES.map((state, i) => (counts[i] ? `${counts[i]} ${state}` : null))
    .filter(Boolean)
    .join(', ');
  button.setAttribute('aria-label', `Cluster of ${count} devices (${summary}). Zoom in`);
  button.innerHTML = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" aria-hidden="true"><circle r="${radius}" cx="${r}" cy="${r}" fill="#ffffff" stroke="#e5e7eb" stroke-width="${stroke}"/>${segments}<text x="${r}" y="${r}" text-anchor="middle" dominant-baseline="central" font-size="${size >= 48 ? 14 : 12}" font-weight="600" fill="#111827">${count}</text></svg>`;
  button.addEventListener('click', (event) => {
    event.stopPropagation();
    onClick();
  });
  return button;
}

function deviceMarkerElement(props: Record<string, unknown>, onClick: () => void): HTMLElement {
  const state = (typeof props['state'] === 'string' ? props['state'] : 'active') as DeviceState;
  const alerts = Number(props['open_alerts'] ?? 0);
  const id = String(props['device_id'] ?? '');
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'fleet-marker fleet-marker-device';
  button.style.cssText =
    'width:24px;height:24px;border:0;padding:0;background:transparent;cursor:pointer;border-radius:9999px;';
  button.setAttribute(
    'aria-label',
    `Device ${id}, ${titleCase(state)}${alerts > 0 ? `, ${alerts} open alert${alerts === 1 ? '' : 's'}` : ''}. Open details`,
  );
  button.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8" fill="${DEVICE_STATE_COLOR[state] ?? '#52525b'}" stroke="#ffffff" stroke-width="3"/>${alerts > 0 ? '<circle cx="19" cy="5" r="4" fill="#b91c1c" stroke="#ffffff" stroke-width="1.5"/>' : ''}</svg>`;
  button.addEventListener('click', (event) => {
    event.stopPropagation();
    onClick();
  });
  return button;
}

interface FleetMapProps {
  points: FleetMapPoint[];
  onSelect: (deviceId: string) => void;
}

function FleetMap({ points, onSelect }: FleetMapProps) {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const mapRef = React.useRef<MapLibreMap | null>(null);
  const markersRef = React.useRef(new Map<string, Marker>());
  const onSelectRef = React.useRef(onSelect);
  onSelectRef.current = onSelect;
  const pointsRef = React.useRef(points);
  pointsRef.current = points;
  const [failed, setFailed] = React.useState<string | null>(null);
  const [loaded, setLoaded] = React.useState(false);

  React.useEffect(() => {
    const container = containerRef.current;
    if (!container || mapRef.current) return;
    let map: MapLibreMap;
    try {
      configureWorkerUrl();
      map = new MapLibreMap({
        container,
        style: publicEnv.mapStyleUrl || FALLBACK_MAP_STYLE,
        center: [5, 48],
        zoom: 2.4,
        attributionControl: { compact: true },
        cooperativeGestures: true,
      });
    } catch (error) {
      setFailed(error instanceof Error ? error.message : 'WebGL is not available in this browser.');
      return;
    }
    mapRef.current = map;
    map.addControl(new NavigationControl({ showCompass: false }), 'top-right');
    map.on('error', (event) => {
      // Tile failures are tolerated (offline); style load failures are not.
      if (!map.isStyleLoaded()) setFailed(event.error?.message ?? 'The map style failed to load.');
    });

    const markers = markersRef.current;
    const updateMarkers = () => {
      if (!map.getSource(SOURCE_ID)) return;
      const features = map.querySourceFeatures(SOURCE_ID);
      const seen = new Set<string>();
      for (const feature of features as MapGeoJSONFeature[]) {
        const props = feature.properties as Record<string, unknown>;
        const geometry = feature.geometry;
        if (geometry.type !== 'Point') continue;
        const [lon, lat] = geometry.coordinates as [number, number];
        const isCluster = Boolean(props['cluster']);
        const key = isCluster
          ? `cluster-${String(props['cluster_id'])}`
          : `device-${String(props['device_id'])}`;
        seen.add(key);
        if (markers.has(key)) continue;
        const element = isCluster
          ? clusterMarkerElement(props, () => {
              const source = map.getSource(SOURCE_ID) as GeoJSONSource | undefined;
              if (!source) return;
              void source.getClusterExpansionZoom(Number(props['cluster_id'])).then((zoom) => {
                map.easeTo({ center: [lon, lat], zoom: Math.min(zoom, 16) });
              });
            })
          : deviceMarkerElement(props, () => onSelectRef.current(String(props['device_id'])));
        const marker = new Marker({ element }).setLngLat([lon, lat]).addTo(map);
        markers.set(key, marker);
      }
      for (const [key, marker] of markers) {
        if (!seen.has(key)) {
          marker.remove();
          markers.delete(key);
        }
      }
    };

    map.on('load', () => {
      const clusterProperties: Record<string, unknown> = {};
      for (const state of DEVICE_STATES) {
        clusterProperties[state] = ['+', ['case', ['==', ['get', 'state'], state], 1, 0]];
      }
      map.addSource(SOURCE_ID, {
        type: 'geojson',
        data: toGeoJson(pointsRef.current),
        cluster: true,
        clusterRadius: 48,
        clusterMaxZoom: 13,
        clusterProperties,
      });
      // MapLibre only tiles a source that some layer renders; without this transparent
      // layer querySourceFeatures() stays empty and no DOM markers are created.
      map.addLayer({
        id: `${SOURCE_ID}-anchor`,
        type: 'circle',
        source: SOURCE_ID,
        paint: { 'circle-radius': 1, 'circle-opacity': 0 },
      });
      map.on('data', (event) => {
        if ('sourceId' in event && event.sourceId === SOURCE_ID && event.isSourceLoaded)
          updateMarkers();
      });
      map.on('move', updateMarkers);
      map.on('moveend', updateMarkers);
      map.on('idle', updateMarkers);
      setLoaded(true);
    });

    return () => {
      for (const marker of markers.values()) marker.remove();
      markers.clear();
      map.remove();
      mapRef.current = null;
    };
  }, []);

  React.useEffect(() => {
    const map = mapRef.current;
    if (!map || !loaded) return;
    const source = map.getSource(SOURCE_ID) as GeoJSONSource | undefined;
    source?.setData(toGeoJson(points));
  }, [points, loaded]);

  // Tear the map down when it fails so its canvas does not outlive the container.
  React.useEffect(() => {
    if (!failed) return;
    for (const marker of markersRef.current.values()) marker.remove();
    markersRef.current.clear();
    mapRef.current?.remove();
    mapRef.current = null;
  }, [failed]);

  if (failed) {
    return (
      <div
        key="fleet-map-fallback"
        className={`${MAP_HEIGHT_CLASS} flex flex-col overflow-auto rounded-xl border p-4`}
      >
        <p className="mb-2 text-sm font-medium">Map unavailable: {failed}</p>
        <ul className="grid gap-1 text-sm sm:grid-cols-2">
          {points.map((p) => (
            <li key={p.device_id}>
              <button
                type="button"
                className="hover:underline"
                onClick={() => onSelect(p.device_id)}
              >
                <span className="font-mono text-xs">{p.device_id}</span> · {titleCase(p.state)} ·{' '}
                {p.lat.toFixed(2)}, {p.lon.toFixed(2)}
              </button>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  return (
    <div
      key="fleet-map-canvas"
      ref={containerRef}
      role="region"
      aria-label="Fleet map with clustered device markers"
      data-testid="fleet-map"
      className={`${MAP_HEIGHT_CLASS} w-full overflow-hidden rounded-xl border`}
    />
  );
}

function DeviceDrawer({ deviceId, onClose }: { deviceId: string | null; onClose: () => void }) {
  const device = useDevice(deviceId ?? '', deviceId !== null);
  return (
    <Sheet open={deviceId !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="overflow-y-auto">
        <SheetHeader>
          <SheetTitle className="font-mono text-base">{deviceId}</SheetTitle>
          <SheetDescription>Device summary from the fleet map.</SheetDescription>
        </SheetHeader>
        <div className="flex flex-col gap-4 px-4 pb-4">
          {device.isLoading && <Skeleton className="h-40 w-full" />}
          {device.isError && (
            <ErrorState error={device.error} onRetry={() => void device.refetch()} />
          )}
          {device.data && (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <DeviceStateBadge state={device.data.state} />
                <AssuranceBadge level={device.data.assurance_level} />
                <CertStatusBadge status={device.data.cert.status} />
              </div>
              <ConnectionIndicator connected={device.data.connected} />
              <KeyValueList
                columns={1}
                items={[
                  {
                    label: 'Product',
                    value: `${device.data.product} (${device.data.hw_revision})`,
                  },
                  { label: 'Firmware', value: device.data.fw_version ?? '—' },
                  { label: 'Groups', value: device.data.groups.join(', ') || '—' },
                  { label: 'Open alerts', value: device.data.open_alerts },
                  { label: 'Last seen', value: <TimeAgo value={device.data.last_seen_at} /> },
                ]}
              />
              <Button asChild>
                <Link href={`/devices/${device.data.id}`}>
                  Open device <ExternalLinkIcon aria-hidden="true" />
                </Link>
              </Button>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

export function FleetMapCard() {
  const summary = useFleetSummary();
  const [selected, setSelected] = React.useState<string | null>(null);
  const points = React.useMemo(() => summary.data?.map ?? [], [summary.data]);
  const stateCounts = React.useMemo(() => {
    const counts: Record<string, number> = {};
    for (const p of points) counts[p.state] = (counts[p.state] ?? 0) + 1;
    return counts;
  }, [points]);

  if (summary.isError) {
    return <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />;
  }

  return (
    <Card className="gap-2 py-0">
      {summary.isLoading ? (
        <Skeleton className={`${MAP_HEIGHT_CLASS} w-full rounded-xl`} />
      ) : (
        <FleetMap points={points} onSelect={setSelected} />
      )}
      <ul className="flex flex-wrap gap-x-4 gap-y-1 px-4 pb-3 text-xs" aria-label="Map legend">
        {DEVICE_STATES.map((state) => (
          <li key={state} className="flex items-center gap-1.5">
            <span
              aria-hidden="true"
              className="inline-block size-2.5 rounded-full"
              style={{ backgroundColor: DEVICE_STATE_COLOR[state] }}
            />
            {titleCase(state)}{' '}
            <span className="tabular text-muted-foreground">({stateCounts[state] ?? 0})</span>
          </li>
        ))}
      </ul>
      <DeviceDrawer deviceId={selected} onClose={() => setSelected(null)} />
    </Card>
  );
}
