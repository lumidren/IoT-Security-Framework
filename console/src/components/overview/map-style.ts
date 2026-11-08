import type { StyleSpecification } from 'maplibre-gl';

/** Minimal raster style used when `NEXT_PUBLIC_MAP_STYLE_URL` is not set. */
export const FALLBACK_MAP_STYLE: StyleSpecification = {
  version: 8,
  name: 'IronMesh OSM raster',
  sources: {
    osm: {
      type: 'raster',
      tiles: ['https://tile.openstreetmap.org/{z}/{x}/{y}.png'],
      tileSize: 256,
      maxzoom: 19,
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors',
    },
  },
  layers: [
    { id: 'background', type: 'background', paint: { 'background-color': '#dfe6ee' } },
    { id: 'osm', type: 'raster', source: 'osm', paint: { 'raster-saturation': -0.35 } },
  ],
};
