'use client';

import dynamic from 'next/dynamic';
import { Skeleton } from '@/components/ui/skeleton';
import { MAP_HEIGHT_CLASS } from '@/lib/constants';

/** The MapLibre bundle is large; load it client-side only, with a reserved height to avoid layout shift. */
export const FleetMapLazy = dynamic(
  () => import('@/components/overview/fleet-map').then((m) => m.FleetMapCard),
  {
    ssr: false,
    loading: () => <Skeleton className={`${MAP_HEIGHT_CLASS} w-full rounded-xl`} />,
  },
);
