'use client';

import dynamic from 'next/dynamic';
import { Skeleton } from '@/components/ui/skeleton';

export const FirmwareChartLazy = dynamic(
  () => import('@/components/overview/firmware-chart').then((m) => m.FirmwareChart),
  {
    ssr: false,
    loading: () => <Skeleton className="h-[300px] w-full rounded-xl" />,
  },
);
