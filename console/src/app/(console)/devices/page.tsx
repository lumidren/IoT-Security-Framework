import type { Metadata } from 'next';
import { Suspense } from 'react';
import { PageHeader } from '@/components/shared/page-header';
import { Skeleton } from '@/components/ui/skeleton';
import { DevicesView } from '@/components/devices/devices-view';

export const metadata: Metadata = { title: 'Devices' };

export default function DevicesPage() {
  return (
    <>
      <PageHeader
        title="Devices"
        description="Every device in the tenant with its lifecycle state, connectivity, certificate health and assurance level."
      />
      <Suspense fallback={<Skeleton className="h-96 w-full" />}>
        <DevicesView />
      </Suspense>
    </>
  );
}
