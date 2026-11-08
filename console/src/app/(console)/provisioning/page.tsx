import type { Metadata } from 'next';
import { Suspense } from 'react';
import { PageHeader } from '@/components/shared/page-header';
import { Skeleton } from '@/components/ui/skeleton';
import { ProvisioningView } from '@/components/provisioning/provisioning-view';

export const metadata: Metadata = { title: 'Provisioning' };

export default function ProvisioningPage() {
  return (
    <>
      <PageHeader
        title="Provisioning queue"
        description="Devices waiting for enrollment approval, devices that enrolled and are pending activation, and failed attestation attempts."
      />
      <Suspense fallback={<Skeleton className="h-96 w-full" />}>
        <ProvisioningView />
      </Suspense>
    </>
  );
}
