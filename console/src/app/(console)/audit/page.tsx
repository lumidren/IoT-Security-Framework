import type { Metadata } from 'next';
import { Suspense } from 'react';
import { PageHeader } from '@/components/shared/page-header';
import { Skeleton } from '@/components/ui/skeleton';
import { AuditView } from '@/components/audit/audit-view';

export const metadata: Metadata = { title: 'Audit log' };

export default function AuditPage() {
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every mutation across the registry, OTA, anomaly and policy services, with actor, target, outcome and request id."
      />
      <Suspense fallback={<Skeleton className="h-96 w-full" />}>
        <AuditView />
      </Suspense>
    </>
  );
}
