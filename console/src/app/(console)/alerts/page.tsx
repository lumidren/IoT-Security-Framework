import type { Metadata } from 'next';
import { Suspense } from 'react';
import { PageHeader } from '@/components/shared/page-header';
import { Skeleton } from '@/components/ui/skeleton';
import { AlertsView } from '@/components/alerts/alerts-view';

export const metadata: Metadata = { title: 'Alerts' };

export default function AlertsPage() {
  return (
    <>
      <PageHeader
        title="Alert center"
        description="Anomalies raised by the detection rules and the isolation-forest model. Acknowledge to take ownership, resolve when the investigation ends."
      />
      <Suspense fallback={<Skeleton className="h-96 w-full" />}>
        <AlertsView />
      </Suspense>
    </>
  );
}
