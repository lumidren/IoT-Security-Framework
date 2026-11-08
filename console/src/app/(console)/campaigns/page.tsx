import type { Metadata } from 'next';
import { Suspense } from 'react';
import { Skeleton } from '@/components/ui/skeleton';
import { CampaignsView } from '@/components/campaigns/campaigns-view';

export const metadata: Metadata = { title: 'Campaigns' };

export default function CampaignsPage() {
  return (
    <Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <CampaignsView />
    </Suspense>
  );
}
