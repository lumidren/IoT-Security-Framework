import type { Metadata } from 'next';
import { Suspense } from 'react';
import { Skeleton } from '@/components/ui/skeleton';
import { CampaignDetailView } from '@/components/campaigns/detail/campaign-detail-view';

export const metadata: Metadata = { title: 'Campaign' };

export default async function CampaignPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <CampaignDetailView id={id} />
    </Suspense>
  );
}
