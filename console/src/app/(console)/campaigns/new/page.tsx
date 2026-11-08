import type { Metadata } from 'next';
import { PageHeader } from '@/components/shared/page-header';
import { CampaignBuilder } from '@/components/campaigns/builder/campaign-builder';

export const metadata: Metadata = { title: 'New campaign' };

export default function NewCampaignPage() {
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Campaigns', href: '/campaigns' }, { label: 'New campaign' }]}
        title="New OTA campaign"
        description="Pick a signed firmware image, choose the target devices, define the rollout stages and review before creating the draft."
      />
      <CampaignBuilder />
    </>
  );
}
