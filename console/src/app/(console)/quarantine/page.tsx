import type { Metadata } from 'next';
import { PageHeader } from '@/components/shared/page-header';
import { QuarantineView } from '@/components/quarantine/quarantine-view';

export const metadata: Metadata = { title: 'Quarantine' };

export default function QuarantinePage() {
  return (
    <>
      <PageHeader
        title="Quarantine"
        description="Devices isolated automatically by the anomaly engine or manually by an operator. Their certificates are revoked and their sessions kicked; release requires an admin."
      />
      <QuarantineView />
    </>
  );
}
