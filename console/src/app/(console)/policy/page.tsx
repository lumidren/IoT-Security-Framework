import type { Metadata } from 'next';
import { PageHeader } from '@/components/shared/page-header';
import { PolicyView } from '@/components/policy/policy-view';

export const metadata: Metadata = { title: 'Policy' };

export default function PolicyPage() {
  return (
    <>
      <PageHeader
        title="MQTT authorization policy"
        description="The Rego policy evaluated by the policy service for every CONNECT, PUBLISH and SUBSCRIBE. Anything not explicitly allowed is denied."
      />
      <PolicyView />
    </>
  );
}
