import type { Metadata } from 'next';
import { PageHeader } from '@/components/shared/page-header';
import { AccessSettingsView } from '@/components/settings/access-settings-view';

export const metadata: Metadata = { title: 'Access settings' };

export default function AccessSettingsPage() {
  return (
    <>
      <PageHeader
        title="Access and tenant settings"
        description="Who can do what in this tenant, machine credentials for pipelines and factories, and the security defaults applied to every device."
      />
      <AccessSettingsView />
    </>
  );
}
