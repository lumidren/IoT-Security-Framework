import type { Metadata } from 'next';
import { PageHeader } from '@/components/shared/page-header';
import { FirmwareChartLazy } from '@/components/overview/firmware-chart-lazy';
import { FleetMapLazy } from '@/components/overview/fleet-map-lazy';
import { KpiGrid } from '@/components/overview/kpi-grid';
import { LiveFeed } from '@/components/overview/live-feed';

export const metadata: Metadata = { title: 'Fleet overview' };

export default function OverviewPage() {
  return (
    <>
      <PageHeader
        title="Fleet overview"
        description="Lifecycle, connectivity, certificate health, open alerts and rollouts across the tenant."
      />
      <div className="flex flex-col gap-6">
        <KpiGrid />
        <div className="grid gap-6 xl:grid-cols-3">
          <section aria-labelledby="map-heading" className="xl:col-span-2">
            <h2 id="map-heading" className="mb-2 text-lg font-semibold">
              Fleet map
            </h2>
            <FleetMapLazy />
          </section>
          <section aria-labelledby="feed-heading">
            <h2 id="feed-heading" className="mb-2 text-lg font-semibold">
              Live activity
            </h2>
            <LiveFeed />
          </section>
        </div>
        <section aria-labelledby="firmware-heading">
          <h2 id="firmware-heading" className="mb-2 text-lg font-semibold">
            Firmware distribution
          </h2>
          <FirmwareChartLazy />
        </section>
      </div>
    </>
  );
}
