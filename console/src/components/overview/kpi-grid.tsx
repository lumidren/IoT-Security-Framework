'use client';

import {
  BellIcon,
  CalendarClockIcon,
  CpuIcon,
  RocketIcon,
  ShieldAlertIcon,
  WifiIcon,
} from 'lucide-react';
import { MetricTile } from '@/components/shared/metric-tile';
import { ErrorState } from '@/components/shared/states';
import { useFleetSummary } from '@/lib/api/hooks';
import { formatNumber } from '@/lib/utils';

export function KpiGrid() {
  const summary = useFleetSummary();
  const data = summary.data;
  if (summary.isError) {
    return <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />;
  }
  const loading = summary.isLoading;
  const byState = data?.by_state ?? {};
  const alerts = data?.alerts_open;
  const openAlerts = alerts ? alerts.critical + alerts.high + alerts.medium + alerts.low : 0;

  return (
    <section
      aria-label="Key fleet indicators"
      className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6"
    >
      <MetricTile
        label="Devices"
        icon={CpuIcon}
        href="/devices"
        isLoading={loading}
        value={formatNumber(data?.devices_total)}
        hint={
          data
            ? `${byState['active'] ?? 0} active · ${byState['provisioned'] ?? 0} provisioned · ${byState['manufactured'] ?? 0} manufactured`
            : undefined
        }
      />
      <MetricTile
        label="Connected"
        icon={WifiIcon}
        href="/devices?connected=true"
        isLoading={loading}
        value={formatNumber(data?.connected)}
        hint={data ? `${formatNumber(data.disconnected)} active devices offline` : undefined}
        tone={data && data.disconnected > data.connected ? 'warning' : 'default'}
      />
      <MetricTile
        label="Certs expiring (24 h)"
        icon={CalendarClockIcon}
        isLoading={loading}
        value={formatNumber(data?.certs.expiring_24h)}
        hint={
          data
            ? `${formatNumber(data.certs.expiring_7d)} within 7 days · ${formatNumber(data.certs.expired)} expired`
            : undefined
        }
        tone={data && data.certs.expiring_24h > 0 ? 'warning' : 'default'}
      />
      <MetricTile
        label="Open alerts"
        icon={BellIcon}
        href="/alerts?state=open"
        isLoading={loading}
        value={formatNumber(openAlerts)}
        hint={
          alerts
            ? `${alerts.critical} critical · ${alerts.high} high · ${alerts.medium} medium · ${alerts.low} low`
            : undefined
        }
        tone={
          alerts && alerts.critical > 0
            ? 'danger'
            : alerts && alerts.high > 0
              ? 'warning'
              : 'default'
        }
      />
      <MetricTile
        label="Quarantined"
        icon={ShieldAlertIcon}
        href="/quarantine"
        isLoading={loading}
        value={formatNumber(byState['quarantined'] ?? 0)}
        hint={data ? `${formatNumber(data.assurance.software)} software-key devices` : undefined}
        tone={(byState['quarantined'] ?? 0) > 0 ? 'danger' : 'default'}
      />
      <MetricTile
        label="Running campaigns"
        icon={RocketIcon}
        href="/campaigns?state=running"
        isLoading={loading}
        value={formatNumber(data?.campaigns_running)}
        hint={data ? `${data.firmware.length} firmware versions in the field` : undefined}
      />
    </section>
  );
}
