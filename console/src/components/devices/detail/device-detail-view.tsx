'use client';

import * as React from 'react';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { PageHeader } from '@/components/shared/page-header';
import { ErrorState } from '@/components/shared/states';
import {
  AssuranceBadge,
  CertStatusBadge,
  ConnectionIndicator,
  DeviceStateBadge,
} from '@/components/shared/status-badges';
import { CertificatesTab } from '@/components/devices/detail/certificates-tab';
import { CommandsTab } from '@/components/devices/detail/commands-tab';
import { ConfigTab } from '@/components/devices/detail/config-tab';
import { DeviceActions } from '@/components/devices/detail/device-actions';
import { OverviewTab } from '@/components/devices/detail/overview-tab';
import { TelemetryTab } from '@/components/devices/detail/telemetry-tab';
import { TimelineTab } from '@/components/devices/detail/timeline-tab';
import { TwinTab } from '@/components/devices/detail/twin-tab';
import { useQueryState } from '@/hooks/use-query-state';
import { useDevice } from '@/lib/api/hooks';
import { usePermission } from '@/providers/session-context';
import { useWsTopics } from '@/providers/ws-provider';

const TABS = [
  'overview',
  'telemetry',
  'twin',
  'commands',
  'config',
  'certificates',
  'timeline',
] as const;
type Tab = (typeof TABS)[number];

export function DeviceDetailView({ id }: { id: string }) {
  const device = useDevice(id);
  const { get, set } = useQueryState();
  const canReadConfig = usePermission('device.config.read');
  const requested = get('tab');
  const tab: Tab = (TABS as readonly string[]).includes(requested)
    ? (requested as Tab)
    : 'overview';
  useWsTopics([`device:${id}`]);

  if (device.isError) {
    return (
      <>
        <PageHeader title={id} crumbs={[{ label: 'Devices', href: '/devices' }, { label: id }]} />
        <ErrorState error={device.error} onRetry={() => void device.refetch()} />
      </>
    );
  }

  const data = device.data;

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Devices', href: '/devices' }, { label: id }]}
        title={<span className="font-mono">{id}</span>}
        description={
          data ? (
            <span className="flex flex-wrap items-center gap-2">
              <span>
                {data.product} · {data.hw_revision}
              </span>
              <DeviceStateBadge state={data.state} />
              <AssuranceBadge level={data.assurance_level} />
              <CertStatusBadge status={data.cert.status} />
              <ConnectionIndicator connected={data.connected} />
            </span>
          ) : (
            <Skeleton className="h-5 w-72" />
          )
        }
        actions={data ? <DeviceActions device={data} /> : null}
      />

      <Tabs
        value={tab}
        onValueChange={(value) => set({ tab: value === 'overview' ? null : value })}
      >
        <TabsList aria-label="Device sections">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="telemetry">Telemetry</TabsTrigger>
          <TabsTrigger value="twin">Twin</TabsTrigger>
          <TabsTrigger value="commands">Commands</TabsTrigger>
          {canReadConfig && <TabsTrigger value="config">Config</TabsTrigger>}
          <TabsTrigger value="certificates">Certificates</TabsTrigger>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
        </TabsList>
        <TabsContent value="overview" className="pt-2">
          {data ? <OverviewTab device={data} /> : <Skeleton className="h-80 w-full" />}
        </TabsContent>
        <TabsContent value="telemetry" className="pt-2">
          {data ? <TelemetryTab device={data} /> : <Skeleton className="h-80 w-full" />}
        </TabsContent>
        <TabsContent value="twin" className="pt-2">
          <TwinTab deviceId={id} />
        </TabsContent>
        <TabsContent value="commands" className="pt-2">
          <CommandsTab deviceId={id} />
        </TabsContent>
        <TabsContent value="config" className="pt-2">
          <ConfigTab deviceId={id} />
        </TabsContent>
        <TabsContent value="certificates" className="pt-2">
          <CertificatesTab deviceId={id} />
        </TabsContent>
        <TabsContent value="timeline" className="pt-2">
          <TimelineTab deviceId={id} />
        </TabsContent>
      </Tabs>
    </>
  );
}
