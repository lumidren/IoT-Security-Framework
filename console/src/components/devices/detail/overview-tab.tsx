'use client';

import * as React from 'react';
import Link from 'next/link';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { CopyButton } from '@/components/shared/copy-button';
import { KeyValueList } from '@/components/shared/key-value';
import { AssuranceBadge, CertStatusBadge } from '@/components/shared/status-badges';
import { Countdown, DateTime, TimeAgo } from '@/components/shared/time';
import { GroupsTagsEditor } from '@/components/devices/detail/groups-tags-editor';
import type { DeviceDetail } from '@/lib/api/schemas';
import { formatBytes, formatNumber, shortHex } from '@/lib/utils';

export function OverviewTab({ device }: { device: DeviceDetail }) {
  const telemetry = device.last_telemetry;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Certificate</CardTitle>
          <CardDescription>
            Operational certificate issued by the IronMesh Device CA (14-day lifetime, renewed at
            50%).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <KeyValueList
            items={[
              { label: 'Status', value: <CertStatusBadge status={device.cert.status} /> },
              {
                label: 'Expires',
                value: device.cert.not_after ? (
                  <span>
                    <Countdown until={device.cert.not_after} />{' '}
                    <span className="text-muted-foreground">
                      (<DateTime value={device.cert.not_after} />)
                    </span>
                  </span>
                ) : (
                  '—'
                ),
              },
              {
                label: 'Serial',
                value: device.cert.serial_hex ? (
                  <span className="inline-flex items-center gap-1">
                    <span className="font-mono text-xs">{shortHex(device.cert.serial_hex, 8)}</span>
                    <CopyButton value={device.cert.serial_hex} label="Copy certificate serial" />
                  </span>
                ) : (
                  '—'
                ),
              },
              { label: 'Certificates on record', value: device.certificates.length },
            ]}
          />
          {device.state === 'quarantined' && (
            <p className="mt-3 text-sm text-destructive">
              Quarantined <TimeAgo value={device.quarantined_at} />: {device.quarantine_reason}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Firmware</CardTitle>
          <CardDescription>
            Reported by the device in its last telemetry sample and verified against the OTA
            known-hash list.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <KeyValueList
            items={[
              {
                label: 'Version',
                value: device.fw_version ? `${device.product}/${device.fw_version}` : '—',
              },
              {
                label: 'Image SHA-256',
                value: device.fw_hash_hex ? (
                  <span className="inline-flex items-center gap-1">
                    <span className="font-mono text-xs">{shortHex(device.fw_hash_hex, 10)}</span>
                    <CopyButton value={device.fw_hash_hex} label="Copy firmware hash" />
                  </span>
                ) : (
                  '—'
                ),
              },
              { label: 'Product', value: `${device.product} (${device.hw_revision})` },
              {
                label: 'Campaigns',
                value: (
                  <Link
                    href={`/campaigns`}
                    className="text-primary underline-offset-4 hover:underline"
                  >
                    View rollouts
                  </Link>
                ),
              },
            ]}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Identity and assurance</CardTitle>
          <CardDescription>
            Identity is the device id in the verified X.509 certificate, never a payload string.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <KeyValueList
            items={[
              { label: 'Assurance', value: <AssuranceBadge level={device.assurance_level} /> },
              { label: 'Secure element', value: device.se_type ?? '—' },
              {
                label: 'Bootstrap serial',
                value: shortHex(device.bootstrap_serial_hex, 8),
                mono: true,
              },
              { label: 'Tenant', value: device.tenant_id, mono: true },
              { label: 'Manufactured', value: <DateTime value={device.created_at} /> },
              { label: 'Provisioned', value: <DateTime value={device.provisioned_at} /> },
              { label: 'Activated', value: <DateTime value={device.activated_at} /> },
              { label: 'Decommissioned', value: <DateTime value={device.decommissioned_at} /> },
              {
                label: 'Location',
                value: device.location
                  ? `${device.location.lat.toFixed(4)}, ${device.location.lon.toFixed(4)}`
                  : '—',
              },
              { label: 'Twin version', value: device.twin_version },
            ]}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Last telemetry</CardTitle>
          <CardDescription>
            {telemetry ? (
              <>
                Received <TimeAgo value={telemetry.ts} />
              </>
            ) : (
              'No telemetry received yet.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {telemetry && (
            <KeyValueList
              columns={3}
              items={[
                {
                  label: 'CPU',
                  value:
                    telemetry.cpu_pct != null ? `${formatNumber(telemetry.cpu_pct, 1)} %` : '—',
                },
                {
                  label: 'Memory',
                  value:
                    telemetry.mem_pct != null ? `${formatNumber(telemetry.mem_pct, 1)} %` : '—',
                },
                {
                  label: 'Temperature',
                  value: telemetry.temp_c != null ? `${formatNumber(telemetry.temp_c, 1)} °C` : '—',
                },
                { label: 'Net RX', value: formatBytes(telemetry.net_rx_bytes) },
                { label: 'Net TX', value: formatBytes(telemetry.net_tx_bytes) },
                {
                  label: 'Uptime',
                  value:
                    telemetry.uptime_s != null
                      ? `${formatNumber(telemetry.uptime_s / 3600, 1)} h`
                      : '—',
                },
                ...(telemetry.rssi != null
                  ? [{ label: 'RSSI', value: `${telemetry.rssi} dBm` }]
                  : []),
                ...(telemetry.free_heap != null
                  ? [{ label: 'Free heap', value: formatBytes(telemetry.free_heap) }]
                  : []),
                ...(telemetry.proc_count != null
                  ? [{ label: 'Processes', value: telemetry.proc_count }]
                  : []),
              ]}
            />
          )}
        </CardContent>
      </Card>

      <div className="lg:col-span-2">
        <GroupsTagsEditor device={device} />
      </div>
    </div>
  );
}
