import type { QueryKey } from '@tanstack/react-query';
import { queryKeys } from '@/lib/api/keys';
import type { WsFrame } from '@/lib/api/schemas';

function str(data: unknown, key: string): string | null {
  if (data && typeof data === 'object') {
    const value = (data as Record<string, unknown>)[key];
    if (typeof value === 'string') return value;
  }
  return null;
}

/**
 * Query keys to invalidate for a WebSocket frame. Pure so it can be unit tested; telemetry frames
 * are applied directly to the cache (see `applyTelemetryFrame`) and return no keys here.
 */
export function invalidationsFor(frame: WsFrame): QueryKey[] {
  const deviceId = str(frame.data, 'device_id');
  switch (frame.type) {
    case 'device.connected':
    case 'device.disconnected': {
      const keys: QueryKey[] = [queryKeys.fleet.all, queryKeys.devices.lists()];
      if (deviceId)
        keys.push(queryKeys.devices.detail(deviceId), queryKeys.devices.timeline(deviceId));
      return keys;
    }
    case 'device.state_changed': {
      const keys: QueryKey[] = [
        queryKeys.fleet.all,
        queryKeys.devices.lists(),
        queryKeys.provisioning.all,
        queryKeys.quarantine.all,
      ];
      if (deviceId)
        keys.push(queryKeys.devices.detail(deviceId), queryKeys.devices.timeline(deviceId));
      return keys;
    }
    case 'twin.updated':
      return deviceId ? [queryKeys.devices.twin(deviceId)] : [];
    case 'command.updated': {
      const keys: QueryKey[] = [];
      if (deviceId) keys.push(queryKeys.devices.commands(deviceId));
      const cmdId = str(frame.data, 'cmd_id');
      if (cmdId) keys.push(queryKeys.commands.detail(cmdId));
      return keys;
    }
    case 'alert.created':
    case 'alert.updated': {
      const keys: QueryKey[] = [queryKeys.alerts.lists(), queryKeys.fleet.all];
      const alertId = str(frame.data, 'id') ?? str(frame.data, 'alert_id');
      if (alertId) keys.push(queryKeys.alerts.detail(alertId));
      if (deviceId)
        keys.push(queryKeys.devices.timeline(deviceId), queryKeys.devices.detail(deviceId));
      return keys;
    }
    case 'campaign.updated': {
      const keys: QueryKey[] = [queryKeys.campaigns.lists(), queryKeys.fleet.all];
      const campaignId = str(frame.data, 'id') ?? str(frame.data, 'campaign_id');
      if (campaignId) keys.push(queryKeys.campaigns.detail(campaignId));
      return keys;
    }
    case 'provisioning.updated':
      return [queryKeys.provisioning.all, queryKeys.devices.lists(), queryKeys.fleet.all];
    case 'audit.created':
      return [queryKeys.audit.all];
    default:
      return [];
  }
}
