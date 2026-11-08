import { ShieldAlertIcon, ShieldCheckIcon, WifiIcon, WifiOffIcon } from 'lucide-react';
import { Badge, type BadgeVariant } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type {
  AlertState,
  AssuranceLevel,
  CampaignDeviceState,
  CampaignState,
  CertStatus,
  CommandStatus,
  DeviceState,
  FirmwareSeverity,
  ProvisioningState,
  Severity,
  StageState,
} from '@/lib/api/schemas';
import { cn, titleCase } from '@/lib/utils';

const DEVICE_STATE_VARIANT: Record<DeviceState, BadgeVariant> = {
  manufactured: 'warning',
  provisioned: 'info',
  active: 'success',
  quarantined: 'danger',
  decommissioned: 'neutral',
};

export const DEVICE_STATE_COLOR: Record<DeviceState, string> = {
  manufactured: '#b45309',
  provisioned: '#0369a1',
  active: '#047857',
  quarantined: '#b91c1c',
  decommissioned: '#52525b',
};

export function DeviceStateBadge({ state, className }: { state: DeviceState; className?: string }) {
  return (
    <Badge variant={DEVICE_STATE_VARIANT[state]} className={className}>
      {titleCase(state)}
    </Badge>
  );
}

const SEVERITY_VARIANT: Record<Severity, BadgeVariant> = {
  critical: 'danger',
  high: 'warning',
  medium: 'info',
  low: 'neutral',
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge variant={SEVERITY_VARIANT[severity]} className={className}>
      {titleCase(severity)}
    </Badge>
  );
}

const ALERT_STATE_VARIANT: Record<AlertState, BadgeVariant> = {
  open: 'danger',
  acked: 'warning',
  resolved: 'success',
};

export function AlertStateBadge({ state, className }: { state: AlertState; className?: string }) {
  return (
    <Badge variant={ALERT_STATE_VARIANT[state]} className={className}>
      {state === 'acked' ? 'Acknowledged' : titleCase(state)}
    </Badge>
  );
}

const CAMPAIGN_STATE_VARIANT: Record<CampaignState, BadgeVariant> = {
  draft: 'neutral',
  running: 'info',
  paused: 'warning',
  halted: 'danger',
  completed: 'success',
  rolled_back: 'purple',
  cancelled: 'neutral',
};

export function CampaignStateBadge({
  state,
  className,
}: {
  state: CampaignState;
  className?: string;
}) {
  return (
    <Badge variant={CAMPAIGN_STATE_VARIANT[state]} className={className}>
      {titleCase(state)}
    </Badge>
  );
}

const STAGE_STATE_VARIANT: Record<StageState, BadgeVariant> = {
  pending: 'neutral',
  running: 'info',
  dwelling: 'warning',
  passed: 'success',
  halted: 'danger',
};

export function StageStateBadge({ state }: { state: StageState }) {
  return <Badge variant={STAGE_STATE_VARIANT[state]}>{titleCase(state)}</Badge>;
}

const CAMPAIGN_DEVICE_VARIANT: Record<CampaignDeviceState, BadgeVariant> = {
  pending: 'neutral',
  notified: 'info',
  downloading: 'info',
  verifying: 'info',
  applying: 'info',
  rebooting: 'info',
  success: 'success',
  failed: 'danger',
  rolled_back: 'purple',
  rejected: 'warning',
};

export function CampaignDeviceStateBadge({ state }: { state: CampaignDeviceState }) {
  return <Badge variant={CAMPAIGN_DEVICE_VARIANT[state]}>{titleCase(state)}</Badge>;
}

const COMMAND_STATUS_VARIANT: Record<CommandStatus, BadgeVariant> = {
  pending: 'neutral',
  sent: 'info',
  acked: 'success',
  failed: 'danger',
  rejected: 'warning',
  expired: 'neutral',
};

export function CommandStatusBadge({ status }: { status: CommandStatus }) {
  return <Badge variant={COMMAND_STATUS_VARIANT[status]}>{titleCase(status)}</Badge>;
}

const CERT_STATUS_VARIANT: Record<CertStatus, BadgeVariant> = {
  valid: 'success',
  expiring: 'warning',
  expired: 'danger',
  revoked: 'danger',
  none: 'neutral',
};

export function CertStatusBadge({ status, className }: { status: CertStatus; className?: string }) {
  return (
    <Badge variant={CERT_STATUS_VARIANT[status]} className={className}>
      {status === 'none' ? 'No certificate' : titleCase(status)}
    </Badge>
  );
}

const PROVISIONING_VARIANT: Record<ProvisioningState, BadgeVariant> = {
  manufactured: 'warning',
  provisioned: 'info',
  failed: 'danger',
};

export function ProvisioningStateBadge({ state }: { state: ProvisioningState }) {
  return <Badge variant={PROVISIONING_VARIANT[state]}>{titleCase(state)}</Badge>;
}

export function FirmwareSeverityBadge({ severity }: { severity: FirmwareSeverity }) {
  return (
    <Badge variant={severity === 'security' ? 'danger' : 'neutral'}>
      {severity === 'security' ? 'Security' : 'Normal'}
    </Badge>
  );
}

/** Software-backed keys get the warning badge required by DESIGN_CONTRACT §10. */
export function AssuranceBadge({
  level,
  className,
}: {
  level: AssuranceLevel | null;
  className?: string;
}) {
  if (level === 'hardware') {
    return (
      <Badge variant="success" className={className}>
        <ShieldCheckIcon aria-hidden="true" /> Hardware
      </Badge>
    );
  }
  if (level === 'software') {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge variant="warning" className={cn('cursor-help', className)} tabIndex={0}>
            <ShieldAlertIcon aria-hidden="true" /> Software keys
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          This device stores its private key in software (encrypted NVS or OS keyring) rather than a
          secure element. It is excluded from hardware-only groups.
        </TooltipContent>
      </Tooltip>
    );
  }
  return (
    <Badge variant="neutral" className={className}>
      Unattested
    </Badge>
  );
}

export function ConnectionIndicator({
  connected,
  className,
}: {
  connected: boolean;
  className?: string;
}) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 text-sm', className)}>
      {connected ? (
        <WifiIcon className="size-4 text-success" aria-hidden="true" />
      ) : (
        <WifiOffIcon className="size-4 text-muted-foreground" aria-hidden="true" />
      )}
      <span>{connected ? 'Connected' : 'Offline'}</span>
    </span>
  );
}
