'use client';

import * as React from 'react';
import { ShieldBanIcon, ShieldCheckIcon, Trash2Icon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/shared/confirm-dialog';
import { useDecommissionDevice, useQuarantineDevice, useReleaseDevice } from '@/lib/api/hooks';
import type { DeviceDetail } from '@/lib/api/schemas';
import { usePermission } from '@/providers/session-context';

type Action = 'quarantine' | 'release' | 'decommission' | null;

export function DeviceActions({ device }: { device: DeviceDetail }) {
  const canQuarantine = usePermission('device.quarantine');
  const canRelease = usePermission('device.release');
  const canDecommission = usePermission('device.decommission');
  const [action, setAction] = React.useState<Action>(null);
  const quarantine = useQuarantineDevice();
  const release = useReleaseDevice();
  const decommission = useDecommissionDevice();

  const terminal = device.state === 'decommissioned';

  return (
    <>
      {canQuarantine && !terminal && device.state !== 'quarantined' && (
        <Button variant="outline" onClick={() => setAction('quarantine')}>
          <ShieldBanIcon aria-hidden="true" /> Quarantine
        </Button>
      )}
      {canRelease && device.state === 'quarantined' && (
        <Button variant="outline" onClick={() => setAction('release')}>
          <ShieldCheckIcon aria-hidden="true" /> Release
        </Button>
      )}
      {canDecommission && !terminal && (
        <Button variant="destructive" onClick={() => setAction('decommission')}>
          <Trash2Icon aria-hidden="true" /> Decommission
        </Button>
      )}

      <ConfirmDialog
        open={action === 'quarantine'}
        onOpenChange={(open) => !open && setAction(null)}
        title={`Quarantine ${device.id}?`}
        description="All certificates are revoked, the policy cache denies the device and its MQTT session is kicked within 10 seconds. The device must re-enroll after release."
        confirmLabel="Quarantine device"
        destructive
        reasonLabel="Reason"
        reasonPlaceholder="Why is this device being isolated?"
        isPending={quarantine.isPending}
        error={quarantine.error}
        onConfirm={({ reason }) =>
          quarantine.mutate(
            { id: device.id, reason },
            {
              onSuccess: () => {
                toast.success('Device quarantined');
                setAction(null);
              },
            },
          )
        }
      />
      <ConfirmDialog
        open={action === 'release'}
        onOpenChange={(open) => !open && setAction(null)}
        title={`Release ${device.id} from quarantine?`}
        description="The device returns to the active state but must re-enroll through EST before it can connect again."
        confirmLabel="Release device"
        reasonLabel="Note"
        reasonPlaceholder="What was investigated and why is it safe to release?"
        isPending={release.isPending}
        error={release.error}
        onConfirm={({ reason }) =>
          release.mutate(
            { id: device.id, note: reason },
            {
              onSuccess: () => {
                toast.success('Device released');
                setAction(null);
              },
            },
          )
        }
      />
      <ConfirmDialog
        open={action === 'decommission'}
        onOpenChange={(open) => !open && setAction(null)}
        title={`Decommission ${device.id}?`}
        description="This is permanent. Certificates are revoked, the device leaves all groups and it can never be re-activated."
        confirmLabel="Decommission permanently"
        destructive
        reasonLabel="Reason"
        reasonPlaceholder="Hardware failure, end of life, returned to vendor…"
        isPending={decommission.isPending}
        error={decommission.error}
        onConfirm={({ reason }) =>
          decommission.mutate(
            { id: device.id, reason },
            {
              onSuccess: () => {
                toast.success('Device decommissioned');
                setAction(null);
              },
            },
          )
        }
      />
    </>
  );
}
