'use client';

import * as React from 'react';
import { CheckIcon, CheckCheckIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/shared/confirm-dialog';
import { useAckAlert, useResolveAlert } from '@/lib/api/hooks';
import type { Alert } from '@/lib/api/schemas';
import { usePermission } from '@/providers/session-context';

export function AlertActions({ alert, size = 'sm' }: { alert: Alert; size?: 'sm' | 'default' }) {
  const canAck = usePermission('alert.ack');
  const canResolve = usePermission('alert.resolve');
  const ack = useAckAlert();
  const resolve = useResolveAlert();
  const [dialog, setDialog] = React.useState<'ack' | 'resolve' | null>(null);

  if (alert.state === 'resolved') return null;

  return (
    <div className="flex flex-wrap gap-1">
      {canAck && alert.state === 'open' && (
        <Button
          size={size}
          variant="outline"
          onClick={() => setDialog('ack')}
          aria-label={`Acknowledge alert ${alert.rule} on ${alert.device_id}`}
        >
          <CheckIcon aria-hidden="true" /> Acknowledge
        </Button>
      )}
      {canResolve && (
        <Button
          size={size}
          variant="outline"
          onClick={() => setDialog('resolve')}
          aria-label={`Resolve alert ${alert.rule} on ${alert.device_id}`}
        >
          <CheckCheckIcon aria-hidden="true" /> Resolve
        </Button>
      )}
      <ConfirmDialog
        open={dialog === 'ack'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Acknowledge this alert?"
        description="You take ownership of the investigation. The alert stays visible until it is resolved."
        confirmLabel="Acknowledge"
        reasonLabel="Note"
        reasonRequired={false}
        isPending={ack.isPending}
        error={ack.error}
        onConfirm={({ reason }) =>
          ack.mutate(
            { id: alert.id, note: reason },
            {
              onSuccess: () => {
                toast.success('Alert acknowledged');
                setDialog(null);
              },
            },
          )
        }
      />
      <ConfirmDialog
        open={dialog === 'resolve'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Resolve this alert?"
        description="Record the outcome. Marking a false positive feeds the rule tuning report."
        confirmLabel="Resolve"
        reasonLabel="Resolution note"
        checkboxLabel="This alert was a false positive"
        isPending={resolve.isPending}
        error={resolve.error}
        onConfirm={({ reason, checked }) =>
          resolve.mutate(
            { id: alert.id, note: reason, falsePositive: checked },
            {
              onSuccess: () => {
                toast.success(checked ? 'Resolved as false positive' : 'Alert resolved');
                setDialog(null);
              },
            },
          )
        }
      />
    </div>
  );
}
