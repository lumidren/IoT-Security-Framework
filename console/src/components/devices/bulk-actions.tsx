'use client';

import * as React from 'react';
import { FolderPlusIcon, Loader2Icon, SendIcon, XIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { FormField } from '@/components/shared/form-field';
import { errorMessage } from '@/components/shared/states';
import { CommandForm } from '@/components/devices/command-form';
import { useSendCommand, useUpdateGroupMembers } from '@/lib/api/hooks';
import type { Group, SendCommandInput } from '@/lib/api/schemas';
import { newIdempotencyKey } from '@/lib/api/client';
import { usePermission } from '@/providers/session-context';

export function BulkActions({
  selectedIds,
  groups,
  onClear,
}: {
  selectedIds: string[];
  groups: Group[];
  onClear: () => void;
}) {
  const canEdit = usePermission('device.edit');
  const canCommand = usePermission('device.command');
  const [groupOpen, setGroupOpen] = React.useState(false);
  const [commandOpen, setCommandOpen] = React.useState(false);
  const [slug, setSlug] = React.useState('');
  const addMembers = useUpdateGroupMembers();
  const sendCommand = useSendCommand();
  const [progress, setProgress] = React.useState<{ done: number; failed: number } | null>(null);

  if (selectedIds.length === 0) return null;

  const submitGroup = async () => {
    if (!slug) return;
    try {
      const result = await addMembers.mutateAsync({ slug, add: selectedIds });
      const addedCount = Array.isArray(result.added) ? result.added.length : result.added;
      if (result.rejected.length > 0) {
        toast.warning(`Added ${addedCount}; ${result.rejected.length} rejected`, {
          description: result.rejected.map((r) => `${r.device_id}: ${r.reason}`).join('\n'),
        });
      } else {
        toast.success(`Added ${addedCount} device${addedCount === 1 ? '' : 's'} to ${slug}`);
      }
      setGroupOpen(false);
      onClear();
    } catch (error) {
      toast.error(errorMessage(error));
    }
  };

  const submitCommand = async (input: SendCommandInput) => {
    setProgress({ done: 0, failed: 0 });
    let done = 0;
    let failed = 0;
    for (const deviceId of selectedIds) {
      try {
        // One idempotency key per device so retries stay safe per target.
        await sendCommand.mutateAsync({
          deviceId,
          input: {
            ...input,
            idempotency_key: `${input.idempotency_key ?? newIdempotencyKey()}-${deviceId}`,
          },
        });
        done += 1;
      } catch {
        failed += 1;
      }
      setProgress({ done, failed });
    }
    if (failed === 0)
      toast.success(`Command ${input.name} queued for ${done} device${done === 1 ? '' : 's'}`);
    else toast.warning(`Queued for ${done}, failed for ${failed}`);
    setProgress(null);
    setCommandOpen(false);
    onClear();
  };

  return (
    <div
      role="region"
      aria-label="Bulk actions"
      className="flex flex-col gap-2 rounded-lg border bg-accent/60 p-3 sm:flex-row sm:items-center sm:justify-between"
    >
      <p className="text-sm font-medium" aria-live="polite">
        {selectedIds.length} device{selectedIds.length === 1 ? '' : 's'} selected
      </p>
      <div className="flex flex-wrap gap-2">
        {canEdit && (
          <Button variant="outline" size="sm" onClick={() => setGroupOpen(true)}>
            <FolderPlusIcon aria-hidden="true" /> Add to group
          </Button>
        )}
        {canCommand && (
          <Button variant="outline" size="sm" onClick={() => setCommandOpen(true)}>
            <SendIcon aria-hidden="true" /> Send command
          </Button>
        )}
        <Button variant="ghost" size="sm" onClick={onClear}>
          <XIcon aria-hidden="true" /> Clear selection
        </Button>
      </div>

      <Dialog open={groupOpen} onOpenChange={setGroupOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Add {selectedIds.length} device{selectedIds.length === 1 ? '' : 's'} to a group
            </DialogTitle>
            <DialogDescription>
              Hardware-only groups reject devices with software-backed keys; those devices are
              reported as rejected.
            </DialogDescription>
          </DialogHeader>
          <FormField id="bulk-group" label="Group" required>
            {(props) => (
              <Select value={slug} onValueChange={setSlug}>
                <SelectTrigger
                  id={props.id}
                  className="w-full"
                  aria-describedby={props['aria-describedby']}
                >
                  <SelectValue placeholder="Pick a group" />
                </SelectTrigger>
                <SelectContent>
                  {groups.map((group) => (
                    <SelectItem key={group.slug} value={group.slug}>
                      {group.name} {group.hardware_only ? '(hardware only)' : ''}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </FormField>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setGroupOpen(false)}
              disabled={addMembers.isPending}
            >
              Cancel
            </Button>
            <Button onClick={() => void submitGroup()} disabled={!slug || addMembers.isPending}>
              {addMembers.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}
              Add to group
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={commandOpen} onOpenChange={(open) => !progress && setCommandOpen(open)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Send a command to {selectedIds.length} device{selectedIds.length === 1 ? '' : 's'}
            </DialogTitle>
            <DialogDescription>
              The command is signed with the tenant key and published to each device&apos;s cmd/req
              topic.
            </DialogDescription>
          </DialogHeader>
          <CommandForm
            idPrefix="bulk-cmd"
            onSubmit={(input) => void submitCommand(input)}
            isPending={progress !== null}
            error={sendCommand.error}
            submitLabel={
              progress
                ? `Sending ${progress.done + progress.failed}/${selectedIds.length}…`
                : 'Send to selected devices'
            }
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
