'use client';

import * as React from 'react';
import { CheckIcon, CircleIcon, ClockIcon, SendIcon, XIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { JsonView } from '@/components/shared/json-view';
import { EmptyState, ErrorState } from '@/components/shared/states';
import { CommandStatusBadge } from '@/components/shared/status-badges';
import { DateTime, TimeAgo } from '@/components/shared/time';
import { CommandForm } from '@/components/devices/command-form';
import { useDeviceCommands, useSendCommand } from '@/lib/api/hooks';
import { CommandStatusSchema, type Command } from '@/lib/api/schemas';
import { cn, titleCase } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

const ALL = '__all__';

function CommandTimeline({ command }: { command: Command }) {
  const steps: Array<{ label: string; at: string | null; state: 'done' | 'failed' | 'pending' }> = [
    { label: 'Created', at: command.created_at, state: 'done' },
    { label: 'Sent', at: command.sent_at, state: command.sent_at ? 'done' : 'pending' },
  ];
  if (command.status === 'acked')
    steps.push({ label: 'Acknowledged', at: command.acked_at, state: 'done' });
  else if (command.status === 'failed' || command.status === 'rejected')
    steps.push({ label: titleCase(command.status), at: command.acked_at, state: 'failed' });
  else if (command.status === 'expired')
    steps.push({ label: 'Expired', at: command.expires_at, state: 'failed' });
  else steps.push({ label: 'Awaiting ack', at: null, state: 'pending' });
  return (
    <ol
      className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs"
      aria-label={`Status timeline for command ${command.name}`}
    >
      {steps.map((step, index) => (
        <li key={step.label} className="flex items-center gap-1.5">
          {index > 0 && (
            <span aria-hidden="true" className="mr-2 hidden h-px w-6 bg-border sm:block" />
          )}
          <span
            className={cn(
              'flex size-5 items-center justify-center rounded-full',
              step.state === 'done' &&
                'bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200',
              step.state === 'failed' &&
                'bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-200',
              step.state === 'pending' && 'bg-muted text-muted-foreground',
            )}
            aria-hidden="true"
          >
            {step.state === 'done' ? (
              <CheckIcon className="size-3" />
            ) : step.state === 'failed' ? (
              <XIcon className="size-3" />
            ) : (
              <CircleIcon className="size-2" />
            )}
          </span>
          <span className="font-medium">{step.label}</span>
          {step.at && <DateTime value={step.at} className="text-muted-foreground" />}
        </li>
      ))}
      <li className="flex items-center gap-1 text-muted-foreground">
        <ClockIcon className="size-3" aria-hidden="true" /> expires{' '}
        <TimeAgo value={command.expires_at} />
      </li>
    </ol>
  );
}

export function CommandsTab({ deviceId }: { deviceId: string }) {
  const canCommand = usePermission('device.command');
  const [status, setStatus] = React.useState('');
  const commands = useDeviceCommands(deviceId, status || undefined);
  const send = useSendCommand();
  const [formKey, setFormKey] = React.useState(0);
  const items = commands.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {canCommand && (
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <SendIcon className="size-4" aria-hidden="true" /> Send command
            </CardTitle>
            <CardDescription>
              Signed with the tenant command key and delivered on cmd/req; the device echoes the
              nonce in its ack.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <CommandForm
              key={formKey}
              onSubmit={(input) =>
                send.mutate(
                  { deviceId, input },
                  {
                    onSuccess: (command) => {
                      toast.success(`Command ${command.name} queued`);
                      setFormKey((k) => k + 1);
                    },
                  },
                )
              }
              isPending={send.isPending}
              error={send.error}
            />
          </CardContent>
        </Card>
      )}
      <Card className={canCommand ? 'lg:col-span-2' : 'lg:col-span-3'}>
        <CardHeader>
          <CardTitle>Command history</CardTitle>
          <div className="flex items-end gap-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="command-status">Status</Label>
              <Select value={status || ALL} onValueChange={(v) => setStatus(v === ALL ? '' : v)}>
                <SelectTrigger id="command-status" className="w-40">
                  <SelectValue placeholder="All" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All</SelectItem>
                  {CommandStatusSchema.options.map((s) => (
                    <SelectItem key={s} value={s}>
                      {titleCase(s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {commands.isError && (
            <ErrorState error={commands.error} onRetry={() => void commands.refetch()} />
          )}
          {commands.isLoading && <Skeleton className="h-40 w-full" />}
          {!commands.isLoading && items.length === 0 && (
            <EmptyState
              title="No commands yet"
              description="Commands sent to this device appear here with their delivery status."
            />
          )}
          <ul className="flex flex-col gap-3">
            {items.map((command) => (
              <li key={command.cmd_id} className="rounded-lg border p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium">{command.name}</span>
                    <CommandStatusBadge status={command.status} />
                  </div>
                  <span className="text-xs text-muted-foreground">
                    by {command.created_by ?? 'unknown'} · <TimeAgo value={command.created_at} />
                  </span>
                </div>
                <div className="mt-2">
                  <CommandTimeline command={command} />
                </div>
                {Object.keys(command.args).length > 0 && (
                  <JsonView
                    value={command.args}
                    maxHeight="max-h-32"
                    className="mt-2"
                    label="Command arguments"
                  />
                )}
                {command.error && (
                  <p className="mt-2 text-sm text-destructive" role="status">
                    {command.error}
                  </p>
                )}
                <p className="mt-2 font-mono text-[11px] text-muted-foreground">
                  cmd {command.cmd_id} · key {command.idempotency_key ?? '—'}
                </p>
              </li>
            ))}
          </ul>
          {commands.hasNextPage && (
            <Button
              variant="outline"
              onClick={() => void commands.fetchNextPage()}
              disabled={commands.isFetchingNextPage}
              className="self-center"
            >
              Load more
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
