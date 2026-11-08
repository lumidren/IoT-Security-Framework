'use client';

import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { useWs } from '@/providers/ws-provider';

const LABELS: Record<string, string> = {
  idle: 'Live updates idle',
  connecting: 'Connecting live updates',
  open: 'Live updates connected',
  reconnecting: 'Live updates reconnecting',
  closed: 'Live updates disconnected',
};

export function WsStatusIndicator() {
  const { status } = useWs();
  const label = LABELS[status] ?? status;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className="flex size-9 items-center justify-center rounded-md"
          role="status"
          aria-live="polite"
          tabIndex={0}
        >
          <span
            aria-hidden="true"
            className={cn(
              'block size-2.5 rounded-full',
              status === 'open' && 'bg-success',
              (status === 'connecting' || status === 'reconnecting') && 'animate-pulse bg-warning',
              (status === 'closed' || status === 'idle') && 'bg-muted-foreground',
            )}
          />
          <span className="sr-only">{label}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}
