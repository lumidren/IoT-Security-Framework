'use client';

import { BuildingIcon } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useTenant } from '@/lib/api/hooks';
import { isMockMode, publicEnv } from '@/lib/env';
import { useCurrentUser } from '@/providers/session-context';

export function TenantBadge() {
  const user = useCurrentUser();
  const tenant = useTenant();
  const name = tenant.data?.name ?? user.tenantName ?? 'Tenant';
  const id = tenant.data?.id ?? user.tenantId;
  const envLabel = isMockMode
    ? 'demo'
    : publicEnv.environment &&
        publicEnv.environment !== 'prod' &&
        publicEnv.environment !== 'production'
      ? publicEnv.environment
      : '';

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant="secondary"
          className="hidden h-8 max-w-56 cursor-default gap-1.5 px-2.5 sm:inline-flex"
          tabIndex={0}
          aria-label={`Tenant ${name}${envLabel ? `, ${envLabel} environment` : ''}`}
        >
          <BuildingIcon aria-hidden="true" />
          <span className="truncate">{name}</span>
          {envLabel && <span className="text-muted-foreground">· {envLabel}</span>}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>
        <p className="font-mono text-xs">{id || 'unknown tenant id'}</p>
        {isMockMode && <p>Demo mode: data is served by a mock service worker.</p>}
        {!isMockMode && publicEnv.environment && <p>Environment: {publicEnv.environment}</p>}
      </TooltipContent>
    </Tooltip>
  );
}
