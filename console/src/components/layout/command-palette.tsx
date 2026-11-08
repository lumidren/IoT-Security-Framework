'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { useTheme } from 'next-themes';
import { CpuIcon, MoonIcon, RocketIcon, SunIcon } from 'lucide-react';
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command';
import { DeviceStateBadge } from '@/components/shared/status-badges';
import { NAV_ITEMS } from '@/components/layout/nav-items';
import { useDebouncedValue } from '@/hooks/use-query-state';
import { useDevices } from '@/lib/api/hooks';
import { usePermission } from '@/providers/session-context';

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const router = useRouter();
  const { setTheme, resolvedTheme } = useTheme();
  const [query, setQuery] = React.useState('');
  const debounced = useDebouncedValue(query.trim(), 250);
  const canCreateCampaign = usePermission('campaign.create');
  const devices = useDevices({ q: debounced, limit: 6 }, open && debounced.length >= 2);

  React.useEffect(() => {
    if (!open) setQuery('');
  }, [open]);

  const go = (href: string) => {
    onOpenChange(false);
    router.push(href);
  };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput
        placeholder="Search pages, devices or actions…"
        value={query}
        onValueChange={setQuery}
        aria-label="Search pages, devices or actions"
      />
      <CommandList>
        <CommandEmpty>No results.</CommandEmpty>
        <CommandGroup heading="Pages">
          {NAV_ITEMS.map((item) => (
            <CommandItem
              key={item.href}
              value={`${item.label} ${item.keywords?.join(' ') ?? ''}`}
              onSelect={() => go(item.href)}
            >
              <item.icon aria-hidden="true" />
              <span>{item.label}</span>
            </CommandItem>
          ))}
        </CommandGroup>
        <CommandSeparator />
        <CommandGroup heading="Actions">
          {canCreateCampaign && (
            <CommandItem
              value="new campaign rollout firmware"
              onSelect={() => go('/campaigns/new')}
            >
              <RocketIcon aria-hidden="true" />
              <span>New OTA campaign</span>
            </CommandItem>
          )}
          <CommandItem
            value="toggle theme dark light"
            onSelect={() => {
              setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
              onOpenChange(false);
            }}
          >
            {resolvedTheme === 'dark' ? (
              <SunIcon aria-hidden="true" />
            ) : (
              <MoonIcon aria-hidden="true" />
            )}
            <span>Switch to {resolvedTheme === 'dark' ? 'light' : 'dark'} theme</span>
          </CommandItem>
        </CommandGroup>
        {debounced.length >= 2 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Devices">
              {devices.isLoading && <CommandItem disabled>Searching devices…</CommandItem>}
              {devices.data?.items.map((device) => (
                <CommandItem
                  key={device.id}
                  value={`${device.id} ${device.product}`}
                  onSelect={() => go(`/devices/${device.id}`)}
                >
                  <CpuIcon aria-hidden="true" />
                  <span className="font-mono text-xs">{device.id}</span>
                  <span className="truncate text-xs text-muted-foreground">{device.product}</span>
                  <DeviceStateBadge state={device.state} className="ml-auto" />
                </CommandItem>
              ))}
              {devices.data && devices.data.items.length === 0 && (
                <CommandItem disabled>No matching devices</CommandItem>
              )}
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  );
}
