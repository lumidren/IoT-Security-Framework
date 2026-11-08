'use client';

import * as React from 'react';
import { ShieldAlertIcon } from 'lucide-react';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { FormField } from '@/components/shared/form-field';
import { useAllDevices, useGroups } from '@/lib/api/hooks';
import type { CampaignTarget, DeviceSummary } from '@/lib/api/schemas';
import { parseTags, tagsToString } from '@/lib/utils';

/** Mirrors the OTA service targeting rule: explicit ids, or group membership (narrowed by tags), or tags alone. */
export function matchesTarget(device: DeviceSummary, target: CampaignTarget): boolean {
  if (device.state !== 'active') return false;
  if (target.device_ids.includes(device.id)) return true;
  const tagEntries = Object.entries(target.tags);
  const tagsMatch = tagEntries.every(([k, v]) => device.tags[k] === v);
  if (target.groups.length > 0)
    return target.groups.some((g) => device.groups.includes(g)) && tagsMatch;
  if (tagEntries.length > 0) return tagsMatch;
  return false;
}

export function TargetPicker({
  target,
  onChange,
  product,
}: {
  target: CampaignTarget;
  onChange: (target: CampaignTarget) => void;
  product: string | null;
}) {
  const groups = useGroups();
  const devices = useAllDevices({ state: 'active' });
  const [tagText, setTagText] = React.useState(tagsToString(target.tags).replace(/, /g, '\n'));
  const [tagError, setTagError] = React.useState<string | null>(null);
  const [idsText, setIdsText] = React.useState(target.device_ids.join('\n'));

  const matched = React.useMemo(() => {
    const all = devices.data?.items ?? [];
    return all.filter((d) => matchesTarget(d, target));
  }, [devices.data, target]);
  const wrongProduct = product ? matched.filter((d) => d.product !== product) : [];
  const software = matched.filter((d) => d.assurance_level === 'software');

  const applyTags = () => {
    const tags = parseTags(tagText);
    if (tags === null) {
      setTagError('Each line must be key:value.');
      return;
    }
    setTagError(null);
    onChange({ ...target, tags });
  };

  const applyIds = () => {
    const ids = idsText
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    onChange({ ...target, device_ids: [...new Set(ids)] });
  };

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="flex flex-col gap-5">
        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1 text-sm font-medium">Groups</legend>
          {groups.isLoading && <Skeleton className="h-24 w-full" />}
          {(groups.data ?? []).map((group) => {
            const id = `target-group-${group.slug}`;
            const checked = target.groups.includes(group.slug);
            return (
              <div key={group.slug} className="flex items-start gap-2">
                <Checkbox
                  id={id}
                  checked={checked}
                  onCheckedChange={(value) =>
                    onChange({
                      ...target,
                      groups:
                        value === true
                          ? [...target.groups, group.slug]
                          : target.groups.filter((g) => g !== group.slug),
                    })
                  }
                />
                <Label htmlFor={id} className="flex-col items-start gap-0.5 font-normal">
                  <span>
                    {group.name}{' '}
                    <span className="text-muted-foreground">({group.member_count})</span>
                  </span>
                  <span className="text-xs text-muted-foreground">{group.description}</span>
                </Label>
              </div>
            );
          })}
        </fieldset>
        <FormField
          id="target-tags"
          label="Tags (narrow the selection)"
          hint="One key:value per line. With groups selected, devices must match every tag; without groups, tags select devices on their own."
          error={tagError}
        >
          {(props) => (
            <Textarea
              {...props}
              value={tagText}
              onChange={(e) => setTagText(e.target.value)}
              onBlur={applyTags}
              rows={3}
              className="font-mono text-xs"
              placeholder={'env:prod\nsite:ber'}
            />
          )}
        </FormField>
        <FormField
          id="target-ids"
          label="Explicit device ids"
          hint="Always included, one per line or comma-separated."
        >
          {(props) => (
            <Textarea
              {...props}
              value={idsText}
              onChange={(e) => setIdsText(e.target.value)}
              onBlur={applyIds}
              rows={3}
              className="font-mono text-xs"
              placeholder="dev-8f3a1c2b9d4e5f60"
            />
          )}
        </FormField>
      </div>
      <div className="flex flex-col gap-3 rounded-lg border p-4" aria-live="polite">
        <p className="text-sm font-medium">Target preview</p>
        {devices.isLoading ? (
          <Skeleton className="h-10 w-40" />
        ) : (
          <p className="text-3xl font-semibold tabular-nums">
            {matched.length}
            {devices.data?.truncated ? '+' : ''}{' '}
            <span className="text-base font-normal text-muted-foreground">
              active device{matched.length === 1 ? '' : 's'}
            </span>
          </p>
        )}
        {devices.data?.truncated && (
          <p className="text-xs text-muted-foreground">
            The preview is capped; the OTA service resolves the exact set when the campaign starts.
          </p>
        )}
        {wrongProduct.length > 0 && (
          <p className="flex items-start gap-1.5 text-sm text-destructive" role="alert">
            <ShieldAlertIcon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            {wrongProduct.length} selected device{wrongProduct.length === 1 ? ' is' : 's are'} not{' '}
            {product}; they will reject the image (product mismatch).
          </p>
        )}
        {software.length > 0 && (
          <p className="flex items-start gap-1.5 text-sm text-warning">
            <ShieldAlertIcon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            {software.length} device{software.length === 1 ? '' : 's'} use software-backed keys.
          </p>
        )}
        <ul className="max-h-48 overflow-y-auto font-mono text-xs text-muted-foreground">
          {matched.slice(0, 25).map((d) => (
            <li key={d.id}>
              {d.id} <span className="opacity-70">· {d.product}</span>
            </li>
          ))}
          {matched.length > 25 && <li>… and {matched.length - 25} more</li>}
        </ul>
      </div>
    </div>
  );
}
