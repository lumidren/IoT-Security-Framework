'use client';

import * as React from 'react';
import { Loader2Icon, PencilIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { FormField } from '@/components/shared/form-field';
import { errorMessage } from '@/components/shared/states';
import { useGroups, useUpdateDevice } from '@/lib/api/hooks';
import type { DeviceDetail } from '@/lib/api/schemas';
import { parseTags, tagsToString } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

export function GroupsTagsEditor({ device }: { device: DeviceDetail }) {
  const canEdit = usePermission('device.edit');
  const groups = useGroups();
  const update = useUpdateDevice(device.id);
  const [editing, setEditing] = React.useState(false);
  const [selected, setSelected] = React.useState<string[]>(device.groups);
  const [tagsText, setTagsText] = React.useState(tagsToString(device.tags).replace(/, /g, '\n'));
  const [tagError, setTagError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!editing) {
      setSelected(device.groups);
      setTagsText(tagsToString(device.tags).replace(/, /g, '\n'));
      setTagError(null);
    }
  }, [device, editing]);

  const save = () => {
    const tags = parseTags(tagsText);
    if (tags === null) {
      setTagError('Each line must be key:value.');
      return;
    }
    setTagError(null);
    update.mutate(
      { groups: selected, tags },
      {
        onSuccess: () => {
          toast.success('Groups and tags updated');
          setEditing(false);
        },
        onError: (error) => toast.error(errorMessage(error)),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Groups and tags</CardTitle>
        <CardDescription>
          Groups drive OTA targeting and bulk commands; tags are free-form key:value labels.
        </CardDescription>
        {canEdit && !editing && device.state !== 'decommissioned' && (
          <CardAction>
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
              <PencilIcon aria-hidden="true" /> Edit
            </Button>
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        {!editing ? (
          <div className="flex flex-col gap-3">
            <div>
              <p className="mb-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                Groups
              </p>
              <div className="flex flex-wrap gap-1.5">
                {device.groups.length === 0 && (
                  <span className="text-sm text-muted-foreground">No groups</span>
                )}
                {device.groups.map((g) => (
                  <Badge key={g} variant="secondary">
                    {g}
                  </Badge>
                ))}
              </div>
            </div>
            <div>
              <p className="mb-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                Tags
              </p>
              <div className="flex flex-wrap gap-1.5">
                {Object.keys(device.tags).length === 0 && (
                  <span className="text-sm text-muted-foreground">No tags</span>
                )}
                {Object.entries(device.tags).map(([k, v]) => (
                  <Badge key={k} variant="outline" className="font-mono text-xs">
                    {k}:{v}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              save();
            }}
          >
            <fieldset className="flex flex-col gap-2">
              <legend className="mb-1 text-sm font-medium">Groups</legend>
              {(groups.data ?? []).map((group) => {
                const disabled = group.hardware_only && device.assurance_level !== 'hardware';
                const id = `group-${group.slug}`;
                return (
                  <div key={group.slug} className="flex items-start gap-2">
                    <Checkbox
                      id={id}
                      checked={selected.includes(group.slug)}
                      disabled={disabled}
                      onCheckedChange={(value) =>
                        setSelected((prev) =>
                          value === true
                            ? [...prev, group.slug]
                            : prev.filter((g) => g !== group.slug),
                        )
                      }
                    />
                    <Label htmlFor={id} className="flex-col items-start gap-0.5 font-normal">
                      <span>{group.name}</span>
                      <span className="text-xs text-muted-foreground">
                        {group.slug}
                        {group.hardware_only ? ' · hardware only' : ''}
                        {disabled ? ' · requires hardware assurance' : ''}
                      </span>
                    </Label>
                  </div>
                );
              })}
            </fieldset>
            <FormField
              id="device-tags"
              label="Tags"
              hint="One key:value per line."
              error={tagError}
            >
              {(props) => (
                <Textarea
                  {...props}
                  value={tagsText}
                  onChange={(e) => setTagsText(e.target.value)}
                  rows={4}
                  className="font-mono text-xs"
                />
              )}
            </FormField>
            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditing(false)}
                disabled={update.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={update.isPending}>
                {update.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
                Save
              </Button>
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  );
}
