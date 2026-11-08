'use client';

import * as React from 'react';
import { AlertTriangleIcon, Loader2Icon, RefreshCwIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { CodeEditor } from '@/components/shared/json-editor';
import { JsonView } from '@/components/shared/json-view';
import { ErrorState, errorMessage } from '@/components/shared/states';
import { DateTime } from '@/components/shared/time';
import { isApiError } from '@/lib/api/client';
import { usePatchTwinDesired, useTwin } from '@/lib/api/hooks';
import { isPlainObject, safeJsonParse } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

export function TwinTab({ deviceId }: { deviceId: string }) {
  const canWrite = usePermission('twin.write');
  const twin = useTwin(deviceId);
  const patch = usePatchTwinDesired(deviceId);
  const [draft, setDraft] = React.useState<string | null>(null);
  const [baseVersion, setBaseVersion] = React.useState<number | null>(null);
  const [parseError, setParseError] = React.useState<string | null>(null);

  const data = twin.data;
  const editorValue = draft ?? (data ? JSON.stringify(data.desired, null, 2) : '');
  const conflict = isApiError(patch.error) && patch.error.isConflict;
  const serverChanged = data !== undefined && baseVersion !== null && data.version !== baseVersion;

  const startEditing = () => {
    if (!data) return;
    setDraft(JSON.stringify(data.desired, null, 2));
    setBaseVersion(data.version);
    setParseError(null);
    patch.reset();
  };

  const submit = () => {
    if (draft === null || baseVersion === null) return;
    const parsed = safeJsonParse(draft);
    if (!parsed.ok || !isPlainObject(parsed.value)) {
      setParseError(parsed.ok ? 'Desired state must be a JSON object.' : parsed.error);
      return;
    }
    setParseError(null);
    patch.mutate(
      { patch: parsed.value, expectedVersion: baseVersion },
      {
        onSuccess: (next) => {
          toast.success(`Desired state published (version ${next.version})`);
          setDraft(null);
          setBaseVersion(null);
        },
      },
    );
  };

  if (twin.isError) return <ErrorState error={twin.error} onRetry={() => void twin.refetch()} />;
  if (!data) return <Skeleton className="h-96 w-full" />;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
        <span>
          Version <span className="tabular font-medium">{data.version}</span>
        </span>
        <span>
          Desired updated <DateTime value={data.desired_updated_at} />
        </span>
        <span>
          Reported updated <DateTime value={data.reported_updated_at} />
        </span>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void twin.refetch()}
          disabled={twin.isFetching}
        >
          <RefreshCwIcon
            aria-hidden="true"
            className={twin.isFetching ? 'animate-spin' : undefined}
          />{' '}
          Refresh
        </Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Desired</CardTitle>
            <CardDescription>
              Published to shadow/desired, signed with the tenant key (retained).
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {draft === null ? (
              <>
                <JsonView value={data.desired} label="Desired state" />
                {canWrite && (
                  <Button variant="outline" onClick={startEditing} className="self-start">
                    Edit desired state
                  </Button>
                )}
              </>
            ) : (
              <>
                {(conflict || serverChanged) && (
                  <Alert variant="warning">
                    <AlertTriangleIcon aria-hidden="true" />
                    <AlertTitle>The twin changed while you were editing</AlertTitle>
                    <AlertDescription>
                      <p>
                        You started from version {baseVersion}; the device twin is now at version{' '}
                        {data.version}. Reload the desired state and re-apply your changes.
                      </p>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          void twin.refetch().then(() => {
                            setDraft(null);
                            setBaseVersion(null);
                            patch.reset();
                          });
                        }}
                      >
                        Reload latest
                      </Button>
                    </AlertDescription>
                  </Alert>
                )}
                <CodeEditor
                  value={editorValue}
                  onChange={setDraft}
                  language="json"
                  ariaLabel="Desired state JSON editor"
                  height="280px"
                />
                {parseError && (
                  <p className="text-sm text-destructive" role="alert">
                    {parseError}
                  </p>
                )}
                {patch.error && !conflict && (
                  <p className="text-sm text-destructive" role="alert">
                    {errorMessage(patch.error)}
                  </p>
                )}
                <div className="flex gap-2">
                  <Button onClick={submit} disabled={patch.isPending || conflict}>
                    {patch.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
                    Publish (expects v{baseVersion})
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setDraft(null)}
                    disabled={patch.isPending}
                  >
                    Cancel
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Reported</CardTitle>
            <CardDescription>Last state the device published to shadow/reported.</CardDescription>
          </CardHeader>
          <CardContent>
            <JsonView value={data.reported} label="Reported state" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Delta</CardTitle>
            <CardDescription>Desired keys the device has not yet reported back.</CardDescription>
          </CardHeader>
          <CardContent>
            {Object.keys(data.delta).length === 0 ? (
              <p className="text-sm text-success">In sync — no pending changes.</p>
            ) : (
              <JsonView value={data.delta} label="Delta" />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
