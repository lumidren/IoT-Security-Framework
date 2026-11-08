'use client';

import * as React from 'react';
import { Loader2Icon, LockIcon } from 'lucide-react';
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
import { useDeviceConfig, usePutDeviceConfig } from '@/lib/api/hooks';
import { isPlainObject, safeJsonParse } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

export function ConfigTab({ deviceId }: { deviceId: string }) {
  const canRead = usePermission('device.config.read');
  const canWrite = usePermission('device.config.write');
  const config = useDeviceConfig(deviceId, canRead);
  const put = usePutDeviceConfig(deviceId);
  const [draft, setDraft] = React.useState<string | null>(null);
  const [parseError, setParseError] = React.useState<string | null>(null);

  if (!canRead) {
    return (
      <Alert variant="warning">
        <LockIcon aria-hidden="true" />
        <AlertTitle>Administrators only</AlertTitle>
        <AlertDescription>
          Device configuration is stored encrypted with the tenant data key and its plaintext is
          shown to admins and owners only.
        </AlertDescription>
      </Alert>
    );
  }

  const notFound = isApiError(config.error) && config.error.status === 404;

  const submit = () => {
    if (draft === null) return;
    const parsed = safeJsonParse(draft);
    if (!parsed.ok || !isPlainObject(parsed.value)) {
      setParseError(parsed.ok ? 'Configuration must be a JSON object.' : parsed.error);
      return;
    }
    setParseError(null);
    put.mutate(parsed.value, {
      onSuccess: (result) => {
        toast.success(`Configuration version ${result.version} published`);
        setDraft(null);
      },
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Encrypted configuration</CardTitle>
        <CardDescription>
          The registry wraps a fresh AES key per message with HPKE to the device&apos;s current
          certificate key and publishes a COSE_Encrypt0 on the retained config topic. Plaintext
          never reaches the broker.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {config.isLoading && <Skeleton className="h-48 w-full" />}
        {config.isError && !notFound && (
          <ErrorState error={config.error} onRetry={() => void config.refetch()} />
        )}
        {notFound && draft === null && (
          <p className="text-sm text-muted-foreground">
            No configuration has been published for this device yet.
          </p>
        )}
        {config.data && draft === null && (
          <>
            <p className="text-sm text-muted-foreground">
              Version <span className="tabular font-medium">{config.data.version}</span> · delivered{' '}
              <DateTime value={config.data.delivered_at} /> · acknowledged{' '}
              <DateTime value={config.data.acked_at} />
            </p>
            <JsonView value={config.data.config} label="Current configuration" />
          </>
        )}
        {draft !== null && (
          <>
            <CodeEditor
              value={draft}
              onChange={setDraft}
              language="json"
              ariaLabel="Configuration JSON editor"
              height="320px"
            />
            {parseError && (
              <p className="text-sm text-destructive" role="alert">
                {parseError}
              </p>
            )}
            {put.error && (
              <p className="text-sm text-destructive" role="alert">
                {errorMessage(put.error)}
              </p>
            )}
          </>
        )}
        {canWrite && (
          <div className="flex gap-2">
            {draft === null ? (
              <Button
                variant="outline"
                onClick={() => setDraft(JSON.stringify(config.data?.config ?? {}, null, 2))}
                disabled={config.isLoading}
              >
                Edit configuration
              </Button>
            ) : (
              <>
                <Button onClick={submit} disabled={put.isPending}>
                  {put.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
                  Encrypt and publish
                </Button>
                <Button variant="outline" onClick={() => setDraft(null)} disabled={put.isPending}>
                  Cancel
                </Button>
              </>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
