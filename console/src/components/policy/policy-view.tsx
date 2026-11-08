'use client';

import * as React from 'react';
import { HistoryIcon, Loader2Icon, RotateCcwIcon, SaveIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { CopyButton } from '@/components/shared/copy-button';
import { FormField } from '@/components/shared/form-field';
import { CodeEditor } from '@/components/shared/json-editor';
import { ErrorState, RequireRole, errorMessage } from '@/components/shared/states';
import { DateTime } from '@/components/shared/time';
import { PolicyDryRunPanel } from '@/components/policy/dry-run-panel';
import { formatProblemError, isApiError } from '@/lib/api/client';
import { usePolicy, usePolicyHistory, useSavePolicy } from '@/lib/api/hooks';
import { shortHex } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

function PolicyHistory() {
  const history = usePolicyHistory();
  const items = history.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <HistoryIcon className="size-4" aria-hidden="true" /> History
        </CardTitle>
        <CardDescription>
          Every saved version with its author, message and content hash.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {history.isError && (
          <ErrorState error={history.error} onRetry={() => void history.refetch()} />
        )}
        {history.isLoading && <Skeleton className="h-32 w-full" />}
        <ol className="divide-y" aria-label="Policy versions">
          {items.map((entry) => (
            <li
              key={entry.version}
              className="flex flex-wrap items-baseline justify-between gap-2 py-2 text-sm"
            >
              <span className="flex flex-col">
                <span>
                  <span className="tabular font-medium">v{entry.version}</span> ·{' '}
                  {entry.message ?? 'no message'}
                </span>
                <span className="text-xs text-muted-foreground">
                  {entry.updated_by ?? 'unknown'} · sha256 {shortHex(entry.sha256_hex, 6)}
                </span>
              </span>
              <DateTime value={entry.updated_at} className="text-xs text-muted-foreground" />
            </li>
          ))}
        </ol>
        {history.hasNextPage && (
          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            onClick={() => void history.fetchNextPage()}
          >
            Load more
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

export function PolicyView() {
  const canRead = usePermission('policy.read');
  const canWrite = usePermission('policy.write');
  const canEvaluate = usePermission('policy.evaluate');
  const policy = usePolicy(canRead);
  const save = useSavePolicy();
  const [draft, setDraft] = React.useState<string | null>(null);
  const [saveOpen, setSaveOpen] = React.useState(false);
  const [message, setMessage] = React.useState('');
  const [messageError, setMessageError] = React.useState<string | null>(null);

  const source = draft ?? policy.data?.rego ?? '';
  const modified = draft !== null && draft !== policy.data?.rego;
  const diagnostics = isApiError(save.error) && save.error.isValidation ? save.error.errors : [];

  const submit = () => {
    if (message.trim().length < 3) {
      setMessageError('Describe the change in a few words.');
      return;
    }
    setMessageError(null);
    save.mutate(
      { rego: source, message: message.trim() },
      {
        onSuccess: (result) => {
          toast.success(`Policy saved as version ${result.version}`);
          setSaveOpen(false);
          setDraft(null);
          setMessage('');
        },
      },
    );
  };

  return (
    <div className="grid gap-6 xl:grid-cols-3">
      <div className="flex flex-col gap-4 xl:col-span-2">
        <RequireRole allowed={canRead} requiredLabel="admin">
          {policy.isError && (
            <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />
          )}
          {policy.isLoading && <Skeleton className="h-[520px] w-full" />}
          {policy.data && (
            <Card>
              <CardHeader>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-col gap-1">
                    <CardTitle className="flex items-center gap-2">
                      Rego source <Badge variant="secondary">v{policy.data.version}</Badge>
                      {modified && <Badge variant="warning">Unsaved changes</Badge>}
                    </CardTitle>
                    <CardDescription className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span>
                        Updated <DateTime value={policy.data.updated_at} /> by{' '}
                        {policy.data.updated_by ?? 'unknown'}
                      </span>
                      <span className="inline-flex items-center gap-1 font-mono text-xs">
                        sha256 {shortHex(policy.data.sha256_hex, 8)}
                        <CopyButton value={policy.data.sha256_hex} label="Copy policy hash" />
                      </span>
                    </CardDescription>
                  </div>
                  <div className="flex gap-2">
                    {modified && (
                      <Button variant="ghost" size="sm" onClick={() => setDraft(null)}>
                        <RotateCcwIcon aria-hidden="true" /> Discard
                      </Button>
                    )}
                    {canWrite ? (
                      <Button size="sm" onClick={() => setSaveOpen(true)} disabled={!modified}>
                        <SaveIcon aria-hidden="true" /> Save new version
                      </Button>
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        Only tenant owners can save policy changes.
                      </p>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <CodeEditor
                  value={source}
                  onChange={canWrite ? setDraft : undefined}
                  readOnly={!canWrite}
                  language="rego"
                  ariaLabel="Rego policy source"
                  height="520px"
                />
              </CardContent>
            </Card>
          )}
        </RequireRole>
        {canRead && <PolicyHistory />}
      </div>
      <div className="flex flex-col gap-4">
        {canEvaluate ? (
          <PolicyDryRunPanel />
        ) : (
          <Alert variant="warning">
            <AlertTitle>Dry run requires the operator role</AlertTitle>
            <AlertDescription>
              Viewers can inspect the policy but cannot evaluate synthetic requests.
            </AlertDescription>
          </Alert>
        )}
      </div>

      <Dialog open={saveOpen} onOpenChange={(open) => !save.isPending && setSaveOpen(open)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Save policy version {policy.data ? policy.data.version + 1 : ''}
            </DialogTitle>
            <DialogDescription>
              The policy service compiles the source and runs the embedded Rego test suite,
              including the built-in invariant tests. It is activated for every broker decision
              immediately after it passes.
            </DialogDescription>
          </DialogHeader>
          <FormField id="policy-message" label="Change message" required error={messageError}>
            {(props) => (
              <Input
                {...props}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Allow retained ota/notify from svc-registry"
              />
            )}
          </FormField>
          {save.error && (
            <Alert variant="destructive">
              <AlertTitle>
                {isApiError(save.error) && save.error.isValidation
                  ? 'The policy was rejected'
                  : 'Save failed'}
              </AlertTitle>
              <AlertDescription>
                <p>{errorMessage(save.error)}</p>
                {diagnostics.length > 0 && (
                  <ul className="list-disc pl-4 font-mono text-xs" data-testid="policy-diagnostics">
                    {diagnostics.map((d, i) => (
                      <li key={i}>{formatProblemError(d)}</li>
                    ))}
                  </ul>
                )}
              </AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setSaveOpen(false)} disabled={save.isPending}>
              Cancel
            </Button>
            <Button onClick={submit} disabled={save.isPending}>
              {save.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
              Compile and save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
