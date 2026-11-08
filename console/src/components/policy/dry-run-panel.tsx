'use client';

import * as React from 'react';
import { CheckCircle2Icon, FlaskConicalIcon, Loader2Icon, XCircleIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { FormField } from '@/components/shared/form-field';
import { errorMessage } from '@/components/shared/states';
import { useEvaluatePolicy } from '@/lib/api/hooks';
import { PolicyEvaluateInputSchema, type PolicyEvaluateInput } from '@/lib/api/schemas';
import { useCurrentUser } from '@/providers/session-context';

const EXAMPLE_DEVICE = 'dev-8f3a1c2b9d4e5f60';

export function PolicyDryRunPanel() {
  const user = useCurrentUser();
  const evaluate = useEvaluatePolicy();
  const [form, setForm] = React.useState({
    clientid: EXAMPLE_DEVICE,
    username: EXAMPLE_DEVICE,
    tenant_id: user.tenantId,
    device_id: EXAMPLE_DEVICE,
    kind: 'device' as 'device' | 'service',
    topic: `im/v1/${user.tenantId}/${EXAMPLE_DEVICE}/telemetry`,
    action: 'publish' as 'publish' | 'subscribe',
    qos: '1',
    retain: false,
  });
  const [errors, setErrors] = React.useState<Record<string, string>>({});

  const update = <K extends keyof typeof form>(key: K, value: (typeof form)[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const parsed = PolicyEvaluateInputSchema.safeParse({ ...form, qos: Number(form.qos) });
    if (!parsed.success) {
      const next: Record<string, string> = {};
      for (const issue of parsed.error.issues)
        next[String(issue.path[0] ?? 'form')] ??= issue.message;
      setErrors(next);
      return;
    }
    setErrors({});
    evaluate.mutate(parsed.data satisfies PolicyEvaluateInput);
  };

  const result = evaluate.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FlaskConicalIcon className="size-4" aria-hidden="true" /> Dry run
        </CardTitle>
        <CardDescription>
          Evaluate the saved policy against a synthetic request. Results are never cached and
          nothing is enforced.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} noValidate className="flex flex-col gap-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <FormField id="dry-clientid" label="Client id" required error={errors['clientid']}>
              {(props) => (
                <Input
                  {...props}
                  value={form.clientid}
                  onChange={(e) => update('clientid', e.target.value)}
                  className="font-mono text-xs"
                />
              )}
            </FormField>
            <FormField
              id="dry-username"
              label="Username (cert CN)"
              required
              error={errors['username']}
            >
              {(props) => (
                <Input
                  {...props}
                  value={form.username}
                  onChange={(e) => update('username', e.target.value)}
                  className="font-mono text-xs"
                />
              )}
            </FormField>
            <FormField id="dry-tenant" label="Tenant id" required error={errors['tenant_id']}>
              {(props) => (
                <Input
                  {...props}
                  value={form.tenant_id}
                  onChange={(e) => update('tenant_id', e.target.value)}
                  className="font-mono text-xs"
                />
              )}
            </FormField>
            <FormField id="dry-device" label="Device id" required error={errors['device_id']}>
              {(props) => (
                <Input
                  {...props}
                  value={form.device_id}
                  onChange={(e) => update('device_id', e.target.value)}
                  className="font-mono text-xs"
                />
              )}
            </FormField>
          </div>
          <FormField id="dry-topic" label="Topic" required error={errors['topic']}>
            {(props) => (
              <Input
                {...props}
                value={form.topic}
                onChange={(e) => update('topic', e.target.value)}
                className="font-mono text-xs"
              />
            )}
          </FormField>
          <div className="grid gap-3 sm:grid-cols-3">
            <FormField id="dry-kind" label="Kind">
              {(props) => (
                <Select
                  value={form.kind}
                  onValueChange={(v) => update('kind', v as 'device' | 'service')}
                >
                  <SelectTrigger id={props.id} className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="device">device</SelectItem>
                    <SelectItem value="service">service</SelectItem>
                  </SelectContent>
                </Select>
              )}
            </FormField>
            <FormField id="dry-action" label="Action">
              {(props) => (
                <Select
                  value={form.action}
                  onValueChange={(v) => update('action', v as 'publish' | 'subscribe')}
                >
                  <SelectTrigger id={props.id} className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="publish">publish</SelectItem>
                    <SelectItem value="subscribe">subscribe</SelectItem>
                  </SelectContent>
                </Select>
              )}
            </FormField>
            <FormField id="dry-qos" label="QoS">
              {(props) => (
                <Select value={form.qos} onValueChange={(v) => update('qos', v)}>
                  <SelectTrigger id={props.id} className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="0">0</SelectItem>
                    <SelectItem value="1">1</SelectItem>
                    <SelectItem value="2">2</SelectItem>
                  </SelectContent>
                </Select>
              )}
            </FormField>
          </div>
          <div className="flex items-center gap-2">
            <Switch
              id="dry-retain"
              checked={form.retain}
              onCheckedChange={(v) => update('retain', v)}
            />
            <Label htmlFor="dry-retain" className="font-normal">
              Retain flag
            </Label>
          </div>
          <Button type="submit" disabled={evaluate.isPending} className="self-start">
            {evaluate.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
            Evaluate
          </Button>
        </form>

        <div className="mt-4" aria-live="polite">
          {evaluate.error && (
            <p className="text-sm text-destructive" role="alert">
              {errorMessage(evaluate.error)}
            </p>
          )}
          {result && (
            <div className="flex flex-col gap-3" data-testid="dry-run-result">
              <p
                className={`flex items-center gap-2 rounded-md border px-3 py-2 text-lg font-semibold ${
                  result.result === 'allow'
                    ? 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-100'
                    : 'border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/60 dark:text-red-100'
                }`}
              >
                {result.result === 'allow' ? (
                  <CheckCircle2Icon className="size-5" aria-hidden="true" />
                ) : (
                  <XCircleIcon className="size-5" aria-hidden="true" />
                )}
                {result.result === 'allow' ? 'Allow' : 'Deny'}
                <span className="ml-auto text-xs font-normal text-muted-foreground">
                  policy v{result.evaluated_version}
                </span>
              </p>
              <div>
                <p className="text-sm font-medium">Matched rules</p>
                {result.matched_rules.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No allow rule matched; the default deny applies.
                  </p>
                ) : (
                  <ul className="list-disc pl-5 font-mono text-xs">
                    {result.matched_rules.map((rule) => (
                      <li key={rule}>{rule}</li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <p className="text-sm font-medium">Trace</p>
                <pre
                  className="max-h-56 overflow-auto rounded-md border bg-muted/50 p-2 font-mono text-xs"
                  tabIndex={0}
                >
                  {result.trace.join('\n')}
                </pre>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
