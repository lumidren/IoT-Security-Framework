'use client';

import * as React from 'react';
import { Loader2Icon, RefreshCwIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { FormField } from '@/components/shared/form-field';
import { errorMessage } from '@/components/shared/states';
import { formatProblemError, isApiError, newIdempotencyKey } from '@/lib/api/client';
import { SendCommandInputSchema, type SendCommandInput } from '@/lib/api/schemas';
import { isPlainObject, safeJsonParse } from '@/lib/utils';

export function CommandForm({
  onSubmit,
  isPending,
  error,
  submitLabel = 'Send command',
  idPrefix = 'cmd',
}: {
  onSubmit: (input: SendCommandInput) => void;
  isPending: boolean;
  error?: unknown;
  submitLabel?: string;
  idPrefix?: string;
}) {
  const [name, setName] = React.useState('');
  const [args, setArgs] = React.useState('{}');
  const [ttl, setTtl] = React.useState('300');
  const [key, setKey] = React.useState(() => newIdempotencyKey());
  const [errors, setErrors] = React.useState<Record<string, string>>({});

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const nextErrors: Record<string, string> = {};
    const parsedArgs = safeJsonParse(args.trim() || '{}');
    if (!parsedArgs.ok) nextErrors['args'] = `Arguments must be valid JSON: ${parsedArgs.error}`;
    else if (!isPlainObject(parsedArgs.value))
      nextErrors['args'] = 'Arguments must be a JSON object.';
    const candidate = {
      name: name.trim(),
      args: parsedArgs.ok && isPlainObject(parsedArgs.value) ? parsedArgs.value : {},
      ttl_s: Number(ttl),
      idempotency_key: key,
    };
    const result = SendCommandInputSchema.safeParse(candidate);
    if (!result.success) {
      for (const issue of result.error.issues) {
        const field = String(issue.path[0] ?? 'form');
        nextErrors[field] ??= issue.message;
      }
    }
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0 || !result.success) return;
    onSubmit(result.data);
  };

  const serverErrors = isApiError(error) ? error.errors.map(formatProblemError) : [];

  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-4">
      <FormField
        id={`${idPrefix}-name`}
        label="Command name"
        required
        error={errors['name']}
        hint="Lower-case identifier the firmware understands, e.g. reboot, rotate_logs, set_log_level."
      >
        {(props) => (
          <Input
            {...props}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="reboot"
            autoComplete="off"
          />
        )}
      </FormField>
      <FormField id={`${idPrefix}-args`} label="Arguments (JSON object)" error={errors['args']}>
        {(props) => (
          <Textarea
            {...props}
            value={args}
            onChange={(e) => setArgs(e.target.value)}
            rows={4}
            className="font-mono text-xs"
            spellCheck={false}
          />
        )}
      </FormField>
      <div className="grid gap-4 sm:grid-cols-2">
        <FormField
          id={`${idPrefix}-ttl`}
          label="Time to live (seconds)"
          required
          error={errors['ttl_s']}
          hint="30 to 86 400. The device rejects the command after it expires."
        >
          {(props) => (
            <Input
              {...props}
              type="number"
              min={30}
              max={86400}
              step={1}
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
            />
          )}
        </FormField>
        <FormField
          id={`${idPrefix}-key`}
          label="Idempotency key"
          hint="Generated automatically; retries with the same key are not re-executed."
        >
          {(props) => (
            <div className="flex gap-2">
              <Input {...props} value={key} readOnly className="font-mono text-xs" />
              <Button
                type="button"
                variant="outline"
                size="icon"
                aria-label="Generate a new idempotency key"
                onClick={() => setKey(newIdempotencyKey())}
              >
                <RefreshCwIcon aria-hidden="true" />
              </Button>
            </div>
          )}
        </FormField>
      </div>
      {error !== undefined && error !== null && (
        <div className="text-sm text-destructive" role="alert">
          <p>{errorMessage(error)}</p>
          {serverErrors.length > 0 && (
            <ul className="list-disc pl-4">
              {serverErrors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      <div className="flex justify-end">
        <Button type="submit" disabled={isPending}>
          {isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
