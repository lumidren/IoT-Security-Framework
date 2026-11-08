'use client';

import * as React from 'react';
import { KeyRoundIcon, Loader2Icon, PlusIcon, Trash2Icon } from 'lucide-react';
import { toast } from 'sonner';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ConfirmDialog } from '@/components/shared/confirm-dialog';
import { CopyButton } from '@/components/shared/copy-button';
import { FormField } from '@/components/shared/form-field';
import { ErrorState, RequireRole, errorMessage } from '@/components/shared/states';
import { DateTime, TimeAgo } from '@/components/shared/time';
import {
  useApiKeys,
  useCreateApiKey,
  useGroups,
  useRevokeApiKey,
  useSetUserRole,
  useTenant,
  useUpdateTenantSettings,
  useUsers,
} from '@/lib/api/hooks';
import {
  CreateApiKeyInputSchema,
  RoleSchema,
  type ApiKey,
  type Role,
  type TenantSettings,
} from '@/lib/api/schemas';
import { ROLE_LABEL } from '@/lib/rbac';
import { useCurrentUser, usePermission } from '@/providers/session-context';

const ROLE_HELP: Record<Role, string> = {
  owner: 'Everything, including saving the MQTT policy and changing roles.',
  admin:
    'Release and decommission devices, upload firmware, roll back campaigns, manage keys and settings.',
  operator: 'Quarantine devices, send commands, edit twins, run campaigns, handle alerts.',
  viewer: 'Read-only access to every page.',
  factory: 'Manufacture devices through the API only.',
};

function UsersSection() {
  const me = useCurrentUser();
  const canRead = usePermission('users.read');
  const canChangeRole = usePermission('users.role');
  const users = useUsers(canRead);
  const setRole = useSetUserRole();

  return (
    <Card>
      <CardHeader>
        <CardTitle>Users and roles</CardTitle>
        <CardDescription>
          Roles come from the identity provider claim at sign-in; owners can override them per
          tenant here.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <RequireRole allowed={canRead} requiredLabel="admin">
          {users.isError && <ErrorState error={users.error} onRetry={() => void users.refetch()} />}
          {users.isLoading && <Skeleton className="h-40 w-full" />}
          {users.data && (
            <div className="rounded-lg border">
              <Table>
                <caption className="sr-only">Tenant users and their roles</caption>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Last sign-in</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.data.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell className="whitespace-normal">
                        <span className="flex flex-col">
                          <span className="font-medium">{user.name ?? user.email}</span>
                          <span className="text-xs text-muted-foreground">{user.email}</span>
                        </span>
                      </TableCell>
                      <TableCell>
                        {canChangeRole && user.email !== me.email ? (
                          <Select
                            value={user.role}
                            onValueChange={(role) =>
                              setRole.mutate(
                                { id: user.id, role: role as Role },
                                {
                                  onSuccess: () =>
                                    toast.success(
                                      `${user.name ?? user.email} is now ${ROLE_LABEL[role as Role]}`,
                                    ),
                                  onError: (error) => toast.error(errorMessage(error)),
                                },
                              )
                            }
                          >
                            <SelectTrigger
                              className="w-36"
                              aria-label={`Role for ${user.name ?? user.email}`}
                            >
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {RoleSchema.options.map((role) => (
                                <SelectItem key={role} value={role}>
                                  {ROLE_LABEL[role]}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        ) : (
                          <Badge variant="outline">{ROLE_LABEL[user.role]}</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <TimeAgo value={user.last_login_at} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          <dl className="mt-4 grid gap-2 text-xs sm:grid-cols-2">
            {RoleSchema.options.map((role) => (
              <div key={role} className="flex gap-2">
                <dt className="w-16 shrink-0 font-medium">{ROLE_LABEL[role]}</dt>
                <dd className="text-muted-foreground">{ROLE_HELP[role]}</dd>
              </div>
            ))}
          </dl>
        </RequireRole>
      </CardContent>
    </Card>
  );
}

function CreateApiKeyDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const create = useCreateApiKey();
  const [name, setName] = React.useState('');
  const [role, setRole] = React.useState<Role>('viewer');
  const [scopes, setScopes] = React.useState('');
  const [expires, setExpires] = React.useState('');
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const [secret, setSecret] = React.useState<{ key: ApiKey; secret: string } | null>(null);

  const reset = () => {
    setName('');
    setRole('viewer');
    setScopes('');
    setExpires('');
    setErrors({});
    setSecret(null);
    create.reset();
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const parsed = CreateApiKeyInputSchema.safeParse({
      name: name.trim(),
      role,
      scopes: scopes
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      expires_at: expires ? new Date(expires).toISOString() : undefined,
    });
    if (!parsed.success) {
      const next: Record<string, string> = {};
      for (const issue of parsed.error.issues)
        next[String(issue.path[0] ?? 'form')] ??= issue.message;
      setErrors(next);
      return;
    }
    setErrors({});
    create.mutate(parsed.data, {
      onSuccess: (result) => setSecret({ key: result.api_key, secret: result.secret }),
    });
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (create.isPending) return;
        onOpenChange(next);
        if (!next) reset();
      }}
    >
      <DialogContent>
        {secret ? (
          <>
            <DialogHeader>
              <DialogTitle>API key created</DialogTitle>
              <DialogDescription>
                Copy the secret now. It is shown once and stored only as a SHA-256 hash.
              </DialogDescription>
            </DialogHeader>
            <Alert variant="warning">
              <KeyRoundIcon aria-hidden="true" />
              <AlertTitle>{secret.key.name}</AlertTitle>
              <AlertDescription>
                <code
                  className="block w-full overflow-x-auto rounded border bg-background px-2 py-1 font-mono text-xs break-all"
                  data-testid="api-key-secret"
                >
                  {secret.secret}
                </code>
                <CopyButton
                  value={secret.secret}
                  label="Copy API key secret"
                  size="sm"
                  variant="outline"
                >
                  Copy secret
                </CopyButton>
              </AlertDescription>
            </Alert>
            <DialogFooter>
              <Button
                onClick={() => {
                  onOpenChange(false);
                  reset();
                }}
              >
                Done
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={submit} noValidate className="flex flex-col gap-4">
            <DialogHeader>
              <DialogTitle>Create an API key</DialogTitle>
              <DialogDescription>
                Keys use the imk_ prefix, carry a role and optional scopes, and are accepted in the
                Authorization header.
              </DialogDescription>
            </DialogHeader>
            <FormField id="key-name" label="Name" required error={errors['name']}>
              {(props) => (
                <Input
                  {...props}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="CI release pipeline"
                />
              )}
            </FormField>
            <FormField id="key-role" label="Role" required hint={ROLE_HELP[role]}>
              {(props) => (
                <Select value={role} onValueChange={(v) => setRole(v as Role)}>
                  <SelectTrigger
                    id={props.id}
                    className="w-full"
                    aria-describedby={props['aria-describedby']}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RoleSchema.options.map((r) => (
                      <SelectItem key={r} value={r}>
                        {ROLE_LABEL[r]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </FormField>
            <FormField
              id="key-scopes"
              label="Scopes"
              hint="Comma-separated, e.g. firmware:upload, campaigns:create. Empty means the full role."
            >
              {(props) => (
                <Input
                  {...props}
                  value={scopes}
                  onChange={(e) => setScopes(e.target.value)}
                  className="font-mono text-xs"
                />
              )}
            </FormField>
            <FormField
              id="key-expires"
              label="Expires"
              hint="Optional. Expired keys are rejected with 401."
            >
              {(props) => (
                <Input
                  {...props}
                  type="date"
                  value={expires}
                  onChange={(e) => setExpires(e.target.value)}
                />
              )}
            </FormField>
            {create.error && (
              <p className="text-sm text-destructive" role="alert">
                {errorMessage(create.error)}
              </p>
            )}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={create.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={create.isPending}>
                {create.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
                Create key
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function ApiKeysSection() {
  const canManage = usePermission('apikeys.manage');
  const keys = useApiKeys(canManage);
  const revoke = useRevokeApiKey();
  const [createOpen, setCreateOpen] = React.useState(false);
  const [revoking, setRevoking] = React.useState<ApiKey | null>(null);

  return (
    <Card>
      <CardHeader>
        <CardTitle>API keys</CardTitle>
        <CardDescription>
          Machine credentials for factories, CI pipelines and SIEM integrations. Secrets are shown
          once at creation.
        </CardDescription>
        {canManage && (
          <CardAction>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <PlusIcon aria-hidden="true" /> Create key
            </Button>
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        <RequireRole allowed={canManage} requiredLabel="admin">
          {keys.isError && <ErrorState error={keys.error} onRetry={() => void keys.refetch()} />}
          {keys.isLoading && <Skeleton className="h-40 w-full" />}
          {keys.data && (
            <div className="rounded-lg border">
              <Table>
                <caption className="sr-only">API keys</caption>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Prefix</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Scopes</TableHead>
                    <TableHead>Last used</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keys.data.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center text-muted-foreground">
                        No API keys yet.
                      </TableCell>
                    </TableRow>
                  )}
                  {keys.data.map((key) => (
                    <TableRow key={key.id}>
                      <TableCell className="font-medium whitespace-normal">{key.name}</TableCell>
                      <TableCell className="font-mono text-xs">{key.prefix}…</TableCell>
                      <TableCell>
                        <Badge variant="outline">{ROLE_LABEL[key.role]}</Badge>
                      </TableCell>
                      <TableCell
                        className="max-w-48 truncate font-mono text-xs text-muted-foreground"
                        title={key.scopes.join(', ')}
                      >
                        {key.scopes.join(', ') || 'full role'}
                      </TableCell>
                      <TableCell>
                        <TimeAgo value={key.last_used_at} />
                      </TableCell>
                      <TableCell>
                        <DateTime value={key.expires_at} />
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setRevoking(key)}
                          aria-label={`Revoke API key ${key.name}`}
                        >
                          <Trash2Icon aria-hidden="true" /> Revoke
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </RequireRole>
      </CardContent>
      <CreateApiKeyDialog open={createOpen} onOpenChange={setCreateOpen} />
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={`Revoke "${revoking?.name ?? ''}"?`}
        description="Requests using this key fail immediately with 401. This cannot be undone."
        confirmLabel="Revoke key"
        destructive
        isPending={revoke.isPending}
        error={revoke.error}
        onConfirm={() => {
          if (!revoking) return;
          revoke.mutate(revoking.id, {
            onSuccess: () => {
              toast.success('API key revoked');
              setRevoking(null);
            },
          });
        }}
      />
    </Card>
  );
}

function TenantSettingsSection() {
  const canEdit = usePermission('tenant.settings');
  const tenant = useTenant();
  const groups = useGroups();
  const update = useUpdateTenantSettings();
  const [draft, setDraft] = React.useState<TenantSettings | null>(null);
  const settings = draft ?? tenant.data?.settings ?? null;
  const dirty = draft !== null && JSON.stringify(draft) !== JSON.stringify(tenant.data?.settings);
  const ttlInvalid = settings
    ? settings.operational_cert_ttl_hours < 7 * 24 || settings.operational_cert_ttl_hours > 30 * 24
    : false;

  const change = (patch: Partial<TenantSettings>) => {
    if (!settings) return;
    setDraft({ ...settings, ...patch });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Tenant security settings</CardTitle>
        <CardDescription>
          Defaults enforced by the PKI, registry and anomaly services for every device in{' '}
          {tenant.data?.name ?? 'this tenant'}.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {tenant.isError && (
          <ErrorState error={tenant.error} onRetry={() => void tenant.refetch()} />
        )}
        {tenant.isLoading && <Skeleton className="h-48 w-full" />}
        {settings && (
          <form
            className="flex flex-col gap-6"
            onSubmit={(e) => {
              e.preventDefault();
              if (!draft || ttlInvalid) return;
              update.mutate(draft, {
                onSuccess: () => {
                  toast.success('Tenant settings saved');
                  setDraft(null);
                },
                onError: (error) => toast.error(errorMessage(error)),
              });
            }}
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <Label htmlFor="allow-software-keys">Allow software-backed keys</Label>
                <p id="allow-software-keys-hint" className="mt-1 text-sm text-muted-foreground">
                  When off, enrollment requires a secure element (ATECC608, TPM 2.0 or OP-TEE) and
                  software-key devices are rejected at EST. Production profiles keep this off.
                </p>
              </div>
              <Switch
                id="allow-software-keys"
                checked={settings.allow_software_keys}
                onCheckedChange={(v) => change({ allow_software_keys: v })}
                disabled={!canEdit}
                aria-describedby="allow-software-keys-hint"
              />
            </div>
            <div className="flex items-start justify-between gap-4">
              <div>
                <Label htmlFor="auto-quarantine">Automatic quarantine</Label>
                <p id="auto-quarantine-hint" className="mt-1 text-sm text-muted-foreground">
                  Lets the anomaly engine quarantine a device when a critical or high alert fires:
                  certificates are revoked and the session is kicked within 10 seconds without
                  waiting for an operator.
                </p>
              </div>
              <Switch
                id="auto-quarantine"
                checked={settings.auto_quarantine}
                onCheckedChange={(v) => change({ auto_quarantine: v })}
                disabled={!canEdit}
                aria-describedby="auto-quarantine-hint"
              />
            </div>
            <div className="flex items-start justify-between gap-4">
              <div>
                <Label htmlFor="require-approval">Require manual approval</Label>
                <p id="require-approval-hint" className="mt-1 text-sm text-muted-foreground">
                  Newly enrolled devices wait in the provisioning queue until an operator approves
                  them instead of activating automatically.
                </p>
              </div>
              <Switch
                id="require-approval"
                checked={settings.require_manual_approval ?? false}
                onCheckedChange={(v) => change({ require_manual_approval: v })}
                disabled={!canEdit}
                aria-describedby="require-approval-hint"
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <FormField
                id="cert-ttl"
                label="Operational certificate lifetime (hours)"
                hint="Between 168 (7 days) and 720 (30 days). Devices renew at 50% of the lifetime."
                error={ttlInvalid ? 'Must be between 168 and 720 hours.' : null}
              >
                {(props) => (
                  <Input
                    {...props}
                    type="number"
                    min={168}
                    max={720}
                    step={1}
                    value={settings.operational_cert_ttl_hours}
                    onChange={(e) => change({ operational_cert_ttl_hours: Number(e.target.value) })}
                    disabled={!canEdit}
                  />
                )}
              </FormField>
              <FormField
                id="default-group"
                label="Default group for new devices"
                hint="Devices join this group when they activate."
              >
                {(props) => (
                  <Select
                    value={settings.default_group ?? '__none__'}
                    onValueChange={(v) => change({ default_group: v === '__none__' ? null : v })}
                    disabled={!canEdit}
                  >
                    <SelectTrigger
                      id={props.id}
                      className="w-full"
                      aria-describedby={props['aria-describedby']}
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__none__">None</SelectItem>
                      {(groups.data ?? []).map((g) => (
                        <SelectItem key={g.slug} value={g.slug}>
                          {g.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </FormField>
            </div>
            {canEdit ? (
              <div className="flex gap-2">
                <Button type="submit" disabled={!dirty || ttlInvalid || update.isPending}>
                  {update.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
                  Save settings
                </Button>
                {dirty && (
                  <Button type="button" variant="ghost" onClick={() => setDraft(null)}>
                    Discard
                  </Button>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                Only admins and owners can change tenant settings.
              </p>
            )}
          </form>
        )}
      </CardContent>
    </Card>
  );
}

export function AccessSettingsView() {
  return (
    <div className="flex flex-col gap-6">
      <UsersSection />
      <ApiKeysSection />
      <TenantSettingsSection />
    </div>
  );
}
