'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import {
  ArrowLeftIcon,
  ArrowRightIcon,
  CheckIcon,
  Loader2Icon,
  ShieldAlertIcon,
} from 'lucide-react';
import { toast } from 'sonner';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { FormField } from '@/components/shared/form-field';
import { KeyValueList } from '@/components/shared/key-value';
import { RequireRole, ErrorState, errorMessage } from '@/components/shared/states';
import { FirmwareSeverityBadge } from '@/components/shared/status-badges';
import { DateTime } from '@/components/shared/time';
import { StageEditor } from '@/components/campaigns/builder/stage-editor';
import { TargetPicker } from '@/components/campaigns/builder/target-picker';
import { UploadFirmwareDialog } from '@/components/campaigns/builder/upload-firmware-dialog';
import { formatProblemError, isApiError } from '@/lib/api/client';
import { useCreateCampaign, useFirmware } from '@/lib/api/hooks';
import type { CampaignTarget, Firmware, FirmwareSeverity, StageInput } from '@/lib/api/schemas';
import { DEFAULT_STAGES, validateStages } from '@/lib/stages';
import { cn, formatBytes, shortHex } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

const STEPS = ['Firmware', 'Target', 'Stages', 'Review'] as const;
const ALL = '__all__';

export function CampaignBuilder() {
  const router = useRouter();
  const canCreate = usePermission('campaign.create');
  const canUpload = usePermission('firmware.upload');
  const [step, setStep] = React.useState(0);
  const [productFilter, setProductFilter] = React.useState('');
  const [firmware, setFirmware] = React.useState<Firmware | null>(null);
  const [target, setTarget] = React.useState<CampaignTarget>({
    groups: [],
    device_ids: [],
    tags: {},
  });
  const [stages, setStages] = React.useState<StageInput[]>(DEFAULT_STAGES.map((s) => ({ ...s })));
  const [name, setName] = React.useState('');
  const [severity, setSeverity] = React.useState<FirmwareSeverity | ''>('');
  const [delta, setDelta] = React.useState(false);
  const [nameError, setNameError] = React.useState<string | null>(null);

  const firmwareList = useFirmware(productFilter || undefined);
  const firmwareItems = React.useMemo(
    () => firmwareList.data?.pages.flatMap((p) => p.items) ?? [],
    [firmwareList.data],
  );
  const products = React.useMemo(
    () => [...new Set(firmwareItems.map((f) => f.product))].sort(),
    [firmwareItems],
  );
  const create = useCreateCampaign();

  const stageIssues = validateStages(stages);
  const targetEmpty =
    target.groups.length === 0 &&
    target.device_ids.length === 0 &&
    Object.keys(target.tags).length === 0;
  const effectiveSeverity: FirmwareSeverity = severity || firmware?.severity || 'normal';

  const canAdvance =
    [firmware !== null, !targetEmpty, stageIssues.length === 0, true][step] ?? false;

  React.useEffect(() => {
    if (firmware && !name) setName(`${firmware.product} ${firmware.version} rollout`);
  }, [firmware, name]);

  const submit = () => {
    if (!firmware) return;
    if (name.trim().length === 0) {
      setNameError('Give the campaign a name.');
      return;
    }
    setNameError(null);
    create.mutate(
      {
        name: name.trim(),
        firmware_id: firmware.id,
        target,
        delta,
        severity: effectiveSeverity,
        stages,
      },
      {
        onSuccess: (campaign) => {
          toast.success(`Campaign "${campaign.name}" created as a draft`);
          router.push(`/campaigns/${campaign.id}`);
        },
      },
    );
  };

  const serverErrors = isApiError(create.error) ? create.error.errors.map(formatProblemError) : [];

  return (
    <RequireRole allowed={canCreate} requiredLabel="operator">
      <div className="flex flex-col gap-6">
        <ol className="flex flex-wrap gap-2" aria-label="Campaign builder steps">
          {STEPS.map((label, index) => (
            <li key={label} className="flex items-center gap-2">
              <button
                type="button"
                className={cn(
                  'flex h-9 items-center gap-2 rounded-md border px-3 text-sm font-medium',
                  index === step && 'border-primary bg-primary text-primary-foreground',
                  index < step && 'bg-accent',
                  index > step && 'text-muted-foreground',
                )}
                aria-current={index === step ? 'step' : undefined}
                onClick={() => index < step && setStep(index)}
                disabled={index > step}
              >
                <span className="flex size-5 items-center justify-center rounded-full bg-background/20 text-xs">
                  {index < step ? <CheckIcon className="size-3" aria-hidden="true" /> : index + 1}
                </span>
                {label}
              </button>
              {index < STEPS.length - 1 && (
                <ArrowRightIcon className="size-4 text-muted-foreground" aria-hidden="true" />
              )}
            </li>
          ))}
        </ol>

        {step === 0 && (
          <Card>
            <CardHeader>
              <CardTitle>1. Pick the firmware image</CardTitle>
              <CardDescription>
                Only images signed by the tenant signing keys are listed. Devices refuse images
                whose version code does not exceed their current one.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="flex flex-wrap items-end justify-between gap-3">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="fw-filter-product">Product</Label>
                  <Select
                    value={productFilter || ALL}
                    onValueChange={(v) => setProductFilter(v === ALL ? '' : v)}
                  >
                    <SelectTrigger id="fw-filter-product" className="w-56">
                      <SelectValue placeholder="All products" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL}>All products</SelectItem>
                      {products.map((p) => (
                        <SelectItem key={p} value={p}>
                          {p}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {canUpload && (
                  <UploadFirmwareDialog products={products} onUploaded={(fw) => setFirmware(fw)} />
                )}
              </div>
              {firmwareList.isError && (
                <ErrorState
                  error={firmwareList.error}
                  onRetry={() => void firmwareList.refetch()}
                />
              )}
              {firmwareList.isLoading && <Skeleton className="h-40 w-full" />}
              {firmwareItems.length > 0 && (
                <RadioGroup
                  value={firmware?.id ?? ''}
                  onValueChange={(id) =>
                    setFirmware(firmwareItems.find((f) => f.id === id) ?? null)
                  }
                  aria-label="Firmware images"
                >
                  {firmwareItems.map((fw) => (
                    <div
                      key={fw.id}
                      className={cn(
                        'flex items-start gap-3 rounded-lg border p-3',
                        firmware?.id === fw.id && 'border-primary bg-accent/40',
                      )}
                    >
                      <RadioGroupItem value={fw.id} id={`fw-${fw.id}`} className="mt-1" />
                      <Label
                        htmlFor={`fw-${fw.id}`}
                        className="flex-1 flex-col items-start gap-1 font-normal"
                      >
                        <span className="flex flex-wrap items-center gap-2">
                          <span className="font-medium">
                            {fw.product}/{fw.version}
                          </span>
                          <span className="tabular text-xs text-muted-foreground">
                            code {fw.version_code}
                          </span>
                          <FirmwareSeverityBadge severity={fw.severity} />
                          {fw.pq_signed && (
                            <span className="text-xs text-muted-foreground">
                              Ed25519 + ML-DSA-65
                            </span>
                          )}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {formatBytes(fw.size)} · sha256 {shortHex(fw.sha256_hex, 8)} ·{' '}
                          <DateTime value={fw.created_at} />
                        </span>
                        {fw.notes && <span className="text-sm">{fw.notes}</span>}
                      </Label>
                    </div>
                  ))}
                </RadioGroup>
              )}
              {firmwareList.hasNextPage && (
                <Button
                  variant="outline"
                  size="sm"
                  className="self-center"
                  onClick={() => void firmwareList.fetchNextPage()}
                >
                  Load more images
                </Button>
              )}
            </CardContent>
          </Card>
        )}

        {step === 1 && (
          <Card>
            <CardHeader>
              <CardTitle>2. Choose the target</CardTitle>
              <CardDescription>
                Groups, tags and explicit device ids. The preview counts active devices that match
                right now.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <TargetPicker
                target={target}
                onChange={setTarget}
                product={firmware?.product ?? null}
              />
            </CardContent>
          </Card>
        )}

        {step === 2 && (
          <Card>
            <CardHeader>
              <CardTitle>3. Define the stages</CardTitle>
              <CardDescription>
                Canary first, then widen. Each stage dwells before the next one starts and halts the
                campaign if failures exceed the budget.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <StageEditor stages={stages} onChange={setStages} issues={stageIssues} />
            </CardContent>
          </Card>
        )}

        {step === 3 && firmware && (
          <Card>
            <CardHeader>
              <CardTitle>4. Review and create</CardTitle>
              <CardDescription>
                The campaign is created as a draft; start it from the campaign page.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              <div className="grid gap-4 sm:grid-cols-2">
                <FormField id="campaign-name" label="Campaign name" required error={nameError}>
                  {(props) => (
                    <Input {...props} value={name} onChange={(e) => setName(e.target.value)} />
                  )}
                </FormField>
                <FormField
                  id="campaign-severity"
                  label="Severity"
                  hint="Defaults to the firmware severity."
                >
                  {(props) => (
                    <Select
                      value={severity || firmware.severity}
                      onValueChange={(v) => setSeverity(v as FirmwareSeverity)}
                    >
                      <SelectTrigger
                        id={props.id}
                        className="w-full"
                        aria-describedby={props['aria-describedby']}
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="normal">Normal</SelectItem>
                        <SelectItem value="security">Security</SelectItem>
                      </SelectContent>
                    </Select>
                  )}
                </FormField>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="campaign-delta"
                  checked={delta}
                  onCheckedChange={(v) => setDelta(v === true)}
                />
                <Label htmlFor="campaign-delta" className="font-normal">
                  Use delta patches where a base image is known (4 KiB block-delta format)
                </Label>
              </div>
              {effectiveSeverity === 'security' && (
                <Alert variant="warning">
                  <ShieldAlertIcon aria-hidden="true" />
                  <AlertTitle>Security rollout: four-eyes rule</AlertTitle>
                  <AlertDescription>
                    Rolling back a security campaign requires a second administrator to confirm with
                    a reason; the action is audited.
                  </AlertDescription>
                </Alert>
              )}
              <KeyValueList
                columns={3}
                items={[
                  {
                    label: 'Firmware',
                    value: `${firmware.product}/${firmware.version} (code ${firmware.version_code})`,
                  },
                  { label: 'Image hash', value: shortHex(firmware.sha256_hex, 10), mono: true },
                  { label: 'Groups', value: target.groups.join(', ') || '—' },
                  {
                    label: 'Tags',
                    value:
                      Object.entries(target.tags)
                        .map(([k, v]) => `${k}:${v}`)
                        .join(', ') || '—',
                  },
                  {
                    label: 'Device ids',
                    value:
                      target.device_ids.length > 0 ? `${target.device_ids.length} explicit` : '—',
                  },
                  { label: 'Stages', value: stages.map((s) => `${s.percent}%`).join(' → ') },
                ]}
              />
              {create.error && (
                <div className="text-sm text-destructive" role="alert">
                  <p>{errorMessage(create.error)}</p>
                  {serverErrors.length > 0 && (
                    <ul className="list-disc pl-4">
                      {serverErrors.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        <div className="flex items-center justify-between">
          <Button
            type="button"
            variant="outline"
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0}
          >
            <ArrowLeftIcon aria-hidden="true" /> Back
          </Button>
          {step < STEPS.length - 1 ? (
            <Button type="button" onClick={() => setStep((s) => s + 1)} disabled={!canAdvance}>
              Next <ArrowRightIcon aria-hidden="true" />
            </Button>
          ) : (
            <Button type="button" onClick={submit} disabled={create.isPending}>
              {create.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
              Create campaign
            </Button>
          )}
        </div>
      </div>
    </RequireRole>
  );
}
