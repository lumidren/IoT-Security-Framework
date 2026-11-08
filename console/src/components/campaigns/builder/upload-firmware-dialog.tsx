'use client';

import * as React from 'react';
import { Loader2Icon, UploadIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { FormField } from '@/components/shared/form-field';
import { errorMessage } from '@/components/shared/states';
import { formatProblemError, isApiError } from '@/lib/api/client';
import { useUploadFirmware } from '@/lib/api/hooks';
import { FirmwareMetadataSchema, type Firmware } from '@/lib/api/schemas';
import { formatBytes } from '@/lib/utils';

export function UploadFirmwareDialog({
  products,
  onUploaded,
}: {
  products: string[];
  onUploaded: (firmware: Firmware) => void;
}) {
  const [open, setOpen] = React.useState(false);
  const [file, setFile] = React.useState<File | null>(null);
  const [product, setProduct] = React.useState('');
  const [version, setVersion] = React.useState('');
  const [versionCode, setVersionCode] = React.useState('');
  const [severity, setSeverity] = React.useState<'normal' | 'security'>('normal');
  const [notes, setNotes] = React.useState('');
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const upload = useUploadFirmware();

  const reset = () => {
    setFile(null);
    setProduct('');
    setVersion('');
    setVersionCode('');
    setSeverity('normal');
    setNotes('');
    setErrors({});
    upload.reset();
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const nextErrors: Record<string, string> = {};
    if (!file) nextErrors['image'] = 'Choose the firmware image to upload.';
    const parsed = FirmwareMetadataSchema.safeParse({
      product: product.trim(),
      version: version.trim(),
      version_code: Number(versionCode),
      notes: notes.trim() || undefined,
      severity,
    });
    if (!parsed.success) {
      for (const issue of parsed.error.issues)
        nextErrors[String(issue.path[0] ?? 'form')] ??= issue.message;
    }
    setErrors(nextErrors);
    if (!file || !parsed.success || Object.keys(nextErrors).length > 0) return;
    upload.mutate(
      { image: file, metadata: parsed.data },
      {
        onSuccess: (firmware) => {
          toast.success(
            `Uploaded ${firmware.product}/${firmware.version} (signed with ${firmware.signing_key_id ?? 'KMS key'})`,
          );
          onUploaded(firmware);
          setOpen(false);
          reset();
        },
      },
    );
  };

  const serverErrors = isApiError(upload.error) ? upload.error.errors.map(formatProblemError) : [];

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (upload.isPending) return;
        setOpen(next);
        if (!next) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline">
          <UploadIcon aria-hidden="true" /> Upload firmware
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-xl">
        <form onSubmit={submit} noValidate className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>Upload a firmware image</DialogTitle>
            <DialogDescription>
              The OTA service hashes the image, signs the manifest with the KMS Ed25519 key (and
              ML-DSA-65 when enabled) and stores it in object storage.
            </DialogDescription>
          </DialogHeader>
          <FormField
            id="fw-image"
            label="Image file"
            required
            error={errors['image']}
            hint={
              file
                ? `${file.name} · ${formatBytes(file.size)}`
                : 'Binary image (.bin) built for the selected product.'
            }
          >
            {(props) => (
              <Input
                {...props}
                type="file"
                accept=".bin,.img,application/octet-stream"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            )}
          </FormField>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField id="fw-product" label="Product" required error={errors['product']}>
              {(props) => (
                <Input
                  {...props}
                  list="fw-products"
                  value={product}
                  onChange={(e) => setProduct(e.target.value)}
                  placeholder="gateway-rpi"
                />
              )}
            </FormField>
            <datalist id="fw-products">
              {products.map((p) => (
                <option key={p} value={p} />
              ))}
            </datalist>
            <FormField id="fw-version" label="Version (semver)" required error={errors['version']}>
              {(props) => (
                <Input
                  {...props}
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                  placeholder="2.4.2"
                />
              )}
            </FormField>
            <FormField
              id="fw-version-code"
              label="Version code"
              required
              error={errors['version_code']}
              hint="Monotonic anti-rollback counter; must exceed every earlier image of the product."
            >
              {(props) => (
                <Input
                  {...props}
                  type="number"
                  min={1}
                  step={1}
                  value={versionCode}
                  onChange={(e) => setVersionCode(e.target.value)}
                  placeholder="2402"
                />
              )}
            </FormField>
            <FormField
              id="fw-severity"
              label="Severity"
              hint="Security images require a second approver before rollback."
            >
              {(props) => (
                <Select
                  value={severity}
                  onValueChange={(v) => setSeverity(v as 'normal' | 'security')}
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
          <FormField id="fw-notes" label="Release notes" error={errors['notes']}>
            {(props) => (
              <Textarea
                {...props}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
              />
            )}
          </FormField>
          {upload.error && (
            <div className="text-sm text-destructive" role="alert">
              <p>{errorMessage(upload.error)}</p>
              {serverErrors.length > 0 && (
                <ul className="list-disc pl-4">
                  {serverErrors.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setOpen(false)}
              disabled={upload.isPending}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={upload.isPending}>
              {upload.isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}{' '}
              Upload and sign
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
