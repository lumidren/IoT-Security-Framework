'use client';

import * as React from 'react';
import { Loader2Icon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { errorMessage } from '@/components/shared/states';

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: React.ReactNode;
  /** Label of the confirm button. */
  confirmLabel: string;
  destructive?: boolean;
  /** When set, a required free-text field is shown and its value passed to `onConfirm`. */
  reasonLabel?: string;
  reasonPlaceholder?: string;
  reasonRequired?: boolean;
  /** Optional checkbox (for example "mark as false positive"). */
  checkboxLabel?: string;
  /** Extra content rendered above the footer. */
  children?: React.ReactNode;
  isPending?: boolean;
  error?: unknown;
  onConfirm: (values: { reason: string; checked: boolean }) => void;
}

/** Accessible confirmation dialog with an optional reason field (errors are tied to the input). */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive = false,
  reasonLabel,
  reasonPlaceholder,
  reasonRequired = true,
  checkboxLabel,
  children,
  isPending = false,
  error,
  onConfirm,
}: ConfirmDialogProps) {
  const id = React.useId();
  const [reason, setReason] = React.useState('');
  const [checked, setChecked] = React.useState(false);
  const [touched, setTouched] = React.useState(false);

  React.useEffect(() => {
    if (!open) {
      setReason('');
      setChecked(false);
      setTouched(false);
    }
  }, [open]);

  const reasonInvalid = Boolean(reasonLabel) && reasonRequired && reason.trim().length < 3;

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (reasonInvalid) return;
    onConfirm({ reason: reason.trim(), checked });
  };

  return (
    <Dialog open={open} onOpenChange={(next) => !isPending && onOpenChange(next)}>
      <DialogContent>
        <form onSubmit={submit} noValidate>
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            {description && <DialogDescription>{description}</DialogDescription>}
          </DialogHeader>
          <div className="my-4 flex flex-col gap-4">
            {children}
            {reasonLabel && (
              <div className="flex flex-col gap-2">
                <Label htmlFor={`${id}-reason`}>
                  {reasonLabel}
                  {reasonRequired && (
                    <span className="text-destructive" aria-hidden="true">
                      *
                    </span>
                  )}
                </Label>
                <Textarea
                  id={`${id}-reason`}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  onBlur={() => setTouched(true)}
                  placeholder={reasonPlaceholder}
                  required={reasonRequired}
                  aria-required={reasonRequired}
                  aria-invalid={touched && reasonInvalid}
                  aria-describedby={touched && reasonInvalid ? `${id}-reason-error` : undefined}
                  rows={3}
                  autoFocus
                />
                {touched && reasonInvalid && (
                  <p id={`${id}-reason-error`} className="text-sm text-destructive" role="alert">
                    Please enter at least 3 characters.
                  </p>
                )}
              </div>
            )}
            {checkboxLabel && (
              <div className="flex items-center gap-2">
                <Checkbox
                  id={`${id}-check`}
                  checked={checked}
                  onCheckedChange={(value) => setChecked(value === true)}
                />
                <Label htmlFor={`${id}-check`} className="font-normal">
                  {checkboxLabel}
                </Label>
              </div>
            )}
            {error !== undefined && error !== null && (
              <p className="text-sm text-destructive" role="alert">
                {errorMessage(error)}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant={destructive ? 'destructive' : 'default'}
              disabled={isPending}
            >
              {isPending && <Loader2Icon className="animate-spin" aria-hidden="true" />}
              {confirmLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
