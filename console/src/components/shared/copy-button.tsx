'use client';

import * as React from 'react';
import { CheckIcon, CopyIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { copyToClipboard } from '@/lib/utils';

export function CopyButton({
  value,
  label,
  size = 'icon-sm',
  variant = 'ghost',
  children,
}: {
  value: string;
  label: string;
  size?: 'icon' | 'icon-sm' | 'sm' | 'default';
  variant?: 'ghost' | 'outline' | 'secondary' | 'default';
  children?: React.ReactNode;
}) {
  const [copied, setCopied] = React.useState(false);
  React.useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);

  return (
    <Button
      variant={variant}
      size={size}
      aria-label={copied ? `${label} copied` : label}
      onClick={async () => {
        const ok = await copyToClipboard(value);
        if (ok) {
          setCopied(true);
          toast.success('Copied to clipboard');
        } else {
          toast.error('Clipboard unavailable');
        }
      }}
    >
      {copied ? <CheckIcon aria-hidden="true" /> : <CopyIcon aria-hidden="true" />}
      {children}
    </Button>
  );
}
