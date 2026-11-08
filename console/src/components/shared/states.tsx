'use client';

import * as React from 'react';
import { AlertTriangleIcon, InboxIcon, LockIcon, RefreshCwIcon } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { formatProblemError, isApiError } from '@/lib/api/client';
import { cn } from '@/lib/utils';

export function errorMessage(error: unknown): string {
  if (isApiError(error)) return error.detail ? `${error.title}: ${error.detail}` : error.title;
  if (error instanceof Error) return error.message;
  return 'Something went wrong.';
}

export function ErrorState({
  error,
  onRetry,
  title,
  className,
}: {
  error: unknown;
  onRetry?: () => void;
  title?: string;
  className?: string;
}) {
  const forbidden = isApiError(error) && error.isForbidden;
  const details = isApiError(error) ? error.errors.map(formatProblemError) : [];
  return (
    <Alert variant={forbidden ? 'warning' : 'destructive'} className={className}>
      {forbidden ? <LockIcon aria-hidden="true" /> : <AlertTriangleIcon aria-hidden="true" />}
      <AlertTitle>{title ?? (forbidden ? 'Not permitted' : 'Could not load data')}</AlertTitle>
      <AlertDescription>
        <p>{errorMessage(error)}</p>
        {details.length > 0 && (
          <ul className="list-disc pl-4">
            {details.slice(0, 5).map((detail, index) => (
              <li key={index}>{detail}</li>
            ))}
          </ul>
        )}
        {onRetry && !forbidden && (
          <Button variant="outline" size="sm" onClick={onRetry} className="mt-2">
            <RefreshCwIcon aria-hidden="true" /> Retry
          </Button>
        )}
      </AlertDescription>
    </Alert>
  );
}

export function EmptyState({
  title,
  description,
  action,
  icon: Icon = InboxIcon,
  className,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
  icon?: React.ComponentType<{ className?: string; 'aria-hidden'?: boolean | 'true' }>;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-6 py-12 text-center',
        className,
      )}
    >
      <Icon className="size-8 text-muted-foreground" aria-hidden="true" />
      <p className="font-medium">{title}</p>
      {description && <p className="max-w-md text-sm text-muted-foreground">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function RequireRole({
  allowed,
  requiredLabel,
  children,
  className,
}: {
  allowed: boolean;
  requiredLabel: string;
  children: React.ReactNode;
  className?: string;
}) {
  if (allowed) return <>{children}</>;
  return (
    <Alert variant="warning" className={className}>
      <LockIcon aria-hidden="true" />
      <AlertTitle>Requires the {requiredLabel} role</AlertTitle>
      <AlertDescription>
        Your current role cannot access this area. Ask a tenant owner to change your role if you
        need it.
      </AlertDescription>
    </Alert>
  );
}
