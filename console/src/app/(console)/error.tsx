'use client';

import { useEffect } from 'react';
import { ErrorState } from '@/components/shared/states';

export default function ConsoleError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);
  return <ErrorState error={error} onRetry={reset} title="This page failed to render" />;
}
