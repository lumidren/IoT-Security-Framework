'use client';

import * as React from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

export type QueryStateUpdate = Record<string, string | null | undefined>;

/**
 * Reads and writes URL search parameters so list filters are shareable and survive reloads.
 * Writing uses `router.replace` without scrolling; empty values remove the key.
 */
export function useQueryState() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const get = React.useCallback((key: string) => searchParams.get(key) ?? '', [searchParams]);

  const set = React.useCallback(
    (update: QueryStateUpdate) => {
      const params = new URLSearchParams(searchParams.toString());
      for (const [key, value] of Object.entries(update)) {
        if (value === null || value === undefined || value === '') params.delete(key);
        else params.set(key, value);
      }
      const query = params.toString();
      router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
    },
    [pathname, router, searchParams],
  );

  return { get, set, searchParams };
}

/** Debounces a fast-changing value (search inputs). */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}
