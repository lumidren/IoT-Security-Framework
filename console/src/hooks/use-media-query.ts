'use client';

import * as React from 'react';

export function useMediaQuery(query: string, defaultValue = false): boolean {
  const subscribe = React.useCallback(
    (callback: () => void) => {
      const media = window.matchMedia(query);
      media.addEventListener('change', callback);
      return () => media.removeEventListener('change', callback);
    },
    [query],
  );
  return React.useSyncExternalStore(
    subscribe,
    () => window.matchMedia(query).matches,
    () => defaultValue,
  );
}

export function useIsMobile(): boolean {
  return useMediaQuery('(max-width: 767px)');
}
