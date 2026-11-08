'use client';

import * as React from 'react';

/**
 * Cursor pagination with a "previous" stack: the API only returns `next_cursor`, so we remember
 * the cursors we came from. Resetting (new filters) clears the stack.
 */
export function useCursorPagination() {
  const [cursor, setCursor] = React.useState<string | null>(null);
  const [stack, setStack] = React.useState<Array<string | null>>([]);

  const next = React.useCallback(
    (nextCursor: string | null | undefined) => {
      if (!nextCursor) return;
      setStack((prev) => [...prev, cursor]);
      setCursor(nextCursor);
    },
    [cursor],
  );

  const previous = React.useCallback(() => {
    setStack((prev) => {
      if (prev.length === 0) return prev;
      const copy = [...prev];
      const last = copy.pop() ?? null;
      setCursor(last);
      return copy;
    });
  }, []);

  const reset = React.useCallback(() => {
    setCursor(null);
    setStack([]);
  }, []);

  return {
    cursor,
    page: stack.length + 1,
    hasPrevious: stack.length > 0,
    next,
    previous,
    reset,
  };
}
