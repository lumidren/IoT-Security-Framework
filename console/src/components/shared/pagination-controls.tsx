'use client';

import { ChevronLeftIcon, ChevronRightIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function PaginationControls({
  page,
  hasPrevious,
  hasNext,
  onPrevious,
  onNext,
  isFetching = false,
  count,
}: {
  page: number;
  hasPrevious: boolean;
  hasNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
  isFetching?: boolean;
  count?: number;
}) {
  return (
    <nav aria-label="Pagination" className="flex items-center justify-between gap-2 py-2">
      <p className="text-sm text-muted-foreground" aria-live="polite">
        Page {page}
        {count !== undefined ? ` · ${count} item${count === 1 ? '' : 's'}` : ''}
        {isFetching ? ' · loading…' : ''}
      </p>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={onPrevious}
          disabled={!hasPrevious || isFetching}
        >
          <ChevronLeftIcon aria-hidden="true" /> Previous
        </Button>
        <Button variant="outline" size="sm" onClick={onNext} disabled={!hasNext || isFetching}>
          Next <ChevronRightIcon aria-hidden="true" />
        </Button>
      </div>
    </nav>
  );
}
