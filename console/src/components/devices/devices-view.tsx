'use client';

import * as React from 'react';
import type { RowSelectionState } from '@tanstack/react-table';
import { PaginationControls } from '@/components/shared/pagination-controls';
import { ErrorState } from '@/components/shared/states';
import { BulkActions } from '@/components/devices/bulk-actions';
import {
  DeviceFilters,
  EMPTY_FILTERS,
  type DeviceFilterValues,
} from '@/components/devices/device-filters';
import { DevicesTable } from '@/components/devices/devices-table';
import { useCursorPagination } from '@/hooks/use-cursor-pagination';
import { useQueryState } from '@/hooks/use-query-state';
import { useDevices, useGroups } from '@/lib/api/hooks';

const FILTER_KEYS = Object.keys(EMPTY_FILTERS) as Array<keyof DeviceFilterValues>;
const PAGE_SIZE = 25;

export function DevicesView() {
  const { get, set } = useQueryState();
  const filters = React.useMemo<DeviceFilterValues>(() => {
    const values = { ...EMPTY_FILTERS };
    for (const key of FILTER_KEYS) values[key] = get(key);
    return values;
  }, [get]);
  const pagination = useCursorPagination();
  const [rowSelection, setRowSelection] = React.useState<RowSelectionState>({});

  const groups = useGroups();
  const devices = useDevices({
    state: filters.state || undefined,
    group: filters.group || undefined,
    tag: filters.tag || undefined,
    q: filters.q || undefined,
    connected: (filters.connected as '' | 'true' | 'false') || undefined,
    assurance: filters.assurance || undefined,
    cursor: pagination.cursor,
    limit: PAGE_SIZE,
  });

  const applyFilters = (values: DeviceFilterValues) => {
    set({ ...values });
    pagination.reset();
    setRowSelection({});
  };

  const selectedIds = React.useMemo(
    () =>
      Object.entries(rowSelection)
        .filter(([, v]) => v)
        .map(([k]) => k),
    [rowSelection],
  );

  return (
    <div className="flex flex-col gap-4">
      <DeviceFilters values={filters} onChange={applyFilters} groups={groups.data ?? []} />
      <BulkActions
        selectedIds={selectedIds}
        groups={groups.data ?? []}
        onClear={() => setRowSelection({})}
      />
      {devices.isError ? (
        <ErrorState error={devices.error} onRetry={() => void devices.refetch()} />
      ) : (
        <>
          <DevicesTable
            devices={devices.data?.items ?? []}
            isLoading={devices.isLoading}
            rowSelection={rowSelection}
            onRowSelectionChange={setRowSelection}
          />
          <PaginationControls
            page={pagination.page}
            hasPrevious={pagination.hasPrevious}
            hasNext={Boolean(devices.data?.next_cursor)}
            onPrevious={pagination.previous}
            onNext={() => pagination.next(devices.data?.next_cursor)}
            isFetching={devices.isFetching}
            count={devices.data?.items.length}
          />
        </>
      )}
    </div>
  );
}
