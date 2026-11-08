'use client';

import * as React from 'react';
import { flexRender, type Table as TanstackTable } from '@tanstack/react-table';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { EmptyState } from '@/components/shared/states';
import { useIsMobile } from '@/hooks/use-media-query';
import { cn } from '@/lib/utils';

export interface DataTableProps<T> {
  table: TanstackTable<T>;
  isLoading?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
  caption: string;
  /** Card rendering for narrow screens (tables collapse to cards below 768px). */
  renderCard?: (row: T, index: number) => React.ReactNode;
  getRowId?: (row: T) => string;
  className?: string;
}

export function DataTable<T>({
  table,
  isLoading = false,
  emptyTitle = 'Nothing to show',
  emptyDescription,
  caption,
  renderCard,
  className,
}: DataTableProps<T>) {
  const isMobile = useIsMobile();
  const rows = table.getRowModel().rows;
  const columnCount = table.getAllLeafColumns().length;

  if (isMobile && renderCard) {
    return (
      <div className={cn('flex flex-col gap-3', className)}>
        <p className="sr-only">{caption}</p>
        {isLoading && rows.length === 0 && (
          <>
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-24 w-full" />
          </>
        )}
        {!isLoading && rows.length === 0 && (
          <EmptyState title={emptyTitle} description={emptyDescription} />
        )}
        <ul className="flex flex-col gap-3">
          {rows.map((row, index) => (
            <li key={row.id}>{renderCard(row.original, index)}</li>
          ))}
        </ul>
      </div>
    );
  }

  return (
    <div className={cn('rounded-lg border', className)}>
      <Table>
        <caption className="sr-only">{caption}</caption>
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <TableHead
                  key={header.id}
                  style={{ width: header.getSize() !== 150 ? header.getSize() : undefined }}
                >
                  {header.isPlaceholder
                    ? null
                    : flexRender(header.column.columnDef.header, header.getContext())}
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {isLoading &&
            rows.length === 0 &&
            Array.from({ length: 5 }).map((_, index) => (
              <TableRow key={`skeleton-${index}`}>
                {Array.from({ length: columnCount }).map((__, cellIndex) => (
                  <TableCell key={cellIndex}>
                    <Skeleton className="h-4 w-full" />
                  </TableCell>
                ))}
              </TableRow>
            ))}
          {!isLoading && rows.length === 0 && (
            <TableRow>
              <TableCell colSpan={columnCount} className="h-32 text-center whitespace-normal">
                <EmptyState
                  title={emptyTitle}
                  description={emptyDescription}
                  className="border-0 py-4"
                />
              </TableCell>
            </TableRow>
          )}
          {rows.map((row) => (
            <TableRow key={row.id} data-state={row.getIsSelected() ? 'selected' : undefined}>
              {row.getVisibleCells().map((cell) => (
                <TableCell key={cell.id}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
