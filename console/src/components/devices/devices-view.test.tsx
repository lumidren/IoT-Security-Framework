import * as React from 'react';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '@/test/render';
import { setupMockServer } from '@/test/msw';
import { DevicesView } from './devices-view';

// Simulated App Router: `router.replace` updates the search params the view reads.
const navigation = vi.hoisted(() => {
  const listeners = new Set<() => void>();
  let search = new URLSearchParams();
  return {
    listeners,
    get search() {
      return search;
    },
    setSearch(next: URLSearchParams) {
      search = next;
      for (const l of listeners) l();
    },
    replace: vi.fn((href: string) => {
      const query = href.split('?')[1] ?? '';
      navigation.setSearch(new URLSearchParams(query));
    }),
  };
});

vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: navigation.replace, push: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => '/devices',
  useSearchParams: () => {
    const subscribe = React.useCallback((cb: () => void) => {
      navigation.listeners.add(cb);
      return () => navigation.listeners.delete(cb);
    }, []);
    return React.useSyncExternalStore(
      subscribe,
      () => navigation.search,
      () => navigation.search,
    );
  },
}));

setupMockServer();

describe('DevicesView filters', () => {
  it('loads the first page and narrows it to quarantined devices through the state filter', async () => {
    const user = userEvent.setup();
    navigation.setSearch(new URLSearchParams());
    renderWithProviders(<DevicesView />);

    const table = await screen.findByRole('table', {
      name: 'Devices matching the current filters',
    });
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBeGreaterThan(10));

    await user.click(screen.getByRole('combobox', { name: 'State' }));
    await user.click(await screen.findByRole('option', { name: 'Quarantined' }));

    expect(navigation.replace).toHaveBeenCalledWith(expect.stringContaining('state=quarantined'), {
      scroll: false,
    });
    await waitFor(() => {
      const rows = within(
        screen.getByRole('table', { name: 'Devices matching the current filters' }),
      )
        .getAllByRole('row')
        .slice(1);
      expect(rows).toHaveLength(4);
      for (const row of rows) expect(within(row).getByText('Quarantined')).toBeInTheDocument();
    });
  });

  it('applies a free-text search and clears all filters', async () => {
    const user = userEvent.setup();
    navigation.setSearch(new URLSearchParams());
    renderWithProviders(<DevicesView />);
    await screen.findByRole('table', { name: 'Devices matching the current filters' });

    await user.type(screen.getByLabelText('Search'), 'edge-nuc{enter}');
    expect(navigation.replace).toHaveBeenLastCalledWith(expect.stringContaining('q=edge-nuc'), {
      scroll: false,
    });
    await waitFor(() => {
      const rows = within(
        screen.getByRole('table', { name: 'Devices matching the current filters' }),
      )
        .getAllByRole('row')
        .slice(1);
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) expect(within(row).getByText(/edge-nuc/)).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'Clear' }));
    expect(navigation.replace).toHaveBeenLastCalledWith('/devices', { scroll: false });
  });

  it('hides bulk actions until rows are selected and respects the viewer role', async () => {
    const user = userEvent.setup();
    navigation.setSearch(new URLSearchParams());
    renderWithProviders(<DevicesView />, { role: 'viewer' });
    await screen.findByRole('table', { name: 'Devices matching the current filters' });
    expect(screen.queryByRole('region', { name: 'Bulk actions' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'Select all devices on this page' }));
    const region = await screen.findByRole('region', { name: 'Bulk actions' });
    expect(within(region).queryByRole('button', { name: /Send command/ })).not.toBeInTheDocument();
    expect(within(region).queryByRole('button', { name: /Add to group/ })).not.toBeInTheDocument();
    expect(within(region).getByRole('button', { name: /Clear selection/ })).toBeInTheDocument();
  });
});
