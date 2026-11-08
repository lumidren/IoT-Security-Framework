import * as React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderOptions } from '@testing-library/react';
import { TooltipProvider } from '@/components/ui/tooltip';
import type { Role } from '@/lib/rbac';
import { DEMO_TENANT_ID, DEMO_TENANT_NAME } from '@/lib/env';
import { SessionProvider, type ConsoleUser } from '@/providers/session-context';

export function testUser(role: Role = 'operator'): ConsoleUser {
  return {
    id: `test-${role}`,
    name: `Test ${role}`,
    email: `${role}@test.local`,
    image: null,
    role,
    tenantId: DEMO_TENANT_ID,
    tenantName: DEMO_TENANT_NAME,
    provider: 'demo',
  };
}

export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

export function renderWithProviders(
  ui: React.ReactElement,
  {
    role = 'operator',
    client,
    ...options
  }: RenderOptions & { role?: Role; client?: QueryClient } = {},
) {
  const queryClient = client ?? createTestQueryClient();
  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <SessionProvider user={testUser(role)}>
          <TooltipProvider>{children}</TooltipProvider>
        </SessionProvider>
      </QueryClientProvider>
    );
  }
  return { queryClient, ...render(ui, { wrapper: Wrapper, ...options }) };
}
