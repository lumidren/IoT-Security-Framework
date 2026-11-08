import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { DEMO_TENANT_ID } from '@/lib/env';
import { renderWithProviders } from '@/test/render';
import { setupMockServer } from '@/test/msw';
import { PolicyDryRunPanel } from './dry-run-panel';

setupMockServer();

describe('PolicyDryRunPanel', () => {
  it('evaluates an owned telemetry publish as allow with the matched rule and trace', async () => {
    const user = userEvent.setup();
    renderWithProviders(<PolicyDryRunPanel />);
    expect(screen.getByLabelText(/Topic/)).toHaveValue(
      `im/v1/${DEMO_TENANT_ID}/dev-8f3a1c2b9d4e5f60/telemetry`,
    );
    await user.click(screen.getByRole('button', { name: 'Evaluate' }));
    const result = await screen.findByTestId('dry-run-result');
    expect(within(result).getByText('Allow')).toBeInTheDocument();
    expect(within(result).getByText('allow[device_publish_own_topic]')).toBeInTheDocument();
    expect(within(result).getByText(/owns_topic=true/)).toBeInTheDocument();
  });

  it('denies publishing to another device topic and explains why', async () => {
    const user = userEvent.setup();
    renderWithProviders(<PolicyDryRunPanel />);
    const topic = screen.getByLabelText(/Topic/);
    await user.clear(topic);
    await user.type(topic, `im/v1/${DEMO_TENANT_ID}/dev-0000000000000001/telemetry`);
    await user.click(screen.getByRole('button', { name: 'Evaluate' }));
    const result = await screen.findByTestId('dry-run-result');
    expect(within(result).getByText('Deny')).toBeInTheDocument();
    expect(within(result).getByText(/default deny applies/)).toBeInTheDocument();
    expect(within(result).getByText(/reason: not_owner/)).toBeInTheDocument();
  });

  it('shows validation errors tied to empty required inputs instead of calling the service', async () => {
    const user = userEvent.setup();
    renderWithProviders(<PolicyDryRunPanel />);
    await user.clear(screen.getByLabelText(/Topic/));
    await user.click(screen.getByRole('button', { name: 'Evaluate' }));
    await waitFor(() => expect(screen.getByText('Topic is required')).toBeInTheDocument());
    expect(screen.getByLabelText(/Topic/)).toHaveAttribute('aria-invalid', 'true');
    expect(screen.queryByTestId('dry-run-result')).not.toBeInTheDocument();
  });
});
