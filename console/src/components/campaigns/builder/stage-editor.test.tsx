import * as React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { StageInput } from '@/lib/api/schemas';
import { DEFAULT_STAGES, validateStages } from '@/lib/stages';
import { StageEditor } from './stage-editor';

function Harness({ initial = DEFAULT_STAGES }: { initial?: StageInput[] }) {
  const [stages, setStages] = React.useState<StageInput[]>(initial.map((s) => ({ ...s })));
  return (
    <>
      <StageEditor stages={stages} onChange={setStages} />
      <output data-testid="valid">
        {validateStages(stages).length === 0 ? 'valid' : 'invalid'}
      </output>
    </>
  );
}

describe('StageEditor', () => {
  it('renders the default plan without errors', () => {
    render(<Harness />);
    expect(screen.getByLabelText('Stage 1 target percent')).toHaveValue(1);
    expect(screen.getByLabelText('Stage 3 target percent')).toHaveValue(100);
    expect(screen.getByLabelText('Stage 1 max failure rate percent')).toHaveValue(5);
    expect(screen.queryAllByRole('alert')).toHaveLength(0);
    expect(screen.getByTestId('valid')).toHaveTextContent('valid');
  });

  it('flags a percent that does not increase and ties the error to the input', () => {
    render(<Harness />);
    const second = screen.getByLabelText('Stage 2 target percent');
    fireEvent.change(second, { target: { value: '1' } });
    const error = screen.getByRole('alert');
    expect(error).toHaveTextContent('greater than the previous stage (1%)');
    expect(second).toHaveAttribute('aria-invalid', 'true');
    expect(second).toHaveAttribute('aria-describedby', error.id);
    expect(screen.getByTestId('valid')).toHaveTextContent('invalid');
  });

  it('requires the final stage to end at 100%', () => {
    render(<Harness />);
    fireEvent.change(screen.getByLabelText('Stage 3 target percent'), { target: { value: '90' } });
    expect(screen.getByRole('alert')).toHaveTextContent('final stage must reach 100%');
  });

  it('adds a stage before the final 100% stage and removes stages', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Add stage' }));
    expect(screen.getAllByLabelText(/target percent/)).toHaveLength(4);
    expect(screen.getByLabelText('Stage 3 target percent')).toHaveValue(55);
    expect(screen.getByLabelText('Stage 4 target percent')).toHaveValue(100);
    expect(screen.getByTestId('valid')).toHaveTextContent('valid');
    await user.click(screen.getByRole('button', { name: 'Remove stage 3' }));
    expect(screen.getAllByLabelText(/target percent/)).toHaveLength(3);
  });

  it('validates failure rate bounds entered as percent', () => {
    render(<Harness />);
    fireEvent.change(screen.getByLabelText('Stage 1 max failure rate percent'), {
      target: { value: '150' },
    });
    expect(screen.getByRole('alert')).toHaveTextContent('between 0 and 1');
  });

  it('resets to the contract default plan', async () => {
    const user = userEvent.setup();
    render(<Harness initial={[{ percent: 100, dwell_s: 0, max_failure_rate: 0.1 }]} />);
    expect(screen.getAllByLabelText(/target percent/)).toHaveLength(1);
    await user.click(screen.getByRole('button', { name: /Reset to 1%/ }));
    expect(screen.getAllByLabelText(/target percent/)).toHaveLength(3);
  });
});
