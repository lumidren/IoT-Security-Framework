import { describe, expect, it } from 'vitest';
import { DEFAULT_STAGES, MAX_STAGES, issuesFor, stagesAreValid, validateStages } from './stages';

describe('validateStages', () => {
  it('accepts the contract default plan', () => {
    expect(validateStages(DEFAULT_STAGES)).toEqual([]);
    expect(stagesAreValid(DEFAULT_STAGES)).toBe(true);
  });

  it('requires at least one stage', () => {
    expect(validateStages([])).toEqual([
      { index: null, field: 'stages', message: 'Add at least one stage.' },
    ]);
  });

  it('requires strictly increasing percents', () => {
    const issues = validateStages([
      { percent: 10, dwell_s: 0, max_failure_rate: 0.05 },
      { percent: 10, dwell_s: 0, max_failure_rate: 0.05 },
      { percent: 100, dwell_s: 0, max_failure_rate: 0.05 },
    ]);
    expect(issuesFor(issues, 1, 'percent')[0]?.message).toContain(
      'greater than the previous stage (10%)',
    );
    expect(issues).toHaveLength(1);
  });

  it('requires the last stage to end at 100%', () => {
    const issues = validateStages([
      { percent: 5, dwell_s: 600, max_failure_rate: 0.05 },
      { percent: 50, dwell_s: 600, max_failure_rate: 0.05 },
    ]);
    expect(issues).toEqual([
      { index: 1, field: 'percent', message: 'The final stage must reach 100% of the target.' },
    ]);
  });

  it('rejects out-of-range or non-integer percents, negative dwell and failure rates outside 0..1', () => {
    const issues = validateStages([
      { percent: 0, dwell_s: -5, max_failure_rate: 1.2 },
      { percent: 50.5, dwell_s: 0, max_failure_rate: -0.1 },
      { percent: 100, dwell_s: Number.NaN, max_failure_rate: 0 },
    ]);
    expect(issuesFor(issues, 0, 'percent')).toHaveLength(1);
    expect(issuesFor(issues, 0, 'dwell_s')).toHaveLength(1);
    expect(issuesFor(issues, 0, 'max_failure_rate')).toHaveLength(1);
    expect(issuesFor(issues, 1, 'percent')).toHaveLength(1);
    expect(issuesFor(issues, 1, 'max_failure_rate')).toHaveLength(1);
    expect(issuesFor(issues, 2, 'dwell_s')).toHaveLength(1);
  });

  it('accepts a single 100% stage', () => {
    expect(validateStages([{ percent: 100, dwell_s: 0, max_failure_rate: 1 }])).toEqual([]);
  });

  it('caps the number of stages', () => {
    const many = Array.from({ length: MAX_STAGES + 1 }, (_, i) => ({
      percent: i + 1,
      dwell_s: 0,
      max_failure_rate: 0,
    }));
    many[many.length - 1]!.percent = 100;
    expect(validateStages(many).some((i) => i.field === 'stages')).toBe(true);
  });
});
