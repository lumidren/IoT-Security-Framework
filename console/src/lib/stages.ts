import type { StageInput } from '@/lib/api/schemas';

export type StageField = 'percent' | 'dwell_s' | 'max_failure_rate';

export interface StageIssue {
  /** Index of the offending stage, or `null` for list-level problems. */
  index: number | null;
  field: StageField | 'stages';
  message: string;
}

/** Contract default: 1% / 10% / 100% with a one hour dwell and 5% failure budget. */
export const DEFAULT_STAGES: StageInput[] = [
  { percent: 1, dwell_s: 3600, max_failure_rate: 0.05 },
  { percent: 10, dwell_s: 3600, max_failure_rate: 0.05 },
  { percent: 100, dwell_s: 0, max_failure_rate: 0.05 },
];

export const MAX_STAGES = 10;

function isInt(n: number): boolean {
  return Number.isFinite(n) && Math.floor(n) === n;
}

/**
 * Validates a rollout plan: 1..MAX_STAGES stages, integer percents in 1..100 that strictly increase
 * and end at exactly 100, non-negative integer dwell seconds and failure rates within [0, 1].
 */
export function validateStages(stages: readonly StageInput[]): StageIssue[] {
  const issues: StageIssue[] = [];
  if (stages.length === 0) {
    issues.push({ index: null, field: 'stages', message: 'Add at least one stage.' });
    return issues;
  }
  if (stages.length > MAX_STAGES) {
    issues.push({
      index: null,
      field: 'stages',
      message: `A rollout can have at most ${MAX_STAGES} stages.`,
    });
  }

  let previousPercent = 0;
  stages.forEach((stage, index) => {
    if (!isInt(stage.percent) || stage.percent < 1 || stage.percent > 100) {
      issues.push({
        index,
        field: 'percent',
        message: 'Percent must be a whole number from 1 to 100.',
      });
    } else if (stage.percent <= previousPercent) {
      issues.push({
        index,
        field: 'percent',
        message: `Percent must be greater than the previous stage (${previousPercent}%).`,
      });
    }
    if (isInt(stage.percent)) previousPercent = Math.max(previousPercent, stage.percent);

    if (!isInt(stage.dwell_s) || stage.dwell_s < 0) {
      issues.push({
        index,
        field: 'dwell_s',
        message: 'Dwell must be zero or a positive whole number of seconds.',
      });
    }
    if (
      !Number.isFinite(stage.max_failure_rate) ||
      stage.max_failure_rate < 0 ||
      stage.max_failure_rate > 1
    ) {
      issues.push({
        index,
        field: 'max_failure_rate',
        message: 'Max failure rate must be between 0 and 1 (0% to 100%).',
      });
    }
  });

  const last = stages[stages.length - 1];
  if (last && isInt(last.percent) && last.percent !== 100) {
    issues.push({
      index: stages.length - 1,
      field: 'percent',
      message: 'The final stage must reach 100% of the target.',
    });
  }
  return issues;
}

export function stagesAreValid(stages: readonly StageInput[]): boolean {
  return validateStages(stages).length === 0;
}

export function issuesFor(issues: readonly StageIssue[], index: number, field: StageField) {
  return issues.filter((i) => i.index === index && i.field === field);
}
