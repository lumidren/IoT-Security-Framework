'use client';

import * as React from 'react';
import { PlusIcon, RotateCcwIcon, Trash2Icon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { StageInput } from '@/lib/api/schemas';
import {
  DEFAULT_STAGES,
  MAX_STAGES,
  issuesFor,
  validateStages,
  type StageField,
  type StageIssue,
} from '@/lib/stages';
import { formatDuration } from '@/lib/utils';

export interface StageEditorProps {
  stages: StageInput[];
  onChange: (stages: StageInput[]) => void;
  /** Externally computed issues; when omitted the editor validates itself. */
  issues?: StageIssue[];
}

function numberOrNaN(value: string): number {
  if (value.trim() === '') return Number.NaN;
  return Number(value);
}

export function StageEditor({ stages, onChange, issues: externalIssues }: StageEditorProps) {
  const issues = externalIssues ?? validateStages(stages);
  const listIssues = issues.filter((i) => i.index === null);

  const update = (index: number, field: StageField, raw: string) => {
    const next = stages.map((stage, i) =>
      i === index
        ? {
            ...stage,
            [field]: field === 'max_failure_rate' ? numberOrNaN(raw) / 100 : numberOrNaN(raw),
          }
        : stage,
    );
    onChange(next);
  };

  const addStage = () => {
    if (stages.length >= MAX_STAGES) return;
    const last = stages[stages.length - 1];
    const previous = stages[stages.length - 2];
    // Insert before the final 100% stage when present, otherwise append.
    if (last && last.percent === 100) {
      const base = previous?.percent ?? 0;
      const percent = Math.min(99, Math.round((base + 100) / 2));
      onChange([...stages.slice(0, -1), { percent, dwell_s: 3600, max_failure_rate: 0.05 }, last]);
    } else {
      onChange([...stages, { percent: 100, dwell_s: 0, max_failure_rate: 0.05 }]);
    }
  };

  const remove = (index: number) => onChange(stages.filter((_, i) => i !== index));

  const fieldError = (index: number, field: StageField) =>
    issuesFor(issues, index, field)[0]?.message;

  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-lg border">
        <Table>
          <caption className="sr-only">
            Rollout stages: cumulative percent of targets, dwell time and failure budget
          </caption>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">#</TableHead>
              <TableHead>Target reached (%)</TableHead>
              <TableHead>Dwell (seconds)</TableHead>
              <TableHead>Max failure rate (%)</TableHead>
              <TableHead className="w-16">
                <span className="sr-only">Remove</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {stages.map((stage, index) => {
              const errors: Partial<Record<StageField, string | undefined>> = {
                percent: fieldError(index, 'percent'),
                dwell_s: fieldError(index, 'dwell_s'),
                max_failure_rate: fieldError(index, 'max_failure_rate'),
              };
              return (
                <TableRow key={index}>
                  <TableCell className="tabular font-medium">{index + 1}</TableCell>
                  {(['percent', 'dwell_s', 'max_failure_rate'] as const).map((field) => {
                    const id = `stage-${index}-${field}`;
                    const error = errors[field];
                    const value =
                      field === 'max_failure_rate'
                        ? Number.isFinite(stage[field])
                          ? Math.round(stage[field] * 1000) / 10
                          : ''
                        : Number.isFinite(stage[field])
                          ? stage[field]
                          : '';
                    return (
                      <TableCell key={field} className="align-top whitespace-normal">
                        <Input
                          id={id}
                          type="number"
                          inputMode="decimal"
                          value={value}
                          min={field === 'percent' ? 1 : 0}
                          max={field === 'dwell_s' ? undefined : 100}
                          step={field === 'max_failure_rate' ? 0.5 : 1}
                          aria-label={`Stage ${index + 1} ${field === 'percent' ? 'target percent' : field === 'dwell_s' ? 'dwell seconds' : 'max failure rate percent'}`}
                          aria-invalid={error ? true : undefined}
                          aria-describedby={error ? `${id}-error` : undefined}
                          onChange={(e) => update(index, field, e.target.value)}
                          className="w-28"
                        />
                        {field === 'dwell_s' &&
                          Number.isFinite(stage.dwell_s) &&
                          stage.dwell_s > 0 && (
                            <p className="mt-1 text-xs text-muted-foreground">
                              {formatDuration(stage.dwell_s)}
                            </p>
                          )}
                        {error && (
                          <p
                            id={`${id}-error`}
                            className="mt-1 text-xs text-destructive"
                            role="alert"
                          >
                            {error}
                          </p>
                        )}
                      </TableCell>
                    );
                  })}
                  <TableCell className="align-top">
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Remove stage ${index + 1}`}
                      onClick={() => remove(index)}
                      disabled={stages.length <= 1}
                    >
                      <Trash2Icon aria-hidden="true" />
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      {listIssues.length > 0 && (
        <ul className="text-sm text-destructive" role="alert">
          {listIssues.map((issue, i) => (
            <li key={i}>{issue.message}</li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={addStage}
          disabled={stages.length >= MAX_STAGES}
        >
          <PlusIcon aria-hidden="true" /> Add stage
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => onChange(DEFAULT_STAGES.map((s) => ({ ...s })))}
        >
          <RotateCcwIcon aria-hidden="true" /> Reset to 1% / 10% / 100%
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        Percents are cumulative and must strictly increase, ending at 100%. A stage passes once its
        dwell time elapses with the failure rate under budget; otherwise the campaign halts
        automatically.
      </p>
    </div>
  );
}
