'use client';

import * as React from 'react';
import { FilterXIcon, SearchIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { DEVICE_STATES, type Group } from '@/lib/api/schemas';
import { titleCase } from '@/lib/utils';

export interface DeviceFilterValues {
  state: string;
  group: string;
  tag: string;
  connected: string;
  assurance: string;
  q: string;
}

export const EMPTY_FILTERS: DeviceFilterValues = {
  state: '',
  group: '',
  tag: '',
  connected: '',
  assurance: '',
  q: '',
};

const ALL = '__all__';

function FilterSelect({
  id,
  label,
  value,
  onChange,
  options,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <div className="flex min-w-36 flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value || ALL} onValueChange={(v) => onChange(v === ALL ? '' : v)}>
        <SelectTrigger id={id} className="w-full" aria-label={label}>
          <SelectValue placeholder="All" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All</SelectItem>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

export function DeviceFilters({
  values,
  onChange,
  groups,
}: {
  values: DeviceFilterValues;
  onChange: (values: DeviceFilterValues) => void;
  groups: Group[];
}) {
  const [search, setSearch] = React.useState(values.q);
  const [tag, setTag] = React.useState(values.tag);
  React.useEffect(() => setSearch(values.q), [values.q]);
  React.useEffect(() => setTag(values.tag), [values.tag]);

  const update = (patch: Partial<DeviceFilterValues>) => onChange({ ...values, ...patch });
  const isFiltered = Object.values(values).some((v) => v !== '');

  return (
    <form
      role="search"
      aria-label="Filter devices"
      className="flex flex-col gap-3 rounded-lg border p-3 md:flex-row md:flex-wrap md:items-end"
      onSubmit={(event) => {
        event.preventDefault();
        update({ q: search.trim(), tag: tag.trim() });
      }}
    >
      <div className="flex min-w-48 flex-1 flex-col gap-1.5">
        <Label htmlFor="device-search">Search</Label>
        <div className="relative">
          <SearchIcon
            className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            id="device-search"
            type="search"
            placeholder="Device id, product or tag value"
            className="pl-8"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>
      <FilterSelect
        id="filter-state"
        label="State"
        value={values.state}
        onChange={(state) => update({ state })}
        options={DEVICE_STATES.map((s) => ({ value: s, label: titleCase(s) }))}
      />
      <FilterSelect
        id="filter-group"
        label="Group"
        value={values.group}
        onChange={(group) => update({ group })}
        options={groups.map((g) => ({ value: g.slug, label: g.name }))}
      />
      <div className="flex min-w-36 flex-col gap-1.5">
        <Label htmlFor="filter-tag">Tag (key:value)</Label>
        <Input
          id="filter-tag"
          placeholder="site:ber"
          value={tag}
          onChange={(e) => setTag(e.target.value)}
          onBlur={() => update({ tag: tag.trim() })}
        />
      </div>
      <FilterSelect
        id="filter-connected"
        label="Connectivity"
        value={values.connected}
        onChange={(connected) => update({ connected })}
        options={[
          { value: 'true', label: 'Connected' },
          { value: 'false', label: 'Offline' },
        ]}
      />
      <FilterSelect
        id="filter-assurance"
        label="Assurance"
        value={values.assurance}
        onChange={(assurance) => update({ assurance })}
        options={[
          { value: 'hardware', label: 'Hardware' },
          { value: 'software', label: 'Software keys' },
        ]}
      />
      <div className="flex gap-2">
        <Button type="submit" variant="secondary">
          Apply
        </Button>
        {isFiltered && (
          <Button
            type="button"
            variant="ghost"
            onClick={() => {
              setSearch('');
              setTag('');
              onChange(EMPTY_FILTERS);
            }}
          >
            <FilterXIcon aria-hidden="true" /> Clear
          </Button>
        )}
      </div>
    </form>
  );
}
