'use client';

import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
  type QueryKey,
} from '@tanstack/react-query';
import { z } from 'zod';
import {
  apiFetch,
  fetchAllPages,
  fetchPage,
  newIdempotencyKey,
  type Query,
} from '@/lib/api/client';
import { queryKeys } from '@/lib/api/keys';
import {
  AlertSchema,
  ApiKeySchema,
  AuditEventSchema,
  BaselineSchema,
  CampaignDeviceSchema,
  CampaignSchema,
  CertificateSchema,
  CommandBatchSchema,
  CommandSchema,
  CreatedApiKeySchema,
  DeviceConfigSchema,
  DeviceDetailSchema,
  DeviceSummarySchema,
  FirmwareSchema,
  FleetHealthSchema,
  FleetSummarySchema,
  GroupMembersResultSchema,
  GroupSchema,
  PolicyDocumentSchema,
  PolicyEvaluateResultSchema,
  PolicyHistoryEntrySchema,
  ProvisioningItemSchema,
  PutConfigResultSchema,
  QuarantineEntrySchema,
  RuleSchema,
  SavePolicyResultSchema,
  SigningKeySchema,
  TelemetrySeriesSchema,
  TenantSchema,
  TimelineEventSchema,
  TwinSchema,
  UserSchema,
  type Alert,
  type Campaign,
  type CreateApiKeyInput,
  type CreateCampaignInput,
  type DeviceDetail,
  type DeviceSummary,
  type FirmwareMetadata,
  type JsonObject,
  type Page,
  type PolicyEvaluateInput,
  type Role,
  type SendCommandInput,
  type TenantSettings,
} from '@/lib/api/schemas';

function invalidate(client: QueryClient, keys: QueryKey[]) {
  return Promise.all(keys.map((queryKey) => client.invalidateQueries({ queryKey })));
}

// ----------------------------------------------------------------------------------------------
// Tenant
// ----------------------------------------------------------------------------------------------

export function useTenant() {
  return useQuery({
    queryKey: queryKeys.tenant,
    queryFn: () => apiFetch('registry', '/v1/tenants/me', { schema: TenantSchema }),
    staleTime: 5 * 60_000,
  });
}

export function useUpdateTenantSettings() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (settings: Partial<TenantSettings>) =>
      apiFetch('registry', '/v1/tenants/me/settings', {
        method: 'PATCH',
        body: settings,
        schema: TenantSchema,
      }),
    onSuccess: (tenant) => {
      client.setQueryData(queryKeys.tenant, tenant);
    },
  });
}

// ----------------------------------------------------------------------------------------------
// Fleet
// ----------------------------------------------------------------------------------------------

export function useFleetSummary() {
  return useQuery({
    queryKey: queryKeys.fleet.summary(),
    queryFn: () => apiFetch('registry', '/v1/fleet/summary', { schema: FleetSummarySchema }),
    refetchInterval: 60_000,
  });
}

export function useFleetHealth(window = '1h') {
  return useQuery({
    queryKey: queryKeys.fleet.health(window),
    queryFn: () =>
      apiFetch('registry', '/v1/fleet/health', { query: { window }, schema: FleetHealthSchema }),
    refetchInterval: 60_000,
  });
}

// ----------------------------------------------------------------------------------------------
// Devices
// ----------------------------------------------------------------------------------------------

export interface DeviceFilters {
  state?: string;
  group?: string;
  tag?: string;
  q?: string;
  connected?: 'true' | 'false' | '';
  assurance?: string;
  cursor?: string | null;
  limit?: number;
}

export function useDevices(filters: DeviceFilters, enabled = true) {
  return useQuery({
    queryKey: queryKeys.devices.list(filters as Record<string, unknown>),
    queryFn: () => fetchPage('registry', '/v1/devices', DeviceSummarySchema, filters as Query),
    placeholderData: keepPreviousData,
    enabled,
  });
}

/** Resolves every device matching `filters` (bounded) — used for target previews. */
export function useAllDevices(filters: Omit<DeviceFilters, 'cursor' | 'limit'>, enabled = true) {
  return useQuery({
    queryKey: [...queryKeys.devices.lists(), 'all', filters],
    queryFn: () =>
      fetchAllPages('registry', '/v1/devices', DeviceSummarySchema, filters as Query, {
        maxPages: 10,
      }),
    enabled,
    staleTime: 30_000,
  });
}

export function useDevice(id: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.devices.detail(id),
    queryFn: () => apiFetch('registry', `/v1/devices/${id}`, { schema: DeviceDetailSchema }),
    enabled: enabled && id.length > 0,
  });
}

export interface TimelineFilters {
  kinds?: string[];
  from?: string;
  to?: string;
}

export function useDeviceTimeline(id: string, filters: TimelineFilters = {}) {
  return useInfiniteQuery({
    queryKey: queryKeys.devices.timeline(id, filters as Record<string, unknown>),
    queryFn: ({ pageParam }) =>
      fetchPage('registry', `/v1/devices/${id}/timeline`, TimelineEventSchema, {
        kinds: filters.kinds && filters.kinds.length > 0 ? filters.kinds.join(',') : undefined,
        from: filters.from,
        to: filters.to,
        cursor: pageParam,
        limit: 50,
      }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled: id.length > 0,
  });
}

export interface TelemetryQuery {
  from: string;
  to: string;
  metrics: string[];
  step: string;
}

export function useDeviceTelemetry(id: string, params: TelemetryQuery, enabled = true) {
  return useQuery({
    queryKey: queryKeys.devices.telemetry(id, params as unknown as Record<string, unknown>),
    queryFn: () =>
      apiFetch('registry', `/v1/devices/${id}/telemetry`, {
        query: { ...params, metrics: params.metrics.join(',') },
        schema: TelemetrySeriesSchema,
      }),
    enabled: enabled && id.length > 0,
    placeholderData: keepPreviousData,
  });
}

export function useDeviceCertificates(id: string) {
  return useQuery({
    queryKey: queryKeys.devices.certificates(id),
    queryFn: () =>
      apiFetch('registry', `/v1/devices/${id}/certificates`, {
        schema: z.array(CertificateSchema),
      }),
    enabled: id.length > 0,
    staleTime: 30_000,
  });
}

function deviceMutationKeys(id: string): QueryKey[] {
  return [
    queryKeys.devices.detail(id),
    queryKeys.devices.lists(),
    queryKeys.fleet.all,
    queryKeys.quarantine.all,
    queryKeys.provisioning.all,
    queryKeys.audit.all,
  ];
}

export function useUpdateDevice(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (patch: { tags?: Record<string, string>; groups?: string[] }) =>
      apiFetch('registry', `/v1/devices/${id}`, {
        method: 'PATCH',
        body: patch,
        schema: DeviceDetailSchema,
      }),
    onSuccess: (device) => {
      client.setQueryData(queryKeys.devices.detail(id), device);
      void invalidate(client, [queryKeys.devices.lists(), queryKeys.groups.all]);
    },
  });
}

export function useQuarantineDevice() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      apiFetch('registry', `/v1/devices/${id}/quarantine`, {
        method: 'POST',
        body: { reason },
        schema: DeviceDetailSchema,
      }),
    onSuccess: (device) => {
      client.setQueryData(queryKeys.devices.detail(device.id), device);
      void invalidate(client, deviceMutationKeys(device.id));
    },
  });
}

export function useReleaseDevice() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) =>
      apiFetch('registry', `/v1/devices/${id}/release`, {
        method: 'POST',
        body: { note },
        schema: DeviceDetailSchema,
      }),
    onSuccess: (device) => {
      client.setQueryData(queryKeys.devices.detail(device.id), device);
      void invalidate(client, deviceMutationKeys(device.id));
    },
  });
}

export function useDecommissionDevice() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      apiFetch('registry', `/v1/devices/${id}/decommission`, {
        method: 'POST',
        body: { reason },
        schema: DeviceDetailSchema,
      }),
    onSuccess: (device) => {
      client.setQueryData(queryKeys.devices.detail(device.id), device);
      void invalidate(client, deviceMutationKeys(device.id));
    },
  });
}

// ----------------------------------------------------------------------------------------------
// Groups
// ----------------------------------------------------------------------------------------------

export function useGroups() {
  return useQuery({
    queryKey: queryKeys.groups.all,
    queryFn: () => apiFetch('registry', '/v1/groups', { schema: z.array(GroupSchema) }),
    staleTime: 60_000,
  });
}

export function useUpdateGroupMembers() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ slug, add, remove }: { slug: string; add: string[]; remove?: string[] }) =>
      apiFetch('registry', `/v1/groups/${slug}/members`, {
        method: 'PUT',
        body: { add, remove: remove ?? [] },
        schema: GroupMembersResultSchema,
      }),
    onSuccess: () => {
      void invalidate(client, [queryKeys.groups.all, queryKeys.devices.all]);
    },
  });
}

// ----------------------------------------------------------------------------------------------
// Twin
// ----------------------------------------------------------------------------------------------

export function useTwin(id: string) {
  return useQuery({
    queryKey: queryKeys.devices.twin(id),
    queryFn: () => apiFetch('registry', `/v1/devices/${id}/twin`, { schema: TwinSchema }),
    enabled: id.length > 0,
  });
}

export function usePatchTwinDesired(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ patch, expectedVersion }: { patch: JsonObject; expectedVersion?: number }) =>
      apiFetch('registry', `/v1/devices/${id}/twin/desired`, {
        method: 'PATCH',
        body: { patch, expected_version: expectedVersion },
        schema: TwinSchema,
      }),
    onSuccess: (twin) => {
      client.setQueryData(queryKeys.devices.twin(id), twin);
      void invalidate(client, [queryKeys.devices.detail(id)]);
    },
  });
}

export function useDeleteTwinDesiredPath(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (path: string) =>
      apiFetch('registry', `/v1/devices/${id}/twin/desired/${encodeURIComponent(path)}`, {
        method: 'DELETE',
        schema: TwinSchema,
      }),
    onSuccess: (twin) => {
      client.setQueryData(queryKeys.devices.twin(id), twin);
    },
  });
}

// ----------------------------------------------------------------------------------------------
// Commands
// ----------------------------------------------------------------------------------------------

export function useDeviceCommands(id: string, status?: string) {
  return useInfiniteQuery({
    queryKey: queryKeys.devices.commands(id, { status }),
    queryFn: ({ pageParam }) =>
      fetchPage('registry', `/v1/devices/${id}/commands`, CommandSchema, {
        status,
        cursor: pageParam,
        limit: 25,
      }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled: id.length > 0,
    refetchInterval: 15_000,
  });
}

export function useSendCommand() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ deviceId, input }: { deviceId: string; input: SendCommandInput }) => {
      const key = input.idempotency_key ?? newIdempotencyKey();
      return apiFetch('registry', `/v1/devices/${deviceId}/commands`, {
        method: 'POST',
        body: { name: input.name, args: input.args, ttl_s: input.ttl_s, idempotency_key: key },
        idempotencyKey: key,
        schema: CommandSchema,
      });
    },
    onSuccess: (command) => {
      void invalidate(client, [
        queryKeys.devices.commands(command.device_id),
        queryKeys.devices.timeline(command.device_id),
      ]);
    },
  });
}

export function useSendGroupCommand() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ slug, input }: { slug: string; input: SendCommandInput }) => {
      const key = input.idempotency_key ?? newIdempotencyKey();
      return apiFetch('registry', `/v1/groups/${slug}/commands`, {
        method: 'POST',
        body: { name: input.name, args: input.args, ttl_s: input.ttl_s, idempotency_key: key },
        idempotencyKey: key,
        schema: CommandBatchSchema,
      });
    },
    onSuccess: () => {
      void invalidate(client, [queryKeys.devices.all]);
    },
  });
}

// ----------------------------------------------------------------------------------------------
// Config
// ----------------------------------------------------------------------------------------------

export function useDeviceConfig(id: string, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.devices.config(id),
    queryFn: () => apiFetch('registry', `/v1/devices/${id}/config`, { schema: DeviceConfigSchema }),
    enabled: enabled && id.length > 0,
    retry: false,
  });
}

export function usePutDeviceConfig(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (config: JsonObject) =>
      apiFetch('registry', `/v1/devices/${id}/config`, {
        method: 'PUT',
        body: { config },
        schema: PutConfigResultSchema,
      }),
    onSuccess: () => {
      void invalidate(client, [queryKeys.devices.config(id), queryKeys.devices.timeline(id)]);
    },
  });
}

// ----------------------------------------------------------------------------------------------
// Provisioning
// ----------------------------------------------------------------------------------------------

export function useProvisioning(state: string, cursor: string | null) {
  return useQuery({
    queryKey: queryKeys.provisioning.list({ state, cursor }),
    queryFn: () =>
      fetchPage('registry', '/v1/provisioning', ProvisioningItemSchema, {
        state,
        cursor,
        limit: 50,
      }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
}

export function useApproveProvisioning() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (deviceId: string) =>
      apiFetch('registry', `/v1/provisioning/${deviceId}/approve`, {
        method: 'POST',
        schema: DeviceSummarySchema,
      }),
    onSuccess: () => {
      void invalidate(client, [
        queryKeys.provisioning.all,
        queryKeys.devices.all,
        queryKeys.fleet.all,
      ]);
    },
  });
}

export function useRejectProvisioning() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ deviceId, reason }: { deviceId: string; reason: string }) =>
      apiFetch('registry', `/v1/provisioning/${deviceId}/reject`, {
        method: 'POST',
        body: { reason },
        schema: DeviceSummarySchema,
      }),
    onSuccess: () => {
      void invalidate(client, [
        queryKeys.provisioning.all,
        queryKeys.devices.all,
        queryKeys.fleet.all,
      ]);
    },
  });
}

// ----------------------------------------------------------------------------------------------
// Audit
// ----------------------------------------------------------------------------------------------

export interface AuditFilters {
  actor?: string;
  action?: string;
  target_type?: string;
  target_id?: string;
  from?: string;
  to?: string;
  cursor?: string | null;
}

export function useAudit(filters: AuditFilters) {
  return useQuery({
    queryKey: queryKeys.audit.list(filters as Record<string, unknown>),
    queryFn: () =>
      fetchPage('registry', '/v1/audit', AuditEventSchema, { ...(filters as Query), limit: 50 }),
    placeholderData: keepPreviousData,
  });
}

// ----------------------------------------------------------------------------------------------
// Users & API keys
// ----------------------------------------------------------------------------------------------

export function useUsers(enabled = true) {
  return useQuery({
    queryKey: queryKeys.users,
    queryFn: () => apiFetch('registry', '/v1/users', { schema: z.array(UserSchema) }),
    enabled,
  });
}

export function useSetUserRole() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) =>
      apiFetch('registry', `/v1/users/${id}/role`, {
        method: 'PUT',
        body: { role },
        schema: UserSchema,
      }),
    onSuccess: () => {
      void invalidate(client, [queryKeys.users, queryKeys.audit.all]);
    },
  });
}

export function useApiKeys(enabled = true) {
  return useQuery({
    queryKey: queryKeys.apiKeys,
    queryFn: () => apiFetch('registry', '/v1/api-keys', { schema: z.array(ApiKeySchema) }),
    enabled,
  });
}

export function useCreateApiKey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateApiKeyInput) =>
      apiFetch('registry', '/v1/api-keys', {
        method: 'POST',
        body: input,
        schema: CreatedApiKeySchema,
      }),
    onSuccess: () => {
      void invalidate(client, [queryKeys.apiKeys, queryKeys.audit.all]);
    },
  });
}

export function useRevokeApiKey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>('registry', `/v1/api-keys/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      void invalidate(client, [queryKeys.apiKeys, queryKeys.audit.all]);
    },
  });
}

// ----------------------------------------------------------------------------------------------
// OTA: firmware & campaigns
// ----------------------------------------------------------------------------------------------

export function useFirmware(product?: string) {
  return useInfiniteQuery({
    queryKey: queryKeys.firmware.list({ product }),
    queryFn: ({ pageParam }) =>
      fetchPage('ota', '/v1/firmware', FirmwareSchema, { product, cursor: pageParam, limit: 50 }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
}

export function useUploadFirmware() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ image, metadata }: { image: File; metadata: FirmwareMetadata }) => {
      const form = new FormData();
      form.append('image', image, image.name);
      form.append('metadata', JSON.stringify(metadata));
      return apiFetch('ota', '/v1/firmware', {
        method: 'POST',
        body: form,
        schema: FirmwareSchema,
      });
    },
    onSuccess: () => {
      void invalidate(client, [queryKeys.firmware.all]);
    },
  });
}

export function useSigningKeys() {
  return useQuery({
    queryKey: queryKeys.signingKeys,
    queryFn: () => apiFetch('ota', '/v1/signing-keys', { schema: z.array(SigningKeySchema) }),
    staleTime: 5 * 60_000,
  });
}

export function useCampaigns(state?: string, cursor?: string | null) {
  return useQuery({
    queryKey: queryKeys.campaigns.list({ state, cursor }),
    queryFn: () => fetchPage('ota', '/v1/campaigns', CampaignSchema, { state, cursor, limit: 50 }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
}

export function useCampaign(id: string) {
  return useQuery({
    queryKey: queryKeys.campaigns.detail(id),
    queryFn: () => apiFetch('ota', `/v1/campaigns/${id}`, { schema: CampaignSchema }),
    enabled: id.length > 0,
    refetchInterval: (query) =>
      query.state.data?.state === 'running' || query.state.data?.state === 'paused'
        ? 15_000
        : false,
  });
}

export function useCampaignDevices(id: string, state?: string) {
  return useInfiniteQuery({
    queryKey: queryKeys.campaigns.devices(id, { state }),
    queryFn: ({ pageParam }) =>
      fetchPage('ota', `/v1/campaigns/${id}/devices`, CampaignDeviceSchema, {
        state,
        cursor: pageParam,
        limit: 50,
      }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled: id.length > 0,
  });
}

export function useCampaignAudit(id: string) {
  return useInfiniteQuery({
    queryKey: queryKeys.campaigns.audit(id),
    queryFn: ({ pageParam }) =>
      fetchPage('ota', `/v1/campaigns/${id}/audit`, AuditEventSchema, {
        cursor: pageParam,
        limit: 50,
      }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled: id.length > 0,
  });
}

export function useCreateCampaign() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateCampaignInput) =>
      apiFetch('ota', '/v1/campaigns', {
        method: 'POST',
        body: input,
        idempotencyKey: newIdempotencyKey(),
        schema: CampaignSchema,
      }),
    onSuccess: (campaign: Campaign) => {
      client.setQueryData(queryKeys.campaigns.detail(campaign.id), campaign);
      void invalidate(client, [queryKeys.campaigns.lists(), queryKeys.fleet.all]);
    },
  });
}

export type CampaignAction = 'start' | 'pause' | 'resume' | 'cancel' | 'halt' | 'rollback';

export function useCampaignAction(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ action, reason }: { action: CampaignAction; reason?: string }) =>
      apiFetch('ota', `/v1/campaigns/${id}/${action}`, {
        method: 'POST',
        body: reason !== undefined ? { reason } : undefined,
        idempotencyKey: newIdempotencyKey(),
        schema: CampaignSchema,
      }),
    onSuccess: (campaign, variables) => {
      if (variables.action !== 'rollback') {
        client.setQueryData(queryKeys.campaigns.detail(id), campaign);
      }
      void invalidate(client, [queryKeys.campaigns.all, queryKeys.fleet.all]);
    },
  });
}

// ----------------------------------------------------------------------------------------------
// Anomaly: alerts, rules, baseline, quarantine
// ----------------------------------------------------------------------------------------------

export interface AlertFilters {
  state?: string;
  severity?: string;
  rule?: string;
  device_id?: string;
  from?: string;
  to?: string;
  cursor?: string | null;
  limit?: number;
}

export function useAlerts(filters: AlertFilters) {
  return useQuery({
    queryKey: queryKeys.alerts.list(filters as Record<string, unknown>),
    queryFn: () =>
      fetchPage('anomaly', '/v1/alerts', AlertSchema, { limit: 50, ...(filters as Query) }),
    placeholderData: keepPreviousData,
  });
}

export function useAlert(id: string) {
  return useQuery({
    queryKey: queryKeys.alerts.detail(id),
    queryFn: () => apiFetch('anomaly', `/v1/alerts/${id}`, { schema: AlertSchema }),
    enabled: id.length > 0,
  });
}

export function useAckAlert() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) =>
      apiFetch('anomaly', `/v1/alerts/${id}/ack`, {
        method: 'POST',
        body: { note },
        schema: AlertSchema,
      }),
    onSuccess: (alert: Alert) => {
      client.setQueryData(queryKeys.alerts.detail(alert.id), alert);
      void invalidate(client, [queryKeys.alerts.lists(), queryKeys.fleet.all]);
    },
  });
}

export function useResolveAlert() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      note,
      falsePositive,
    }: {
      id: string;
      note: string;
      falsePositive: boolean;
    }) =>
      apiFetch('anomaly', `/v1/alerts/${id}/resolve`, {
        method: 'POST',
        body: { note, false_positive: falsePositive },
        schema: AlertSchema,
      }),
    onSuccess: (alert: Alert) => {
      client.setQueryData(queryKeys.alerts.detail(alert.id), alert);
      void invalidate(client, [
        queryKeys.alerts.lists(),
        queryKeys.fleet.all,
        queryKeys.devices.detail(alert.device_id),
      ]);
    },
  });
}

export function useRules() {
  return useQuery({
    queryKey: queryKeys.rules,
    queryFn: () => apiFetch('anomaly', '/v1/rules', { schema: z.array(RuleSchema) }),
    staleTime: 60_000,
  });
}

export function useBaseline(deviceId: string) {
  return useQuery({
    queryKey: queryKeys.devices.baseline(deviceId),
    queryFn: () =>
      apiFetch('anomaly', `/v1/devices/${deviceId}/baseline`, { schema: BaselineSchema }),
    enabled: deviceId.length > 0,
  });
}

export function useQuarantineList(cursor: string | null) {
  return useQuery({
    queryKey: queryKeys.quarantine.list({ cursor }),
    queryFn: () =>
      fetchPage('anomaly', '/v1/quarantine', QuarantineEntrySchema, { cursor, limit: 50 }),
    placeholderData: keepPreviousData,
  });
}

// ----------------------------------------------------------------------------------------------
// Policy
// ----------------------------------------------------------------------------------------------

export function usePolicy(enabled = true) {
  return useQuery({
    queryKey: queryKeys.policy.current(),
    queryFn: () => apiFetch('policy', '/v1/policy', { schema: PolicyDocumentSchema }),
    enabled,
    retry: false,
  });
}

export function usePolicyHistory() {
  return useInfiniteQuery({
    queryKey: queryKeys.policy.history(),
    queryFn: ({ pageParam }) =>
      fetchPage('policy', '/v1/policy/history', PolicyHistoryEntrySchema, {
        cursor: pageParam,
        limit: 25,
      }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
}

export function useSavePolicy() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ rego, message }: { rego: string; message: string }) =>
      apiFetch('policy', '/v1/policy', {
        method: 'PUT',
        body: { rego, message },
        schema: SavePolicyResultSchema,
      }),
    onSuccess: () => {
      void invalidate(client, [queryKeys.policy.all, queryKeys.audit.all]);
    },
  });
}

export function useEvaluatePolicy() {
  return useMutation({
    mutationFn: (input: PolicyEvaluateInput) =>
      apiFetch('policy', '/v1/policy/evaluate', {
        method: 'POST',
        body: { input },
        schema: PolicyEvaluateResultSchema,
      }),
  });
}

// Re-exported for convenience in components.
export type { DeviceDetail, DeviceSummary, Page };
