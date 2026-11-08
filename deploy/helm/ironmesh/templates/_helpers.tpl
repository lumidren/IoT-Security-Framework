{{/*
Chart name.
*/}}
{{- define "ironmesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Release-wide base name. values.yaml pins fullnameOverride=ironmesh so that in-cluster
hostnames (ironmesh-pki, ironmesh-policy, ...) are stable regardless of the release name.
*/}}
{{- define "ironmesh.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Name of a service's Kubernetes objects: <fullname>-<service>.
Usage: {{ include "ironmesh.svcName" (dict "root" $ "name" $name) }}
*/}}
{{- define "ironmesh.svcName" -}}
{{- printf "%s-%s" (include "ironmesh.fullname" .root) .name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ironmesh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels for release-level objects.
*/}}
{{- define "ironmesh.labels" -}}
helm.sh/chart: {{ include "ironmesh.chart" . }}
app.kubernetes.io/name: {{ include "ironmesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ironmesh
ironmesh.dev/environment: {{ .Values.global.environment | quote }}
{{- end -}}

{{/*
Labels for one service. Usage: include "ironmesh.svcLabels" (dict "root" $ "name" $name)
*/}}
{{- define "ironmesh.svcLabels" -}}
{{ include "ironmesh.labels" .root }}
app.kubernetes.io/component: {{ .name }}
ironmesh.dev/job: {{ include "ironmesh.svcName" . }}
{{- end -}}

{{/*
Selector labels for one service (immutable once deployed).
*/}}
{{- define "ironmesh.svcSelectorLabels" -}}
app.kubernetes.io/name: {{ include "ironmesh.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .name }}
{{- end -}}

{{/*
Pod selector for a service, usable inside NetworkPolicy from/to blocks.
*/}}
{{- define "ironmesh.podSelector" -}}
podSelector:
  matchLabels:
    {{- include "ironmesh.svcSelectorLabels" . | nindent 4 }}
{{- end -}}

{{/*
Pod selector for the EMQX sub-chart pods.
*/}}
{{- define "ironmesh.emqxPodSelector" -}}
podSelector:
  matchLabels:
    app.kubernetes.io/name: emqx
    app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Pod selector for the Redpanda sub-chart broker pods.
*/}}
{{- define "ironmesh.redpandaPodSelector" -}}
podSelector:
  matchLabels:
    app.kubernetes.io/name: redpanda
    app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Fully qualified image reference for a service.
Usage: include "ironmesh.image" (dict "root" $ "svc" $svc)
*/}}
{{- define "ironmesh.image" -}}
{{- $registry := .root.Values.global.imageRegistry -}}
{{- $tag := default (default .root.Chart.AppVersion .root.Values.global.imageTag) .svc.image.tag -}}
{{- if .svc.image.digest -}}
{{- printf "%s/%s@%s" $registry .svc.image.repository .svc.image.digest -}}
{{- else -}}
{{- printf "%s/%s:%s" $registry .svc.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret that holds a service's secret environment variables.
*/}}
{{- define "ironmesh.secretName" -}}
{{- $svc := index .root.Values.services .name -}}
{{- if and $svc.secret $svc.secret.existingSecret -}}
{{- $svc.secret.existingSecret -}}
{{- else -}}
{{- printf "%s-secret" (include "ironmesh.svcName" .) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the TLS Secret (tls.crt/tls.key/ca.crt, Services CA) mounted into a service.
*/}}
{{- define "ironmesh.tlsSecretName" -}}
{{- $svc := index .root.Values.services .name -}}
{{- if and $svc.tls $svc.tls.existingSecret -}}
{{- $svc.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-tls" (include "ironmesh.svcName" .) -}}
{{- end -}}
{{- end -}}

{{/*
Kafka bootstrap servers: Redpanda sub-chart when enabled, otherwise the external value.
*/}}
{{- define "ironmesh.kafkaBootstrap" -}}
{{- if .Values.redpanda.enabled -}}
{{- printf "%s-redpanda:%d" .Release.Name (int .Values.redpanda.listeners.kafka.port) -}}
{{- else -}}
{{- .Values.kafka.bootstrapServers -}}
{{- end -}}
{{- end -}}

{{/*
Public hostname of a component (console|registry|ota|pki|mqtt): explicit value or <name>.<domain>.
Usage: include "ironmesh.host" (dict "root" $ "name" "console")
*/}}
{{- define "ironmesh.host" -}}
{{- $explicit := index .root.Values.hosts .name -}}
{{- if $explicit -}}
{{- $explicit -}}
{{- else -}}
{{- printf "%s.%s" .name .root.Values.global.domain -}}
{{- end -}}
{{- end -}}

{{/*
Pod security context shared by every IronMesh pod.
*/}}
{{- define "ironmesh.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.podSecurity.runAsUser }}
runAsGroup: {{ .Values.podSecurity.runAsGroup }}
fsGroup: {{ .Values.podSecurity.fsGroup }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
Container security context shared by every IronMesh container.
*/}}
{{- define "ironmesh.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
privileged: false
runAsNonRoot: true
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
Render the OTel environment shared by every service.
Usage: include "ironmesh.otelEnv" (dict "root" $ "name" $name)
*/}}
{{- define "ironmesh.otelEnv" -}}
- name: OTEL_SERVICE_NAME
  value: {{ printf "ironmesh-%s" .name | quote }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .root.Values.otelCollector.endpoint | quote }}
- name: OTEL_EXPORTER_OTLP_PROTOCOL
  value: grpc
{{- /* POD_NAME, POD_NAMESPACE and NODE_NAME are defined by the Deployment before this block. */}}
- name: OTEL_RESOURCE_ATTRIBUTES
  value: {{ printf "service.namespace=ironmesh,deployment.environment=%s,service.version=%s,k8s.pod.name=$(POD_NAME),k8s.namespace.name=$(POD_NAMESPACE),k8s.node.name=$(NODE_NAME)" .root.Values.global.environment (default .root.Chart.AppVersion .root.Values.global.imageTag) | quote }}
- name: OTEL_TRACES_SAMPLER
  value: parentbased_traceidratio
- name: OTEL_TRACES_SAMPLER_ARG
  value: {{ .root.Values.otelCollector.traceSamplingRatio | quote }}
{{- end -}}
