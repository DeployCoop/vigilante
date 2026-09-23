{{/*
Expand the name of the chart.
*/}}
{{- define "wazuh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "wazuh.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "wazuh.namespace" -}}
{{- if .Values.namespaceOverride -}}
{{- .Values.namespaceOverride -}}
{{- else -}}
{{- .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{- define "wazuh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh.labels" -}}
helm.sh/chart: {{ include "wazuh.chart" . }}
app.kubernetes.io/name: wazuh
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{- define "wazuh.indexerHost" -}}
wazuh-indexer.{{ include "wazuh.namespace" . }}.svc.cluster.local
{{- end }}

{{- define "wazuh.managerHost" -}}
wazuh-manager.{{ include "wazuh.namespace" . }}.svc.cluster.local
{{- end }}

{{- define "wazuh.persistence.storageClass" -}}
{{- if . }}
storageClassName: {{ . | quote }}
{{- end }}
{{- end }}
