{{/*
Expand the name of the chart.
*/}}
{{- define "opencti.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "opencti.fullname" -}}
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

{{/*
Namespace for rendered resources.
*/}}
{{- define "opencti.namespace" -}}
{{- .Release.Namespace }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "opencti.labels" -}}
helm.sh/chart: {{ include "opencti.chart" . }}
{{ include "opencti.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "opencti.selectorLabels" -}}
app.kubernetes.io/name: {{ include "opencti.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Chart name and version.
*/}}
{{- define "opencti.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Component labels: opencti.labels plus the component name.
*/}}
{{- define "opencti.componentLabels" -}}
{{- $ctx := .context }}
{{- $component := .component }}
{{- include "opencti.labels" $ctx }}
app.kubernetes.io/component: {{ $component }}
{{- end }}

{{/*
Component selector labels: opencti.selectorLabels plus the component name.
*/}}
{{- define "opencti.componentSelectorLabels" -}}
{{- $ctx := .context }}
{{- $component := .component }}
{{- include "opencti.selectorLabels" $ctx }}
app.kubernetes.io/component: {{ $component }}
{{- end }}

{{/*
Image reference for a component: <repository>:<tag or .Chart.AppVersion>.
*/}}
{{- define "opencti.image" -}}
{{- $ctx := .context }}
{{- $component := .component }}
{{- $image := index $ctx.Values $component "image" }}
{{- printf "%s:%s" $image.repository (default $ctx.Chart.AppVersion $image.tag) }}
{{- end }}

{{/*
Image pull policy for a component (component value, else IfNotPresent).
*/}}
{{- define "opencti.imagePullPolicy" -}}
{{- $ctx := .context }}
{{- $component := .component }}
{{- $image := index $ctx.Values $component "image" }}
{{- default "IfNotPresent" $image.pullPolicy }}
{{- end }}
