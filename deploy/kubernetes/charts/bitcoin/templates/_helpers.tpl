{{- define "bitcoin.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 253 | trimSuffix "-" }}
{{- end }}

{{- define "bitcoin.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 253 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 253 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 253 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "bitcoin.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 253 | trimSuffix "-" }}
{{- end }}

{{- define "bitcoin.labels" -}}
helm.sh/chart: {{ include "bitcoin.chart" . }}
{{ include "bitcoin.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "bitcoin.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bitcoin.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "bitcoin.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "bitcoin.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
