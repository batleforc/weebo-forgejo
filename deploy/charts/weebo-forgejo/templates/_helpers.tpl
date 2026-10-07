{{/*
Chart name and version as used by the chart label.
*/}}
{{- define "weebo-forgejo.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Full release name.
*/}}
{{- define "weebo-forgejo.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "weebo-forgejo.labels" -}}
helm.sh/chart: {{ include "weebo-forgejo.chart" . }}
{{ include "weebo-forgejo.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "weebo-forgejo.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
ServiceAccount name.
*/}}
{{- define "weebo-forgejo.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "weebo-forgejo.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Webhook TLS Secret name (produced by the cert-manager Certificate).
*/}}
{{- define "weebo-forgejo.webhookTlsSecretName" -}}
{{- printf "%s-webhook-tls" (include "weebo-forgejo.fullname" .) -}}
{{- end -}}

{{/*
Name of the self-signed Issuer the chart provisions when
certManager.createIssuer is true.
*/}}
{{- define "weebo-forgejo.webhookIssuerName" -}}
{{- printf "%s-webhook" (include "weebo-forgejo.fullname" .) -}}
{{- end -}}
