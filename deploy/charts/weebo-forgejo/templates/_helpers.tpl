{{/*
Chart name (nameOverride wins).
*/}}
{{- define "weebo-forgejo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

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
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "weebo-forgejo.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "weebo-forgejo.labels" -}}
helm.sh/chart: {{ include "weebo-forgejo.chart" . }}
{{ include "weebo-forgejo.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "weebo-forgejo.selectorLabels" -}}
app.kubernetes.io/name: {{ include "weebo-forgejo.name" . }}
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
Operator image: repository@digest when a digest is set, else
repository:tag (tag defaulting to `v` + appVersion, the release tag).
*/}}
{{- define "weebo-forgejo.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default (printf "v%s" .Chart.AppVersion)) -}}
{{- end -}}
{{- end -}}

{{/*
Leader-election Lease name (env LEASE_NAME).
*/}}
{{- define "weebo-forgejo.leaseName" -}}
{{- .Values.leaderElection.leaseName | default "weebo-forgejo-operator-leader" -}}
{{- end -}}

{{/*
Webhook TLS Secret name: produced by the cert-manager Certificate, or
user-provided when cert-manager is disabled.
*/}}
{{- define "weebo-forgejo.webhookTlsSecretName" -}}
{{- if .Values.webhook.certManager.enabled -}}
{{- printf "%s-webhook-tls" (include "weebo-forgejo.fullname" .) -}}
{{- else -}}
{{- required "webhook.tls.secretName is required when webhook.certManager.enabled is false (a kubernetes.io/tls Secret valid for the webhook Service)" .Values.webhook.tls.secretName -}}
{{- end -}}
{{- end -}}

{{/*
Name of the self-signed Issuer the chart provisions when
certManager.createIssuer is true.
*/}}
{{- define "weebo-forgejo.webhookIssuerName" -}}
{{- printf "%s-webhook" (include "weebo-forgejo.fullname" .) -}}
{{- end -}}

{{/*
Whether the Prometheus metrics endpoint is served.
*/}}
{{- define "weebo-forgejo.metricsEnabled" -}}
{{- if .Values.metrics.prometheus.enabled -}}true{{- end -}}
{{- end -}}
