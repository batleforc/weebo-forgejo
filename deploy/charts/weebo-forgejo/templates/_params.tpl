{{/*
weebo-forgejo's parameters for the kit's library chart (weebo-operator-lib,
see its README): everything templates/operator.yaml renders that is not a
value.
*/}}
{{- define "operator.params" -}}
group: forgejo.weebo.io
versions: [v1alpha1]
# Every kind a controller watches (cluster-wide, or the namespaced ones in
# watch.namespace only), and the kinds it references.
kinds:
  - forgejoinstances
  - forgejolocalinstances
  - forgejousers
  - forgejouserkeys
  - forgejoorganizations
  - forgejoteams
  - forgejorepositories
  - forgejowebhooks
  - forgejodeploykeys
  - forgejooauth2applications
  - forgejoaccesstokens
  - forgejonamespacepolicies
# Checked by the ForgejoNamespacePolicy allow-list on admission (unless
# bound to a ForgejoLocalInstance).
admitted:
  - forgejousers
  - forgejouserkeys
  - forgejoorganizations
  - forgejoteams
  - forgejorepositories
  - forgejowebhooks
  - forgejodeploykeys
  - forgejooauth2applications
  - forgejoaccesstokens
# The namespaced kinds: what a team may manage (rbac.namespacedExample),
# and the watch Role's (watch.namespace). ForgejoInstance and
# ForgejoNamespacePolicy, cluster-scoped, stay with cluster admins.
namespacedKinds:
  - forgejolocalinstances
  - forgejousers
  - forgejouserkeys
  - forgejoorganizations
  - forgejoteams
  - forgejorepositories
  - forgejowebhooks
  - forgejodeploykeys
  - forgejooauth2applications
  - forgejoaccesstokens
env:
  - name: WEEBO_FORGEJO_MAX_INFLIGHT
    value: {{ .Values.forgejoMaxInflight | quote }}
egress:
  - comment: Forgejo instances.
    rules: {{ toJson .Values.networkPolicy.egress.forgejo }}
{{- $sel := printf "namespace=%q, job=%q" .Release.Namespace (printf "%s-metrics" (include "weebo-operator.fullname" .)) }}
{{- $requests := printf "{__name__=~\"weebo_forgejo_forgejo_requests(_total)*\", %s" $sel }}
alerts:
  - alert: WeeboForgejoForgejoApiErrors
    expr: |
      sum by (operation) (rate({{ $requests }}, result=~"unreachable|error"}[15m]))
        /
      sum by (operation) (rate({{ $requests }}}[15m]))
        > 0.2
    for: 15m
    labels:
      severity: warning
    annotations:
      summary: {{`'Forgejo API {{ $labels.operation }} failing ({{ $value | humanizePercentage }})'`}}
      description: Forgejo is unhealthy or unreachable; affected CRs report InstanceUnreachable.
{{- end -}}
