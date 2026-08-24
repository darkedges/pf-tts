{{- define "wai-strict.name" -}}wai-strict{{- end -}}
{{- define "wai-strict.fullname" -}}{{ .Release.Name }}-wai-strict{{- end -}}
{{- define "wai-strict.labels" -}}
app.kubernetes.io/name: {{ include "wai-strict.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "wai-strict.image" -}}
{{- $image := index . 0 -}}
{{- if $image.digest -}}
{{ required "image repository is required" $image.repository }}@{{ $image.digest }}
{{- else -}}
{{ required "image repository is required" $image.repository }}:{{ required "image tag or digest is required" $image.tag }}
{{- end -}}
{{- end -}}
{{- define "wai-strict.podSecurityContext" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end -}}
{{- define "wai-strict.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}
{{- define "wai-strict.commonEnv" -}}
- name: SPIFFE_ENDPOINT
  value: {{ .Values.global.spiffeEndpoint | quote }}
- name: PF_TRANSACTION_ISSUER
  value: {{ required "global.pingFederate.issuer is required" .Values.global.pingFederate.issuer | quote }}
- name: PF_JWKS_URL
  value: {{ required "global.pingFederate.jwksURL is required" .Values.global.pingFederate.jwksURL | quote }}
- name: PF_CA_FILE
  value: /run/pingfederate/ca.pem
{{- end -}}
{{- define "wai-strict.commonVolumes" -}}
- name: spiffe-workload-api
  csi:
    driver: csi.spiffe.io
    readOnly: true
- name: pingfederate-ca
  secret:
    secretName: {{ required "global.pingFederate.caSecretName is required" .Values.global.pingFederate.caSecretName }}
    items:
      - key: {{ .Values.global.pingFederate.caSecretKey }}
        path: ca.pem
{{- end -}}
{{- define "wai-strict.commonMounts" -}}
- name: spiffe-workload-api
  mountPath: /run/spire/sockets
  readOnly: true
- name: pingfederate-ca
  mountPath: /run/pingfederate
  readOnly: true
{{- end -}}
