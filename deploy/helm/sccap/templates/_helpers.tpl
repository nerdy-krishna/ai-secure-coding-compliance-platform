{{- define "sccap.name" -}}sccap{{- end }}
{{- define "sccap.fullname" -}}{{ printf "%s-sccap" .Release.Name | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "sccap.labels" -}}
app.kubernetes.io/name: {{ include "sccap.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}
{{- define "sccap.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sccap.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "sccap.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "sccap.fullname" .) .Values.serviceAccount.name }}{{ else }}{{ default "default" .Values.serviceAccount.name }}{{ end -}}
{{- end }}
{{- define "sccap.apiImage" -}}{{ printf "%s:%s" .Values.images.api.repository .Values.images.api.tag }}{{- end }}
{{- define "sccap.workerImage" -}}{{ printf "%s:%s" .Values.images.worker.repository .Values.images.worker.tag }}{{- end }}
{{- define "sccap.envFrom" -}}
{{- $root := .root -}}
- secretRef:
    name: {{ .secret }}
{{- if $root.Values.runtime.existingConfigMap }}
- configMapRef:
    name: {{ $root.Values.runtime.existingConfigMap }}
{{- end }}
{{- end }}
{{- define "sccap.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 1001
runAsGroup: 1001
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end }}
{{- define "sccap.spread" -}}
- maxSkew: 1
  topologyKey: kubernetes.io/hostname
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      {{- include "sccap.selectorLabels" . | nindent 6 }}
- maxSkew: 1
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      {{- include "sccap.selectorLabels" . | nindent 6 }}
{{- end }}
