{{/*
Expand the name of the chart.
*/}}
{{- define "aisoc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "aisoc.fullname" -}}
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
Create chart label
*/}}
{{- define "aisoc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "aisoc.labels" -}}
helm.sh/chart: {{ include "aisoc.chart" . }}
{{ include "aisoc.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "aisoc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aisoc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The broker address every service in the release should dial.

One definition rather than a string repeated per template: the release's own
brokers when the chart deploys them, and whatever the operator named
otherwise. `kafka.bootstrapServers` stays the escape hatch for a managed
broker (MSK, Confluent Cloud, Redpanda), which is the production shape.
*/}}
{{- define "aisoc.kafkaBootstrap" -}}
{{- if .Values.kafka.deploy.enabled -}}
{{- printf "%s-kafka.%s.svc.cluster.local:9092" (include "aisoc.fullname" .) .Release.Namespace -}}
{{- else -}}
{{- .Values.kafka.bootstrapServers | default "kafka:9092" -}}
{{- end -}}
{{- end }}

{{/*
The KRaft controller quorum, as `<node-id>@<stable-dns>:9093` per broker.

Every voter has to be listed on every broker or the quorum never forms, and
the names have to be the StatefulSet's stable per-pod DNS rather than the
client Service, which load-balances and would point a controller at a peer
chosen at random.
*/}}
{{- define "aisoc.kafkaQuorumVoters" -}}
{{- $fullname := include "aisoc.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- $voters := list -}}
{{- range $i := until (int .Values.kafka.deploy.replicaCount) -}}
{{- $voters = append $voters (printf "%d@%s-kafka-%d.%s-kafka-headless.%s.svc.cluster.local:9093" $i $fullname $i $fullname $ns) -}}
{{- end -}}
{{- join "," $voters -}}
{{- end }}

{{/*
Service account name
*/}}
{{- define "aisoc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aisoc.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
