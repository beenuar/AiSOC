---
sidebar_position: 24
title: Kubernetes Audit Logs
description: Dual-mode Kubernetes apiserver audit log connector — webhook (apiserver pushes to AiSOC's inbox) or file_tail (AiSOC reads a local audit log forward from a byte cursor). Powers cluster-level detections for kubectl exec, RBAC escalation, ServiceAccount token theft, and impersonation.
---

# Kubernetes Audit Logs

The Kubernetes Audit Logs connector ingests **apiserver audit events**
— the canonical record of every call hitting the Kubernetes control
plane. These are the events that power detection content under
`detections/cloud/kubernetes-*.yaml` (kubectl exec into a pod,
ServiceAccount token theft, RBAC privilege escalation,
`impersonate` abuse, and similar high-signal cluster-level
behaviours).

Unlike the cloud-platform connectors (AWS GuardDuty, GCP SCC,
Azure Defender) which only see what the cloud provider's own
security service surfaces, this connector reads the audit log
**directly** from the apiserver — so the detection content can
match on raw verbs, raw resources, raw users, and raw response
codes instead of a vendor-normalised abstraction.

## Two delivery modes

Kubernetes audit logging supports two output channels, and AiSOC
exposes both as a single connector with a `mode` switch:

| Mode | When to pick it | How AiSOC consumes it |
|---|---|---|
| **`webhook`** | Managed clusters (EKS / GKE / AKS) where you cannot mount the apiserver audit log into a sidecar | The apiserver POSTs each `EventList` batch to AiSOC's tenant-scoped endpoint `POST /v1/ingest/k8s-audit/<tenant_id>` and authenticates with the `X-AiSOC-K8s-Token` shared-secret header. The Go ingest service normalises every item in the batch directly. A legacy fallback via the AiSOC inbox at `/v1/inbox/<token>` is also supported for clusters that cannot set custom headers in audit-webhook kubeconfig. |
| **`file_tail`** | Self-hosted clusters where the audit log path is mountable | The connector pod tails the audit log file forward from a byte cursor on its configured poll interval. Cursor survives pod restarts; file rotation / truncation resets cleanly. |

You only configure one mode per connector instance. To cover
multiple clusters, add one instance per cluster.

## What you get

Every audit event is normalised to a stable shape regardless of
mode:

| Field | Source | Notes |
|---|---|---|
| `cluster_name` | Operator-supplied | Stamped on every event — filter detections by cluster |
| `k8s_user` / `k8s_user_groups` | `user.username`, `user.groups` | Who made the request |
| `k8s_impersonated_user` | `impersonatedUser.username` | Non-null = the request used `impersonate` |
| `k8s_verb` | `verb` | `get` / `list` / `watch` / `create` / `update` / `patch` / `delete` / `deletecollection` / `connect` / `impersonate` |
| `k8s_resource` | `objectRef.resource` | `pods`, `secrets`, `clusterrolebindings`, … |
| `k8s_subresource` | `objectRef.subresource` | `exec`, `attach`, `portforward`, `proxy`, `log`, `token` |
| `k8s_namespace` / `k8s_object_name` | `objectRef.namespace` / `objectRef.name` | Target of the request |
| `k8s_response_code` | `responseStatus.code` | 200 / 403 / 404 / 409 / 500 / … |
| `src_ip` / `source_ips` | `sourceIPs[0]`, `sourceIPs` | First IP surfaces as `src_ip` so detections can match a single column |
| `k8s_user_agent` | `userAgent` | `kubectl/v1.29.0`, controller-manager, kubelet, … |
| `audit_id` | `auditID` | Unique per request — use for deduplication |
| `raw_event` | The full `audit.k8s.io/v1` Event | Always preserved so detection content can match on any field |

## Capabilities

| Capability | Notes |
|---|---|
| `PULL_AUDIT` | Primary capability — audit events flow into the audit-event pipeline |
| `PULL_ALERTS` | High-severity events surface as alerts |

Kubernetes audit logs are passive — there is no `BLOCK` /
`ISOLATE` capability here. To **respond** to a suspicious audit
event (e.g. revoke a ServiceAccount, delete a pod) route the
alert through a playbook that uses a Kubernetes execution
connector or your own `kubectl` runner.

## Severity heuristic

The connector buckets events into AiSOC's four-tier severity
ladder using verb + resource + response code:

| Condition | AiSOC severity |
|---|---|
| `verb=impersonate` (any resource) | `high` |
| `verb=create/update/patch/delete` on `clusterrolebindings` or `rolebindings` | `high` |
| `verb=create/update/patch/delete` on `secrets`, `serviceaccounts`, `clusterroles`, `roles`, `certificatesigningrequests` | `high` |
| `subresource ∈ {exec, attach, portforward, proxy}` on `pods` | `high` |
| `verb=create/update/patch/delete` on `deployments`, `daemonsets`, `statefulsets`, `pods`, `jobs`, `cronjobs`, `replicasets` | `medium` |
| `responseStatus.code >= 400` (denied / failed requests) | `medium` |
| `verb=get/list/watch` on sensitive resources (`secrets`, RBAC, etc.) | `low` |
| Everything else (steady-state read traffic) | `info` |

The default poll-bucket cap is high enough that even a busy
cluster's `info` events do not crowd out the `high` band — but
in practice you do **not** want to surface every `get pods` in
the UI. Detection rules in `detections/cloud/kubernetes-*.yaml`
filter on `severity ∈ {high, medium}` only.

## Prerequisites

- A **Kubernetes cluster** with apiserver audit logging
  configured.
- For **webhook mode**:
  - Cluster admin access to update the apiserver's
    `--audit-webhook-config-file` flag (or push an `AuditSink`
    resource).
  - Network reachability from the apiserver to AiSOC's ingest
    endpoint.
  - The AiSOC ingest service must have `K8S_AUDIT_SHARED_SECRET`
    set in its environment. The webhook is **disabled by default**
    and the route returns `503 Service Unavailable` until an
    operator turns it on. Pick a long random value
    (`openssl rand -base64 32`) and store it in your secret manager.
  - The tenant ID you want to attribute events to. The route is
    `POST /v1/ingest/k8s-audit/<tenant_id>` so the tenant boundary
    is set at apiserver-config time.
  - **(Legacy / fallback)** For control planes that cannot set
    custom headers in audit-webhook kubeconfig, a bound inbox token
    created with the `k8s-audit` template is also supported.
- For **file_tail mode**:
  - The apiserver audit log path mounted **read-only** into the
    AiSOC connector pod.
  - A writeable directory next to that path for the byte cursor
    file (defaults to `<audit_log_path>.aisoc-cursor`).

## Setup — webhook mode (recommended for managed clusters)

The recommended webhook path is the dedicated tenant-scoped
endpoint:

```
POST https://<your-aisoc-host>/v1/ingest/k8s-audit/<tenant_id>
Content-Type: application/json
X-AiSOC-K8s-Token: <shared-secret>
```

The endpoint accepts a Kubernetes
[`audit.k8s.io/v1` `EventList`](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/#audit-k8s-io-v1-EventList)
JSON document — the exact shape the apiserver pushes when you
configure an `--audit-webhook-config-file`. Every item in the
batch is normalised to OCSF `API Activity (6003)`, severity
classified using the heuristic above, and forwarded to the
detection pipeline.

The route is **disabled by default** so a stock AiSOC install
will return `503 Service Unavailable` until you turn it on.
Authentication is via a single installation-wide shared secret
(`K8S_AUDIT_SHARED_SECRET`), compared with constant-time
equality so a partial-prefix attacker cannot brute-force it
byte by byte.

### 1. Enable the webhook on the AiSOC ingest service

Set both env vars on the `services/ingest` deployment, then
restart:

```bash
# Pick a long random value once and store it in your secret manager.
export K8S_AUDIT_SHARED_SECRET="$(openssl rand -base64 32)"

# Optional — defaults to 16 MiB. Bump if your audit-batch-max-size
# is unusually large.
export K8S_AUDIT_MAX_BODY_BYTES=16777216
```

If `K8S_AUDIT_SHARED_SECRET` is unset or empty, the webhook
remains off. This is intentional — accidentally leaving an
unauthenticated audit-event sink open to the internet would be
a coverage hole, not an integration win.

### 2. Wire up the apiserver

Write an `audit-webhook-config-file` kubeconfig that targets
the AiSOC route and presents the shared secret as a header.
Apiserver kubeconfigs do not natively support custom request
headers, so use the cluster's `tls-server-name` /
`server` fields and either an apiserver authn-proxy or a
sidecar to inject the header. The most common pattern is a
small forwarder (e.g. nginx) that the apiserver hits over
loopback, which then adds the header before forwarding to
AiSOC. A reference apiserver kubeconfig that talks to such a
forwarder:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: aisoc-audit
    cluster:
      server: http://127.0.0.1:8080/forward
contexts:
  - name: aisoc-audit
    context:
      cluster: aisoc-audit
current-context: aisoc-audit
```

And the matching forwarder snippet (nginx):

```nginx
server {
    listen 127.0.0.1:8080;
    location /forward {
        proxy_set_header X-AiSOC-K8s-Token "<shared-secret>";
        proxy_set_header Content-Type application/json;
        proxy_pass https://<your-aisoc-host>/v1/ingest/k8s-audit/<tenant_id>;
    }
}
```

For **self-managed kubeadm**, add to your apiserver static-pod
manifest:

```yaml
spec:
  containers:
    - command:
        - kube-apiserver
        - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
        - --audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
        - --audit-webhook-batch-max-size=400
        - --audit-webhook-batch-max-wait=30s
```

For **EKS** specifically, control-plane logging publishes audit
to CloudWatch — pair this connector with the AiSOC AWS
CloudTrail / VPC Flow Logs connectors and run a thin Lambda
that subscribes to the audit log group and POSTs each batch
to the AiSOC endpoint with the header set.

Use the bundled
[recommended audit policy](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#audit-policy)
as a starting point — at minimum log `Metadata` for RBAC,
secrets, and pod subresources.

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → Kubernetes Audit Logs**.
2. **Delivery mode**: `Webhook`.
3. **Cluster name**: a human-readable cluster identifier
   (e.g. `prod-eks-us-east-1`). This is stamped on every event
   so detections can filter by cluster.
4. Leave **Inbox token** blank when using the dedicated route.
5. **Test connection** — AiSOC confirms the dedicated route is
   reachable and the shared secret is configured on the ingest
   service.
6. **Save**.

Audit events start flowing within a few seconds of the apiserver
picking up the webhook config (kube-apiserver does **not**
hot-reload audit config on managed clusters — a control-plane
restart may be required, which managed providers handle for
you).

### Setup — webhook mode (legacy inbox-token path)

If your control plane will not let you inject a custom header,
fall back to the AiSOC inbox path. Each token is bound to a
normalisation template at creation time, so the apiserver does
not need to know anything about AiSOC's internal schema — it
just POSTs raw audit events to the bound URL.

1. **Inbox → Tokens → Create token**.
2. **Template**: `k8s-audit`.
3. **Label**: a human-readable name (e.g. `prod-eks-legacy`).
4. Copy the token.

The endpoint to give the apiserver is:

```
POST https://<your-aisoc-host>/v1/inbox/<token>
Content-Type: application/json
```

Then in the connector configuration paste the token into the
**Inbox token (legacy path)** field. AiSOC routes events from
this path through the same `k8s-audit` normalisation template
as the dedicated route, so detections behave identically.

## Setup — file_tail mode (self-hosted clusters)

### 1. Configure the apiserver to write to a file

Add to your apiserver static-pod manifest:

```yaml
spec:
  containers:
    - command:
        - kube-apiserver
        - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
        - --audit-log-path=/var/log/kubernetes/audit/audit.log
        - --audit-log-maxage=30
        - --audit-log-maxbackup=10
        - --audit-log-maxsize=100
      volumeMounts:
        - name: audit-log
          mountPath: /var/log/kubernetes/audit
  volumes:
    - name: audit-log
      hostPath:
        path: /var/log/kubernetes/audit
        type: DirectoryOrCreate
```

### 2. Mount the audit log into the AiSOC connector pod

The connector reads the audit log via standard POSIX file APIs —
mount it read-only into `services/connectors` at a stable path:

```yaml
spec:
  containers:
    - name: connectors
      volumeMounts:
        - name: k8s-audit-log
          mountPath: /var/log/kubernetes/audit
          readOnly: true
        - name: k8s-audit-cursor
          mountPath: /var/lib/aisoc/k8s-audit
  volumes:
    - name: k8s-audit-log
      hostPath:
        path: /var/log/kubernetes/audit
        type: Directory
    - name: k8s-audit-cursor
      emptyDir: {}
```

(In production, replace `emptyDir` with a PVC so the cursor
survives pod restarts.)

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → Kubernetes Audit Logs**.
2. **Delivery mode**: `File tail`.
3. **Cluster name**: a human-readable cluster identifier.
4. **Audit log path**: `/var/log/kubernetes/audit/audit.log`
   (default).
5. **Cursor file path**: `/var/lib/aisoc/k8s-audit/audit.cursor`
   if you mounted a dedicated cursor volume. Defaults to
   `<audit_log_path>.aisoc-cursor` if blank.
6. **Test connection** — AiSOC confirms the audit log exists
   and is readable.
7. **Save**.

## Polling details

- Default poll interval: **300 seconds** (overrideable per
  instance).
- **Webhook mode**: `fetch_alerts` returns an empty list every
  poll — audit events arrive at the inbox in real time and are
  routed through the normaliser independently. The connector
  poll exists only to surface health / status in the UI.
- **File tail mode**: each poll reads the audit log forward
  from the saved byte cursor up to a hard cap of **8 MiB per
  poll** to bound memory. The cursor is written atomically after
  each successful read.
- **Rotation handling**: if the file size shrinks between polls
  (logrotate truncated it, or the apiserver opened a new
  segment) the cursor resets to 0 — AiSOC starts over from the
  top of the current segment.
- **Partial-line handling**: a final line without a trailing
  `\n` is treated as in-flight and left for the next poll, so
  the cursor never advances past an incomplete JSON record.

## Recommended audit policy

The connector itself is policy-agnostic — feed it whatever you
configure on the apiserver — but for the bundled detection
content you want **at least** the following stages and
resources logged at `Metadata` level or above:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Always log RBAC mutations + bindings
  - level: RequestResponse
    resources:
      - group: rbac.authorization.k8s.io
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
  # Always log pod exec/attach/portforward/proxy
  - level: Request
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward", "pods/proxy"]
  # Always log secret + serviceaccount activity
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "serviceaccounts"]
  # Always log token creation
  - level: Metadata
    resources:
      - group: ""
        resources: ["serviceaccounts/token"]
  # Catch-all — request-level, not response-level
  - level: Metadata
```

A full reference policy lives in the
[Kubernetes upstream docs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#audit-policy).

## Troubleshooting

**Apiserver logs `failed to send audit events to webhook: 503`** —
the AiSOC ingest service is up, but `K8S_AUDIT_SHARED_SECRET`
is unset. The webhook stays disabled until an operator turns
it on. Set the env var on `services/ingest`, restart, retry.

**Apiserver logs `failed to send audit events to webhook: 401`** —
the shared secret on the apiserver side does not match the one
on AiSOC. Check the value the forwarder is injecting into the
`X-AiSOC-K8s-Token` header. Note that AiSOC compares with
constant-time equality, so a partial-prefix match also fails
(this is intentional).

**Apiserver logs `failed to send audit events to webhook: 413`** —
either the body exceeded `K8S_AUDIT_MAX_BODY_BYTES` (default 16
MiB) or the batch exceeded the ingest `MaxBatchSize` cap. Lower
the apiserver's `--audit-webhook-batch-max-size` or raise the
AiSOC limit.

**`Test connection` returns `inbox_token is required in webhook
mode`** — you picked **Webhook** with the **legacy** path but
did not paste a token. Either switch to the dedicated route
(leave the token field blank) or create a token bound to the
`k8s-audit` template under **Inbox → Tokens**.

**`Test connection` returns `audit log path … not found`** —
the connector pod cannot see the file. Check your volume
mount (`kubectl exec` into the pod and `ls -l` the path) and
that the apiserver is actually writing to the configured path.

**Webhook mode is configured but no events arrive** — the
apiserver may not have hot-reloaded the audit config. Restart
the apiserver (or, for managed clusters, wait for the control
plane to roll). You can also smoke-test the dedicated route end
to end with `curl`:

```bash
curl -X POST https://<your-aisoc-host>/v1/ingest/k8s-audit/<tenant_id> \
  -H "Content-Type: application/json" \
  -H "X-AiSOC-K8s-Token: <shared-secret>" \
  -d '{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[]}'
```

A `200 OK` with `{"accepted":0,"rejected":0,...}` confirms the
endpoint is reachable and authenticated.

**File tail mode keeps reading from the top** — your cursor
file is not persistent. Mount a real volume (PVC or hostPath)
for the cursor directory instead of `emptyDir`.

**Severity is too noisy / too quiet** — adjust the audit policy
upstream, not the connector. AiSOC's severity heuristic operates
on what the apiserver actually sends. If you only log
`Metadata`-level requests for RBAC, that's still enough for the
detection content — the verbs and resources are present.

## Related

- [Universal capture / inbox](/docs/connectors/universal-capture) —
  the underlying webhook-receiver infrastructure that
  `webhook` mode reuses.
- [Wiz](/docs/connectors/wiz),
  [Lacework](/docs/connectors/lacework),
  [Prisma Cloud](/docs/connectors/prisma-cloud),
  [Orca](/docs/connectors/orca) — CNAPP connectors that can see
  Kubernetes posture and runtime findings from the cloud side.
  Pair them with this connector for both posture (CNAPP) and
  raw activity (apiserver audit).
