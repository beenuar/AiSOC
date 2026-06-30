# Walkthrough — `kubernetes-privesc`

> **Namespace SA bound to `cluster-admin`.** A namespace-scoped
> ServiceAccount in the `experiments` namespace is bound to the
> `cluster-admin` ClusterRole by `dev-onboard@example.com` at 02:14
> UTC — outside the standard change-management window. The SA then
> immediately lists `secrets` in `kube-system`.

- **Fixture:** [`examples/alerts/kubernetes-privesc.json`](./alerts/kubernetes-privesc.json)
- **MITRE techniques:** T1098, T1078
- **Severity at intake:** `critical`
- **Confidence band (sandbox):** 100/100, `high`

## Run it

```bash
# Offline simulator:
aisoc-sandbox demo --scenario kubernetes-privesc

# Real stack:
pnpm aisoc:submit examples/alerts/kubernetes-privesc.json
```

## What the agent does, step by step

### Step 0 · DetectAgent · detect

Two native detections fire: `k8s-clusterrolebinding-cluster-admin`
(any new binding to `cluster-admin` outside a change-management
window) and `k8s-secrets-list-by-sa` (a ServiceAccount listing
`kube-system` secrets). Fusion lifts to `critical` because of the
`cluster-admin` blast radius.

### Step 1 · TriageAgent · triage

The graph walk identifies that `dev-onboard@example.com` has not
performed any admin RBAC actions in the last 30 days, that the SA
`debug-runner` was created less than 24 h prior, and that the
namespace `experiments` has no production workloads — three
independent signals consistent with credential-takeover-then-privesc.

**Decision:** Confidence `high` (100/100).

### Step 2 · HuntAgent · hunt

Sweeps the last 24 h for every action by `dev-onboard@example.com`
across the cluster, and every action by the new SA `debug-runner`.
The hunt surfaces the secret-list call as the only follow-on action
so far — the actor hasn't yet exfiltrated anything from `kube-system`.

### Step 3 · RespondAgent · respond

Proposes containment that breaks the privilege chain without taking
the cluster down:

- `k8s.clusterrolebinding.delete({"name": "debug-runner-cluster-admin"})`
- `k8s.serviceaccount.disable({"namespace": "experiments", "name": "debug-runner"})`
- `user.session.revoke_all({"user": "dev-onboard@example.com"})`
- `case.create(...)` at severity `critical`
- `case.notify({"channel": "pagerduty", "service": "kubernetes-on-call"})`

**Decision:** 5 actions proposed; awaiting analyst approval (severity critical).

## What the analyst would do next

1. Approve the `clusterrolebinding.delete` first — it cuts the actor's
   privilege immediately. The SA `disable` and the user session revoke
   can follow in any order.
2. Audit every secret in `kube-system` that the SA could have read in
   its short window of cluster-admin access. Rotate anything sensitive.
3. Open a separate ticket on the change-management process: a
   binding to `cluster-admin` should require a PR + two approvers,
   not a single API call.
4. Review the `experiments` namespace's IAM bindings — there might be
   other latent SA-with-broad-perms patterns to clean up before they
   become incidents.
