---
id: ha-deployment
title: Reference HA deployment
sidebar_label: Reference HA deployment
---

# Reference high-availability deployment

**What "HA" means on this page, precisely:** losing one node, or one pod of any
component, costs neither availability nor data. It does not mean multi-region,
and it does not mean zero-downtime schema migrations. Both are out of scope and
neither is claimed.

```bash
helm install aisoc infra/helm/aisoc -n aisoc --create-namespace \
  -f infra/helm/aisoc/values-ha.yaml
```

## What was actually exercised, and what was not

On **2026-09-27** the chart was installed on a three-node
[kind](https://kind.sigs.k8s.io/) cluster (Kubernetes v1.34.0) on an Apple M5
Max with 8 CPUs and 15.6 GiB allocated to the container runtime, with
`values-ha.yaml` plus `ci/kind-values.yaml`. Three Kafka brokers formed a KRaft
quorum, two ingest replicas and two fusion replicas came up, the migration
chain applied, and 10,000 events pushed through the public ingest endpoint all
became alert rows. A fusion pod was then destroyed mid-stream and no event was
lost or duplicated. The figures are on the
[Measured performance](./performance.md) page and the raw JSON is under
`docs/perf/results/`.

**Not exercised, and therefore not claimed:**

- a managed Kubernetes service (EKS, GKE, AKS) or a bare-metal cluster;
- more than three nodes, or nodes that are separate machines rather than
  containers on one kernel;
- a real cloud load balancer or ingress controller in front of the release;
- managed PostgreSQL or ClickHouse (see below);
- NetworkPolicy enforcement, which needs a CNI that implements it;
- persistent volumes, which the kind run deliberately switched off;
- sustained operation. The longest run was a few minutes.

`docs/audit/REPOSITORY_REALITY.md` carries the same distinction in the same
words. Do not read "the chart installs and survives a pod kill on kind" as
"the chart is production-ready on your cluster".

## The two stateful things this chart does not make highly available

PostgreSQL and ClickHouse are left external on purpose. Replicated Postgres
with automated failover, and a sharded replicated ClickHouse, are each a full
operational discipline. A chart that shipped a single-pod database under a file
called `values-ha.yaml` would be claiming something it does not do.

### PostgreSQL

The alert store, the case store, the audit log and every tenant row. Losing it
loses the product. Point the release at a service that does replication and
point-in-time recovery for you:

| Option | Failover | Point-in-time recovery | Notes |
|---|---|---|---|
| Amazon RDS / Aurora PostgreSQL | Multi-AZ, automatic | Yes | The commercial deployment uses Multi-AZ RDS |
| Google Cloud SQL for PostgreSQL | Regional, automatic | Yes | |
| Azure Database for PostgreSQL Flexible Server | Zone-redundant | Yes | |
| CloudNativePG operator | In-cluster, automatic | Yes, via WAL archiving | If you must stay in the cluster |
| The bundled Bitnami subchart | None | None | Development only. `postgresql.enabled` is `false` for this reason |

Whichever you choose, the **two-role split is not optional**. `aisoc` owns the
schema and applies migrations; `aisoc_app` is the DML-only runtime role every
service connects as. A managed service's master user is a superuser, and a
superuser ignores every row-level-security policy in this schema even under
`FORCE ROW LEVEL SECURITY`, so running the services as the owner leaves all
of the policies filtering nothing, silently. Verify with:

```bash
python scripts/check_runtime_db_role.py --dsn "$DATABASE_URL"
```

`rolsuper` and `rolbypassrls` must both read false and the role must own
nothing.

### ClickHouse

The event lake behind `/lake/sql` and hunt. It is a `full`-profile capability:
CORE does not run it and the alert path does not depend on it, so losing it
costs historical search rather than detection.

| Option | Notes |
|---|---|
| ClickHouse Cloud | Managed replication and backups |
| Altinity.Cloud | Managed, also available in your own account |
| Altinity ClickHouse operator | In-cluster; `ReplicatedMergeTree` plus ClickHouse Keeper |
| A single container | Development only. This is what `docker-compose` runs |

Set `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT` (9000, the native port, not 8123),
`CLICKHOUSE_DATABASE`, `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD` on the API
and fusion. There is no `CLICKHOUSE_URL`: nothing reads that name, and
supplying only a URL leaves the client on its defaults, which is how
`/lake/sql` once answered every query with `Connection refused (localhost:9000)`
while fusion archived to the same store perfectly well.

## Kafka

`values-ha.yaml` runs three brokers in KRaft combined mode with replication
factor 3 and `min.insync.replicas=2`. A write is acknowledged once two brokers
hold it, so one broker can be lost with neither data loss nor a write stall,
and the PodDisruptionBudget refuses to make a second broker unavailable
voluntarily.

Swap in a managed broker by turning the bundled one off:

```yaml
kafka:
  deploy:
    enabled: false
  bootstrapServers: "b-1.example.kafka.us-east-1.amazonaws.com:9092,b-2...:9092"
```

Amazon MSK, Confluent Cloud and Redpanda Cloud all work; the platform uses
plain Kafka protocol with no vendor extensions.

Two things the chart now does that it did not before, both because the absence
was invisible rather than noisy:

- **Every deployment gets `KAFKA_BOOTSTRAP_SERVERS`.** It used to be set on
  the UEBA deployment and nowhere else, so ingest and fusion fell through to
  their in-code default of `localhost:9092`, which inside a pod resolves to
  the pod itself. Every object installed, every probe went green, and the
  spine was not connected.
- **A post-install hook creates the topics.** Auto-creation alone loses the
  first batch after an install: the produce that triggers creation is the one
  that fails with `Unknown Topic Or Partition`. Pre-creating also pins
  partitions and replication factor rather than inheriting whatever the broker
  defaults happened to be.

### Fusion replicas are capped by partitions, not by the HPA

Fusion replicas are members of one Kafka consumer group, so the useful ceiling
is the partition count. With `numPartitions: 3`, a fourth replica idles.
Raise `kafka.deploy.numPartitions` before raising `maxReplicas`, and note that
increasing partitions on an existing topic does not redistribute the data
already in it.

## Readiness, and why a detached consumer is not restarted

Consumer services expose `/readyz`, which evaluates a probe per subscription
and answers 503 naming any that have detached. The chart wires it as the
readiness probe for `api`, `ingest`, `alert-fusion`, `agents` and `realtime`.
It used to wire `/health` for both probes, and `/health` answers 200 while the
process is alive whatever its consumer is doing.

A detached replica is therefore pulled out of service but **not** killed. That
is deliberate: restarting on readiness failure turns a broker or schema fault
into a restart loop that hides the cause. What the chart does instead is
*order* startup, with an init container that holds a consumer back until a
broker answers, so the common case (a cold install racing the brokers' quorum
election) cannot leave a pod running with nothing consuming.

If `/readyz` is 503 for a fusion replica, look at the broker before you look at
the pod.

## Migrations

The chart does not run them. Apply the chain as the **owner** role, with
`AISOC_APP_DB_PASSWORD` in the environment so the runtime role gets its login:

```bash
kubectl -n aisoc exec deploy/aisoc-api -- python -m app.scripts.run_migrations
```

Run it before or during the rollout, not after: a service that starts against
an older schema fails in whatever way that schema's absence produces. The
CI upgrade test (`.github/workflows/upgrade-test.yml`) exercises the previous
minor to the current one with data already present, which is the case a fresh
install never covers.

## Failure injection

Prove the deployment survives losing a fusion replica on your own cluster
rather than trusting this page:

```bash
AISOC_INGEST_TOKEN=<token> python3 scripts/chaos/fusion_restart.py \
    --target kubernetes --namespace aisoc \
    --ingest-url https://<your-ingest-host>/v1/ingest/batch
```

It pushes a paced stream, destroys a replica part way through, and then asserts
against PostgreSQL that every accepted event produced exactly one alert row. It
fails on a missing event and on a duplicated one, and it names the sequence
numbers so a failure is reproducible.
