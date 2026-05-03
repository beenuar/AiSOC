---
sidebar_position: 2
---

# Kubernetes Deployment

## Helm Chart

```bash
helm repo add aisoc https://beenuar.github.io/aisoc/charts
helm install aisoc aisoc/aisoc \
  --set openai.apiKey=sk-... \
  --set postgres.password=secret \
  --namespace aisoc --create-namespace
```

## Manual Manifests

Kubernetes manifests are available in `deploy/k8s/`:

```
deploy/k8s/
├── namespace.yaml
├── configmap.yaml
├── secrets.yaml
├── postgres/
├── redis/
├── api/
├── agents/
├── realtime/
└── web/
```

Apply:

```bash
kubectl apply -f deploy/k8s/ -n aisoc
```

## Scaling

```bash
# Scale the agents service
kubectl scale deployment aisoc-agents --replicas=3 -n aisoc
```

## Ingress

Configure an Ingress controller to route:
- `aisoc.example.com` → `web` service (port 3000)
- `api.aisoc.example.com` → `api` service (port 8000)
- `ws.aisoc.example.com` → `realtime` service (port 8002)
