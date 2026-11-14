/**
 * AiSOC — osquery-tls Terraform Module
 *
 * Deploys the aisoc-osquery-tls FastAPI service on Kubernetes (EKS).
 * Handles TLS enrollment, config distribution, log ingestion, and
 * distributed query lifecycle for osqueryd agents.
 */

# ─── Namespace ────────────────────────────────────────────────────────────────

resource "kubernetes_namespace" "osquery_tls" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "app.kubernetes.io/part-of"    = "aisoc"
    }
  }
}

locals {
  namespace = var.create_namespace ? kubernetes_namespace.osquery_tls[0].metadata[0].name : var.namespace
}

# ─── Secret ───────────────────────────────────────────────────────────────────

resource "kubernetes_secret" "osquery_tls" {
  metadata {
    name      = "aisoc-osquery-tls"
    namespace = local.namespace
    labels    = local.common_labels
  }

  data = {
    enroll-secret   = var.enroll_secret
    database-url    = var.database_url
    ingest-base-url = var.ingest_base_url
  }
}

# ─── Deployment ───────────────────────────────────────────────────────────────

resource "kubernetes_deployment" "osquery_tls" {
  metadata {
    name      = "aisoc-osquery-tls"
    namespace = local.namespace
    labels    = local.common_labels
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "aisoc-osquery-tls"
      }
    }

    template {
      metadata {
        labels = local.common_labels
        annotations = {
          "checksum/secret" = sha256(jsonencode(kubernetes_secret.osquery_tls.data))
        }
      }

      spec {
        container {
          name  = "osquery-tls"
          image = "${var.image_repository}:${var.image_tag}"

          port {
            name           = "http"
            container_port = 8007
            protocol       = "TCP"
          }

          env {
            name = "AISOC_OSQUERY_TLS_ENROLL_SECRET"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.osquery_tls.metadata[0].name
                key  = "enroll-secret"
              }
            }
          }

          env {
            name = "DATABASE_URL"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.osquery_tls.metadata[0].name
                key  = "database-url"
              }
            }
          }

          env {
            name = "AISOC_INGEST_BASE_URL"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.osquery_tls.metadata[0].name
                key  = "ingest-base-url"
              }
            }
          }

          resources {
            requests = {
              cpu    = var.resources.requests.cpu
              memory = var.resources.requests.memory
            }
            limits = {
              cpu    = var.resources.limits.cpu
              memory = var.resources.limits.memory
            }
          }

          liveness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            initial_delay_seconds = 15
            period_seconds        = 30
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 3
          }
        }

        termination_grace_period_seconds = 30
      }
    }
  }
}

# ─── Service ──────────────────────────────────────────────────────────────────

resource "kubernetes_service" "osquery_tls" {
  metadata {
    name      = "aisoc-osquery-tls"
    namespace = local.namespace
    labels    = local.common_labels
  }

  spec {
    selector = {
      "app.kubernetes.io/name" = "aisoc-osquery-tls"
    }

    port {
      name        = "http"
      port        = 8007
      target_port = "http"
      protocol    = "TCP"
    }

    type = "ClusterIP"
  }
}

# ─── HPA (optional) ───────────────────────────────────────────────────────────

resource "kubernetes_horizontal_pod_autoscaler_v2" "osquery_tls" {
  count = var.autoscaling.enabled ? 1 : 0

  metadata {
    name      = "aisoc-osquery-tls"
    namespace = local.namespace
    labels    = local.common_labels
  }

  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.osquery_tls.metadata[0].name
    }

    min_replicas = var.autoscaling.min_replicas
    max_replicas = var.autoscaling.max_replicas

    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = var.autoscaling.target_cpu_utilization
        }
      }
    }
  }
}

# ─── Locals ───────────────────────────────────────────────────────────────────

locals {
  common_labels = {
    "app.kubernetes.io/name"       = "aisoc-osquery-tls"
    "app.kubernetes.io/component"  = "osquery-tls"
    "app.kubernetes.io/part-of"    = "aisoc"
    "app.kubernetes.io/managed-by" = "terraform"
    "app.kubernetes.io/version"    = var.image_tag
  }
}
