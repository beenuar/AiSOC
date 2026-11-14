output "service_name" {
  description = "Kubernetes Service name for aisoc-osquery-tls"
  value       = kubernetes_service.osquery_tls.metadata[0].name
}

output "service_namespace" {
  description = "Kubernetes namespace the service is deployed in"
  value       = local.namespace
}

output "service_cluster_ip" {
  description = "ClusterIP allocated to the service"
  value       = kubernetes_service.osquery_tls.spec[0].cluster_ip
}

output "service_port" {
  description = "Port the service listens on"
  value       = 8007
}

output "deployment_name" {
  description = "Kubernetes Deployment name"
  value       = kubernetes_deployment.osquery_tls.metadata[0].name
}

output "internal_url" {
  description = "In-cluster URL for other services to reach osquery-tls"
  value       = "http://${kubernetes_service.osquery_tls.metadata[0].name}.${local.namespace}.svc.cluster.local:8007"
}
