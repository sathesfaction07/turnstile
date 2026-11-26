output "gateway_service" {
  value = google_cloud_run_v2_service.gateway.name
}

output "gateway_service_account" {
  value = google_service_account.gateway.email
}
