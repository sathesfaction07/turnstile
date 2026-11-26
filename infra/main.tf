# Turnstile on Cloud Run, between Apigee and the on-premises policy system.
#
# Validated in CI (`terraform validate`), never applied by this repository: the portfolio runs
# at zero cost. Applying it needs a project with billing, an Apigee X organisation, and a
# network path (Interconnect or VPN) to the policy system.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "vpcaccess.googleapis.com",
    "artifactregistry.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# The gateway's identity. It can read its two secrets and nothing else; it has no access to
# any Google API data.
resource "google_service_account" "gateway" {
  account_id   = "turnstile-gateway"
  display_name = "Turnstile MCP gateway"
}

resource "google_secret_manager_secret" "legacy_password" {
  secret_id = "turnstile-legacy-password"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "agent_registry" {
  secret_id = "turnstile-agent-registry"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_iam_member" "gateway_reads" {
  for_each = {
    password = google_secret_manager_secret.legacy_password.id
    registry = google_secret_manager_secret.agent_registry.id
  }
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gateway.email}"
}

# Egress to the on-premises policy system goes through the VPC, never the internet.
resource "google_vpc_access_connector" "to_onprem" {
  name          = "turnstile-onprem"
  region        = var.region
  network       = var.network
  ip_cidr_range = var.connector_cidr
  depends_on    = [google_project_service.apis]
}

resource "google_cloud_run_v2_service" "gateway" {
  name     = "turnstile"
  location = var.region
  # Only the internal load balancer that Apigee routes to can reach the service.
  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.gateway.email
    # The legacy system takes 4 concurrent requests; each instance holds 3 at most
    # (pas_client.max_concurrency), so one instance is the safe ceiling until the
    # concurrency limit is shared across instances.
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    vpc_access {
      connector = google_vpc_access_connector.to_onprem.id
      egress    = "PRIVATE_RANGES_ONLY"
    }
    volumes {
      name = "registry"
      secret {
        secret = google_secret_manager_secret.agent_registry.secret_id
        items {
          version = "latest"
          path    = "agents.json"
        }
      }
    }
    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/turnstile/gateway:${var.image_tag}"
      env {
        name  = "LEGACY_URL"
        value = var.legacy_url
      }
      env {
        name  = "LEGACY_USER"
        value = var.legacy_user
      }
      env {
        name = "LEGACY_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.legacy_password.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "TURNSTILE_AGENTS_FILE"
        value = "/secrets/registry/agents.json"
      }
      env {
        name  = "TURNSTILE_RESOURCE_URL"
        value = var.resource_url
      }
      volume_mounts {
        name       = "registry"
        mount_path = "/secrets/registry"
      }
      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }
  depends_on = [google_secret_manager_secret_iam_member.gateway_reads]
}
