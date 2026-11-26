variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "network" {
  type        = string
  description = "VPC network with a route to the on-premises policy system."
}

variable "connector_cidr" {
  type    = string
  default = "10.8.0.0/28"
}

variable "legacy_url" {
  type        = string
  description = "Base URL of the policy system's SOAP service, reachable from the VPC."
}

variable "legacy_user" {
  type    = string
  default = "svc_gateway"
}

variable "resource_url" {
  type        = string
  description = "The gateway's public MCP URL behind Apigee; agent tokens must be issued for it."
}

variable "image_tag" {
  type    = string
  default = "latest"
}
