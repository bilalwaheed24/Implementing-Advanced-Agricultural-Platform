# Secrets come from .env via TF_VAR_* (scripts/tf_local_up.sh exports them); they are never
# written to a tfvars file. Terraform state does hold them — it is gitignored (*.tfstate).

variable "jwt_secret" {
  type      = string
  sensitive = true
}

variable "encryption_key" {
  type      = string
  sensitive = true
}

variable "service_token" {
  type      = string
  sensitive = true
}

variable "postgres_password" {
  type      = string
  sensitive = true
}

variable "frontend_port" {
  description = "Host port for the UI (bound to 127.0.0.1 only)"
  type        = number
  default     = 8080
}

variable "image_tag" {
  description = "Tag of the locally built images (docker compose build produces :local)"
  type        = string
  default     = "local"
}
