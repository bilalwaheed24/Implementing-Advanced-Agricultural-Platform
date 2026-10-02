# Local deployment of the five-service stack with Terraform (ADR-016), on the Docker engine
# of this machine. Same topology and hardening as docker-compose.yml:
#
#   browser → frontend :8080 → api → ai | ledger | db
#
# The AWS target lives in ../terraform. Run this one with scripts/tf_local_up.sh.
terraform {
  required_version = ">= 1.5"
  required_providers {
    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }
  }
}

provider "docker" {}

locals {
  name   = "absp"
  db_url = "postgresql+psycopg://absp:${var.postgres_password}@db:5432/absp"

  # Applied to every application container.
  hardening = {
    read_only     = true
    security_opts = ["no-new-privileges:true"]
  }
}

# ---------------------------------------------------------------------------
# Images — built by `docker compose build`; Terraform deploys what is there.
# A rebuilt image has a new id, so the next apply replaces its container.
# ---------------------------------------------------------------------------
data "docker_image" "app" {
  for_each = toset(["api", "ai", "ledger", "frontend"])
  name     = "absp-${each.key}:${var.image_tag}"
}

resource "docker_image" "postgres" {
  name         = "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
  keep_locally = true
}

# ---------------------------------------------------------------------------
# Networks and volumes
# ---------------------------------------------------------------------------
resource "docker_network" "edge" { # frontend ↔ api
  name = "${local.name}-edge"
}

resource "docker_network" "backend" { # api ↔ ai / ledger / db, no outside access
  name     = "${local.name}-backend"
  internal = true
}

resource "docker_volume" "pgdata" { name = "${local.name}-pgdata" }
resource "docker_volume" "ledger" { name = "${local.name}-ledger" }
resource "docker_volume" "data" { name = "${local.name}-data" }

# ---------------------------------------------------------------------------
# Containers. `wait = true` blocks until the container's health check passes, which
# gives the same start order as compose's `condition: service_healthy`.
# ---------------------------------------------------------------------------
resource "docker_container" "db" {
  name          = "${local.name}-db"
  image         = docker_image.postgres.image_id
  restart       = "unless-stopped"
  security_opts = local.hardening.security_opts
  env = [
    "POSTGRES_DB=absp",
    "POSTGRES_USER=absp",
    "POSTGRES_PASSWORD=${var.postgres_password}",
  ]
  volumes {
    volume_name    = docker_volume.pgdata.name
    container_path = "/var/lib/postgresql/data"
  }
  networks_advanced {
    name    = docker_network.backend.name
    aliases = ["db"]
  }
  healthcheck {
    test     = ["CMD-SHELL", "pg_isready -U absp -d absp"]
    interval = "10s"
    retries  = 5
  }
  wait         = true
  wait_timeout = 120
}

resource "docker_container" "ledger" {
  name          = "${local.name}-ledger"
  image         = data.docker_image.app["ledger"].id
  restart       = "unless-stopped"
  read_only     = local.hardening.read_only
  security_opts = local.hardening.security_opts
  tmpfs         = { "/tmp" = "" }
  capabilities { drop = ["ALL"] }
  env = [
    "SERVICE_TOKEN=${var.service_token}",
    "LEDGER_ALLOW_RESET=true", # demo only: lets seed_demo.py --reset wipe the chain
  ]
  volumes {
    volume_name    = docker_volume.ledger.name
    container_path = "/data/ledger"
  }
  networks_advanced {
    name    = docker_network.backend.name
    aliases = ["ledger"]
  }
  wait         = true
  wait_timeout = 120
}

resource "docker_container" "ai" {
  name          = "${local.name}-ai"
  image         = data.docker_image.app["ai"].id
  restart       = "unless-stopped"
  read_only     = local.hardening.read_only
  security_opts = local.hardening.security_opts
  tmpfs         = { "/tmp" = "" }
  capabilities { drop = ["ALL"] }
  env = ["SERVICE_TOKEN=${var.service_token}"]
  networks_advanced {
    name    = docker_network.backend.name
    aliases = ["ai"]
  }
  wait         = true
  wait_timeout = 300
}

resource "docker_container" "api" {
  name          = "${local.name}-api"
  image         = data.docker_image.app["api"].id
  restart       = "unless-stopped"
  read_only     = local.hardening.read_only
  security_opts = local.hardening.security_opts
  tmpfs         = { "/tmp" = "" }
  capabilities { drop = ["ALL"] }
  command = ["--seed"] # creates the schema and seeds demo data on first start
  env = [
    "ENV=development",
    "DEMO_MODE=true",
    "DATABASE_URL=${local.db_url}",
    "AI_SERVICE_URL=http://ai:8100",
    "LEDGER_SERVICE_URL=http://ledger:8200",
    "SERVICE_TOKEN=${var.service_token}",
    "JWT_SECRET=${var.jwt_secret}",
    "ENCRYPTION_KEY=${var.encryption_key}",
    "CORS_ORIGINS=http://127.0.0.1:${var.frontend_port},http://localhost:${var.frontend_port}",
    "DATA_DIR=/app/data",
  ]
  volumes {
    volume_name    = docker_volume.data.name
    container_path = "/app/data"
  }
  networks_advanced {
    name    = docker_network.edge.name
    aliases = ["api"]
  }
  networks_advanced {
    name = docker_network.backend.name
  }
  wait         = true
  wait_timeout = 300
  depends_on   = [docker_container.db, docker_container.ai, docker_container.ledger]
}

resource "docker_container" "frontend" {
  name          = "${local.name}-frontend"
  image         = data.docker_image.app["frontend"].id
  restart       = "unless-stopped"
  read_only     = local.hardening.read_only
  security_opts = local.hardening.security_opts
  tmpfs         = { "/tmp" = "" }
  capabilities { drop = ["ALL"] }
  ports {
    internal = 8080
    external = var.frontend_port
    ip       = "127.0.0.1" # the only published port
  }
  networks_advanced {
    name = docker_network.edge.name
  }
  wait         = true
  wait_timeout = 60
  depends_on   = [docker_container.api]
}
