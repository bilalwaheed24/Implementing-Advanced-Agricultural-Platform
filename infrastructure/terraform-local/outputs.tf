output "url" {
  value = "http://127.0.0.1:${var.frontend_port}"
}

output "containers" {
  value = [for c in [docker_container.frontend, docker_container.api, docker_container.ai,
  docker_container.ledger, docker_container.db] : c.name]
}
