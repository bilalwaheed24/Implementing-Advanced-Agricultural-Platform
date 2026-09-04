output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "database_endpoint" {
  value     = aws_db_instance.postgres.endpoint
  sensitive = true
}

output "secrets_manager_arn" {
  value = aws_secretsmanager_secret.app.arn
}

output "exports_bucket" {
  value = aws_s3_bucket.exports.bucket
}

output "vpc_id" {
  value = aws_vpc.main.id
}
