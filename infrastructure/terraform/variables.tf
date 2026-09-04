variable "project" {
  description = "Project name used to prefix resources"
  type        = string
  default     = "absp"
}

variable "environment" {
  description = "development | staging | production"
  type        = string
  default     = "production"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "app_cpu" {
  type    = number
  default = 512
}

variable "app_memory" {
  type    = number
  default = 1024
}

variable "app_desired_count" {
  type    = number
  default = 2
}
