# Nullapart Infrastructure Variables
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "af-south-1"
}

variable "environment" {
  description = "Environment: dev, staging, production"
  type        = string
  default     = "dev"
}

variable "deployment_id" {
  description = "Unique deployment identifier (e.g., CZA-1)"
  type        = string
  default     = "CZA-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "mail_node_instance_type" {
  description = "EC2 instance type for mail nodes"
  type        = string
  default     = "t3.small"
}

variable "mail_node_desired_capacity" {
  description = "Desired number of mail nodes"
  type        = number
  default     = 2
}

variable "postfix_config" {
  description = "Postfix configuration map"
  type        = map(string)
  default     = {}
}
variable "redis_auth_token" {
  description = "Redis AUTH token loaded from the approved secret store at deployment time"
  type        = string
  sensitive   = true
}

variable "mail_spool_volume_gib" {
  description = "Persistent encrypted Postfix spool volume size per mail node"
  type        = number
  default     = 100
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for the Control Plane ALB HTTPS listener"
  type        = string
}
