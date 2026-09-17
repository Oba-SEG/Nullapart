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