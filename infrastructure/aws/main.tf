# Nullapart AWS Infrastructure
# This is a foundational template - detailed production IaC comes later

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
  
  # Production uses remote state with encryption
  # backend "s3" {
  #   bucket = "nullapart-terraform-state"
  #   key    = "infrastructure/terraform.tfstate"
  #   region = "af-south-1"
  # }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Nullapart"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# GitHub OIDC Provider for CI/CD deployment identity.
# Resolve the live certificate chain instead of shipping a placeholder thumbprint.
data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    data.tls_certificate.github_actions.certificates[
      length(data.tls_certificate.github_actions.certificates) - 1
    ].sha1_fingerprint
  ]
  tags = {
    Name = "nullapart-github-oidc"
  }
}

# Deployment role assumed by GitHub Actions CI/CD
resource "aws_iam_role" "github_actions_deploy" {
  name = "nullapart-${var.environment}-github-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:obakeng-SEG/Nullapart:ref:refs/heads/main"
        }
      }
    }]
  })
}

# Deployment policy: ECS + ECR + S3 + RDS + SQS + CloudWatch (least privilege)
resource "aws_iam_role_policy" "github_actions_deploy" {
  name = "nullapart-deploy-policy"
  role = aws_iam_role.github_actions_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:UpdateService",
          "ecs:DescribeServices",
          "ecs:DescribeTaskDefinition",
          "ecs:RegisterTaskDefinition",
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:ResourceTag/Project" = "Nullapart"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = "${aws_s3_bucket.artifacts.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:ResourceTag/Project" = "Nullapart"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "*"
      },
    ]
  })
}

# VPC Configuration
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "nullapart-${var.environment}"
  cidr = var.vpc_cidr
  
  azs             = ["${var.aws_region}a", "${var.aws_region}b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
  
  enable_nat_gateway     = true
  single_nat_gateway     = var.environment == "dev"
  enable_dns_hostnames   = true
  enable_dns_support     = true
  
  tags = {
    Name = "nullapart-vpc"
  }
}

# Security Groups
module "security_groups" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"
  
  for_each = toset([
    "control-plane",
    "mail-node",
    "redis",
    "postgresql"
  ])
  
  name        = "nullapart-${var.environment}-${each.key}"
  description = "Security group for ${each.key} in ${var.environment}"
  vpc_id      = module.vpc.vpc_id
  
  # Ingress rules added per service in dedicated modules
  egress_with_self = [
    {
      rule = "all-all"
    }
  ]
  
  tags = {
    Name = "nullapart-${var.environment}-${each.key}"
  }
}

# ECS Cluster for Control Plane (ordinary containers)
resource "aws_ecs_cluster" "control_plane" {
  name = "nullapart-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "nullapart-ecs"
  }
}

resource "aws_ecs_cluster_capacity_providers" "control_plane" {
  cluster_name = aws_ecs_cluster.control_plane.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 1
  }
}

# Dedicated EC2 mail nodes (stable SMTP identity / queue lifecycle)
resource "aws_launch_template" "mail_node" {
  name_prefix = "nullapart-mail-${var.environment}-"

  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = var.mail_node_instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.mail_node.name
  }

  network_interfaces {
    security_groups             = [module.security_groups["mail-node"].security_group_id]
    associate_public_ip_address = true
  }

  user_data = base64encode("#TODO: Postfix + Rspamd bootstrap script")

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "nullapart-mail-node"
      Environment = var.environment
    }
  }
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_autoscaling_group" "mail_nodes" {
  name                = "nullapart-mail-${var.environment}"
  min_size            = var.mail_node_desired_capacity
  max_size            = var.mail_node_desired_capacity * 2
  desired_capacity    = var.mail_node_desired_capacity
  vpc_zone_identifier = module.vpc.public_subnets

  launch_template {
    id      = aws_launch_template.mail_node.id
    version = "$Latest"
  }

  tags = [{
    key                 = "Name"
    value               = "nullapart-mail-node"
    propagate_at_launch = true
  }]
}

resource "aws_iam_instance_profile" "mail_node" {
  name = "nullapart-mail-${var.environment}"
  role = aws_iam_role.mail_node.name
}

resource "aws_iam_role" "mail_node" {
  name = "nullapart-mail-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

# RDS PostgreSQL
module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"
  
  identifier = "nullapart-${var.environment}"
  
  engine               = "postgres"
  engine_version       = "16.3"
  family               = "postgres16"
  major_engine_version = "16"
  
  instance_class    = var.environment == "prod" ? "db.r6g.large" : "db.t4g.medium"
  allocated_storage = 100
  max_allocated_storage = 500
  
  db_name  = "nullapart"
  username = "nullapart_admin"
  # password set via SSM Parameter Store or OpenBao
  
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnets
  security_groups    = [module.security_groups["postgresql"].security_group_id]
  
  backup_retention_period = var.environment == "prod" ? 30 : 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "mon:04:00-mon:05:00"
  
  skip_final_snapshot       = var.environment != "prod"
  final_snapshot_identifier = "nullapart-${var.environment}-final"
  
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  
  tags = {
    Name = "nullapart-rds"
  }
}

# ElastiCache Redis/Valkey
resource "aws_elasticache_subnet_group" "redis" {
  name       = "nullapart-${var.environment}-redis"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "nullapart-${var.environment}-redis"
  description          = "Nullapart regional cache/runtime state"

  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.environment == "prod" ? "cache.t4g.small" : "cache.t4g.micro"
  port                 = 6379
  parameter_group_name = "default.redis7"

  num_cache_clusters         = var.environment == "prod" ? 2 : 1
  automatic_failover_enabled = var.environment == "prod"
  multi_az_enabled           = var.environment == "prod"

  subnet_group_name  = aws_elasticache_subnet_group.redis.name
  security_group_ids = [module.security_groups["redis"].security_group_id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.redis_auth_token

  snapshot_retention_limit = var.environment == "prod" ? 7 : 1
  snapshot_window          = "03:00-05:00"
  maintenance_window       = "mon:05:00-mon:06:00"
  apply_immediately        = var.environment != "prod"

  tags = {
    Name = "nullapart-redis"
  }
}

# S3 for artifacts
resource "aws_s3_bucket" "artifacts" {
  bucket = "nullapart-${var.environment}-artifacts-${var.aws_region}"
  
  tags = {
    Name        = "nullapart-artifacts"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.control_plane.name
}

output "mail_asg_name" {
  description = "Mail node autoscaling group name"
  value       = aws_autoscaling_group.mail_nodes.name
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = module.rds.db_instance_endpoint
}