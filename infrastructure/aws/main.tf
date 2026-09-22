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
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
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

# Dedicated EC2 mail nodes
#
# Mail nodes intentionally use stable instance slots rather than an ASG because
# SMTP identity (EIP/PTR/HELO) and queued responsibility must survive ordinary
# instance replacement. Each slot owns a persistent encrypted spool volume and EIP.
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_instance" "mail_node" {
  count = var.mail_node_desired_capacity

  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.mail_node_instance_type
  subnet_id              = element(module.vpc.public_subnets, count.index % length(module.vpc.public_subnets))
  vpc_security_group_ids = [module.security_groups["mail-node"].security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.mail_node.name

  associate_public_ip_address = false

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 20
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  user_data = base64encode("# Bootstrap intentionally supplied by immutable image/config management before production commissioning.")

  tags = {
    Name        = format("mxin-%s-%02d", var.environment, count.index + 1)
    Environment = var.environment
    NodeSlot    = tostring(count.index + 1)
  }
}

resource "aws_eip" "mail_node" {
  count  = var.mail_node_desired_capacity
  domain = "vpc"

  tags = {
    Name     = format("nullapart-%s-mail-%02d", var.environment, count.index + 1)
    NodeSlot = tostring(count.index + 1)
  }
}

resource "aws_eip_association" "mail_node" {
  count         = var.mail_node_desired_capacity
  instance_id   = aws_instance.mail_node[count.index].id
  allocation_id = aws_eip.mail_node[count.index].id
}

resource "aws_ebs_volume" "mail_spool" {
  count = var.mail_node_desired_capacity

  availability_zone = aws_instance.mail_node[count.index].availability_zone
  encrypted         = true
  type              = "gp3"
  size              = var.mail_spool_volume_gib

  tags = {
    Name     = format("nullapart-%s-mail-spool-%02d", var.environment, count.index + 1)
    NodeSlot = tostring(count.index + 1)
    Purpose  = "postfix-spool"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_volume_attachment" "mail_spool" {
  count = var.mail_node_desired_capacity

  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.mail_spool[count.index].id
  instance_id = aws_instance.mail_node[count.index].id
}

# Internet-facing SMTP only. No SSH ingress.
resource "aws_security_group_rule" "mail_smtp_ingress" {
  type              = "ingress"
  from_port         = 25
  to_port           = 25
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = module.security_groups["mail-node"].security_group_id
  description       = "Internet SMTP"
}

resource "aws_security_group_rule" "mail_smtp_egress" {
  type              = "egress"
  from_port         = 25
  to_port           = 25
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = module.security_groups["mail-node"].security_group_id
  description       = "Direct MX delivery"
}

resource "aws_security_group_rule" "mail_https_egress" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = module.security_groups["mail-node"].security_group_id
  description       = "Approved HTTPS dependencies and package/image retrieval"
}

resource "aws_iam_instance_profile" "mail_node" {
  name = "nullapart-${var.environment}-mail"
  role = aws_iam_role.mail_node.name
}

resource "aws_iam_role" "mail_node" {
  name = "nullapart-${var.environment}-mail"

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

resource "aws_iam_role_policy_attachment" "mail_node_ssm" {
  role       = aws_iam_role.mail_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# RDS PostgreSQL — password managed via Secrets Manager
resource "random_password" "rds_master" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "rds_password" {
  name        = "nullapart-${var.environment}-rds-password"
  description = "Master password for Nullapart RDS PostgreSQL"
  tags = {
    Name = "nullapart-rds-password"
  }
}

resource "aws_secretsmanager_secret_version" "rds_password" {
  secret_id = aws_secretsmanager_secret.rds_password.id
  secret_string = jsonencode({
    username = "nullapart_admin"
    password = random_password.rds_master.result
    engine   = "postgres"
    host     = module.rds.db_instance_address
    port     = module.rds.db_instance_port
    dbname   = "nullapart"
  })
}

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
  password = random_password.rds_master.result
  
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

output "mail_node_ids" {
  description = "Stable mail node instance slots"
  value       = aws_instance.mail_node[*].id
}

output "mail_node_eips" {
  description = "Stable public SMTP addresses used for PTR/HELO commissioning"
  value       = aws_eip.mail_node[*].public_ip
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = module.rds.db_instance_endpoint
}