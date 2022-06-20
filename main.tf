terraform {
  cloud {
    organization = "jonassteinberg"

    workspaces {
      name = "burgerworld-hello-ecs"
    }
  }
}

locals {
  enabled = module.this.enabled
}

module "source_endpoint_label" {
  source  = "cloudposse/label/null"
  version = "0.25.0"

  attributes = [var.team_name]
  context    = module.this.context
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

#######
# KMS #
#######

resource "aws_kms_key" "burgerworld-hello-ecs-ecr-symmetric-key" {

  description = "symmetric key used for general burgerworld-hello-ecs ecr encryption"
  key_usage   = var.burgerworld_hello_ecs_ecr_symmetric_key_usage
  # required by ecr to be SYMMETRIC_DEFAULT
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  is_enabled               = var.burgerworld_hello_ecs_ecr_symmetric_key_is_enabled
  enable_key_rotation      = var.burgerworld_hello_ecs_ecr_symmetric_key_rotation
  tags = {
    creator = "jonassteinberg1@gmail.com"
    created = "06-16-2022-16-57-31"
  }
}

resource "aws_kms_alias" "burgerworld-hello-ecs-ecr-symmetric-key-alias" {
  name          = "alias/${var.burgerworld-hello-ecs-ecr-symmetric-key-alias}"
  target_key_id = aws_kms_key.burgerworld-hello-ecs-ecr-symmetric-key.key_id
}

#######
# ECR #
#######

resource "aws_ecr_repository" "burgerworld-hello-ecs-integration-test-local" {
  name                 = "${var.burgerworld_hello_ecs_app_name}-integration-test-local"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = var.burgerworld_hello_ecs_encryption_type
    kms_key         = aws_kms_key.burgerworld-hello-ecs-ecr-symmetric-key.arn
  }
  tags = {
    Name = "${var.burgerworld_hello_ecs_app_name}-integration-test-local"
  }
}

resource "aws_ecr_repository" "burgerworld-hello-ecs-web-local" {
  name                 = "${var.burgerworld_hello_ecs_app_name}-web-local"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = var.burgerworld_hello_ecs_encryption_type
    kms_key         = aws_kms_key.burgerworld-hello-ecs-ecr-symmetric-key.arn
  }
  tags = {
    Name = "${var.burgerworld_hello_ecs_app_name}-web"
  }
}

resource "aws_ecr_repository" "burgerworld-hello-ecs-web" {
  name                 = "${var.burgerworld_hello_ecs_app_name}-web"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = var.burgerworld_hello_ecs_encryption_type
    kms_key         = aws_kms_key.burgerworld-hello-ecs-ecr-symmetric-key.arn
  }
  tags = {
    Name = "${var.burgerworld_hello_ecs_app_name}-web"
  }
}

resource "aws_ecr_repository" "burgerworld-hello-ecs-nginx" {
  name                 = "${var.burgerworld_hello_ecs_app_name}-nginx"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = var.burgerworld_hello_ecs_encryption_type
    kms_key         = aws_kms_key.burgerworld-hello-ecs-ecr-symmetric-key.arn
  }
  tags = {
    Name = "${var.burgerworld_hello_ecs_app_name}-nginx"
  }
}

resource "aws_ecr_repository" "burgerworld-hello-ecs-integration-test" {
  name                 = "${var.burgerworld_hello_ecs_app_name}-integration-test"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = var.burgerworld_hello_ecs_encryption_type
    kms_key         = aws_kms_key.burgerworld-hello-ecs-ecr-symmetric-key.arn
  }
  tags = {
    Name = "${var.burgerworld_hello_ecs_app_name}-integration-test"
  }
}

resource "aws_ecr_registry_policy" "burgerworld-hello-ecs-ecr-permissions-policy" {
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "burgerworld-hello-ecs-ecr-permissions-policy",
        Effect = "Allow",
        Principal = {
          "AWS" : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/admin"
        },
        Action = [
          "ecr:*"
        ],
        Resource = [
          "arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}/*"
        ]
      }
    ]
  })
}

#######
# IAM #
#######

data "aws_iam_policy_document" "burgerworld-hello-ecs-ecr-permissions-policy-document" {
  statement {
    sid    = "burgerworld-hello-ecs-ecr-permissions-policy"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/admin"]
    }
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeRepositories",
      "ecr:GetRepositoryPolicy",
      "ecr:ListImages",
      "ecr:DeleteRepository",
      "ecr:BatchDeleteImage",
      "ecr:SetRepositoryPolicy",
      "ecr:DeleteRepositoryPolicy"
    ]
  }
}

resource "aws_ecr_repository_policy" "burgerworld-hello-ecs-integration-test-repository-policy" {
  repository = aws_ecr_repository.burgerworld-hello-ecs-integration-test.name
  policy     = data.aws_iam_policy_document.burgerworld-hello-ecs-ecr-permissions-policy-document.json
}

resource "aws_ecr_repository_policy" "burgerworld-hello-ecs-web-repository-policy" {
  repository = aws_ecr_repository.burgerworld-hello-ecs-web.name
  policy     = data.aws_iam_policy_document.burgerworld-hello-ecs-ecr-permissions-policy-document.json
}

resource "aws_ecr_repository_policy" "burgerworld-hello-ecs-web-local-repository-policy" {
  repository = aws_ecr_repository.burgerworld-hello-ecs-web-local.name
  policy     = data.aws_iam_policy_document.burgerworld-hello-ecs-ecr-permissions-policy-document.json
}
resource "aws_ecr_repository_policy" "burgerworld-hello-ecs-nginx-repository-policy" {
  repository = aws_ecr_repository.burgerworld-hello-ecs-nginx.name
  policy     = data.aws_iam_policy_document.burgerworld-hello-ecs-ecr-permissions-policy-document.json
}
resource "aws_ecr_repository_policy" "burgerworld-hello-ecs-integration-test-local-repository-policy" {
  repository = aws_ecr_repository.burgerworld-hello-ecs-integration-test-local.name
  policy     = data.aws_iam_policy_document.burgerworld-hello-ecs-ecr-permissions-policy-document.json
}

resource "aws_iam_role" "ecs-task-execution-role" {
  name               = "${var.burgerworld_hello_ecs_app_name}-execution-task-role"
  assume_role_policy = data.aws_iam_policy_document.assume-role-policy.json
  tags = {
    Name        = "${var.burgerworld_hello_ecs_app_name}-iam-role"
    Environment = var.burgerworld_hello_ecs_deployment_environment
  }
}

data "aws_iam_policy_document" "assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "ecs-task-execution-role-policy" {
  role       = aws_iam_role.ecs-task-execution-role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}
