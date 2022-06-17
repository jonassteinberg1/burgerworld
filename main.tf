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

resource "aws_ecr_repository" "burgerworld-hello-ecs-ecr" {
  name                 = "${var.burgerworld_hello_ecs_app_name}-${var.burgerworld_hello_ecs_deployment_environment}-ecr"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = var.burgerworld_hello_ecs_encryption_type
    kms_key         = aws_kms_key.burgerworld-hello-ecs-ecr-symmetric-key.arn
  }
  tags = {
    Name        = "${var.burgerworld_hello_ecs_app_name}-${var.burgerworld_hello_ecs_deployment_environment}-ecr"
    Environment = var.burgerworld_hello_ecs_deployment_environment
  }
}
