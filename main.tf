locals {
  enabled = module.this.enabled
}

module "source_endpoint_label" {
  source  = "cloudposse/label/null"
  version = "0.25.0"

  attributes = [var.team_name]
  context    = module.this.context
}

resource "aws_ecr_repository" "burgerworld-hello-ecs-ecr" {
  name                 = "${var.burgerworld_hello_ecs_app_name}-${var.burgerworld_hello_ecs_deployment_environment}-ecr"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = var.burgerworld_hello_ecs_encryption_type
    kms_key         = var.burgerworld_hello_ecs_kms_key_arn
  }
  tags = {
    Name        = "${var.burgerworld_hello_ecs_app_name}-${var.burgerworld_hello_ecs_deployment_environment}-ecr"
    Environment = var.burgerworld_hello_ecs_deployment_environment
  }
}
