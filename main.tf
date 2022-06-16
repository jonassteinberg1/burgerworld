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
  name = "${var.burgerworld-hello-ecs_app_name}-${var.burgerworld-hello-ecs_deployment_environment}-ecr"
  tags = {
    Name        = "${var.burgerworld-hello-ecs_app_name}-${var.burgerworld-hello-ecs_deployment_environment}-ecr"
    Environment = var.burgerworld-hello-ecs_deployment_environment
  }
}
