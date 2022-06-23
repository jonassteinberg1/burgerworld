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

data "aws_iam_policy_document" "ecs-agent" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs-agent" {
  name               = "ecs-agent"
  assume_role_policy = data.aws_iam_policy_document.ecs-agent.json
}

resource "aws_iam_role_policy_attachment" "ecs-agent" {
  role       = aws_iam_role.ecs-agent.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ecs-agent" {
  name = "ecs-agent"
  role = aws_iam_role.ecs-agent.name
}

resource "aws_iam_role" "burgerworld-hello-ecs-service-role" {
  name               = "burgerworld-hello-ecs-service-role"
  assume_role_policy = data.aws_iam_policy_document.burgerworld-hello-ecs-service-policy.json
}

resource "aws_iam_role_policy_attachment" "burgerworld-hello-ecs-service-role-attachment" {
  role       = aws_iam_role.burgerworld-hello-ecs-service-role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole"
}

data "aws_iam_policy_document" "burgerworld-hello-ecs-service-policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
  }
}

######
# SG #
######

resource "aws_security_group" "ecs-sg" {
  vpc_id      = var.burgerworld_hello_ecs_vpc_id
  description = "main ecs security group"

  ingress {
    description = "nginx public port"
    from_port   = 1337
    to_port     = 1337
    protocol    = "tcp"
    cidr_blocks = ["72.50.221.50/32"]
  }

  egress {
    description = "full egress"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["72.50.221.50/32", "172.31.0.0/16"]
  }
}

#######
# ASG #
#######
resource "aws_launch_configuration" "burgerworld-hello-ecs-launch-configuration" {
  image_id             = "ami-0f863d7367abe5d6f"
  iam_instance_profile = aws_iam_instance_profile.ecs-agent.name
  security_groups      = [aws_security_group.ecs-sg.id]
  user_data            = "#!/bin/bash\necho ECS_CLUSTER=burgerworld-hell-ecs-ecs-cluster >> /etc/ecs/ecs.config"
  instance_type        = "t2.micro"

  root_block_device {
    volume_type           = "standard"
    volume_size           = "30"
    delete_on_termination = "true"
    encrypted             = "true"
  }

  metadata_options {
    http_tokens = "required"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "burgerworld-hello-ecs-asg" {
  name                      = "${var.burgerworld_hello_ecs_app_name}-${var.burgerworld_hello_ecs_deployment_environment}-ecs-cluster"
  vpc_zone_identifier       = var.burgerworld-hello-ecs-autoscaling-group-vpc-zone-identifier
  launch_configuration      = aws_launch_configuration.burgerworld-hello-ecs-launch-configuration.name
  desired_capacity          = 2
  min_size                  = 1
  max_size                  = 10
  health_check_grace_period = 300
  health_check_type         = "EC2"
}

#######
# ECS #
#######

resource "aws_ecs_cluster" "burgerworld-hello-ecs-ecs-cluster" {
  name = "${var.burgerworld_hello_ecs_app_name}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = {
    Name        = "${var.burgerworld_hello_ecs_app_name}-ecs-cluster"
    Environment = var.burgerworld_hello_ecs_deployment_environment
  }
}

resource "aws_ecs_task_definition" "burgerworld-hello-ecs-task-definition" {
  container_definitions    = data.template_file.burgerworld-hello-ecs-task-definition-json.rendered
  family                   = "burgerworld-hello-ecs"
  network_mode             = "awsvpc"
  memory                   = "128"
  cpu                      = "256"
  requires_compatibilities = ["EC2"]
}

data "template_file" "burgerworld-hello-ecs-task-definition-json" {
  template = file("${path.module}/task-definition.json")
}

resource "aws_ecs_service" "burgerworld-hello-ecs-service" {
  cluster         = aws_ecs_cluster.burgerworld-hello-ecs-ecs-cluster.id
  desired_count   = 1
  launch_type     = "EC2"
  name            = "burgerworld-hello-ecs"
  task_definition = aws_ecs_task_definition.burgerworld-hello-ecs-task-definition.arn

  load_balancer {
    container_name   = "burgerworld-hello-ecs"
    container_port   = "1337"
    target_group_arn = aws_lb_target_group.burgerworld-hello-ecs-lb-target-group.arn
  }

  network_configuration {
    security_groups  = aws_security_group.ecs-sg.id
    subnets          = var.burgerworld-hello-ecs-alb-subnets
    assign_public_ip = "false"
  }

  depends_on = [aws_lb_listener.burgerworld-hello-ecs-alb-listener]
}

#######
# ALB #
#######

resource "aws_lb" "burgerworld-hello-ecs-loadbalancer" {
  load_balancer_type         = var.burgerworld-hello-ecs-loadbalancer-type
  internal                   = "false" # tfsec:ignore:aws-elb-alb-not-public
  name                       = "${var.burgerworld_hello_ecs_app_name}-cluster"
  subnets                    = var.burgerworld-hello-ecs-alb-subnets
  security_groups            = [aws_security_group.ecs-sg.id]
  drop_invalid_header_fields = "true"
}

resource "aws_lb_target_group" "burgerworld-hello-ecs-lb-target-group" {
  name        = "burgerworld-hello-ecs"
  port        = "1337"
  protocol    = "HTTP"
  vpc_id      = "vpc-ff04929b"
  target_type = "ip"

  health_check {
    healthy_threshold   = "3"
    interval            = "10"
    port                = "1337"
    protocol            = "HTTP"
    path                = "/"
    unhealthy_threshold = "3"
  }
}

resource "aws_lb_listener" "burgerworld-hello-ecs-alb-listener" {

  default_action {
    target_group_arn = aws_lb_target_group.burgerworld-hello-ecs-lb-target-group.id
    type             = "forward"
  }

  load_balancer_arn = aws_lb.burgerworld-hello-ecs-loadbalancer.arn
  port              = "1337"
  protocol          = "HTTP" # tfsec:ignore:aws-elb-http-not-used
}
