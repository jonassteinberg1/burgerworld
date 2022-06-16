variable "aws_profile" {
  description = "aws profile to use for terraform planning and applying"
  type        = string
  default     = "default"
}

variable "aws_region" {
  description = "aws region in which to orchestrate"
  type        = string
  default     = "us-east-1"
}

variable "team_name" {
  description = "name of the team administrating and deploying services to the cluster"
  type        = string
  default     = "burgerworld-hello-ecs"
}

variable "burgerworld_hello_ecs_app_name" {
  description = "name of the burgerworld-hello-ecs app name"
  type        = string
  default     = "burgerworld-hello-ecs"
}

variable "burgerworld_hello_ecs_deployment_environment" {
  description = "name of the burgerworld-hello-ecs deployment environment"
  type        = string
  default     = "dev"
}
