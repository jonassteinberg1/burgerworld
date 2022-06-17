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

variable "burgerworld_hello_ecs_ecr_symmetric_key_usage" {
  description = "usage of the burgerworld-hello-ecs kms symmetric key for ecr image encryption"
  type        = string
  default     = "ENCRYPT_DECRYPT"
}

variable "burgerworld_hello_ecs_ecr_symmetric_key_is_enabled" {
  description = "enable the burgerworld-hello-ecs kms symmetric key for ecr image encryption"
  type        = string
  default     = "true"
}

variable "burgerworld_hello_ecs_ecr_symmetric_key_rotation" {
  description = "enable kms key rotation for burgerworld-hello-ecs kms symmetric key for ecr image encryption"
  type        = string
  default     = "true"
}

variable "burgerworld-hello-ecs-ecr-symmetric-key-alias" {
  description = "alias for the burgerworld-hello-ecs kms symmetric key for ecr image encryption"
  type        = string
  default     = "burger-hello-ecs-ecr"
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

variable "burgerworld_hello_ecs_encryption_type" {
  description = "type of burgerworld-hello-ecs encryption type to use"
  type        = string
  default     = "KMS"
}
