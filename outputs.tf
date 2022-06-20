output "burgerworld-hello-ecs-integration-test-repository-name" {
  value = aws_ecr_repository.burgerworld-hello-ecs-integration-test.repository_url
}

output "burgerworld-hello-ecs-web-repository-name" {
  value = aws_ecr_repository.burgerworld-hello-ecs-web.repository_url
}


output "burgerworld-hello-ecs-dec-ecr-repository-policy-document-json" {
  value = data.aws_iam_policy_document.burgerworld-hello-ecs-ecr-permissions-policy-document.json
}
