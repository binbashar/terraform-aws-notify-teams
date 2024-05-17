#=============================#
# Notifications Outputs       #
#=============================#
#
# AWS SNS -> Lambda -> teams: tools-monitoring
#
output "sns_topic_arn_monitoring" {
  description = "ARN of the created SNS topic for teams"
  value       = module.notify_teams.this_teams_topic_arn
}

output "sns_topic_arn" {
  description = "The ARN of the SNS topic from which messages will be sent to teams"
  value       = module.notify_teams.teams_topic_arn
}

output "lambda_iam_role_arn_monitoring" {
  description = "The ARN of the IAM role used by Lambda function"
  value       = module.notify_teams.lambda_iam_role_arn
}

output "lambda_iam_role_name_monitoring" {
  description = "The name of the IAM role used by Lambda function"
  value       = module.notify_teams.lambda_iam_role_name
}

output "notify_teams_lambda_function_arn_monitoring" {
  description = "The ARN of the Lambda function"
  value       = module.notify_teams.notify_teams_lambda_function_arn
}

output "notify_teams_lambda_function_invoke_arn_monitoring" {
  description = "The ARN to be used for invoking Lambda function from API Gateway"
  value       = module.notify_teams.notify_teams_lambda_function_invoke_arn
}

output "notify_teams_lambda_function_last_modified_monitoring" {
  description = "The date Lambda function was last modified"
  value       = module.notify_teams.notify_teams_lambda_function_last_modified
}

output "notify_teams_lambda_function_name_monitoring" {
  description = "The name of the Lambda function"
  value       = module.notify_teams.notify_teams_lambda_function_name
}

output "notify_teams_lambda_function_version_monitoring" {
  description = "TLatest published version of your Lambda function"
  value       = module.notify_teams.notify_teams_lambda_function_version
}