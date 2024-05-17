provider "aws" {
  region = local.region
}

locals {
  name   = "ex-${replace(basename(path.cwd), "_", "-")}"
  region = "eu-west-1"
  tags = {
    Owner       = "user"
    Environment = "dev"
  }
}

################################################################################
# Supporting Resources
################################################################################

resource "aws_sns_topic" "example" {
  name = local.name
  tags = local.tags
}

################################################################################
# teams Notify Module
################################################################################

module "notify_teams" {
  source = "../../"

  sns_topic_name   = aws_sns_topic.example.name
  create_sns_topic = false

  teams_webhook_url = "https://xxxxx.webhook.office.com/xxxxxxxxx"

  tags = local.tags
}

################################################################################
# Integration Testing Support
# This populates a file that is gitignored to aid in executing the integration tests locally
################################################################################

resource "local_file" "integration_testing" {
  filename = "${path.module}/../../functions/.int.env"
  content  = <<-EOT
    REGION=${local.region}
    LAMBDA_FUNCTION_NAME=${module.notify_teams.notify_teams_lambda_function_name}
    SNS_TOPIC_ARN=${aws_sns_topic.example.arn}
    EOT
}
