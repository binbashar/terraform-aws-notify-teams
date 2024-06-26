locals {
  custom = {
    name = "ex-${replace(basename(path.cwd), "_", "-")}-custom"
    tags = merge({ "Type" = "custom" }, local.tags)
  }
}

################################################################################
# Supporting Resources
################################################################################

resource "aws_sns_topic" "custom_lambda" {
  name = local.custom.name
  tags = local.custom.tags
}

################################################################################
# teams Notify Module
################################################################################

module "custom_lambda" {
  source = "../../"

  lambda_function_name = "custom_lambda"
  lambda_source_path   = "../../functions/mylambda.py"

  iam_role_name_prefix = "custom"

  sns_topic_name = aws_sns_topic.custom_lambda.name

  teams_webhook_url = "https://xxxxx.webhook.office.com/xxxxxxxxx"

  tags = local.custom.tags
}
