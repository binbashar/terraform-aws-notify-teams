# AWS Notify Teams Terraform module

This module creates an SNS topic (or uses an existing one) and an AWS Lambda function that sends notifications to a Microsoft Teams channel through a [Workflows webhook](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498).

Start by creating a webhook with the Workflows app in the Teams channel, using the "Post to a channel when a webhook request is received" template.

> Office 365 Connectors (the classic Teams "Incoming Webhook") were retired in May 2026. Workflows webhooks accept the MessageCard payloads this module sends, and the messages are posted by the Workflows bot.

## Supported Features

- AWS Lambda runtime Python 3.13 (configurable with `lambda_runtime`)
- Create new SNS topic or use existing one
- Support plaintext and KMS-encrypted version of the Teams webhook URL
- Support different types of SNS messages:
  - AWS CloudWatch Alarms
  - AWS GuardDuty Findings
  - AWS Health Events
  - Payloads that are already Teams messages (MessageCard or Adaptive Card), forwarded as-is
  - Any other JSON or plain-text message (e.g. AWS Budgets), rendered as a generic card

## Usage

```hcl
module "notify_teams" {
  source = "github.com/binbashar/terraform-aws-notify-teams.git?ref=<version>"

  sns_topic_name = "teams-topic"

  teams_webhook_url = "https://xxxxx.logic.azure.com/workflows/xxxxxxxxx"
}
```

To keep the webhook URL out of the Lambda configuration in plaintext, encrypt it with KMS (e.g. with `aws_kms_ciphertext`), pass the ciphertext as `teams_webhook_url` and the key as `kms_key_arn`. Any value that does not start with `http` is decrypted with KMS at runtime.

The Lambda function fails when the webhook answers with a non-2xx status, so the invocation shows up in the Lambda `Errors` metric and SNS retries it.

## Using with Terraform Cloud Agents

[Terraform Cloud Agents](https://www.terraform.io/docs/cloud/workspaces/agent.html) are a paid feature, available as part of the Terraform Cloud for Business upgrade package.

This module packages the Lambda function locally, so it requires Python 3. You can customize [tfc-agent](https://hub.docker.com/r/hashicorp/tfc-agent) to include Python using this sample `Dockerfile`:

```
FROM hashicorp/tfc-agent:latest
RUN apt-get -y update && apt-get -y install python3 python3-pip
ENTRYPOINT ["/bin/tfc-agent"]
```

## Use existing SNS topic or create new

If you want to subscribe the AWS Lambda Function created by this module to an existing SNS topic you should specify `create_sns_topic = false` as an argument and specify the name of existing SNS topic name in `sns_topic_name`.

## Examples

- [notify-teams-simple](https://github.com/binbashar/terraform-aws-notify-teams/tree/master/examples/notify-teams-simple) - Creates SNS topic which sends messages to Teams channel.

## Testing with pytest

The unit tests run offline (no AWS or Teams calls):

    pip install pytest boto3
    pytest functions/notify_teams_test.py


<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.79 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.79 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_lambda"></a> [lambda](#module\_lambda) | terraform-aws-modules/lambda/aws | 7.21.1 |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_sns_topic.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_subscription.sns_notify_teams](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_cloudwatch_log_group_kms_key_id"></a> [cloudwatch\_log\_group\_kms\_key\_id](#input\_cloudwatch\_log\_group\_kms\_key\_id) | The ARN of the KMS Key to use when encrypting log data for Lambda | `string` | `null` | no |
| <a name="input_cloudwatch_log_group_retention_in_days"></a> [cloudwatch\_log\_group\_retention\_in\_days](#input\_cloudwatch\_log\_group\_retention\_in\_days) | Specifies the number of days you want to retain log events in log group for Lambda. | `number` | `0` | no |
| <a name="input_cloudwatch_log_group_tags"></a> [cloudwatch\_log\_group\_tags](#input\_cloudwatch\_log\_group\_tags) | Additional tags for the Cloudwatch log group | `map(string)` | `{}` | no |
| <a name="input_create"></a> [create](#input\_create) | Whether to create all resources | `bool` | `true` | no |
| <a name="input_create_sns_topic"></a> [create\_sns\_topic](#input\_create\_sns\_topic) | Whether to create new SNS topic | `bool` | `true` | no |
| <a name="input_iam_role_boundary_policy_arn"></a> [iam\_role\_boundary\_policy\_arn](#input\_iam\_role\_boundary\_policy\_arn) | The ARN of the policy that is used to set the permissions boundary for the role | `string` | `null` | no |
| <a name="input_iam_role_name_prefix"></a> [iam\_role\_name\_prefix](#input\_iam\_role\_name\_prefix) | A unique role name beginning with the specified prefix | `string` | `"lambda"` | no |
| <a name="input_iam_role_tags"></a> [iam\_role\_tags](#input\_iam\_role\_tags) | Additional tags for the IAM role | `map(string)` | `{}` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | ARN of the KMS key used for decrypting Teams webhook url | `string` | `""` | no |
| <a name="input_lambda_description"></a> [lambda\_description](#input\_lambda\_description) | The description of the Lambda function | `string` | `null` | no |
| <a name="input_lambda_function_name"></a> [lambda\_function\_name](#input\_lambda\_function\_name) | The name of the Lambda function to create | `string` | `"notify_teams"` | no |
| <a name="input_lambda_function_s3_bucket"></a> [lambda\_function\_s3\_bucket](#input\_lambda\_function\_s3\_bucket) | S3 bucket to store artifacts | `string` | `null` | no |
| <a name="input_lambda_function_store_on_s3"></a> [lambda\_function\_store\_on\_s3](#input\_lambda\_function\_store\_on\_s3) | Whether to store produced artifacts on S3 or locally. | `bool` | `false` | no |
| <a name="input_lambda_function_tags"></a> [lambda\_function\_tags](#input\_lambda\_function\_tags) | Additional tags for the Lambda function | `map(string)` | `{}` | no |
| <a name="input_lambda_function_vpc_security_group_ids"></a> [lambda\_function\_vpc\_security\_group\_ids](#input\_lambda\_function\_vpc\_security\_group\_ids) | List of security group ids when Lambda Function should run in the VPC. | `list(string)` | `null` | no |
| <a name="input_lambda_function_vpc_subnet_ids"></a> [lambda\_function\_vpc\_subnet\_ids](#input\_lambda\_function\_vpc\_subnet\_ids) | List of subnet ids when Lambda Function should run in the VPC. Usually private or intra subnets. | `list(string)` | `null` | no |
| <a name="input_lambda_role"></a> [lambda\_role](#input\_lambda\_role) | IAM role attached to the Lambda Function.  If this is set then a role will not be created for you. | `string` | `""` | no |
| <a name="input_lambda_runtime"></a> [lambda\_runtime](#input\_lambda\_runtime) | The Lambda runtime used by the function | `string` | `"python3.13"` | no |
| <a name="input_lambda_source_path"></a> [lambda\_source\_path](#input\_lambda\_source\_path) | The source path of a custom Lambda function. Defaults to the bundled functions/notify\_teams.py | `string` | `null` | no |
| <a name="input_log_events"></a> [log\_events](#input\_log\_events) | Boolean flag to enabled/disable logging of incoming events | `bool` | `false` | no |
| <a name="input_reserved_concurrent_executions"></a> [reserved\_concurrent\_executions](#input\_reserved\_concurrent\_executions) | The amount of reserved concurrent executions for this lambda function. A value of 0 disables lambda from being triggered and -1 removes any concurrency limitations | `number` | `-1` | no |
| <a name="input_sns_topic_kms_key_id"></a> [sns\_topic\_kms\_key\_id](#input\_sns\_topic\_kms\_key\_id) | ARN of the KMS key used for enabling SSE on the topic | `string` | `""` | no |
| <a name="input_sns_topic_name"></a> [sns\_topic\_name](#input\_sns\_topic\_name) | The name of the SNS topic to create | `string` | n/a | yes |
| <a name="input_sns_topic_tags"></a> [sns\_topic\_tags](#input\_sns\_topic\_tags) | Additional tags for the SNS topic | `map(string)` | `{}` | no |
| <a name="input_subscription_filter_policy"></a> [subscription\_filter\_policy](#input\_subscription\_filter\_policy) | (Optional) A valid filter policy that will be used in the subscription to filter messages seen by the target resource. | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources | `map(string)` | `{}` | no |
| <a name="input_teams_webhook_url"></a> [teams\_webhook\_url](#input\_teams\_webhook\_url) | The URL of Teams webhook | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_lambda_cloudwatch_log_group_arn"></a> [lambda\_cloudwatch\_log\_group\_arn](#output\_lambda\_cloudwatch\_log\_group\_arn) | The Amazon Resource Name (ARN) specifying the log group |
| <a name="output_lambda_iam_role_arn"></a> [lambda\_iam\_role\_arn](#output\_lambda\_iam\_role\_arn) | The ARN of the IAM role used by Lambda function |
| <a name="output_lambda_iam_role_name"></a> [lambda\_iam\_role\_name](#output\_lambda\_iam\_role\_name) | The name of the IAM role used by Lambda function |
| <a name="output_notify_teams_lambda_function_arn"></a> [notify\_teams\_lambda\_function\_arn](#output\_notify\_teams\_lambda\_function\_arn) | The ARN of the Lambda function |
| <a name="output_notify_teams_lambda_function_invoke_arn"></a> [notify\_teams\_lambda\_function\_invoke\_arn](#output\_notify\_teams\_lambda\_function\_invoke\_arn) | The ARN to be used for invoking Lambda function from API Gateway |
| <a name="output_notify_teams_lambda_function_last_modified"></a> [notify\_teams\_lambda\_function\_last\_modified](#output\_notify\_teams\_lambda\_function\_last\_modified) | The date Lambda function was last modified |
| <a name="output_notify_teams_lambda_function_name"></a> [notify\_teams\_lambda\_function\_name](#output\_notify\_teams\_lambda\_function\_name) | The name of the Lambda function |
| <a name="output_notify_teams_lambda_function_version"></a> [notify\_teams\_lambda\_function\_version](#output\_notify\_teams\_lambda\_function\_version) | Latest published version of your Lambda function |
| <a name="output_this_teams_topic_arn"></a> [this\_teams\_topic\_arn](#output\_this\_teams\_topic\_arn) | The ARN of the SNS topic from which messages will be sent to Teams |
<!-- END_TF_DOCS -->

## Authors

Original code by [Anton Babenko](https://github.com/antonbabenko) with help from [these awesome contributors](https://github.com/binbashar/terraform-aws-notify-teams/graphs/contributors).

## License

Apache 2 Licensed. See [LICENSE](https://github.com/binbashar/terraform-aws-notify-teams/tree/master/LICENSE) for full details.
