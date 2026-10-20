# -*- coding: utf-8 -*-
import base64
import json
import logging
import os
import urllib.parse
import urllib.request
from enum import Enum
from typing import Any, Dict, Optional, Union
from urllib.error import HTTPError

import boto3

# Set default region if not provided
REGION = os.environ.get("AWS_REGION", "us-east-1")

# Create client so its cached/frozen between invocations
KMS_CLIENT = boto3.client("kms", region_name=REGION)


class AwsService(Enum):
    """AWS service supported by function"""

    cloudwatch = "cloudwatch"
    guardduty = "guardduty"


def decrypt_url(encrypted_url: str) -> str:
    """Decrypt encrypted URL with KMS

    :param encrypted_url: URL to decrypt with KMS
    :returns: plaintext URL
    """
    try:
        decrypted_payload = KMS_CLIENT.decrypt(
            CiphertextBlob=base64.b64decode(encrypted_url)
        )
        return decrypted_payload["Plaintext"].decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")
        return ""


def get_service_url(region: str, service: str) -> str:
    """Get the appropriate service URL for the region

    :param region: name of the AWS region
    :param service: name of the AWS service
    :returns: AWS console url formatted for the region and service provided
    """
    try:
        service_name = AwsService[service].value
        if region.startswith("us-gov-"):
            return f"https://console.amazonaws-us-gov.com/{service_name}/home?region={region}"
        else:
            return f"https://console.aws.amazon.com/{service_name}/home?region={region}"

    except KeyError:
        print(f"Service {service} is currently not supported")
        raise


class CloudWatchAlarmState(Enum):
    """Maps CloudWatch notification state to teams message format color"""

    OK = "00FF00"  # Verde
    ALARM = "FF0000"  # Rojo
    INSUFFICIENT_DATA = "FFFF00"  # Amarillo

def format_cloudwatch_alarm(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Format CloudWatch alarm event into teams message format.

    :params message: SNS message body containing CloudWatch alarm event.
    :region: AWS region where the event originated from.
    :returns: formatted teams message payload.
    """
    
    cloudwatch_url = get_service_url(region=region, service="cloudwatch")
    alarm_name = message["AlarmName"]
    alarm_link = f"[{alarm_name}]({cloudwatch_url}#alarm:alarmFilter=ANY;name={urllib.parse.quote(alarm_name)})"

    return {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "themeColor": CloudWatchAlarmState[message["NewStateValue"]].value,
        "title": f"AWS CloudWatch notification - {alarm_name}",
        "text": f"Alarm Description: {message['AlarmDescription']}",
        "sections": [
            {
                "facts": [
                    {"name": "Alarm Name", "value": alarm_link},
                    {"name": "Alarm reason", "value": message['NewStateReason']},
                    {"name": "Old State", "value": message['OldStateValue']},
                    {"name": "Current State", "value": message['NewStateValue']}
                ]
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "View in CloudWatch",
                "targets": [
                    {"os": "default", "uri": cloudwatch_url}
                ]
            }
        ]
    }


class GuardDutyFindingSeverity(Enum):
    """Maps GuardDuty finding severity to teams message format color."""
    Low = "#777777"
    Medium = "#FFCC00"  # Yellow (an approximation for "warning")
    High = "#FF0000"    # Red (an approximation for "danger")


def format_guardduty_finding(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    guardduty_url = get_service_url(region=region, service="guardduty")
    detail = message["detail"]
    service = detail.get("service", {})
    severity_score = detail.get("severity")

    if severity_score < 4.0:
        severity = "Low"
    elif severity_score < 7.0:
        severity = "Medium"
    else:
        severity = "High"

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": GuardDutyFindingSeverity[severity].value,
        "summary": f"GuardDuty Finding: {detail.get('title')}",
        "sections": [{
            "activityTitle": f"AWS GuardDuty Finding - {detail.get('title')}",
            "facts": [
                {"name": "Description", "value": f"{detail['description']}"},
                {"name": "Finding Type", "value": f"{detail['type']}"},
                {"name": "First Seen", "value": f"{service['eventFirstSeen']}"},
                {"name": "Last Seen", "value": f"{service['eventLastSeen']}"},
                {"name": "Severity", "value": severity},
                {"name": "Account ID", "value": f"{detail['accountId']}"},
                {"name": "Count", "value": f"{service['count']}"},
                {"name": "Link to Finding", "value": f"[Open in AWS Console]({guardduty_url}#/findings?search=id%3D{detail['id']})"}
            ]
        }]
    }


def determine_severity(severity_score: float) -> str:
    """
    Determine the severity level based on the score.

    :params severity_score: Score value of the severity
    :returns: Severity level as a string
    """

    if severity_score < 4.0:
        return "Low"
    elif severity_score < 7.0:
        return "Medium"
    else:
        return "High"



class AwsHealthCategory(Enum):
    """Maps AWS Health event categories to Teams message format color.

    Member names match the eventTypeCategory values AWS Health sends.
    """
    issue = "#FF5733"
    accountNotification = "#FFC300"
    scheduledChange = "#33FF57"
    investigation = "#335BFF"


AWS_HEALTH_DEFAULT_COLOR = "#777777"  # Gray for unmapped categories


def get_aws_health_color(category: Optional[str]) -> str:
    """Get the message color for an AWS Health event category"""
    try:
        return AwsHealthCategory[category].value
    except KeyError:
        return AWS_HEALTH_DEFAULT_COLOR

def format_aws_health(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Format AWS Health event into Teams message format."""
    aws_health_url = f"https://phd.aws.amazon.com/phd/home?region={region}#/dashboard/open-issues"
    detail = message.get("detail", {})
    resources = message.get("resources", ["<unknown>"])
    service = detail.get("service", "<unknown>")
    event_descriptions = detail.get('eventDescription', [])
    latest_description = event_descriptions[0]['latestDescription'] if event_descriptions else '<unknown>'

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": get_aws_health_color(detail.get("eventTypeCategory")),
        "summary": f"New AWS Health Event for {service}",
        "sections": [{
            "activityTitle": f"New AWS Health Event for {service}",
            "facts": [
                {"name": "Affected Service", "value": f"`{service}`"},
                {"name": "Affected Region", "value": f"`{message.get('region')}`"},
                {"name": "Code", "value": f"`{detail.get('eventTypeCode')}`"},
                {"name": "Event Description", "value": f"`{latest_description}`"},
                {"name": "Affected Resources", "value": f"`{', '.join(resources)}`"},
                {"name": "Start Time", "value": f"`{detail.get('startTime', '<unknown>')}`"},
                {"name": "End Time", "value": f"`{detail.get('endTime', '<unknown>')}`"},
            ],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "Link to Event",
                "targets": [{"os": "default", "uri": aws_health_url}]
            }]
        }]
    }





def format_default(
    message: Union[str, Dict], subject: Optional[str] = None
) -> Dict[str, Any]:
    """
    Default formatter, converting event into teams message format

    :params message: SNS message body containing message/event
    :returns: formatted teams message payload
    """

    summary = "AWS notification"
    title = subject if subject else "Message"
    facts = []

    if isinstance(message, dict):
        for k, v in message.items():
            value = f"{json.dumps(v)}" if isinstance(v, (dict, list)) else str(v)
            facts.append({"name": k, "value": value})
    else:
        facts.append({"name": title, "value": message})

    teams_message = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": summary,
        "sections": [{
            "activityTitle": title,
            "facts": facts
        }]
    }

    return teams_message



def is_teams_payload(message: Dict[str, Any]) -> bool:
    """Check whether the message is already a Teams payload (MessageCard or Adaptive Card message)"""
    return message.get("@type") == "MessageCard" or (
        message.get("type") == "message" and "attachments" in message
    )


def get_teams_message_payload(message: Union[str, Dict], region: str, subject: Optional[str] = None) -> Dict:
    """
    Parse notification message and format into Microsoft Teams message payload

    :params message: SNS message body notification payload
    :params region: AWS region where the event originated from
    :params subject: Optional subject line for Microsoft Teams notification
    :returns: Microsoft Teams message payload
    """

    if isinstance(message, str):
        try:
            message = json.loads(message)
        except json.JSONDecodeError:
            logging.info("Not a structured payload, just a string message")

    # Plain-text messages (e.g. AWS Budgets) and non-object JSON go to the default formatter
    if not isinstance(message, dict):
        return format_default(message=str(message), subject=subject)

    if "AlarmName" in message:
        return format_cloudwatch_alarm(message=message, region=region)

    if message.get("detail-type") == "GuardDuty Finding":
        return format_guardduty_finding(message=message, region=message["region"])

    if message.get("detail-type") == "AWS Health Event":
        return format_aws_health(message=message, region=message["region"])

    if is_teams_payload(message):
        return message

    return format_default(message=message, subject=subject)


def send_teams_notification(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send notification payload to Microsoft Teams

    :params payload: formatted Microsoft Teams message card
    :returns: response status code and headers
    """

    teams_url = os.environ["TEAMS_WEBHOOK_URL"]

    if not teams_url.startswith("http"):
        teams_url = decrypt_url(teams_url)

    headers = {"Content-Type": "application/json"}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(teams_url, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req) as result:
            return {"code": result.getcode(), "info": result.info().as_string()}

    except HTTPError as e:
        return {"code": e.getcode(), "info": e.info().as_string()}


def lambda_handler(event: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Lambda function to parse notification events and forward to teams

    :param event: lambda expected event object
    :param context: lambda expected context object
    :returns: JSON list with the response of each record
    """
    if os.environ.get("LOG_EVENTS", "False") == "True":
        logging.info(f"Event logging enabled: `{json.dumps(event)}`")

    responses = []
    for record in event["Records"]:
        sns = record["Sns"]
        subject = sns.get("Subject")
        message = sns["Message"]
        region = sns["TopicArn"].split(":")[3]

        payload = get_teams_message_payload(
            message=message, region=region, subject=subject
        )
        responses.append(send_teams_notification(payload=payload))

    # Workflows webhooks answer 202 Accepted, legacy connectors answered 200 OK
    failed = [r for r in responses if not 200 <= r["code"] < 300]
    if failed:
        logging.error(f"Error: received status `{failed}` using event `{event}`")
        # Raising marks the invocation as failed, so SNS retries it
        raise RuntimeError(f"Teams webhook returned {[r['code'] for r in failed]}")

    return json.dumps(responses)
