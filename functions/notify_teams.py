# -*- coding: utf-8 -*-
import base64
import json
import logging
import os
import urllib.parse
import urllib.request
from enum import Enum
from typing import Any, Dict, Optional, Union, cast
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
    """Maps AWS Health event categories to Teams message format color"""
    ISSUE = "#FF5733"  # Example color for the 'ISSUE' category
    ACCOUNT_NOTIFICATION = "#FFC300"  # Example color for 'ACCOUNT_NOTIFICATION'
    SCHEDULED_CHANGE = "#33FF57"  # Example color for 'SCHEDULED_CHANGE'
    INVESTIGATION = "#335BFF"  # Example color for 'INVESTIGATION'
    DEFAULT = "#777777"  # Default gray color for unmapped categories

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
        "themeColor": AwsHealthCategory[detail.get("eventTypeCategory", "DEFAULT")].value,
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



def get_teams_message_payload(message: Union[str, Dict], region: str, subject: Optional[str] = None) -> Dict:
    """
    Parse notification message and format into Microsoft Teams message payload

    :params message: SNS message body notification payload
    :params region: AWS region where the event originated from
    :params subject: Optional subject line for Microsoft Teams notification
    :returns: Microsoft Teams message payload
    """

    # Since Teams format is different, you might want to adjust the formatting functions
    # For simplicity, I'm reusing the teams functions but these will need to be updated to match Teams card format
    
    if isinstance(message, str):
        try:
            message = json.loads(message)
        except json.JSONDecodeError:
            logging.info("Not a structured payload, just a string message")

    message = cast(Dict[str, Any], message)

    if "AlarmName" in message:
        notification = format_cloudwatch_alarm(message=message, region=region)
        # Modify format_cloudwatch_alarm to match Teams format

    elif (
        isinstance(message, Dict) and message.get("detail-type") == "GuardDuty Finding"
    ):
        notification = format_guardduty_finding(
            message=message, region=message["region"]
        )
        # Modify format_guardduty_finding to match Teams format

    elif isinstance(message, Dict) and message.get("detail-type") == "AWS Health Event":
        notification = format_aws_health(message=message, region=message["region"])
        # Modify format_aws_health to match Teams format

    elif "attachments" in message or "text" in message:
        # Modify this section to match Teams format
        pass

    else:
        notification = format_default(message=message, subject=subject)
        # Modify format_default to match Teams format

    return notification



def send_teams_notification(payload: Dict[str, Any]) -> str:
    """
    Send notification payload to Microsoft Teams

    :params payload: formatted Microsoft Teams message card
    :returns: response details from sending notification
    """
    
    teams_url = os.environ["TEAMS_WEBHOOK_URL"]
    
    if not teams_url.startswith("http"):
        teams_url = decrypt_url(teams_url)
    
    headers = {"Content-Type": "application/json"}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(teams_url, data=data, headers=headers)
    
    try:
        result = urllib.request.urlopen(req)
        return json.dumps({"code": result.getcode(), "info": result.info().as_string()})
    
    except HTTPError as e:
        logging.error(f"{e}: result")
        return json.dumps({"code": e.getcode(), "info": e.info().as_string()})



def lambda_handler(event: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Lambda function to parse notification events and forward to teams

    :param event: lambda expected event object
    :param context: lambda expected context object
    :returns: none
    """
    if os.environ.get("LOG_EVENTS", "False") == "True":
        logging.info(f"Event logging enabled: `{json.dumps(event)}`")

    for record in event["Records"]:
        sns = record["Sns"]
        subject = sns["Subject"]
        message = sns["Message"]
        region = sns["TopicArn"].split(":")[3]

        payload = get_teams_message_payload(
            message=message, region=region, subject=subject
        )
        response = send_teams_notification(payload=payload)

    if json.loads(response)["code"] != 200:
        response_info = json.loads(response)["info"]
        logging.error(
            f"Error: received status `{response_info}` using event `{event}` and context `{context}`"
        )

    return response