# -*- coding: utf-8 -*-
"""
Offline unit tests for notify_teams. No AWS or Teams calls are made.

Run with: pytest functions/notify_teams_test.py
"""
import glob
import json
import os
from email.message import Message

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import notify_teams  # noqa: E402

EVENTS_DIR = os.path.join(os.path.dirname(__file__), "events")

BUDGET_MESSAGE = (
    "AWS Budget Notification October 08, 2026\n"
    "You requested that we alert you when the ACTUAL Cost associated with your "
    "monthly budget is greater than $100.00 for the current month.\n"
    "Budget Name: monthly\n"
)


def sns_event(message, subject="Test subject"):
    return {
        "Records": [
            {
                "Sns": {
                    "Subject": subject,
                    "Message": message,
                    "TopicArn": "arn:aws:sns:us-east-1:000000000000:test-topic",
                }
            }
        ]
    }


class FakeResponse:
    def __init__(self, code):
        self.code = code

    def getcode(self):
        return self.code

    def info(self):
        return Message()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture
def webhook(monkeypatch):
    """Capture posted payloads and answer with the given status code"""
    sent = []
    state = {"code": 202}

    def fake_urlopen(req):
        sent.append(json.loads(req.data))
        return FakeResponse(state["code"])

    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://example.invalid/webhook")
    monkeypatch.setattr(notify_teams.urllib.request, "urlopen", fake_urlopen)
    return sent, state


@pytest.mark.parametrize("path", sorted(glob.glob(os.path.join(EVENTS_DIR, "*.json"))))
def test_sample_events_are_formatted(path):
    with open(path) as f:
        message = json.load(f)

    payload = notify_teams.get_teams_message_payload(message, "us-east-1")

    assert payload["@type"] == "MessageCard"


@pytest.mark.parametrize(
    "message",
    [BUDGET_MESSAGE, "the context matters", "send the attachments", "42"],
)
def test_plain_text_uses_default_formatter(message):
    payload = notify_teams.get_teams_message_payload(message, "us-east-1", "Subject")

    assert payload["sections"][0]["activityTitle"] == "Subject"
    assert payload["sections"][0]["facts"][0]["value"] == message


def test_unknown_aws_health_category_uses_default_color():
    with open(os.path.join(EVENTS_DIR, "aws_health_event.json")) as f:
        message = json.load(f)
    message["detail"]["eventTypeCategory"] = "somethingNew"

    payload = notify_teams.get_teams_message_payload(message, "us-east-1")

    assert payload["themeColor"] == notify_teams.AWS_HEALTH_DEFAULT_COLOR


def test_teams_payload_is_forwarded_as_is():
    card = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive"}]}

    assert notify_teams.get_teams_message_payload(json.dumps(card), "us-east-1") == card


@pytest.mark.parametrize("code", [200, 202])
def test_handler_accepts_2xx(webhook, code):
    sent, state = webhook
    state["code"] = code

    response = notify_teams.lambda_handler(sns_event(BUDGET_MESSAGE), {})

    assert json.loads(response)[0]["code"] == code
    assert len(sent) == 1


def test_handler_raises_on_failure(webhook):
    sent, state = webhook
    state["code"] = 400

    with pytest.raises(RuntimeError):
        notify_teams.lambda_handler(sns_event(BUDGET_MESSAGE), {})
