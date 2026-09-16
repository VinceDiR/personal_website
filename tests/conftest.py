"""Shared fixtures: an app configured for tests with mail suppressed."""

import os
import sys
from datetime import timedelta

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.update(
    MAIL_SERVER="smtp.example.test",
    EMAIL_PORT="587",
    EMAIL="owner@example.test",
    EMAIL_PW="pw",
    RECAPTCHA_SITE_KEY="site",
    RECAPTCHA_SECRET_KEY="secret",
    SITE_URL="https://vincentdirenzo.com",
)
os.environ.pop("SPAM_BLOCK_ENABLED", None)
os.environ.pop("FORM_SECRET", None)

import app as app_module  # noqa: E402  (env must be set before import)
import guards  # noqa: E402
import spamcheck  # noqa: E402

app_module.app.config.update(TESTING=True)
app_module.mail.state.suppress = True

BROWSER_HEADERS = {
    "Origin": "http://localhost",
    "Referer": "http://localhost/",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (test)",
}

GOOD_FORM = {
    "name": "Jane Recruiter",
    "email": "jane@example.test",
    "subject": "Data engineer role",
    "message": "Hi Vince, I read your Medium post on Airflow. Open to a data engineer role?",
    "g-recaptcha-response": "token",
}


@pytest.fixture(autouse=True)
def reset_state():
    """Clears per-process spam state between tests."""
    app_module.rate_limiter.reset()
    spamcheck._DUPES.clear()
    yield
    app_module.rate_limiter.reset()
    spamcheck._DUPES.clear()


@pytest.fixture
def client():
    """Flask test client."""
    return app_module.app.test_client()


@pytest.fixture
def aged_token(monkeypatch):
    """A valid render token that appears to be 20 seconds old at check time."""
    token = app_module.form_token.mint()
    real_now = guards.utcnow()
    monkeypatch.setattr(guards, "utcnow", lambda: real_now + timedelta(seconds=20))
    return token


@pytest.fixture
def captcha_ok(monkeypatch):
    """Makes siteverify report success for the canonical host."""
    monkeypatch.setattr(
        guards,
        "_siteverify",
        lambda token, ip, secret: {
            "success": True,
            "hostname": "vincentdirenzo.com",
            "challenge_ts": "2099-01-01T00:00:00Z",
        },
    )


@pytest.fixture
def outbox():
    """Captures messages Flask-Mail would have sent."""
    with app_module.mail.record_messages() as messages:
        yield messages


def post_form(client, form, token=None, headers=None, **kwargs):
    """Posts the form the way main.js does: multipart with browser headers and the token."""
    data = dict(form)
    if token is not None:
        data["ft"] = token
    return client.post(
        "/contact",
        data=data,
        content_type="multipart/form-data",
        headers={**BROWSER_HEADERS, **(headers or {})},
        **kwargs,
    )
