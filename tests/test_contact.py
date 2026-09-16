"""Contact endpoint gates, end to end through the Flask test client."""

import json
import pathlib
import re
from datetime import timedelta

import pytest

import guards
import spamcheck
from conftest import GOOD_FORM, app_module, post_form

SPAM_FORM = {
    **GOOD_FORM,
    "name": "SEO Team",
    "email": "info@cheapseo.xyz",
    "subject": "Rank on Google",
    "message": "I noticed your website needs backlinks and link building. "
    "See http://cheapseo.xyz and http://bit.ly/x for our affordable pricing.",
}


def contact_logs(caplog):
    """Parses every `contact {...}` JSON line emitted during the test."""
    return [
        json.loads(r.getMessage().removeprefix("contact "))
        for r in caplog.records
        if r.getMessage().startswith("contact {")
    ]


def contact_log(caplog):
    """Parses the one decision record an attempt is expected to log."""
    records = contact_logs(caplog)
    assert len(records) == 1, f"expected one contact log line, got {len(records)}"
    return records[0]


def test_index_embeds_token_and_is_uncacheable(client):
    response = client.get("/")
    assert response.status_code == 200
    assert 'data-ft="' in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "private, no-store"


def test_index_offers_linkedin_without_javascript(client):
    body = client.get("/").get_data(as_text=True)
    assert "<noscript>" in body
    assert app_module.LINKEDIN_URL in body
    # The honeypot's purpose must not ship to the client.
    assert "honeypot" not in body.lower()


def test_form_token_endpoint_mints_a_usable_token(client, monkeypatch, captcha_ok, outbox):
    response = client.get("/form-token", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "private, no-store"
    token = response.get_json()["token"]
    real_now = guards.utcnow()
    monkeypatch.setattr(guards, "utcnow", lambda: real_now + timedelta(seconds=20))
    assert post_form(client, GOOD_FORM, token).status_code == 200
    assert len(outbox) == 1


def test_non_canonical_host_is_404(client, aged_token):
    response = post_form(client, GOOD_FORM, aged_token, base_url="https://myapp.herokuapp.com")
    assert response.status_code == 404
    assert response.get_json()["ok"] is False


def test_missing_fields_is_honest_400(client, aged_token):
    response = post_form(client, {**GOOD_FORM, "message": " "}, aged_token)
    assert response.status_code == 400
    assert "every field" in response.get_json()["error"]


def test_urlencoded_post_is_silently_dropped(client, aged_token, outbox):
    response = client.post(
        "/contact", data={**GOOD_FORM, "ft": aged_token}, headers={"Accept": "application/json"}
    )
    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert outbox == []


def test_native_post_without_javascript_gets_an_html_notice(client, aged_token, outbox):
    response = client.post(
        "/contact", data={**GOOD_FORM, "ft": aged_token}, headers={"Accept": "text/html"}
    )
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    body = response.get_data(as_text=True)
    # A native submit is always dropped, so this path must not claim the message arrived.
    assert app_module.SUCCESS_MESSAGE not in body
    assert app_module.HTML_SUBMIT_MESSAGE in body
    assert "may not have reached me" in body
    assert app_module.LINKEDIN_URL in body
    assert outbox == []


def test_foreign_origin_is_dropped(client, aged_token, outbox):
    response = post_form(client, GOOD_FORM, aged_token, headers={"Origin": "https://evil.example"})
    assert response.status_code == 200 and response.get_json()["ok"] is True
    assert outbox == []


def test_honeypot_is_dropped(client, aged_token, outbox, captcha_ok):
    response = post_form(client, {**GOOD_FORM, "website": "http://spam.example"}, aged_token)
    assert response.status_code == 200 and response.get_json()["ok"] is True
    assert outbox == []


def test_header_injection_is_dropped(client, aged_token, outbox, captcha_ok):
    poisoned = {**GOOD_FORM, "subject": "Role\r\nBcc: victim@example.test"}
    response = post_form(client, poisoned, aged_token)
    assert response.status_code == 200 and response.get_json()["ok"] is True
    assert outbox == []


def test_missing_token_is_dropped(client, outbox, captcha_ok):
    response = post_form(client, GOOD_FORM, token=None)
    assert response.status_code == 200 and response.get_json()["ok"] is True
    assert outbox == []


def test_forged_token_is_dropped(client, outbox, captcha_ok):
    forged = guards.FormToken(["some-other-secret"]).mint()
    response = post_form(client, GOOD_FORM, forged)
    assert response.status_code == 200 and response.get_json()["ok"] is True
    assert outbox == []


def test_too_fast_submit_is_scored_not_dropped(client, outbox, captcha_ok, caplog):
    with caplog.at_level("INFO"):
        response = post_form(client, GOOD_FORM, app_module.form_token.mint())
    assert response.status_code == 200
    # A fast submit alone is weak evidence, so it buys points instead of silence.
    assert len(outbox) == 1
    assert "request:ft-too-fast" in outbox[0].body
    assert contact_log(caplog)["decision"] in {"sent", "flagged"}


def test_expired_token_gets_reload_prompt(client, monkeypatch, outbox, captcha_ok):
    import itsdangerous.timed as timed

    # Mint a token whose signed timestamp is 13 hours in the past.
    real_time = timed.time.time
    monkeypatch.setattr(timed.time, "time", lambda: real_time() - 13 * 3600)
    token = app_module.form_token.mint()
    monkeypatch.setattr(timed.time, "time", real_time)
    response = post_form(client, GOOD_FORM, token)
    assert response.status_code == 400
    payload = response.get_json()
    assert "reload" in payload["error"]
    # main.js keys its silent retry off this code.
    assert payload["code"] == "ft-expired"
    assert outbox == []


def test_captcha_failure_is_honest_400(client, aged_token, monkeypatch, outbox):
    monkeypatch.setattr(guards, "_siteverify", lambda *a: {"success": False})
    response = post_form(client, GOOD_FORM, aged_token)
    assert response.status_code == 400
    assert "reCAPTCHA" in response.get_json()["error"]
    assert outbox == []


def test_unconfigured_captcha_secret_is_503(client, aged_token, monkeypatch, outbox):
    monkeypatch.setenv("RECAPTCHA_SECRET_KEY", "")
    response = post_form(client, GOOD_FORM, aged_token)
    assert response.status_code == 503
    assert "@" not in response.get_json()["error"]
    assert "configured" in response.get_json()["error"]
    assert outbox == []


def test_captcha_foreign_hostname_is_dropped(client, aged_token, monkeypatch, outbox):
    monkeypatch.setattr(
        guards, "_siteverify", lambda *a: {"success": True, "hostname": "other.example"}
    )
    response = post_form(client, GOOD_FORM, aged_token)
    assert response.status_code == 200 and response.get_json()["ok"] is True
    assert outbox == []


def test_captcha_outage_delivers_flagged(client, aged_token, monkeypatch, outbox):
    monkeypatch.setattr(guards, "_siteverify", lambda *a: None)
    response = post_form(client, GOOD_FORM, aged_token)
    assert response.status_code == 200
    assert len(outbox) == 1
    assert outbox[0].subject.startswith("[Possible spam] ")


def test_happy_path_sends_with_footer(client, aged_token, captcha_ok, outbox, caplog):
    with caplog.at_level("INFO"):
        response = post_form(client, GOOD_FORM, aged_token)
    assert response.status_code == 200
    assert response.get_json() == {"ok": True, "message": app_module.SUCCESS_MESSAGE}
    assert len(outbox) == 1
    msg = outbox[0]
    assert msg.subject == "Website Inquiry: Data engineer role"
    assert msg.reply_to == ("Jane Recruiter", "jane@example.test")
    assert "-- spam score" in msg.body
    assert msg.extra_headers["X-Spam-Score"]
    logged = contact_log(caplog)
    assert logged["decision"] == "sent"
    assert logged["ip"] == "127.0.0.1"
    # The mail itself is in the inbox, so its text is not duplicated into the log.
    assert "preview" not in logged and "subject" not in logged


def test_spammy_content_is_flagged_not_dropped_by_default(
    client, aged_token, captcha_ok, outbox, caplog
):
    with caplog.at_level("INFO"):
        response = post_form(client, SPAM_FORM, aged_token)
    assert response.status_code == 200
    assert len(outbox) == 1
    assert outbox[0].subject.startswith("[Possible spam] Website Inquiry:")
    logged = contact_log(caplog)
    assert logged["decision"] == "flagged"
    # Flagged mail keeps a preview so the log is enough to tune the rules.
    assert len(logged["preview"]) <= 120


def test_block_enabled_drops_high_score(client, aged_token, captcha_ok, outbox, monkeypatch):
    monkeypatch.setattr(spamcheck, "BLOCK_ENABLED", True)
    response = post_form(client, SPAM_FORM, aged_token)
    assert response.status_code == 200 and response.get_json()["ok"] is True
    assert outbox == []


def test_bbcode_is_flagged_not_dropped(client, aged_token, captcha_ok, outbox):
    response = post_form(
        client, {**GOOD_FORM, "message": "[url=http://x.example]hi[/url]"}, aged_token
    )
    assert response.status_code == 200
    assert len(outbox) == 1
    assert "markup:bbcode" in outbox[0].body


def test_markdown_link_is_delivered_clean(client, aged_token, captcha_ok, outbox):
    message = (
        "Hi Vince, we're hiring a data engineer. The JD is "
        "[here](https://bigcorp.example/jobs/42) if you want a look. Open to a chat?"
    )
    response = post_form(client, {**GOOD_FORM, "message": message}, aged_token)
    assert response.status_code == 200
    assert len(outbox) == 1
    assert not outbox[0].subject.startswith("[Possible spam]")


def test_crlf_newlines_do_not_truncate_the_message(client, aged_token, captcha_ok, outbox):
    # 5100 bytes on the wire, 4930 once CRLF collapses to LF: under the 5000 limit.
    paragraph = "Thanks for the Airflow post.\r\n"
    response = post_form(client, {**GOOD_FORM, "message": paragraph * 170}, aged_token)
    assert response.status_code == 200
    assert len(outbox) == 1
    assert outbox[0].body.count("Thanks for the Airflow post.") == 170
    assert "shape:overlength-message" not in outbox[0].body


def test_rate_limit_returns_429_after_four_sends(client, aged_token, captcha_ok, outbox):
    for _ in range(4):
        assert post_form(client, GOOD_FORM, aged_token).status_code == 200
    response = post_form(client, GOOD_FORM, aged_token)
    assert response.status_code == 429
    assert "wait" in response.get_json()["error"]
    assert len(outbox) == 4


def test_rejected_submissions_do_not_consume_the_send_allowance(
    client, aged_token, monkeypatch, outbox
):
    # Six failed reCAPTCHAs used to fill the hourly bucket and lock the visitor out.
    monkeypatch.setattr(guards, "_siteverify", lambda *a: {"success": False})
    for _ in range(6):
        assert post_form(client, GOOD_FORM, aged_token).status_code == 400
    monkeypatch.setattr(
        guards,
        "_siteverify",
        lambda *a: {
            "success": True,
            "hostname": "vincentdirenzo.com",
            "challenge_ts": "2099-01-01T00:00:00Z",
        },
    )
    assert post_form(client, GOOD_FORM, aged_token).status_code == 200
    assert len(outbox) == 1


def test_attempt_flood_is_dropped_silently(client, aged_token, monkeypatch, outbox):
    monkeypatch.setattr(guards, "_siteverify", lambda *a: {"success": False})
    for _ in range(guards.RateLimiter.ATTEMPT_LIMIT):
        assert post_form(client, GOOD_FORM, aged_token).status_code == 400
    response = post_form(client, GOOD_FORM, aged_token)
    assert response.status_code == 200 and response.get_json()["ok"] is True
    assert outbox == []


def test_oversized_body_is_json_413(client, aged_token, caplog):
    with caplog.at_level("INFO"):
        response = post_form(client, {**GOOD_FORM, "message": "x" * 70_000}, aged_token)
    assert response.status_code == 413
    assert response.get_json()["ok"] is False
    assert contact_log(caplog)["reason"] == "too-large"


def test_overlength_within_2x_is_scored_not_dropped(client, aged_token, captcha_ok, outbox):
    response = post_form(client, {**GOOD_FORM, "message": "y " * 3000}, aged_token)
    assert response.status_code == 200
    assert len(outbox) == 1
    assert "shape:overlength-message" in outbox[0].body


def test_get_contact_is_json_405(client):
    response = client.get("/contact", headers={"Accept": "application/json"})
    assert response.status_code == 405
    assert response.get_json()["ok"] is False


def test_client_ip_via_cloudflare():
    with app_module.app.test_request_context(
        "/contact",
        headers={"X-Forwarded-For": "203.0.113.9, 104.16.1.1", "CF-Connecting-IP": "203.0.113.9"},
    ):
        assert guards.client_ip() == ("203.0.113.9", True)
    with app_module.app.test_request_context(
        "/contact",
        headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.7", "CF-Connecting-IP": "9.9.9.9"},
    ):
        # Peer is not Cloudflare, so the forged CF header is ignored.
        assert guards.client_ip() == ("198.51.100.7", False)


def test_hostname_of_handles_ports_and_ipv6():
    assert guards.hostname_of("vincentdirenzo.com:443") == "vincentdirenzo.com"
    assert guards.hostname_of("[::1]:5002") == "::1"
    assert guards.hostname_of("127.0.0.1:5002") == "127.0.0.1"


@pytest.mark.parametrize("secret_env", [None, "explicit-secret"])
def test_form_secret_is_deterministic(monkeypatch, secret_env):
    if secret_env:
        monkeypatch.setenv("FORM_SECRET", secret_env)
    else:
        monkeypatch.delenv("FORM_SECRET", raising=False)
    monkeypatch.delenv("FORM_SECRET_PREVIOUS", raising=False)
    first, weak_first = guards.derive_form_secret()
    second, weak_second = guards.derive_form_secret()
    assert first == second == [first[-1]]
    assert weak_first is weak_second is False


def test_previous_form_secrets_still_verify_open_tabs(monkeypatch):
    monkeypatch.setenv("FORM_SECRET", "current-secret")
    monkeypatch.setenv("FORM_SECRET_PREVIOUS", "older-secret, oldest-secret")
    keys, weak = guards.derive_form_secret()
    # Signing uses the last key; the older ones only verify.
    assert keys == ["older-secret", "oldest-secret", "current-secret"]
    assert weak is False
    old_token = guards.FormToken(["older-secret"]).mint()
    minted, _ = guards.FormToken(keys).check({}, old_token)
    assert minted is not None


def test_no_harvestable_contact_channel_is_served(client):
    """The form and LinkedIn are the only two channels; nothing else may reach the wire."""
    home = client.get("/").get_data(as_text=True)
    # The no-JS notice is server-rendered HTML, so it needs the same check as the page.
    notice = client.post("/contact", data={}, headers={"Accept": "text/html"}).get_data(
        as_text=True
    )
    for surface, body in (("index", home), ("notice", notice)):
        assert not re.search(r"[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}", body), f"address in {surface}"
        assert "mailto:" not in body, f"mailto in {surface}"
        assert "tel:" not in body, f"tel link in {surface}"
        assert app_module.LINKEDIN_URL in body, f"no LinkedIn fallback in {surface}"


def test_error_messages_never_name_another_channel(client, aged_token, monkeypatch, outbox):
    """Rate-limit and misconfiguration replies used to hand out the address."""
    monkeypatch.setenv("RECAPTCHA_SECRET_KEY", "")
    for message in (
        post_form(client, GOOD_FORM, aged_token).get_json()["error"],
        guards.RATE_LIMITED_MESSAGE,
        guards.UNCONFIGURED_MESSAGE,
    ):
        assert "@" not in message
        assert "email me" not in message.lower()
        assert "LinkedIn" in message or "configured" in message


def test_resume_has_exactly_one_url_and_is_never_cached(client):
    """A copy under static/ would also be served with a one-year cache, outliving a swap."""
    served = client.get("/resume")
    assert served.status_code == 200
    assert served.headers["Cache-Control"] == "no-cache, max-age=0"
    assert served.mimetype == "application/pdf"
    # The old location must not resolve, or a superseded resume lingers in CDN caches.
    assert client.get("/static/assets/img/cv.pdf").status_code == 404
    assert not (pathlib.Path(app_module.app.static_folder) / "assets" / "img" / "cv.pdf").exists()
