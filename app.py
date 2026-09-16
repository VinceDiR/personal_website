"""Flask app behind vincentdirenzo.com.

Serves the single-page portfolio, the resume PDF, and a contact form that
relays messages by email after a stack of spam gates (see guards.py and
spamcheck.py). Every contact attempt is logged as one JSON line so the gates
can be tuned from Heroku logs.
"""

import hashlib
import json
import logging
import os
import re
import smtplib
from datetime import datetime, timezone
from functools import lru_cache

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_mail import Mail, Message
from werkzeug.exceptions import RequestEntityTooLarge

import guards
import spamcheck

load_dotenv()

SITE_URL = os.environ.get("SITE_URL", "https://vincentdirenzo.com").rstrip("/")
ALLOWED_HOSTS = guards.canonical_hosts(SITE_URL) | guards.DEV_HOSTS
# Deliberately outside static/: every file under static/ is also served at its own
# unversioned URL with a one-year cache, which would keep a superseded resume in CDN
# and browser caches long after the file on disk is swapped.
RESUME_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resume")
RESUME_FILE = "cv.pdf"
RESUME_DOWNLOAD_NAME = "Vincent-DiRenzo-Resume.pdf"
ONE_YEAR_SECONDS = 60 * 60 * 24 * 365
FIELD_LIMITS = {"name": 200, "email": 200, "subject": 200, "message": 5000}
EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+")
SUCCESS_MESSAGE = "Your message has been sent. Thank you!"
# A native submit cannot carry the render token, which main.js copies out of a data-
# attribute, so a success on the HTML path is never a real send. Claiming one would lie to a
# person whose JavaScript failed to load and cost a message that matters. The wording is the
# same for every outcome on this path, so a bot still learns nothing from it.
HTML_SUBMIT_MESSAGE = "Thanks for filling in the form."
# The form and LinkedIn are the only channels published anywhere. No address or phone
# number ships in the HTML, so there is nothing on the page for a harvester to scrape.
LINKEDIN_URL = "https://www.linkedin.com/in/vincedirenzo"
SMTP_TIMEOUT_SECONDS = 20

_SMTP_INIT = smtplib.SMTP.__init__


def _smtp_init_with_timeout(self, *args, **kwargs):
    """Gives every SMTP connection a socket timeout.

    Flask-Mail 0.10 exposes no timeout setting and smtplib defaults to blocking
    forever, so one stalled mail server would hold a gunicorn thread until the
    dyno restarts. Patching the constructor keeps the timeout on mail sockets
    only, unlike socket.setdefaulttimeout.
    """
    kwargs.setdefault("timeout", SMTP_TIMEOUT_SECONDS)
    _SMTP_INIT(self, *args, **kwargs)


smtplib.SMTP.__init__ = _smtp_init_with_timeout

app = Flask(__name__)
app.config.update(
    MAIL_SERVER=os.environ.get("MAIL_SERVER"),
    MAIL_PORT=int(os.environ.get("EMAIL_PORT", "587")),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get("EMAIL"),
    MAIL_PASSWORD=os.environ.get("EMAIL_PW"),
    MAIL_DEFAULT_SENDER=os.environ.get("EMAIL"),
    # Static assets are versioned by content hash (see static_url), so they can be cached hard.
    SEND_FILE_MAX_AGE_DEFAULT=ONE_YEAR_SECONDS,
    # The contact form is the only upload; anything bigger than this is abuse.
    MAX_CONTENT_LENGTH=64 * 1024,
    MAX_FORM_MEMORY_SIZE=64 * 1024,
    MAX_FORM_PARTS=12,
)
app.logger.setLevel(logging.INFO)
# Keep Jinja loop/set tags from leaving blank lines in the rendered HTML.
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

mail = Mail(app)

_form_keys, _secret_is_weak = guards.derive_form_secret()
if _secret_is_weak:
    app.logger.warning("FORM_SECRET derived from empty secrets; fine for local dev only")
form_token = guards.FormToken(_form_keys)
rate_limiter = guards.RateLimiter()


@lru_cache(maxsize=None)
def _asset_version(filename: str) -> str | None:
    """Returns a short content hash for a file under the static folder.

    Args:
        filename: Path relative to the static folder.

    Returns:
        The first eight hex characters of the file's MD5 digest, or None if the
        file cannot be read.
    """
    try:
        with open(os.path.join(app.static_folder, filename), "rb") as handle:
            return hashlib.md5(handle.read()).hexdigest()[:8]
    except OSError:
        return None


@app.template_global()
def static_url(filename: str) -> str:
    """Builds a cache-busting URL for a static asset.

    Args:
        filename: Path relative to the static folder.

    Returns:
        The static URL with a ``v`` query parameter derived from the file
        contents, so browsers and the CDN refetch only when the file changes.
    """
    return url_for("static", filename=filename, v=_asset_version(filename))


@app.context_processor
def inject_globals() -> dict:
    """Exposes values every template needs.

    Returns:
        A dict with the canonical site URL and the current year.
    """
    return {"site_url": SITE_URL, "year": datetime.now(timezone.utc).year}


@app.after_request
def set_security_headers(response):
    """Adds baseline security headers to every response.

    Args:
        response: The outgoing Flask response.

    Returns:
        The same response with the headers added.
    """
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.get("/")
def index():
    """Renders the portfolio page with a fresh contact-form token.

    Returns:
        The rendered index template, marked uncacheable so the token is never
        served stale by a CDN or the browser cache.
    """
    response = make_response(
        render_template(
            "index.html",
            sitekey=os.environ.get("RECAPTCHA_SITE_KEY", ""),
            form_token=form_token.mint(),
            linkedin_url=LINKEDIN_URL,
        )
    )
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.get("/form-token")
def refresh_form_token():
    """Mints a replacement render token for a page that has been open too long.

    Returns:
        JSON with a fresh token. Worth no more than reloading the page, which
        also mints one, so it needs no gate of its own.
    """
    response = jsonify(token=form_token.mint())
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.get("/resume")
def show_resume():
    """Serves the resume PDF inline so the browser's own viewer renders it.

    Returns:
        The PDF response, marked no-cache so an updated resume shows up
        immediately.
    """
    return send_from_directory(
        RESUME_DIR,
        RESUME_FILE,
        mimetype="application/pdf",
        download_name=RESUME_DOWNLOAD_NAME,
        max_age=0,
    )


@app.get("/favicon.ico")
def favicon():
    """Redirects the implicit favicon request to the logo.

    Returns:
        A redirect to the versioned logo asset.
    """
    return redirect(static_url("assets/img/logo.png"))


@app.get("/robots.txt")
def robots():
    """Serves a permissive robots.txt.

    Returns:
        A plain-text response allowing all crawlers.
    """
    return "User-agent: *\nAllow: /\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


NOTICE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Contact | Vincent DiRenzo</title></head>
<body style="font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem">
<p>{message}</p>
<p>This form needs JavaScript to send, and your browser did not run it, so your message
may not have reached me. Please <a href="{linkedin}" rel="me noopener">reach me on LinkedIn</a>
instead.</p>
<p><a href="/">Back to the site</a></p>
</body></html>
"""


def _wants_json() -> bool:
    """True when the caller is the contact form's fetch(), which sets Accept."""
    return "application/json" in request.headers.get("Accept", "")


def _respond(ok: bool, message: str, status: int = 200, code: str | None = None):
    """Answers in whichever format the caller can read.

    A browser submitting the form natively (no JavaScript, or a script that
    failed to load) gets HTML instead of raw JSON. The wording is the same for a
    real send and a silent drop, so the HTML path is not a feedback channel
    either.

    Args:
        ok: Whether to report success.
        message: Text for the visitor.
        status: HTTP status code.
        code: Machine-readable reason, used by main.js to retry with a new token.

    Returns:
        A ``(response, status)`` tuple.
    """
    if _wants_json():
        payload = {"ok": True, "message": message} if ok else {"ok": False, "error": message}
        if code:
            payload["code"] = code
        return jsonify(payload), status
    page = NOTICE_PAGE.format(message=HTML_SUBMIT_MESSAGE if ok else message, linkedin=LINKEDIN_URL)
    return page, status, {"Content-Type": "text/html; charset=utf-8"}


def _fmt_hits(hits) -> list[str]:
    """Renders raw ``(family, label, points)`` hits for the decision log."""
    return [f"{family}:{label}({points:+g})" for family, label, points in hits]


def _log(rec: dict) -> None:
    """Writes the one-line decision record for this attempt.

    Delivered mail is already in the inbox, so its subject and body preview are
    left out of the log; for anything filtered they are the only way to tune the
    rules.
    """
    safe = dict(rec)
    if safe.get("decision") == "sent":
        safe.pop("preview", None)
        safe.pop("subject", None)
    # ensure_ascii keeps a bot's embedded newlines from forging a second log line.
    app.logger.info("contact %s", json.dumps(safe, ensure_ascii=True, default=str))


@app.errorhandler(413)
def request_too_large(exc):
    """Turns Werkzeug's HTML 413 into the JSON main.js expects.

    A 413 raised while the contact view parses the body is handled there. This
    catches the rest, so an oversized body never returns Werkzeug's HTML page.
    """
    if request.path == "/contact":
        _log(
            {
                "decision": "rejected",
                "reason": "too-large",
                "host": guards.hostname_of(request.host),
            }
        )
        return _respond(False, "That request was too large.", 413, "too-large")
    return exc.get_response()


@app.errorhandler(405)
def method_not_allowed(exc):
    """Turns Werkzeug's HTML 405 into JSON for the contact endpoint."""
    if request.path == "/contact":
        return _respond(False, "Method not allowed.", 405, "method")
    return exc.get_response()


@app.post("/contact")
def contact():
    """Handles a contact form submission and logs one decision record.

    Returns:
        JSON with ``ok`` set, plus ``message`` on success or ``error`` on
        failure. Silently dropped spam receives the same success body as a
        real send so bots learn nothing.
    """
    rec: dict = {"decision": "error", "reason": None, "score": 0, "hits": []}
    hits: list = []
    try:
        return _handle_contact(rec, hits)
    except RequestEntityTooLarge:
        # Werkzeug raises this while parsing the body, so log it here rather than
        # letting the 413 handler add a second line for the same request.
        rec.update(decision="rejected", reason="too-large")
        return _respond(False, "That request was too large.", 413, "too-large")
    except guards.Drop as exc:
        rec.update(decision="dropped", reason=exc.reason)
        return _respond(True, SUCCESS_MESSAGE)
    except guards.Reject as exc:
        rec.update(decision="rejected", reason=exc.reason)
        return _respond(False, exc.message, exc.status, exc.reason)
    finally:
        # Gates that exited early never reached the scorer, so show what they did collect.
        if not rec["hits"]:
            rec["hits"] = _fmt_hits(hits)
        _log(rec)


def _handle_contact(rec: dict, hits: list):
    """Runs the gates in order, then scores and sends.

    Order: host, fields present, request shape, honeypot, render token, email
    syntax, header injection, rate limit, mail config, reCAPTCHA, content score,
    send. Cheap local checks run first so bot traffic never reaches the network
    calls.

    Args:
        rec: Decision-log record filled in as the gates run.
        hits: Soft hits accumulated so far; appended to in place so an early
            exit still logs what fired.

    Returns:
        The success response.

    Raises:
        guards.Drop: To answer with a fake success and send nothing.
        guards.Reject: To answer with an honest error.
    """
    guards.check_host(rec, ALLOWED_HOSTS)
    form = request.form
    # The wire carries CRLF; normalising first keeps a long message from being
    # truncated tens of characters early just because it has paragraphs.
    raw = {field: form.get(field, "").replace("\r\n", "\n") for field in FIELD_LIMITS}
    if not all(value.strip() for value in raw.values()):
        raise guards.Reject("Please fill in every field.", 400, "missing-fields")

    hits += guards.check_shape(rec, form, request.files, FIELD_LIMITS, ALLOWED_HOSTS)
    guards.check_honeypot(rec, form)
    minted, token_hits = form_token.check(rec, form.get(guards.TOKEN_FIELD, ""))
    hits += token_hits

    name, email, subject, message = (
        raw[field].strip()[: FIELD_LIMITS[field]]
        for field in ("name", "email", "subject", "message")
    )
    if not EMAIL_RE.fullmatch(email):
        raise guards.Reject("Please enter a valid email address.", 400, "email-syntax")
    guards.check_injection(name, email, subject)

    ip, via_cloudflare = guards.client_ip()
    rec.update(
        ip=ip,
        cf=via_cloudflare,
        ua=request.user_agent.string[:120],
        email_domain=email.rpartition("@")[2].lower(),
        subject=subject[:80],
        preview=message[:120],
    )
    if not via_cloudflare and rec["host"] not in guards.DEV_HOSTS:
        hits.append(("request", "not-cloudflare", 3))
    hits += rate_limiter.check(rec, ip)

    recipient = os.environ.get("EMAIL")
    if not recipient or not app.config["MAIL_SERVER"]:
        app.logger.error("Contact form used but mail settings are missing")
        raise guards.Reject(guards.UNCONFIGURED_MESSAGE, 503, "mail-unconfigured")

    hits += guards.verify_captcha(
        rec,
        form.get("g-recaptcha-response", ""),
        ip,
        os.environ.get("RECAPTCHA_SECRET_KEY", ""),
        ALLOWED_HOSTS,
        minted,
    )

    verdict = spamcheck.score(name, email, subject, message, hits)
    rec.update(
        score=verdict.total,
        hits=verdict.hits,
        url_count=verdict.url_count,
        would_block=verdict.would_block,
    )
    if verdict.verdict == "block":
        raise guards.Drop("score")

    flagged = verdict.verdict == "flag" or rec.get("captcha") == "unverified"
    prefix = "[Possible spam] " if flagged else ""
    footer = (
        f"-- spam score {verdict.total:g}: {', '.join(verdict.hits) or 'none'}; "
        f"ip={ip} cf={int(via_cloudflare)}"
    )
    msg = Message(
        subject=f"{prefix}Website Inquiry: {subject}",
        recipients=[recipient],
        reply_to=(name, email),
        body=f"From: {name} <{email}>\nSubject: {subject}\n\n{message}\n\n{footer}\n",
        extra_headers={"X-Spam-Score": f"{verdict.total:g}"},
    )
    try:
        mail.send(msg)
    except Exception as exc:  # pylint: disable=broad-except
        app.logger.exception("Failed to send contact email")
        raise guards.Reject(
            "Your message couldn't be sent right now. Please try again later.", 502, "smtp"
        ) from exc

    # Only a delivered message spends the visitor's hourly allowance.
    rate_limiter.commit(ip)
    rec.update(decision="flagged" if flagged else "sent", reason=None)
    return _respond(True, SUCCESS_MESSAGE)


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5002")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
