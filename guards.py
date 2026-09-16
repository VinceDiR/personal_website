"""Request-side gates for the contact form.

Everything here runs before the content scorer and mostly before any network
call: canonical-host check, client IP resolution behind Cloudflare and the
Heroku router, request-shape checks that a real browser running main.js always
passes, the honeypot, the signed render-time token, a per-worker rate limiter,
and hardened reCAPTCHA verification.

Gates signal outcomes with two exceptions: ``Drop`` means answer with a fake
success and send nothing (bots get no feedback); ``Reject`` means an honest
error a human can act on.
"""

from __future__ import annotations

import collections
import hashlib
import ipaddress
import os
import threading
import time
import urllib.parse
from datetime import datetime, timezone

import requests
from flask import request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

Hit = tuple[str, str, float]

SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
HTTP_TIMEOUT_SECONDS = 6
DEV_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
EXPECTED_FIELDS = frozenset(
    {"name", "email", "subject", "message", "g-recaptcha-response", "ft", "website", "subscribe"}
)
HONEYPOT_TEXT_FIELD = "website"
HONEYPOT_CHECKBOX_FIELD = "subscribe"
TOKEN_FIELD = "ft"
FORM_TOKEN_MAX_AGE_SECONDS = 12 * 3600
FORM_TOKEN_MIN_AGE_SECONDS = 3
FORM_TOKEN_FAST_AGE_SECONDS = 8

# Published Cloudflare edge ranges. Drift only demotes requests to cf=0 (a score
# signal), never a drop, so a stale list degrades gracefully.
CF_RANGES = tuple(
    ipaddress.ip_network(n)
    for n in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
)

CAPTCHA_FAILED_MESSAGE = "reCAPTCHA verification failed. Please try again."
TOKEN_EXPIRED_MESSAGE = (
    "This page has been open a while. Please reload the page and send your message again."
)
RATE_LIMITED_MESSAGE = (
    "You have sent several messages recently. Please wait an hour, or reach me on LinkedIn."
)
UNCONFIGURED_MESSAGE = "The contact form isn't configured right now. Please reach me on LinkedIn."


class Drop(Exception):
    """Silently discard the submission but answer as if it were sent."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Reject(Exception):
    """Refuse the submission with an honest, human-readable error."""

    def __init__(self, message: str, status: int, reason: str):
        super().__init__(message)
        self.message = message
        self.status = status
        self.reason = reason


def utcnow() -> datetime:
    """Returns the current UTC time (separate function so tests can freeze it)."""
    return datetime.now(timezone.utc)


def hostname_of(host_header: str) -> str:
    """Extracts the host name from a Host header value.

    Parsed rather than split on ``:`` so an IPv6 literal such as ``[::1]:5002``
    yields ``::1`` instead of an empty string.

    Args:
        host_header: Raw ``Host`` header, with or without a port.

    Returns:
        The lowercased host name, or an empty string when unparseable.
    """
    try:
        return (urllib.parse.urlsplit(f"//{host_header}").hostname or "").lower()
    except ValueError:
        return ""


def canonical_hosts(site_url: str) -> frozenset[str]:
    """Derives the accepted public host names from the site URL.

    Args:
        site_url: The canonical origin, e.g. ``https://vincentdirenzo.com``.

    Returns:
        The bare host and its ``www.`` variant.
    """
    host = (urllib.parse.urlsplit(site_url).hostname or "vincentdirenzo.com").lower()
    bare = host.removeprefix("www.")
    return frozenset({bare, "www." + bare})


def derive_form_secret() -> tuple[list[str], bool]:
    """Picks the keys used to sign and verify render-time tokens.

    ``FORM_SECRET`` wins when set. Otherwise the key is derived from secrets that
    are already identical on every worker and dyno, because a per-process random
    key would fail half of all submissions with two gunicorn workers.

    ``FORM_SECRET_PREVIOUS`` (comma-separated) keeps older keys valid for
    verification, so rotating a secret does not silently discard every message
    from a page that was already open.

    Returns:
        ``(keys, is_weak)`` with the signing key last, as itsdangerous expects.
        ``is_weak`` is True when every derivation input was blank.
    """
    previous = [
        k.strip() for k in os.environ.get("FORM_SECRET_PREVIOUS", "").split(",") if k.strip()
    ]
    explicit = os.environ.get("FORM_SECRET")
    if explicit:
        return previous + [explicit], False
    parts = (os.environ.get("RECAPTCHA_SECRET_KEY", ""), os.environ.get("EMAIL_PW", ""))
    derived = hashlib.sha256("|".join(parts).encode()).hexdigest()
    return previous + [derived], not any(parts)


def client_ip() -> tuple[str, bool]:
    """Resolves the visitor's IP behind Cloudflare and the Heroku router.

    The Heroku router appends the connecting peer to ``X-Forwarded-For``, so the
    last entry is trustworthy. When that peer is a Cloudflare edge, the visitor
    is in ``CF-Connecting-IP``; otherwise the request bypassed Cloudflare and
    the peer itself is the visitor. ``request.remote_addr`` is never used as a
    key because it is always the router's private address in production.

    Returns:
        ``(ip, via_cloudflare)``.
    """
    forwarded = [
        p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()
    ]
    peer = forwarded[-1] if forwarded else (request.remote_addr or "")
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return (peer[:45] or "unknown", False)
    if any(peer_ip in net for net in CF_RANGES):
        candidate = request.headers.get("CF-Connecting-IP") or (
            forwarded[-2] if len(forwarded) >= 2 else peer
        )
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            candidate = peer
        return (candidate, True)
    return (peer, False)


def check_host(rec: dict, allowed_hosts: frozenset[str]) -> None:
    """Refuses submissions that did not arrive via the public host name.

    Posting straight to ``<app>.herokuapp.com`` skips Cloudflare and makes the
    client-IP headers forgeable, so it gets a 404.

    Args:
        rec: Decision-log record to annotate.
        allowed_hosts: Canonical hosts plus dev hosts.

    Raises:
        Reject: With a 404 for any other host.
    """
    host = hostname_of(request.host)
    rec["host"] = host
    if host not in allowed_hosts:
        raise Reject("Not found", 404, "host")


def check_shape(rec: dict, form, files, limits: dict[str, int], allowed_hosts) -> list[Hit]:
    """Checks that the POST looks like the one main.js sends.

    Present-and-wrong headers are hard drops (a real browser cannot produce
    them); absent headers only add soft points, because privacy extensions and
    old browsers omit them.

    Args:
        rec: Decision-log record to annotate.
        form: ``request.form``.
        files: ``request.files``.
        limits: Per-field maxlength values from the template.
        allowed_hosts: Canonical hosts plus dev hosts.

    Returns:
        Soft hits to feed the scorer.

    Raises:
        Drop: For any signal a browser running the page's JS cannot emit.
    """
    hits: list[Hit] = []
    if request.mimetype != "multipart/form-data":
        rec["ct"] = request.mimetype
        raise Drop("content-type")
    origin = request.headers.get("Origin")
    if origin and hostname_of(urllib.parse.urlsplit(origin).netloc) not in allowed_hosts:
        raise Drop("origin")
    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site and fetch_site != "same-origin":
        raise Drop("sec-fetch-site")
    fetch_mode = request.headers.get("Sec-Fetch-Mode")
    if fetch_mode and fetch_mode != "cors":
        raise Drop("sec-fetch-mode")
    if set(form) - EXPECTED_FIELDS or files:
        rec["fields"] = sorted(set(form) | set(files))
        raise Drop("extra-fields")
    for field, limit in limits.items():
        # The textarea maxlength counts LF but the wire carries CRLF.
        length = len(form.get(field, "").replace("\r\n", "\n"))
        if length > 2 * limit:
            raise Drop("overlength")
        if length > limit:
            hits.append(("shape", f"overlength-{field}", 4))
    if not origin and not request.headers.get("Referer"):
        hits.append(("request", "no-origin-referer", 1))
    if not fetch_site:
        hits.append(("request", "no-sec-fetch", 1))
    if "application/json" not in request.headers.get("Accept", ""):
        hits.append(("request", "accept", 1))
    return hits


def check_honeypot(rec: dict, form) -> None:
    """Drops submissions that filled the off-screen fields.

    Args:
        rec: Decision-log record; the trapped value is stored for auditing.
        form: ``request.form``.

    Raises:
        Drop: When either honeypot field carries a value.
    """
    trapped = form.get(HONEYPOT_TEXT_FIELD, "").strip()
    if trapped or form.get(HONEYPOT_CHECKBOX_FIELD):
        rec["hp"] = (trapped or "checkbox")[:60]
        raise Drop("honeypot")


def check_injection(*values: str) -> None:
    """Drops submissions carrying header-injection newlines.

    Flask-Mail raises on these when building the message, which would otherwise
    surface as a 502 and a stack trace for what is plainly a bot.

    Args:
        *values: Field values destined for mail headers.

    Raises:
        Drop: When any value contains a carriage return or line feed.
    """
    if any("\r" in v or "\n" in v for v in values):
        raise Drop("header-injection")


class FormToken:
    """Signed, timestamped token minted when the page renders and returned by main.js.

    Proves the page was served by this app recently and that JavaScript ran:
    HTTP-only submitters parse ``<input>`` elements, not ``data-*`` attributes.
    """

    def __init__(self, keys: list[str] | str):
        self._signer = URLSafeTimedSerializer(keys, salt="contact-form")

    def mint(self) -> str:
        """Returns a fresh token for embedding in the page."""
        return self._signer.dumps("v1")

    def check(self, rec: dict, token: str) -> tuple[datetime, list[Hit]]:
        """Validates a token and its age.

        Args:
            rec: Decision-log record; the token age is stored.
            token: Value of the ``ft`` form field.

        Returns:
            ``(minted_at, hits)`` where hits carry a soft penalty for fast submits.
            A submit faster than a person can type is scored, not dropped: a
            browser that restores a form on reload can produce one.

        Raises:
            Reject: When the token is older than the max age (a human gets a reload prompt).
            Drop: When the token is missing or forged.
        """
        try:
            _, minted = self._signer.loads(
                token, max_age=FORM_TOKEN_MAX_AGE_SECONDS, return_timestamp=True
            )
        except SignatureExpired as exc:
            raise Reject(TOKEN_EXPIRED_MESSAGE, 400, "ft-expired") from exc
        except BadSignature as exc:
            raise Drop("ft-invalid") from exc
        age = (utcnow() - minted).total_seconds()
        rec["ft_age"] = round(age, 1)
        hits: list[Hit] = []
        if age < FORM_TOKEN_MIN_AGE_SECONDS:
            hits.append(("request", "ft-too-fast", 4))
        elif age < FORM_TOKEN_FAST_AGE_SECONDS:
            hits.append(("request", "ft-fast", 3))
        return minted, hits


class RateLimiter:
    """Sliding-window limiter kept in process memory.

    Two separate windows, because they defend different things. *Attempts* are
    requests that got as far as the reCAPTCHA call and cap how much traffic one
    IP can push at Google. *Sends* are messages actually delivered, and only
    those consume the per-IP, per-network and site-wide allowances -- otherwise a
    bot posting garbage could spend a real visitor's budget, or the whole site's.

    State is per gunicorn worker and resets on restart, so effective limits are
    up to twice the configured numbers; they are sized to be acceptable doubled.
    """

    WINDOW_SECONDS = 3600
    IP_LIMIT = 4
    NET_LIMIT = 10
    ALL_SOFT_LIMIT = 20
    ALL_HARD_LIMIT = 60
    ATTEMPT_LIMIT = 20
    MAX_KEYS = 5000

    def __init__(self):
        self._lock = threading.Lock()
        self._sends: dict[str, collections.deque] = {}
        self._attempts: dict[str, collections.deque] = {}
        # The site-wide window is its own attribute so key eviction can never drop it.
        self._all: collections.deque = collections.deque()

    def reset(self) -> None:
        """Clears all counters (tests)."""
        with self._lock:
            self._sends.clear()
            self._attempts.clear()
            self._all.clear()

    def _trim(self, bucket: collections.deque, now: float) -> collections.deque:
        while bucket and bucket[0] < now - self.WINDOW_SECONDS:
            bucket.popleft()
        return bucket

    def _count(self, store: dict, key: str, now: float) -> int:
        """Counts a window without creating a key, so refused requests leave no trace."""
        bucket = store.get(key)
        if bucket is None:
            return 0
        if not self._trim(bucket, now):
            del store[key]
            return 0
        return len(bucket)

    def _append(self, store: dict, key: str, now: float) -> None:
        self._trim(store.setdefault(key, collections.deque()), now).append(now)
        if len(store) > self.MAX_KEYS:
            # Evict the least recently used keys rather than clearing the table.
            oldest = sorted(store, key=lambda k: store[k][-1])[: len(store) - self.MAX_KEYS]
            for stale in oldest:
                del store[stale]

    @staticmethod
    def _network(ip: str) -> str:
        try:
            prefix = 64 if ":" in ip else 24
            return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        except ValueError:
            return "?"

    def check(self, rec: dict, ip: str) -> list[Hit]:
        """Enforces the limits and records one attempt.

        Args:
            rec: Decision-log record; counters are stored under ``rl``.
            ip: Resolved client IP.

        Returns:
            A soft hit when the whole site is unusually busy.

        Raises:
            Reject: With a 429 when this IP, its /24 (or /64), or the site has
                delivered too many messages this hour.
            Drop: When one IP is hammering the endpoint, which is not a human.
        """
        net = self._network(ip)
        now = time.monotonic()
        with self._lock:
            ip_n = self._count(self._sends, f"ip:{ip}", now)
            net_n = self._count(self._sends, f"net:{net}", now)
            all_n = len(self._trim(self._all, now))
            attempts = self._count(self._attempts, ip, now)
            over_attempts = attempts >= self.ATTEMPT_LIMIT
            if not over_attempts:
                self._append(self._attempts, ip, now)
        rec["rl"] = {
            "ip": f"{ip_n}/{self.IP_LIMIT}",
            "net": f"{net_n}/{self.NET_LIMIT}",
            "all": f"{all_n}/{self.ALL_SOFT_LIMIT}",
            "try": f"{attempts}/{self.ATTEMPT_LIMIT}",
            "pid": os.getpid(),
        }
        if over_attempts:
            raise Drop("rl-attempts")
        if ip_n >= self.IP_LIMIT:
            raise Reject(RATE_LIMITED_MESSAGE, 429, "rl-ip")
        if net_n >= self.NET_LIMIT:
            raise Reject(RATE_LIMITED_MESSAGE, 429, "rl-net")
        if all_n >= self.ALL_HARD_LIMIT:
            raise Reject(RATE_LIMITED_MESSAGE, 429, "rl-all")
        if all_n >= self.ALL_SOFT_LIMIT:
            return [("request", "global-busy", 4)]
        return []

    def commit(self, ip: str) -> None:
        """Counts a delivered message against the per-IP, per-network and site windows."""
        now = time.monotonic()
        with self._lock:
            self._append(self._sends, f"ip:{ip}", now)
            self._append(self._sends, f"net:{self._network(ip)}", now)
            self._trim(self._all, now).append(now)


def _siteverify(token: str, ip: str, secret: str) -> dict | None:
    """Calls Google's siteverify endpoint.

    Returns:
        The parsed JSON object, or None when Google could not be reached or
        answered with something other than an object.
    """
    try:
        response = requests.post(
            SITEVERIFY_URL,
            data={"secret": secret, "response": token, "remoteip": ip},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def verify_captcha(
    rec: dict, token: str, ip: str, secret: str, allowed_hosts, minted: datetime
) -> list[Hit]:
    """Verifies the reCAPTCHA token and judges the details Google returns.

    A definitive failure is an honest 400. An unreachable verifier is NOT a
    failure (that would silently block everyone during a Google outage); it
    adds enough points to flag the mail instead. A token solved under a foreign
    hostname is a drop; a matching hostname proves little because solving farms
    spoof it.

    Args:
        rec: Decision-log record; the siteverify summary is stored under ``captcha``.
        token: The ``g-recaptcha-response`` form value.
        ip: Resolved client IP, passed to Google as ``remoteip``.
        secret: reCAPTCHA secret key.
        allowed_hosts: Canonical hosts plus dev hosts.
        minted: When the render token was issued, to spot pre-solved tokens.

    Returns:
        Soft hits for the scorer.

    Raises:
        Reject: When the secret is unset, the token is missing, or Google says
            it is invalid.
        Drop: When the token was solved on another site.
    """
    if not secret:
        # Without a secret every token would "fail", which would 400 every human.
        raise Reject(UNCONFIGURED_MESSAGE, 503, "captcha-unconfigured")
    if not token:
        raise Reject(CAPTCHA_FAILED_MESSAGE, 400, "captcha-missing")
    result = _siteverify(token, ip, secret)
    if result is None:
        rec["captcha"] = "unverified"
        return [("captcha", "unverified", 6)]
    rec["captcha"] = {
        k: result.get(k) for k in ("success", "hostname", "challenge_ts", "error-codes")
    }
    if not result.get("success"):
        raise Reject(CAPTCHA_FAILED_MESSAGE, 400, "captcha-fail")
    hits: list[Hit] = []
    raw_hostname = result.get("hostname")
    hostname = raw_hostname.lower() if isinstance(raw_hostname, str) else ""
    if hostname and hostname not in allowed_hosts:
        raise Drop("captcha-hostname")
    if not hostname:
        hits.append(("captcha", "no-hostname", 3))
    solved_at = result.get("challenge_ts")
    if isinstance(solved_at, str):
        try:
            solved = datetime.fromisoformat(solved_at.replace("Z", "+00:00"))
            if solved.tzinfo is not None and solved < minted:
                hits.append(("captcha", "solved-before-render", 3))
        except ValueError:
            pass
    return hits
