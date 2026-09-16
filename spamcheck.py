"""Content scoring for contact-form submissions.

Pure functions over the four form fields plus request-level hits collected by
the app. Every rule adds a ``(family, label, points)`` hit; the total decides
between ``allow``, ``flag`` (deliver with a subject prefix) and ``block`` (drop
silently). Blocking additionally needs two independent families each
contributing three or more points, so no single signal, and never vocabulary
alone, can block a message. Nothing here can drop a message on its own while
``SPAM_BLOCK_ENABLED`` is off. Stdlib only. Tune the lists below from the
``contact {...}`` decision log lines.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import unicodedata
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache

Hit = tuple[str, str, float]

OWNER_DOMAIN = "vincentdirenzo.com"


def _env_int(name: str, default: int) -> int:
    """Reads an integer environment variable, falling back on bad or missing values.

    Args:
        name: Environment variable name.
        default: Value used when the variable is unset or not an integer.

    Returns:
        The parsed integer or the default.
    """
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


FLAG_THRESHOLD = _env_int("SPAM_FLAG_THRESHOLD", 6)
BLOCK_THRESHOLD = _env_int("SPAM_BLOCK_THRESHOLD", 12)
BLOCK_ENABLED = os.environ.get("SPAM_BLOCK_ENABLED") == "1"
TRUST_FLOOR = -5
DUPE_TTL_SECONDS = 24 * 3600
DUPE_MAX_ENTRIES = 500
DUPE_MIN_CHARS = 40

# --- Owner-editable lists -------------------------------------------------------------------

# Distinct phrase in subject+message: +5 each, capped at 12.
STRONG_PHRASES = (
    "backlink",
    "guest post",
    "sponsored post",
    "link exchange",
    "link building",
    "seo service",
    "search engine optimization",
    "first page of google",
    "rank on google",
    "web design service",
    "redesign your website",
    "mobile app development",
    "increase your traffic",
    "boost your sales",
    "appointment setting",
    "crypto",
    "bitcoin",
    "forex",
    "binary option",
    "casino",
    "quick loan",
    "loan offer",
    "viagra",
    "cialis",
    "escort",
    "passive income",
    "make money",
    "investment opportunity",
    "domain renewal",
    "domain will expire",
    "dear business owner",
    "dear sir/madam",
    "dear webmaster",
    "click here",
    "act now",
    "limited time offer",
    "unsubscribe",
    "100% free",
    "buy followers",
    "instagram followers",
    "youtube subscribers",
    "explainer video",
    "logo design",
    "video editing",
    "press release",
    "content writing service",
    "virtual assistant",
    "data entry",
    "cold email",
    "email list",
    "b2b leads",
    "copyright infringement",
    "dmca",
)

# Distinct phrase: +2 each, capped at 6. Openers and business-speak; prune from real traffic.
# Phrases a recruiter at a marketing firm might legitimately use belong here, not above.
WEAK_PHRASES = (
    "i noticed your website",
    "i came across your website",
    "i visited your website",
    "i noticed your",
    "your website",
    "your site",
    "your blog",
    "your business",
    "your company",
    "free quote",
    "free consultation",
    "affordable",
    "pricing",
    "our services",
    "our company",
    "our team",
    "our agency",
    "digital marketing",
    "marketing agency",
    "lead generation",
    "work from home",
    "traffic",
    "ranking",
    "domain authority",
    "get back to me",
    "we pay",
    "paid collaboration",
    "special offer",
    "discount",
    "guarantee",
    "no obligation",
    "cheap",
    "telegram",
    "whatsapp",
)

# Distinct phrase: -1 each, capped at -3. Things real correspondents say.
TRUST_PHRASES = (
    "vince",
    "vincent",
    "direnzo",
    "data engineer",
    "airflow",
    "medium",
    "article",
    "your post",
    "hearst",
    "bigquery",
    "pipeline",
    "composer",
    "recruiter",
    "role",
    "position",
    "opportunity",
    "interview",
    "resume",
    "linkedin",
    "github",
    "spark",
    "dbt",
    "sql",
    "python",
    "hiring",
    "job",
)

NAME_SPAM_WORDS = frozenset(
    {"seo", "marketing", "agency", "team", "support", "admin", "design", "digital", "media"}
)
ROLE_LOCAL_PARTS = frozenset(
    {
        "info",
        "admin",
        "sales",
        "marketing",
        "seo",
        "support",
        "contact",
        "webmaster",
        "office",
        "team",
    }
)
DISPOSABLE_DOMAINS = frozenset(
    {
        "mailinator.com",
        "guerrillamail.com",
        "10minutemail.com",
        "temp-mail.org",
        "yopmail.com",
        "sharklasers.com",
        "trashmail.com",
        "getnada.com",
        "dispostable.com",
        "maildrop.cc",
        "tempmail.com",
        "fakeinbox.com",
        "mohmal.com",
        "emailondeck.com",
        "mintemail.com",
    }
)
# Links to these hosts score nothing and count as a small trust signal, unless the
# link is a redirector (see _is_redirector), which is how an allowlist gets abused.
TRUSTED_LINK_HOSTS = frozenset(
    {
        "linkedin.com",
        "github.com",
        "medium.com",
        "calendly.com",
        "x.com",
        "twitter.com",
        "stackoverflow.com",
        "kaggle.com",
        "youtube.com",
        "docs.google.com",
        "greenhouse.io",
        "lever.co",
        "ashbyhq.com",
        "workable.com",
    }
)
# Links to these hosts are ignored entirely (mail providers people mention in passing).
IGNORED_LINK_HOSTS = frozenset(
    {
        OWNER_DOMAIN,
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
    }
)
SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "rb.gy",
        "is.gd",
        "goo.gl",
        "shorturl.at",
        "tiny.cc",
    }
)
BAD_TLDS = frozenset(
    {
        "ru",
        "xyz",
        "top",
        "shop",
        "site",
        "online",
        "club",
        "icu",
        "buzz",
        "work",
        "cn",
        "su",
        "ws",
        "rest",
        "cf",
        "ga",
        "gq",
        "ml",
        "tk",
    }
)
# Path segments that mean "this trusted host will forward you somewhere else".
REDIRECT_SEGMENTS = frozenset({"redirect", "redir", "url", "away", "out", "exit", "l.php", "r"})

# --- Link detection -------------------------------------------------------------------------

# Recognised as a link when the token carries a path or scheme. Ambiguous two-letter
# TLDs live here only, because "sentence.To be clear" must not read as a domain.
PATH_TLDS = frozenset(
    """com net org io co ai dev app me info biz us uk ca au de fr es it nl se no fi dk pl cz
    ch at be pt ie in jp cn kr br mx ar cl za ng ke ae il tr gr ro hu sk bg hr si lt lv ee ua
    by kz ph vn th my sg id hk tw nz edu gov mil int eu asia xyz top shop site online club icu
    buzz work store website link live fun space tech host press agency digital marketing email
    solutions services company today world life pro cc tv ly gg sh st to ru su ws rest cf ga
    gq ml tk is be it am as so do re my no at by""".split()
)
# A bare domain with no path or scheme must end in one of these. English words that
# commonly follow a sentence period are deliberately absent.
BARE_TLDS = frozenset(
    """com net org io co ai dev app info biz us uk ca au de fr es it nl se dk pl cz ch be pt
    ie jp cn kr br mx za ng ke ae il tr gr ro hu sk bg hr si lt lv ee ua by kz ph vn th my sg
    id hk tw nz edu gov eu asia xyz shop site online club icu buzz store website space tech
    host press agency digital marketing solutions services company ru su ws cf ga gq ml
    tk""".split()
)

# Payload words matched against hostnames and link paths, not prose. Spun-text spam
# carries no scoreable sentences: the giveaway is the sender domain (cialis-otc.com) and
# a slug repeated across reputable hosts (bandlab.com/apotekalmacom). STRONG_PHRASES
# cannot be reused here because a real correspondent's domain may hold crypto or seo,
# and a gambling firm hiring a data engineer is an ordinary employer. Pharma and adult
# words have no such overlap.
PAYLOAD_WORDS = (
    """viagra cialis levitra kamagra sildenafil tadalafil tramadol xanax ambien oxycodone
    adderall pharmacy pharmacie apotek apteka drugstore pillstore rxonline escort camgirl
    porn""".split()
)

_TOKEN_RE = re.compile(r"[^\s<>\"'()\[\]{}]+")
_HOSTISH_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")
_SCHEME_PREFIXES = ("http://", "https://", "www.")
_EMAIL_RE = re.compile(r"[^\s@<>]+@[^\s@<>]+\.[a-z]{2,}", re.IGNORECASE)
_MONEY_RE = re.compile(r"\$\s?\d|\d\s?%")
_HREF_RE = re.compile(r"<a\s+href|href=", re.IGNORECASE)
_TAG_RE = re.compile(r"<[a-zA-Z][^<>@]{0,60}>")
# Real BBCode, not a Markdown link: "[url=...]" or a closing "[/url]". A bare "[URL]"
# or "[link to the JD](https://...)" is something a person writes, so it must not match.
_BBCODE_RE = re.compile(
    r"\[(?:url|link|img)\s*=\s*[^\]\n]{1,300}\]|\[/(?:url|link|img)\]", re.IGNORECASE
)
# A URL with userinfo: "http://linkedin.com@spam.example" reads as trusted to a human.
_USERINFO_URL_RE = re.compile(r"(?:https?://|www\.)[^\s/?#]*@", re.IGNORECASE)
_NESTED_URL_RE = re.compile(r"https?(?::|%3a)|www\.", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)]}>'\""
# Invisible characters that survive NFKC and would otherwise split a phrase in two.
_EXTRA_INVISIBLE = frozenset("\u034f")


def _phrase_re(phrases: tuple[str, ...]) -> re.Pattern:
    """Compiles a whole-word alternation of phrases with an optional plural ``s``."""
    return re.compile(r"\b(?:" + "|".join(re.escape(p) for p in phrases) + r")s?\b")


_STRONG_RE = _phrase_re(STRONG_PHRASES)
_WEAK_RE = _phrase_re(WEAK_PHRASES)
_TRUST_RE = _phrase_re(TRUST_PHRASES)
_NAME_SPAM_RE = _phrase_re(tuple(sorted(NAME_SPAM_WORDS)))
# Substring, not whole-word: these hide inside slugs like apotekalmacom66.
_PAYLOAD_RE = re.compile("|".join(re.escape(w) for w in PAYLOAD_WORDS))


@dataclass
class Verdict:
    """Result of scoring one submission.

    Attributes:
        total: Sum of all hit points after the trust floor.
        verdict: One of ``allow``, ``flag``, ``block``.
        hits: Human-readable ``family:label(+points)`` strings, in evaluation order.
        would_block: True when the block rule matched, even if blocking is disabled.
        url_count: Number of distinct links found in subject+message.
    """

    total: float
    verdict: str
    hits: list[str]
    would_block: bool
    url_count: int


@lru_cache(maxsize=4096)
def _is_invisible(char: str) -> bool:
    """True for zero-width and other non-rendering characters."""
    return (
        unicodedata.category(char) == "Cf"
        or char in _EXTRA_INVISIBLE
        or "\ufe00" <= char <= "\ufe0f"
    )


def _norm(text: str) -> str:
    """Normalises text for matching: NFKC, drop invisible characters, casefold.

    Invisible characters are removed rather than preserved so that a phrase
    smuggled through as ``back<soft hyphen>link`` still matches ``backlink``.
    """
    normalized = unicodedata.normalize("NFKC", text)
    if any(_is_invisible(c) for c in normalized):
        normalized = "".join(c for c in normalized if not _is_invisible(c))
    return normalized.casefold()


def _ascii_fold(text: str) -> str:
    """Strips accents and non-ASCII characters (``Zoe`` with a diaeresis -> ``Zoe``)."""
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


@lru_cache(maxsize=4096)
def _is_latin(char: str) -> bool:
    """True for Latin-script letters, including accented ones."""
    return unicodedata.name(char, "LATIN").startswith("LATIN")


def _is_latin_alnum(char: str) -> bool:
    """True for digits and Latin letters, used to spot characters hidden inside a word."""
    return char.isdigit() or (char.isalpha() and _is_latin(char))


def _has_invisible_in_word(text: str) -> bool:
    """True when an invisible character sits between two Latin letters or digits.

    Zero-width joiners between emoji and the zero-width non-joiner used in
    Persian and Indic scripts are legitimate, so only the in-word case counts.
    """
    for index, char in enumerate(text):
        if not _is_invisible(char) or index == 0 or index + 1 >= len(text):
            continue
        if _is_latin_alnum(text[index - 1]) and _is_latin_alnum(text[index + 1]):
            return True
    return False


def _registrable(host: str) -> str:
    """Approximates the registrable domain as the last two labels."""
    return ".".join(host.split(".")[-2:])


def _tld(host: str) -> str:
    """Returns the last label of a host name."""
    return host.rsplit(".", 1)[-1]


def _looks_like_link(token: str) -> bool:
    """True when a whitespace-delimited token is a URL or a bare domain.

    A plain token scan replaces the nested-quantifier regex this used to use,
    which cost over a second of CPU on a 5000-character message.
    """
    lowered = token.lower()
    if lowered.startswith(_SCHEME_PREFIXES):
        return True
    head, slash, _ = lowered.partition("/")
    head = head.rstrip(_TRAILING_PUNCT)
    if "." not in head or not _HOSTISH_RE.fullmatch(head):
        return False
    return _tld(head) in (PATH_TLDS if slash else BARE_TLDS)


def _replace_links(text: str, placeholder: str = " ") -> str:
    """Blanks out every URL and bare domain, leaving the prose behind."""
    return _TOKEN_RE.sub(
        lambda m: placeholder if _looks_like_link(m.group(0)) else m.group(0), text
    )


def _link_host(url: str) -> tuple[str, str | None]:
    """Cleans a URL-ish match and extracts its host.

    Args:
        url: Raw token, possibly with trailing punctuation.

    Returns:
        ``(cleaned_url, host)`` where host is None when the URL cannot be parsed
        (treated as untrusted by callers). Userinfo is discarded by urlsplit, so
        ``http://linkedin.com@spam.example`` resolves to ``spam.example``.
    """
    url = url.rstrip(_TRAILING_PUNCT)
    target = url if url.lower().startswith(("http://", "https://")) else "http://" + url
    try:
        host = urllib.parse.urlsplit(target).hostname
    except ValueError:
        return url, None
    if not host:
        return url, None
    return url, host.lower().removeprefix("www.")


def _is_redirector(url: str) -> bool:
    """True when a URL forwards elsewhere, which is how a trusted host gets borrowed."""
    target = url if url.lower().startswith(("http://", "https://")) else "http://" + url
    try:
        parts = urllib.parse.urlsplit(target)
    except ValueError:
        return False
    if _NESTED_URL_RE.search(f"{parts.query} {parts.fragment}"):
        return True
    segments = {s for s in parts.path.lower().split("/") if s}
    return bool(segments & REDIRECT_SEGMENTS)


def _extract_links(text_cf: str) -> list[tuple[str, str | None]]:
    """Finds distinct links in text.

    Email addresses are not links: the ``@`` stops them matching the host
    pattern, so they are skipped without a scrubbing pass that a URL containing
    an ``@`` could hide behind.

    Args:
        text_cf: Normalised text.

    Returns:
        Distinct ``(url, host)`` pairs.
    """
    seen: dict[str, str | None] = {}
    for token in _TOKEN_RE.findall(text_cf):
        if not _looks_like_link(token):
            continue
        url, host = _link_host(token)
        if url and url not in seen:
            seen[url] = host
    return list(seen.items())


def _classify_links(links, sender_reg: str = "") -> tuple[list, bool, int, int]:
    """Splits links by how much they are worth worrying about.

    Args:
        links: ``(url, host)`` pairs.
        sender_reg: Registrable domain of the sender's own email address.

    Returns:
        ``(untrusted, saw_trusted, own_domain_count, redirector_count)``. A link
        to the sender's own domain is neither suspicious nor a trust signal: a
        recruiter linking their employer is the single most common real case.
    """
    untrusted, trusted, own, redirectors = [], False, 0, 0
    for url, host in links:
        if host is None:
            untrusted.append((url, None))
            continue
        reg = _registrable(host)
        if host in IGNORED_LINK_HOSTS or reg in IGNORED_LINK_HOSTS:
            continue
        if sender_reg and reg == sender_reg:
            own += 1
            continue
        if host in TRUSTED_LINK_HOSTS or reg in TRUSTED_LINK_HOSTS:
            if _is_redirector(url):
                redirectors += 1
                untrusted.append((url, host))
                continue
            trusted = True
            continue
        untrusted.append((url, host))
    return untrusted, trusted, own, redirectors


def _score_links(subject_cf: str, text_cf: str, sender_reg: str) -> tuple[list[Hit], int, int]:
    """Scores link count, shorteners, cheap TLDs, redirectors and links in the subject.

    Returns:
        ``(hits, untrusted_count, total_link_count)``.
    """
    hits: list[Hit] = []
    links = _extract_links(text_cf)
    untrusted, trusted, own, redirectors = _classify_links(links, sender_reg)
    count = len(untrusted)
    if count:
        hits.append(("links", f"untrusted-url x{count}", min(2 * count, 8)))
    if count >= 3:
        hits.append(("links", "many-urls", 2))
    shorteners = sum(
        1
        for _, h in untrusted
        if h and (h in SHORTENER_HOSTS or _registrable(h) in SHORTENER_HOSTS)
    )
    if shorteners:
        hits.append(("links", "shortener", min(3 * shorteners, 6)))
    payloads = {m.group() for url, _ in untrusted if (m := _PAYLOAD_RE.search(url))}
    if payloads:
        hits.append(("links", f"payload-link:{'/'.join(sorted(payloads))}", 4))
    bad_tlds = sum(1 for _, h in untrusted if h and _tld(h) in BAD_TLDS)
    if bad_tlds:
        hits.append(("links", "bad-tld", min(2 * bad_tlds, 4)))
    if redirectors:
        hits.append(("links", "redirector", min(4 * redirectors, 8)))
    if _USERINFO_URL_RE.search(text_cf):
        hits.append(("links", "userinfo-url", 3))
    if _classify_links(_extract_links(subject_cf), sender_reg)[0]:
        hits.append(("links", "url-in-subject", 2))
    if trusted:
        hits.append(("trust", "trusted-link", -1))
    if own:
        hits.append(("links", f"own-domain-url x{own}", 0))
    return hits, count, len(links)


def _score_vocab(text_cf: str) -> list[Hit]:
    """Scores spam vocabulary, money talk, and trust words."""
    hits: list[Hit] = []
    strong = {m.rstrip("s") for m in _STRONG_RE.findall(text_cf)}
    weak = {m.rstrip("s") for m in _WEAK_RE.findall(text_cf)}
    trust = {m.rstrip("s") for m in _TRUST_RE.findall(text_cf)}
    if strong:
        hits.append(("vocab", "strong:" + ",".join(sorted(strong))[:80], min(5 * len(strong), 12)))
    if weak:
        hits.append(("vocab", "weak:" + ",".join(sorted(weak))[:80], min(2 * len(weak), 6)))
    money = len(_MONEY_RE.findall(text_cf))
    if money:
        hits.append(("vocab", "money-talk", min(money, 2)))
    if trust:
        hits.append(("trust", "words:" + ",".join(sorted(trust))[:80], max(-len(trust), -3)))
    return hits


def _score_markup(name_raw: str, message_raw: str, text_cf: str) -> list[Hit]:
    """Scores HTML, BBCode and characters hidden inside words."""
    hits: list[Hit] = []
    if _HREF_RE.search(text_cf):
        hits.append(("markup", "href", 6))
    elif _TAG_RE.search(text_cf):
        hits.append(("markup", "html-tag", 3))
    if _BBCODE_RE.search(text_cf):
        hits.append(("markup", "bbcode", 8))
    if _has_invisible_in_word(message_raw) or _has_invisible_in_word(name_raw):
        hits.append(("markup", "invisible-chars", 4))
    return hits


def _score_script(raw_text: str) -> list[Hit]:
    """Scores non-Latin letter share and mixed-script tokens on an English-language site."""
    hits: list[Hit] = []
    letters = [c for c in raw_text if unicodedata.category(c).startswith("L")]
    if len(letters) >= 8:
        ratio = sum(1 for c in letters if not _is_latin(c)) / len(letters)
        if ratio >= 0.5:
            hits.append(("script", f"non-latin {ratio:.0%}", 5))
        elif ratio >= 0.2:
            hits.append(("script", f"non-latin {ratio:.0%}", 2))
    for token in re.findall(r"\w+", raw_text):
        token_letters = [c for c in token if unicodedata.category(c).startswith("L")]
        if (
            len(token_letters) >= 4
            and any(_is_latin(c) for c in token_letters)
            and any(not _is_latin(c) for c in token_letters)
        ):
            hits.append(("script", "mixed-script-token", 4))
            break
    return hits


def _score_name(name_cf: str, subject_cf: str, message_cf: str, sender_reg: str) -> list[Hit]:
    """Scores anomalies in the name field."""
    hits: list[Hit] = []
    domains = [host for _, host in _extract_links(name_cf) if host]
    if "http" in name_cf:
        hits.append(("name", "url-in-name", 6))
    elif domains and not (sender_reg and any(_registrable(d) == sender_reg for d in domains)):
        # A company domain typed as the name is odd but not rare; their own domain is fine.
        hits.append(("name", "domain-in-name", 3))
    if "@" in name_cf:
        hits.append(("name", "at-sign", 2))
    if any(c.isdigit() for c in name_cf):
        hits.append(("name", "digit", 2))
    if len(name_cf.split()) > 5:
        hits.append(("name", "many-words", 2))
    if _NAME_SPAM_RE.search(name_cf):
        hits.append(("name", "spam-word", 2))
    for token in re.findall(r"[^\W\d_]+", name_cf):
        # Only Latin words have vowels to be missing.
        if len(token) >= 6 and all(_is_latin(c) for c in token):
            if not any(v in token for v in "aeiouy"):
                hits.append(("name", "no-vowel", 2))
                break
    stripped = name_cf.strip()
    if stripped and stripped in (subject_cf.strip(), message_cf.strip()):
        hits.append(("name", "equals-subject-or-message", 3))
    return hits


def _score_email(email_cf: str, name_cf: str) -> list[Hit]:
    """Scores the sender address: throwaway domains, role accounts, random local parts."""
    hits: list[Hit] = []
    local, _, domain = email_cf.rpartition("@")
    if domain in DISPOSABLE_DOMAINS or _registrable(domain) in DISPOSABLE_DOMAINS:
        hits.append(("email", "disposable-domain", 4))
    if "." not in domain:
        hits.append(("email", "no-dot-domain", 2))
    if _tld(domain) in BAD_TLDS:
        hits.append(("email", "bad-tld", 2))
    payload = _PAYLOAD_RE.search(domain)
    if payload:
        hits.append(("email", f"payload-domain:{payload.group()}", 6))
    if re.sub(r"\d+$", "", local) in ROLE_LOCAL_PARTS:
        hits.append(("email", "role-account", 2))
    if local.startswith(("noreply", "no-reply", "no_reply")):
        hits.append(("email", "noreply", 4))
    alnum = [c for c in local if c.isalnum()]
    if len(alnum) >= 8:
        transitions = sum(1 for a, b in zip(alnum, alnum[1:]) if a.isdigit() != b.isdigit())
        digits = sum(c.isdigit() for c in alnum)
        if transitions >= 4 or digits > len(alnum) / 2 or not any(v in local for v in "aeiouy"):
            hits.append(("email", "random-local", 2))
    folded_local = _ascii_fold(local)
    for token in re.findall(r"[a-z]{3,}", _ascii_fold(name_cf)):
        if token not in NAME_SPAM_WORDS and token in folded_local:
            hits.append(("trust", "name-in-email", -1))
            break
    return hits


def _score_shape(
    subject_cf: str, message_cf: str, message_raw: str, residue: str, untrusted_links: int
) -> list[Hit]:
    """Scores message shape: length extremes, shouting, subject copied into the body."""
    hits: list[Hit] = []
    if len(residue) < 10 and untrusted_links:
        hits.append(("links", "link-only", 4))
    elif len(residue) < 15 and not untrusted_links:
        hits.append(("shape", "very-short", 2))
    if subject_cf.strip() and subject_cf.strip() == message_cf.strip():
        hits.append(("shape", "subject-equals-message", 3))
    letters = [c for c in message_raw if c.isalpha()]
    if len(letters) >= 20 and sum(c.isupper() for c in letters) / len(letters) > 0.5:
        hits.append(("shape", "shouting", 2))
    if message_raw.count("!") >= 3:
        hits.append(("shape", "exclamation", 1))
    if len(message_raw) > 3000:
        hits.append(("shape", "very-long", 1))
    return hits


_DUPES: dict[str, tuple[float, set[str]]] = {}
_DUPES_LOCK = threading.Lock()


def _fingerprint(name_cf: str, text_cf: str) -> str | None:
    """Builds a template fingerprint that survives swapped links, numbers and names.

    Returns:
        A SHA-1 hex digest, or None when the residual text is too short to be meaningful.
    """
    text = _replace_links(text_cf, "URL")
    text = _EMAIL_RE.sub("EMAIL", text)
    text = re.sub(r"\d+", "0", text)
    for token in re.findall(r"\w{3,}", name_cf):
        text = text.replace(token, " ")
    text = re.sub(r"\s+", " ", text).strip()[:400]
    if len(text) < DUPE_MIN_CHARS:
        return None
    return hashlib.sha1(text.encode()).hexdigest()


def _score_dupe(fingerprint: str | None, email_cf: str, now: float | None = None) -> list[Hit]:
    """Scores the same message template arriving from several sender domains.

    Counted per sender domain, not per address, so two colleagues at one agency
    forwarding the same job description do not look like a blast.

    State is per process and bounded; it resets on restart, which only means a
    blast straddling a restart is under-counted.
    """
    if fingerprint is None:
        return []
    now = time.monotonic() if now is None else now
    sender = _registrable(email_cf.rpartition("@")[2]) or email_cf
    with _DUPES_LOCK:
        expired = [k for k, (seen, _) in _DUPES.items() if now - seen > DUPE_TTL_SECONDS]
        for key in expired:
            del _DUPES[key]
        while len(_DUPES) >= DUPE_MAX_ENTRIES:
            _DUPES.pop(next(iter(_DUPES)))
        _, senders = _DUPES.setdefault(fingerprint, (now, set()))
        senders.add(sender)
        count = len(senders)
    if count >= 3:
        return [("dupe", f"same-body x{count} senders", 8)]
    if count == 2:
        return [("dupe", "same-body x2 senders", 4)]
    return []


def score(
    name: str,
    email: str,
    subject: str,
    message: str,
    extra_hits=(),
    *,
    flag_threshold: int | None = None,
    block_threshold: int | None = None,
    block_enabled: bool | None = None,
) -> Verdict:
    """Scores a contact-form submission.

    Args:
        name: Sender name as typed.
        email: Sender address as typed.
        subject: Subject as typed.
        message: Message body as typed.
        extra_hits: ``(family, label, points)`` hits gathered by the request gates.
        flag_threshold: Override for ``SPAM_FLAG_THRESHOLD`` (tests).
        block_threshold: Override for ``SPAM_BLOCK_THRESHOLD`` (tests).
        block_enabled: Override for ``SPAM_BLOCK_ENABLED`` (tests).

    Returns:
        A Verdict with the total, the decision, and every contributing hit.
    """
    flag_t = FLAG_THRESHOLD if flag_threshold is None else flag_threshold
    block_t = BLOCK_THRESHOLD if block_threshold is None else block_threshold
    block_on = BLOCK_ENABLED if block_enabled is None else block_enabled

    name_cf, email_cf = _norm(name), _norm(email)
    subject_cf, message_cf = _norm(subject), _norm(message)
    text_cf = f"{subject_cf}\n{message_cf}"
    raw_text = f"{subject}\n{message}"
    sender_reg = _registrable(email_cf.rpartition("@")[2])

    hits: list[Hit] = list(extra_hits)
    link_hits, untrusted_count, url_count = _score_links(subject_cf, text_cf, sender_reg)
    hits += link_hits
    hits += _score_vocab(text_cf)
    hits += _score_markup(name, message, text_cf)
    hits += _score_script(raw_text)
    hits += _score_name(name_cf, subject_cf, message_cf, sender_reg)
    hits += _score_email(email_cf, name_cf)
    # Unicode-aware, so a Japanese or Greek message is not mistaken for an empty one.
    residue = "".join(c for c in _replace_links(text_cf) if c.isalnum())
    hits += _score_shape(subject_cf, message_cf, message, residue, untrusted_count)
    hits += _score_dupe(_fingerprint(name_cf, text_cf), email_cf)

    positive = sum(p for _, _, p in hits if p > 0)
    negative = max(TRUST_FLOOR, sum(p for _, _, p in hits if p < 0))
    total = positive + negative
    family_points: dict[str, float] = defaultdict(float)
    for family, _, points in hits:
        if points > 0:
            family_points[family] += points
    strong_families = sum(1 for points in family_points.values() if points >= 3)
    would_block = total >= block_t and strong_families >= 2
    if would_block and block_on:
        verdict = "block"
    elif total >= flag_t:
        verdict = "flag"
    else:
        verdict = "allow"
    return Verdict(
        total=total,
        verdict=verdict,
        hits=[f"{family}:{label}({points:+g})" for family, label, points in hits],
        would_block=would_block,
        url_count=url_count,
    )
