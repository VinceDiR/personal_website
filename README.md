# vincentdirenzo.com

Personal portfolio site: a single Flask page (Bootstrap 5 + the DevFolio template), a resume
PDF, and a contact form that emails me after a stack of spam checks. Deployed on Heroku behind
Cloudflare.

The form and LinkedIn are the only two ways to reach me that the site publishes. No address
and no phone number ships in the HTML, the resume PDF, or any error message, so there is
nothing on the page for a harvester to scrape. Two tests in `tests/test_contact.py` fail if one
creeps back in.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
cp .env.example .env   # fill in values, or leave blank to run without the contact form
.venv/bin/python app.py  # http://127.0.0.1:5002
.venv/bin/python -m pytest  # 70 tests, no network
.venv/bin/black --line-length 100 . && .venv/bin/flake8 .
```

`.env` is loaded automatically. Without the mail and reCAPTCHA settings the page renders fine;
only the contact form returns an error.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `MAIL_SERVER`, `EMAIL_PORT` | SMTP host and port (STARTTLS, default port 587) |
| `EMAIL`, `EMAIL_PW` | SMTP login; `EMAIL` is also the sender and the inbox that receives messages |
| `RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY` | reCAPTCHA v2 checkbox keys |
| `SITE_URL` | Canonical origin (default `https://vincentdirenzo.com`); also defines the accepted hosts |
| `FORM_SECRET` | Optional. Signs the render-time form token; derived from the secrets above when unset |
| `FORM_SECRET_PREVIOUS` | Optional. Comma-separated old form secrets, still accepted for verification. Set this when rotating `FORM_SECRET` so pages already open keep working |
| `SPAM_FLAG_THRESHOLD` | Score at which mail is delivered with a `[Possible spam]` prefix (default 6) |
| `SPAM_BLOCK_THRESHOLD` | Score at which mail is dropped, once blocking is enabled (default 12) |
| `SPAM_BLOCK_ENABLED` | Set to `1` to drop high-scoring mail. Off by default: flag-only |
| `PORT`, `WEB_CONCURRENCY` | Set by Heroku; used by `gunicorn.conf.py` |

`EMAIL_API_ENDPOINT` / `EMAIL_API_KEY` (the paid deliverability check) are no longer read.
Run `heroku config:unset EMAIL_API_ENDPOINT EMAIL_API_KEY` to clean them up.

## Deploy

Both deploy paths run gunicorn with the settings in `gunicorn.conf.py`:

- **Heroku buildpack**: `Procfile` + `.python-version` (`3.12`). Push to deploy.
- **Container**: `docker build -t personal-website . && docker run -p 8000:8000 --env-file .env personal-website`

## Routes

| Path | What it does |
| --- | --- |
| `/` | The page. Uncacheable because it embeds a fresh form token |
| `/form-token` | Mints a replacement form token for a page left open past the 12-hour expiry |
| `/resume` | Serves `resume/cv.pdf` inline (replace that file to update the resume) |
| `/contact` (POST) | Contact form handler; returns JSON |
| `/robots.txt`, `/favicon.ico` | Crawler and browser conveniences |

The PDF lives in `resume/`, not `static/`, on purpose: every file under `static/` is also served
at its own unversioned URL with a one-year cache, so a copy there would keep a superseded resume
in CDN caches long after the swap. Serving it only through `/resume` leaves exactly one URL,
and it is `no-cache`.

The published `cv.pdf` is a scrubbed copy: same layout, but the contact line carries only the city,
LinkedIn, GitHub and this site. Keep the version with the address and phone number for actual
applications, where an ATS expects both.

## Spam filtering

reCAPTCHA v2 alone does not stop form spam: solving farms sell valid tokens for a fraction of a
cent, and human outreach spammers solve the checkbox themselves. The form therefore runs these
layers, in order, and logs one JSON line per attempt (`guards.py` and `spamcheck.py`):

1. **Host gate**: POSTs that bypass Cloudflare and hit `*.herokuapp.com` directly get a 404.
2. **Request shape**: the POST must look like the one `main.js` sends (multipart body, same-origin
   `Origin`/`Sec-Fetch-*` when present, only the expected fields, no CR/LF in the fields that
   become mail headers). Wrong values are dropped silently; missing headers only add points.
3. **Honeypot**: two off-screen fields (`website`, `subscribe`) that people never fill.
4. **Render token**: the page embeds a signed timestamp on the `<form>` element that `main.js`
   copies into the POST. Missing or forged tokens are dropped silently. A submit in under 3
   seconds scores 4 points and under 8 seconds scores 3, rather than being dropped, because
   people do paste a message they wrote elsewhere. A token older than 12 hours returns
   `code: "ft-expired"`; `main.js` fetches a replacement from `/form-token` and retries once, so a
   tab left open overnight still sends.
5. **Rate limit**: 4 delivered messages per hour per IP and 10 per /24, with an honest 429. Only
   mail that actually goes out counts against those, so failing the captcha a few times cannot
   lock a visitor out. A separate cap of 20 attempts per hour per IP is dropped silently; that one
   exists to keep a single bot from hammering the siteverify call. Per gunicorn worker, so
   effectively up to double.
6. **reCAPTCHA**: verified with the visitor's IP; a token solved on another site is dropped; a
   Google outage delivers the mail flagged instead of failing everyone. If
   `RECAPTCHA_SECRET_KEY` is missing the form answers 503 and points at LinkedIn, rather
   than rejecting every human.
7. **Content score**: links (including bare domains, `user@host` URLs and open redirectors on
   otherwise trusted hosts), vocabulary, HTML and BBCode markup, invisible characters used to
   split keywords, non-Latin text, name and email anomalies, message shape, and identical bodies
   from several sender domains. Pharma and adult words are additionally matched against the
   sender's domain and link paths, where spun-text spam hides its payload (`cialis-otc.com`, a
   shared `apotek...` slug on three reputable hosts) with nothing scoreable in the prose;
   gambling words are deliberately excluded because betting firms hire data engineers. Trust
   words (recruiter, role, Airflow, a LinkedIn or GitHub link) subtract points, and a link to
   the sender's own domain is neutral rather than suspicious.
   Score 6+ is delivered with a `[Possible spam]` subject prefix; 12+ from at least two
   independent signal families is dropped once `SPAM_BLOCK_ENABLED=1`.

Dropped submissions receive the same success response as real ones, so bots get no feedback.
Every delivered mail ends with a footer listing its score and the rules that fired. A browser that
posts the form without JavaScript is always dropped -- the render token lives in a `data-`
attribute that only `main.js` reads -- so its HTML notice never claims the message arrived; it
says JavaScript is required and points at LinkedIn. Same wording for every outcome on that path,
so it is still not a feedback channel.

### Rollout and tuning

1. Deploy with `SPAM_BLOCK_ENABLED` unset. Everything is delivered; spam arrives prefixed.
2. Add a Gmail filter for `subject:"[Possible spam] Website Inquiry"` that labels and archives
   (never deletes).
3. After a week or two, read the footers and the log lines. Prune `WEAK_PHRASES` that show up in
   real mail, add phrases you see in spam, and check nothing you wanted was `would_block: true`.
4. Set `SPAM_BLOCK_ENABLED=1` on Heroku.

Log recipes:

```bash
heroku logs --tail --source app | grep 'contact {'
heroku logs -n 1500 --source app | grep '"decision": "dropped"' | grep -o '"reason": "[^"]*"' | sort | uniq -c
heroku logs -n 1500 --source app | grep '"would_block": true'
```

Heroku keeps only the last 1500 log lines; attach the free Papertrail add-on before tuning.

### Cloudflare and reCAPTCHA settings worth turning on

- reCAPTCHA admin console: Security Preference "Most secure", and "Verify the origin of
  reCAPTCHA solutions" ON.
- Cloudflare > Security > WAF > Rate limiting rules (one rule is free): `POST /contact`,
  3 requests per 10 seconds per IP, block for 10 seconds. This is shared across workers and
  survives restarts, unlike the in-process limiter.
- Do not put a Managed Challenge on `POST /contact`: `fetch()` cannot answer it, so every real
  submission would fail.
- Later option: Cloudflare Turnstile as a drop-in reCAPTCHA replacement. Its tokens are bound to
  the solving browser and IP, which defeats solving farms outright.

## Working on the site

- **Content** lives in `templates/index.html`. Projects and blog posts are Jinja lists near the
  top of their sections; add a tuple to add a card.
- **Images** go in `static/assets/img/`. Keep the hero at or under 1920px wide and card images
  around 820px wide; anything larger is wasted bandwidth. Static files are served with a one-year
  cache and a content-hash `?v=` query string (`static_url()` in `app.py`), so replacing a file
  busts the cache automatically.
- **Styles** are in `static/assets/css/style.css`; behaviour is in `static/assets/js/main.js`.
- Only three vendor libraries are used: Bootstrap CSS, Bootstrap Icons, and Typed.js.
