"""Gunicorn settings shared by the Heroku Procfile and the Docker image."""

import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = 4  # contact requests block on reCAPTCHA, email validation, and SMTP
timeout = 60
errorlog = "-"
loglevel = "info"
forwarded_allow_ips = "*"  # trust the Heroku router / Cloudflare for X-Forwarded-*
