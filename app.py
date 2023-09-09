"""Docstring for app.py."""
import os
import json
import requests
from requests.exceptions import ConnectTimeout
from flask import Flask, render_template, request
from flask_mail import Mail, Message

app = Flask(__name__)

app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER")
app.config["MAIL_PORT"] = os.environ.get("EMAIL_PORT")
app.config["MAIL_USERNAME"] = os.environ.get("EMAIL")
app.config["MAIL_PASSWORD"] = os.environ.get("EMAIL_PW")
app.config["SECURITY_EMAIL_SENDER"] = os.environ.get("EMAIL")
app.config["MAIL_USE_TLS"] = True
app.config["USE_SSL"] = False

mail = Mail(app)


@app.route("/")
def index():
    """Docstring for index."""
    return render_template("index.html", sitekey=os.environ.get("RECAPTCHA_SITE_KEY"))


@app.route("/resume")
def show_resume():
    """Docstring for show_resume."""
    return render_template("resume.html")


@app.route("/contact", methods=["POST"])
def contact():
    """Docstring for contact."""
    contact_name = request.form["name"]
    contact_email = request.form["email"]
    contact_subject = request.form["subject"]
    contact_message = request.form["message"]
    captcha_response = request.form["g-recaptcha-response"]

    if is_human(captcha_response) is False:
        return "reCAPTCHA failed!"

    status = is_valid_email(contact_email)
    if status is False:
        return "Could not validate email address!"

    if status in ("valid", "unknown"):
        msg = Message(
            f"Website Inquiry: {contact_subject}",
            sender=contact_email,
            recipients=[os.environ.get("EMAIL")],
        )
        msg.body = f"""
        From: {contact_name} <{contact_email}>
        Subject: {contact_subject}
        Body: {contact_message}
        # """
        mail.send(msg)
        print("Email sent successfully")
        return "Message Sent!"

    return "Invalid email address!"


def is_human(captcha_response):
    """Docstring for is_human."""
    secret = os.environ.get("RECAPTCHA_SECRET_KEY")
    payload = {"response": captcha_response, "secret": secret}
    try:
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify", payload, timeout=10
        )
        response_text = json.loads(response.text)
        return response_text["success"]
    except ConnectTimeout:
        return False


def is_valid_email(email):
    """Docstring for is_valid_email."""
    try:
        response = requests.get(
            os.environ.get("EMAIL_API_ENDPOINT"),
            params={"api_key": os.environ.get("EMAIL_API_KEY"), "email": email},
            timeout=30,
        )
        
        data = response.json()

        # Check the 'deliverability' field in the response data.
        if data.get('deliverability') == "DELIVERABLE":
            return "valid"
        return False

    except ConnectTimeout:
        return False




if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(host="0.0.0.0", port=port)
