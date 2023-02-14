"""Docstring for app.py."""
import os
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_mail import Mail, Message



load_dotenv()
app = Flask(__name__)


app.config['MAIL_SERVER']= os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = os.environ.get('EMAIL_PORT')
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PW')
app.config['MAIL_USE_TLS'] = True

mail = Mail(app)

@app.route("/")
def index():
    """Docstring for index."""
    return render_template("index.html")

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

    response = requests.get(
    os.environ.get('EMAIL_API_ENDPOINT'),
    params = {'email': contact_email},
    headers= {'Authorization': os.environ.get('EMAIL_API_KEY')}, timeout=5)

    status = response.json()['status']

    if status == "valid":
        msg = Message(f"Website Inquiry: {contact_subject}", sender=contact_email, recipients=[os.environ.get('EMAIL')])
        msg.body = f"""
        From: {contact_name} <{contact_email}>
        Subject: {contact_subject}
        Body: {contact_message}
        """
        mail.send(msg)
        return "Message sent"
    if status == "invalid":
        return "Invalid email address"
    return None

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5002))
    app.run(debug=True, host='0.0.0.0', port=port)
