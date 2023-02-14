"""Docstring for app.py."""
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_mail import Mail, Message
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

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

    msg = Message(f"{contact_name} - {contact_subject}", sender=contact_email, recipients=[os.environ.get('EMAIL')])
    msg.body = contact_message
    mail.send(msg)
    return "Success!"

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5002))
    app.run(debug=True, host='0.0.0.0', port=port)
