"""Docstring for app.py."""
import os
import subprocess
from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

@app.route("/")
def index():
    """Docstring for index."""
    return render_template("index.html")

@app.route("/resume")
def show_resume():
    """Docstring for show_resume."""
    return render_template("resume.html")

@app.route("/forms/contact.php", methods=['POST'])
def contact():
    """Docstring for contact."""
    subprocess.call(["php", "form/contact.php"])

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5002))
    app.run(debug=True, host='0.0.0.0', port=port)
