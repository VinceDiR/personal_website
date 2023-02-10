"""Docstring for app.py."""
import os
from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def index():
    """Docstring for index."""
    return render_template("index.html")

@app.route("/resume")
def show_resume():
    """Docstring for show_resume."""
    return render_template("resume.html")

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5002))
    app.run(debug=True, host='0.0.0.0', port=port)
