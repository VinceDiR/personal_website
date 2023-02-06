from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/blog")
def show_post(post_id):
    return render_template("blog-single.html")

@app.route("/portfolio")
def show_portfolio():
    return render_template("portfolio-details.html")

@app.route("/resume")
def show_resume():
    return render_template("resume.html")