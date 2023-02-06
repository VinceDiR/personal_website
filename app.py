from flask import Flask, send_file, render_template

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/resume")
def show_resume():
    return render_template("resume.html")

@app.route("/portfolio")
def show_portfolio():
    return render_template("portfolio-details.html")

@app.route("/blog")
def show_blog():
    return render_template("blog-single.html")
if __name__ == "__main__":
    app.run(debug=True)
