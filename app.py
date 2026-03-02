from flask import Flask, render_template, request
from services.analyzer import analyze_target
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

#app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
API_KEY = os.getenv("API_KEY")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    inp = request.form.get("inp")
    inp_type = request.form.get("inp_type")

    # call function
    result = analyze_target(inp_type,inp)

    return render_template("result.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)