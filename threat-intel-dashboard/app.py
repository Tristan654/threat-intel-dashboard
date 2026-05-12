#-------Imports--------
from flask import Flask, render_template, request
from aggregator import run_analysis
#----------Variable------
app = Flask(__name__)


#---------Route GET ----------
@app.route("/")
def index():
    return render_template("index.html")

#-----------Route POST -------------
@app.route("/analyze", methods=["POST"])
def analyze():
    indicator = request.form.get("indicator")
    report = run_analysis(indicator)
    return render_template("results.html", report=report)


#-----Run_Flask-----
if __name__ == "__main__":
    app.run(debug=True)#debug recharge la page quand tu change le code