from flask import Flask, jsonify


app = Flask(__name__)


@app.route("/")
def hello_world():
    return jsonify(hello="world")


#@app.route("/static/<path:filename>")
#def staticfiles(filename):
#    return send_from_directory(app.config["STATIC_FOLDER"], filename)
