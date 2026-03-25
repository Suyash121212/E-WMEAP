from flask import Flask, request, jsonify
from flask_cors import CORS
from scanners.header_scanner import analyze_headers
from scanners.banner_scanner import detect_server_banner
from scanners.port_scanner import scan_ports

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return {"message": "E-WMEAP Backend Running"}

@app.route("/scan/header", methods=["POST"])
def header_scan():

    data = request.json
    url = data.get("url")

    result = analyze_headers(url)

    return jsonify(result)

@app.route("/scan/banner", methods=["POST"])
def scan_banner():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = detect_server_banner(url)
    return jsonify(result)

@app.route("/scan/ports", methods=["POST"])
def scan_port():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = scan_ports(url)
    return jsonify(result)



if __name__ == "__main__":
    app.run(debug=True)