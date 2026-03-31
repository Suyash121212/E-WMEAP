from flask import Flask, request, jsonify
from flask_cors import CORS
from modules.tls_scanner import analyze_tls
from modules.header_scanner import analyze_headers
from modules.port_scanner import scan_ports_sync
from modules.directory_scanner import scan_directories

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return {"message": "E-WMEAP Backend Running"}

# Header scanner
@app.route("/scan/header", methods=["POST"])
def scan_header():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = analyze_headers(url)
    return jsonify(result)

# TLS scanner
@app.route("/scan/tls", methods=["POST"])
def scan_tls():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = analyze_tls(url)
    return jsonify(result)

# Port scanner
@app.route("/scan/ports", methods=["POST"])
def scan_ports():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    try:
        result = scan_ports_sync(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Directory scanner
@app.route("/scan/directories", methods=["POST"])
def scan_dirs():
    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    # Ensure scheme is present
    if not url.startswith("http"):
        url = "https://" + url
    result = scan_directories(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)