# from flask import Flask, request, jsonify
# from flask_cors import CORS
# from scanners.header_scanner import analyze_headers
# from scanners.banner_scanner import detect_server_banner
# from scanners.port_scanner import scan_ports

# app = Flask(__name__)
# CORS(app)

# @app.route("/")
# def home():
#     return {"message": "E-WMEAP Backend Running"}

# @app.route("/scan/header", methods=["POST"])
# def header_scan():

#     data = request.json
#     url = data.get("url")

#     result = analyze_headers(url)

#     return jsonify(result)

# @app.route("/scan/banner", methods=["POST"])
# def scan_banner():
#     data = request.get_json()
#     url = data.get("url")
#     if not url:
#         return jsonify({"error": "URL is required"}), 400
#     result = detect_server_banner(url)
#     return jsonify(result)

# @app.route("/scan/ports", methods=["POST"])
# def scan_port():
#     data = request.get_json()
#     url = data.get("url")
#     if not url:
#         return jsonify({"error": "URL is required"}), 400
#     result = scan_ports(url)
#     return jsonify(result)



# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, request, jsonify
from flask_cors import CORS

# ✅ IMPORT YOUR MODULES (correct path based on your folder)
from modules.header_scanner import analyze_headers
from modules.banner_scanner import detect_server_banner
from modules.port_scanner import run_port_scan
app = Flask(__name__)
CORS(app)

# -----------------------------------
# 🔹 ROOT
# -----------------------------------
@app.route("/")
def home():
    return {
        "message": "E-WMEAP Backend Running",
        "modules": ["Header Scanner", "Banner Scanner", "Port Scanner + CVE"]
    }


# -----------------------------------
# 🔹 HEADER SCAN
# -----------------------------------
@app.route("/scan/header", methods=["POST"])
def header_scan():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is required"}), 400

        result = analyze_headers(url)

        return jsonify({
            "status": "success",
            "type": "header_scan",
            "data": result
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------------
# 🔹 BANNER SCAN
# -----------------------------------
@app.route("/scan/banner", methods=["POST"])
def scan_banner():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is required"}), 400

        result = detect_server_banner(url)

        return jsonify({
            "status": "success",
            "type": "banner_scan",
            "data": result
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------------
# 🔹 PORT + CVE SCAN (MAIN MODULE 🔥)
# -----------------------------------
@app.route("/scan/ports", methods=["POST"])
def scan_ports():
    try:
        data = request.get_json()
        target = data.get("url")   # keep 'url' to match frontend

        if not target:
            return jsonify({"error": "Target URL/IP is required"}), 400

        results = run_port_scan(target)

        return jsonify({
            "status": "success",
            "type": "port_scan",
            "target": target,
            "results": results
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------------
# 🔹 FUTURE MODULE PLACEHOLDER
# -----------------------------------
@app.route("/health")
def health():
    return {"status": "ok"}


# -----------------------------------
# 🔹 MAIN
# -----------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)