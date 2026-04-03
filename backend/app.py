import io
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask import send_file
from modules.tls_scanner import analyze_tls
from modules.header_scanner import analyze_headers
from modules.port_scanner import scan_ports_sync
from modules.directory_scanner import scan_directories
from modules.business_logic_scanner import scan_business_logic
from modules.github_scanner import scan_github_repo
from modules.cloud_scanner import scan_cloud
from modules.risk_engine import build_risk_report, generate_pdf
app = Flask(__name__)
CORS(app)
SCAN_STORE = {} 
@app.route("/")
def home():
    return {"message": "E-WMEAP Backend Running"}

# Header scanner
@app.route("/scan/header", methods=["POST"])
def scan_header():
    data = request.get_json()
    url = data.get("url", "").strip()
    scan_id = data.get("scan_id","")
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = analyze_headers(url)
    if scan_id and scan_id in SCAN_STORE:
        SCAN_STORE[scan_id]["headers"] = result
    return jsonify(result)

# TLS scanner
@app.route("/scan/tls", methods=["POST"])
def scan_tls():
    data = request.get_json()
    url = data.get("url", "").strip()
    scan_id = data.get("scan_id","")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = analyze_tls(url)
    if scan_id and scan_id in SCAN_STORE:
        SCAN_STORE[scan_id]["tls"] = result

    return jsonify(result)

# Port scanner
@app.route("/scan/ports", methods=["POST"])
def scan_ports():
    data = request.get_json()
    url = data.get("url", "").strip()
    scan_id = data.get("scan_id","")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    try:
        if scan_id and scan_id in SCAN_STORE:
            SCAN_STORE[scan_id]["ports"] = scan_ports_sync(url)
        result = scan_ports_sync(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Directory scanner
@app.route("/scan/directories", methods=["POST"])
def scan_dirs():
    data = request.get_json()
    url  = data.get("url", "").strip()
    scan_id = data.get("scan_id","")

    if not url:
        return jsonify({"error": "URL is required"}), 400
    # Ensure scheme is present
    if not url.startswith("http"):
        url = "https://" + url
    result = scan_directories(url)
    if scan_id and scan_id in SCAN_STORE:
        SCAN_STORE[scan_id]["directories"] = result

    return jsonify(result)

# Business logic scanner
@app.route("/scan/business", methods=["POST"])
def scan_business():
    data      = request.get_json()
    url       = data.get("url", "").strip()
    scan_id   = data.get("scan_id","")
    jwt_token = data.get("jwt_token", "").strip() or None
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith("http"):
        url = "https://" + url
    result = scan_business_logic(url, jwt_token=jwt_token)
    if scan_id and scan_id in SCAN_STORE:
        SCAN_STORE[scan_id]["business_logic"] = result
    return jsonify(result)

# github repo scanner
@app.route("/scan/github", methods=["POST"])    
def scan_github():
    data     = request.get_json()
    repo_url = data.get("repo_url", "").strip()
    scan_id  = data.get("scan_id","")

    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400
    
    result = scan_github_repo(repo_url)
    if scan_id and scan_id in SCAN_STORE:
        SCAN_STORE[scan_id]["github"] = scan_github_repo(repo_url)
    return jsonify(result)

@app.route("/scan/cloud", methods=["POST"])
def scan_cloud_route():
    data = request.get_json()
    url  = data.get("url", "").strip()
    scan_id = data.get("scan_id","")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith("http"):
        url = "https://" + url
    result = scan_cloud(url)
    if scan_id and scan_id in SCAN_STORE:
        SCAN_STORE[scan_id]["cloud"] = result
    return jsonify(result)

@app.route("/scan/init", methods=["POST"])
def scan_init():
    import time, uuid
    data    = request.get_json()
    url     = data.get("url","").strip()
    scan_id = str(uuid.uuid4())[:8]
    SCAN_STORE[scan_id] = {"url": url, "created_at": time.time()}
    return jsonify({"scan_id": scan_id})
@app.route("/scan/risk-report", methods=["POST"])
def risk_report():
    data    = request.get_json()
    scan_id = data.get("scan_id","")
    url     = data.get("url","").strip()

    scan_results = SCAN_STORE.get(scan_id, {})
    for key in ("headers","tls","ports","directories","business","secrets","cloud","banner"):
        if key in data:
            scan_results[key] = data[key]
 
    report = build_risk_report(scan_results, url, scan_id)
    SCAN_STORE[scan_id]["report"] = report
    return jsonify(report)

# 6. PDF download route:
@app.route("/scan/report/pdf/<scan_id>", methods=["GET"])
def download_pdf(scan_id):
    store_entry = SCAN_STORE.get(scan_id, {})
    report      = store_entry.get("report")
    if not report:
        return jsonify({"error": "No report found. Run /scan/risk-report first."}), 404
 
    try:
        pdf_bytes = generate_pdf(report)
        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)
        domain = report.get("domain","scan").replace(".", "_")
        filename = f"ewmeap_{domain}_{report.get('scan_timestamp','')[:10]}.pdf"
        return send_file(buf, mimetype="application/pdf",
                         as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    


if __name__ == "__main__":
    app.run(debug=True, port=5000)