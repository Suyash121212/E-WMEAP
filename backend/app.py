import io
import time
import uuid
from typing import Any, Callable, Dict, Optional

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from modules.business_logic_scanner import scan_business_logic
from modules.cloud_scanner import scan_cloud
from modules.directory_scanner import scan_directories
from modules.github_scanner import scan_github_repo
from modules.header_scanner import analyze_headers
from modules.port_scanner import scan_ports_sync
from modules.risk_engine import build_risk_report, generate_pdf
from modules.tls_scanner import analyze_tls

app = Flask(__name__)
CORS(app)

SCAN_STORE: Dict[str, Dict[str, Any]] = {}
JSONDict = Dict[str, Any]


def _get_request_data() -> JSONDict:
    return request.get_json(silent=True) or {}


def _get_required_field(data: JSONDict, field_name: str) -> Optional[str]:
    value = str(data.get(field_name, "")).strip()
    return value or None


def _normalize_url(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else f"https://{url}"


def _scan_id_from(data: JSONDict) -> str:
    return str(data.get("scan_id", "")).strip()


def _store_scan_result(scan_id: str, key: str, result: Any) -> None:
    if scan_id and scan_id in SCAN_STORE:
        SCAN_STORE[scan_id][key] = result


def _run_scan(
    *,
    field_name: str,
    store_key: str,
    scanner: Callable[..., Any],
    normalize_url: bool = False,
    scanner_kwargs: Optional[Dict[str, Any]] = None,
) -> Any:
    data = _get_request_data()
    field_value = _get_required_field(data, field_name)
    if not field_value:
        return jsonify({"error": f"{field_name} is required"}), 400

    scan_id = _scan_id_from(data)
    target = _normalize_url(field_value) if normalize_url else field_value
    result = scanner(target, **(scanner_kwargs or {}))
    _store_scan_result(scan_id, store_key, result)
    return jsonify(result)


@app.route("/")
def home() -> JSONDict:
    return {"message": "E-WMEAP Backend Running"}


@app.route("/scan/header", methods=["POST"])
def scan_header() -> Any:
    return _run_scan(
        field_name="url",
        store_key="headers",
        scanner=analyze_headers,
        normalize_url=True,
    )


@app.route("/scan/tls", methods=["POST"])
def scan_tls() -> Any:
    return _run_scan(
        field_name="url",
        store_key="tls",
        scanner=analyze_tls,
        normalize_url=True,
    )


@app.route("/scan/ports", methods=["POST"])
def scan_ports() -> Any:
    return _run_scan(
        field_name="url",
        store_key="ports",
        scanner=scan_ports_sync,
        normalize_url=True,
    )


@app.route("/scan/directories", methods=["POST"])
def scan_dirs() -> Any:
    return _run_scan(
        field_name="url",
        store_key="directories",
        scanner=scan_directories,
        normalize_url=True,
    )


@app.route("/scan/business", methods=["POST"])
def scan_business() -> Any:
    data = _get_request_data()
    url = _get_required_field(data, "url")
    if not url:
        return jsonify({"error": "url is required"}), 400

    result = scan_business_logic(
        _normalize_url(url),
        jwt_token=_get_required_field(data, "jwt_token"),
    )
    scan_id = _scan_id_from(data)
    _store_scan_result(scan_id, "business", result)
    _store_scan_result(scan_id, "business_logic", result)
    return jsonify(result)


@app.route("/scan/github", methods=["POST"])
def scan_github() -> Any:
    return _run_scan(
        field_name="repo_url",
        store_key="github",
        scanner=scan_github_repo,
    )


@app.route("/scan/cloud", methods=["POST"])
def scan_cloud_route() -> Any:
    return _run_scan(
        field_name="url",
        store_key="cloud",
        scanner=scan_cloud,
        normalize_url=True,
    )


@app.route("/scan/init", methods=["POST"])
def scan_init() -> Any:
    data = _get_request_data()
    scan_id = str(uuid.uuid4())[:8]
    SCAN_STORE[scan_id] = {
        "url": str(data.get("url", "")).strip(),
        "created_at": time.time(),
    }
    return jsonify({"scan_id": scan_id})


@app.route("/scan/risk-report", methods=["POST"])
def risk_report() -> Any:
    data = _get_request_data()
    scan_id = _scan_id_from(data)
    url = str(data.get("url", "")).strip()

    scan_results = dict(SCAN_STORE.get(scan_id, {}))
    for key in ("headers", "tls", "ports", "directories", "business", "business_logic", "secrets", "cloud", "banner"):
        if key in data:
            scan_results[key] = data[key]

    if "business_logic" not in scan_results and "business" in scan_results:
        scan_results["business_logic"] = scan_results["business"]
    if "business" not in scan_results and "business_logic" in scan_results:
        scan_results["business"] = scan_results["business_logic"]

    report = build_risk_report(scan_results, url, scan_id)
    if scan_id:
        SCAN_STORE.setdefault(scan_id, {"url": url, "created_at": time.time()})
        SCAN_STORE[scan_id]["report"] = report
    return jsonify(report)


@app.route("/scan/report/pdf/<scan_id>", methods=["GET"])
def download_pdf(scan_id: str) -> Any:
    report = SCAN_STORE.get(scan_id, {}).get("report")
    if not report:
        return jsonify({"error": "No report found. Run /scan/risk-report first."}), 404

    try:
        pdf_bytes = generate_pdf(report)
        buffer = io.BytesIO(pdf_bytes)
        buffer.seek(0)
        domain = report.get("domain", "scan").replace(".", "_")
        filename = f"ewmeap_{domain}_{report.get('scan_timestamp', '')[:10]}.pdf"
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
