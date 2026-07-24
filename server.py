"""
Demo server cho đề tài "Rò rỉ dữ liệu cá nhân trong hệ sinh thái IoT - Smart Home"
Có 2 endpoint để so sánh trực quan:
  - /vulnerable/upload : mô phỏng thiết bị THIẾU bảo mật
  - /fixed/upload       : mô phỏng thiết bị ĐÃ áp dụng data minimization + auth + audit log

Chạy: python server.py
Mặc định chạy ở http://0.0.0.0:5000
"""

from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import json
import os

app = Flask(__name__)

# ---- "Database" đơn giản dùng file JSON cho dễ demo, khỏi cần cài DB ----
VULN_LOG = "vulnerable_log.json"
FIXED_LOG = "fixed_log.json"
AUDIT_LOG = "audit_log.json"

# API key hợp lệ cho bản "fixed" (trong thực tế nên lưu ở nơi an toàn hơn, đây chỉ demo)
VALID_API_KEYS = {"esp32-demo-key-001"}

# Các field được coi là "nhạy cảm" -> dùng để minh họa việc bản vulnerable vô tình log cả field này
SENSITIVE_FIELDS = {"gps", "wifi_ssid", "wifi_password", "device_serial", "owner_name", "raw_image"}


def append_json_log(path, entry):
    data = []
    if os.path.exists(path):
        with open(path, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    data.append(entry)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# =========================================================
# BẢN VULNERABLE — mô phỏng lỗi thường gặp trong IoT thật
# =========================================================
@app.route("/vulnerable/upload", methods=["POST"])
def vulnerable_upload():
    # LỖI 1: Không xác thực -> ai cũng gọi được endpoint này
    payload = request.get_json(force=True, silent=True) or {}

    # LỖI 2: Log nguyên văn toàn bộ payload, kể cả field nhạy cảm (GPS, SSID wifi, tên chủ nhà...)
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": request.remote_addr,
        "raw_payload": payload,  # <-- lưu hết, không lọc gì cả
    }
    append_json_log(VULN_LOG, entry)

    # LỖI 3: Phản hồi lại toàn bộ dữ liệu đã nhận (dễ lộ khi bắt gói tin phản hồi)
    return jsonify({"status": "received", "echo": payload}), 200


# =========================================================
# BẢN FIXED — áp dụng data minimization, auth, audit log
# =========================================================
@app.route("/fixed/upload", methods=["POST"])
def fixed_upload():
    # KHẮC PHỤC 1: Bắt buộc có API key trong header
    api_key = request.headers.get("X-API-Key")
    if api_key not in VALID_API_KEYS:
        append_json_log(AUDIT_LOG, {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "UNAUTHORIZED_ATTEMPT",
            "source_ip": request.remote_addr,
        })
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(force=True, silent=True) or {}

    # KHẮC PHỤC 2: Data minimization -> chỉ nhận đúng field cần thiết, bỏ hết field thừa/nhạy cảm
    allowed_fields = {"event", "value", "ts"}
    minimal_payload = {k: v for k, v in payload.items() if k in allowed_fields}

    dropped_fields = [k for k in payload.keys() if k not in allowed_fields]

    # KHẮC PHỤC 3: Log tách biệt - dữ liệu nghiệp vụ và audit log riêng, không log field nhạy cảm
    append_json_log(FIXED_LOG, {
        "timestamp": datetime.utcnow().isoformat(),
        "data": minimal_payload,
    })

    append_json_log(AUDIT_LOG, {
        "timestamp": datetime.utcnow().isoformat(),
        "event": "DATA_RECEIVED",
        "source_ip": request.remote_addr,
        "dropped_sensitive_fields": dropped_fields,  # ghi nhận đã lọc bỏ field gì, phục vụ minh bạch
    })

    # KHẮC PHỤC 4: Chỉ phản hồi tối thiểu, không echo lại dữ liệu
    return jsonify({"status": "ok"}), 200


# =========================================================
# KHẮC PHỤC 5: mô phỏng retention policy - xóa log cũ hơn N ngày
# =========================================================
@app.route("/fixed/cleanup", methods=["POST"])
def cleanup_old_logs():
    retention_days = int(request.args.get("days", 7))
    cutoff = datetime.utcnow() - timedelta(days=retention_days)

    if os.path.exists(FIXED_LOG):
        with open(FIXED_LOG, "r") as f:
            data = json.load(f)
        kept = [d for d in data if datetime.fromisoformat(d["timestamp"]) > cutoff]
        removed_count = len(data) - len(kept)
        with open(FIXED_LOG, "w") as f:
            json.dump(kept, f, indent=2, ensure_ascii=False)
        return jsonify({"removed": removed_count, "remaining": len(kept)}), 200

    return jsonify({"removed": 0}), 200


# ---- Endpoint tiện ích để xem log khi demo trực tiếp ----
@app.route("/view/<log_name>", methods=["GET"])
def view_log(log_name):
    mapping = {"vulnerable": VULN_LOG, "fixed": FIXED_LOG, "audit": AUDIT_LOG}
    path = mapping.get(log_name)
    if not path or not os.path.exists(path):
        return jsonify([])
    with open(path, "r") as f:
        return jsonify(json.load(f))


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "IoT Data Leakage Demo Server",
        "endpoints": [
            "POST /vulnerable/upload",
            "POST /fixed/upload (header: X-API-Key)",
            "GET /view/vulnerable",
            "GET /view/fixed",
            "GET /view/audit",
        ]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)