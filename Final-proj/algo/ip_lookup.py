import re
import requests
from flask import Blueprint, request, jsonify
from middleware.detect_ssrf import detect_ssrf
from middleware.detect_xss import detect_xss
from datetime import datetime

ip_lookup_bp = Blueprint('ip_lookup', __name__)

# Regex for validating IP address
IP_REGEX = r"^(?:\d{1,3}\.){3}\d{1,3}$"

# Geolocation API config
GEO_API_KEY = "594cd859dbb84ec8aa4597200216b506"
GEO_API_URL = "https://api.ipgeolocation.io/ipgeo"

def log_attack(ip, reason):
    with open("logs/attacks.log", "a") as log:
        log.write(f"[{datetime.now()}] [ATTACK DETECTED] IP: {ip} | Reason: {reason}\n")

@ip_lookup_bp.route("/lookup-ip", methods=["POST"])
def lookup_ip():
    data = request.get_json()
    ip_input = data.get("ip", "").strip()
    client_ip = request.remote_addr

    # 1. XSS Detection
    if detect_xss(("ip", ip_input), ip=client_ip):
        return jsonify({"error": "XSS attack detected!"}), 403

    # 2. SSRF Detection
    if detect_ssrf(ip_input, ip=client_ip):
        log_attack(ip_input, "SSRF attempt")
        return jsonify({"error": "Malicious request blocked!"}), 403

    # 3. IP Format Validation
    if not re.match(IP_REGEX, ip_input):
        log_attack(ip_input, "Malformed IP")
        return jsonify({"error": "Invalid IP address format."}), 400

    # 4. External API Call
    try:
        response = requests.get(GEO_API_URL, params={
            "apiKey": GEO_API_KEY,
            "ip": ip_input
        })

        if response.status_code == 200:
            data = response.json()
            return jsonify({
                "ip": data.get("ip", ""),
                "country_name": data.get("country_name", ""),
                "state_prov": data.get("state_prov", ""),
                "city": data.get("city", ""),
                "latitude": data.get("latitude", ""),
                "longitude": data.get("longitude", "")
            }), 200
        else:
            return jsonify({"error": "Unable to fetch data from geolocation service."}), 502

    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({"error": "Internal server error"}), 500
