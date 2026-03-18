#!/usr/bin/env python3
# mock_server.py - Local vulnerable/fixed Java deserialization mock
# Run with: python3 src/mock_server.py [--mode vulnerable|fixed]
#
# vulnerable mode: simulates an unpatched server (returns 200 for gadget chains)
# fixed mode:      simulates a patched server (returns 400 for gadget chains)

import argparse
from datetime import datetime, timezone

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("[ERROR] Flask not found. Run: pip3 install flask")
    exit(1)

app = Flask(__name__)

# Gadget chain signatures — these hex prefixes identify known bad payloads
# Real Java serialized objects start with aced0005
KNOWN_GADGET_PREFIXES = [
    "aced000573720011",  # CommonsCollections6 (TC-01)
    "aced000573720012",  # Spring gadget chain (TC-04)
]

BENIGN_PREFIXES = [
    "rO0ABXNyAA5qYXZhLmxhbmcuTG9uZzs=",  # base64 benign Long object
]

INVALID_MAGIC = [
    "deadbeef",  # not a valid Java serialized object
]

MODE = "vulnerable"  # default, overridden by --mode flag


@app.route("/api/v1/session/restore", methods=["POST"])
@app.route("/post", methods=["POST"])
def handle_post():
    raw_body = request.get_data()
    hex_body = raw_body.hex()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Check for invalid magic bytes — always reject these
    if hex_body.startswith("deadbeef"):
        return jsonify({
            "status": "rejected",
            "reason": "invalid_magic_bytes",
            "timestamp": timestamp
        }), 400

    # Check if it's a known gadget chain
    is_gadget = any(hex_body.startswith(p) for p in KNOWN_GADGET_PREFIXES)

    if is_gadget:
        if MODE == "vulnerable":
            # Simulate deserialization happening — slow response + 200
            import time
            time.sleep(6)  # triggers temporal anomaly (>5s threshold)
            return jsonify({
                "status": "deserialized",
                "message": "object processed",
                "timestamp": timestamp
            }), 200
        else:
            # Fixed mode — class-check fires before deserialization
            return jsonify({
                "status": "rejected",
                "reason": "class_not_in_allowlist",
                "timestamp": timestamp
            }), 400

    # Benign object — always accept
    return jsonify({
        "status": "accepted",
        "message": "valid object processed",
        "timestamp": timestamp
    }), 200


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock Java deserialization server")
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "fixed"],
        default="vulnerable",
        help="vulnerable = simulates unpatched server, fixed = simulates patched server"
    )
    args = parser.parse_args()
    MODE = args.mode

    print(f"\n[mock_server] Starting in {MODE.upper()} mode")
    print(f"[mock_server] Listening on http://127.0.0.1:5000")
    print(f"[mock_server] Endpoints: POST /post  or  POST /api/v1/session/restore\n")

    app.run(host="127.0.0.1", port=5000, debug=False)
