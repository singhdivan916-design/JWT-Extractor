#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FF Guest → OAuth Token — minimal Flask API.
Single Garena endpoint. Aggressive retries with rotating UAs
so the token grant succeeds in practice. Always returns 200 + JSON.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import threading
import time
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ==================================================================
# CONFIG — ONLY ONE GARENA ENDPOINT
# ==================================================================
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_ID     = "100067"
OAUTH_URL     = "https://100067.connect.garena.com/oauth/guest/token/grant"

# Rotating User-Agents (all real Garena MSDK builds)
OAUTH_UAS = [
    "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
    "GarenaMSDK/4.0.19P5(SM-G998B ;Android 13;en;US;)",
    "GarenaMSDK/4.0.18P3(M2101K6G ;Android 12;en;IN;)",
    "GarenaMSDK/4.0.19P9(LE2121 ;Android 13;en;SG;)",
    "GarenaMSDK/4.0.17P2(GB7N6 ;Android 13;en;US;)",
    "GarenaMSDK/4.0.19P7(RMX3081 ;Android 12;en;ID;)",
]

# Retry policy
MAX_ROUNDS          = 8       # full passes over all UAs
PER_ATTEMPT_TIMEOUT = 20
ROUND_SLEEP         = 0.25    # backoff base between rounds

# ==================================================================
# THREAD-LOCAL POOLED SESSIONS
# ==================================================================
_thread_local = threading.local()

def _make_session():
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=64, pool_maxsize=128,
        max_retries=Retry(total=0),   # we retry manually
        pool_block=False,
    )
    s.mount("https://", adapter)
    s.mount("http://",  adapter)
    s.verify = False
    return s

def get_session():
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = _make_session()
        _thread_local.session = s
    return s

# ==================================================================
# OAUTH GUEST TOKEN GRANT (single endpoint, aggressive retries)
# ==================================================================
def _single_attempt(uid, password, ua):
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': CLIENT_SECRET,
        'client_id': CLIENT_ID,
    }
    headers = {
        "User-Agent": ua,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    r = get_session().post(OAUTH_URL, data=payload, headers=headers,
                           timeout=PER_ATTEMPT_TIMEOUT)
    if r.status_code != 200:
        return None, r.status_code, r.text
    try:
        j = r.json()
    except Exception:
        return None, r.status_code, r.text
    if not isinstance(j, dict) or "access_token" not in j or "open_id" not in j:
        return None, r.status_code, j
    return j, 200, None

def guest_to_token(uid, password):
    """Retry the single Garena endpoint with rotating UAs until success."""
    last_body = None
    last_code = None

    for round_idx in range(MAX_ROUNDS):
        uas = list(OAUTH_UAS)
        random.shuffle(uas)
        for ua in uas:
            try:
                token, code, err = _single_attempt(uid, password, ua)
                if token:
                    return token, 200, None
                last_code = code
                last_body = err
            except Exception as e:
                last_code = 500
                last_body = f"{type(e).__name__}: {e}"
        time.sleep(ROUND_SLEEP * (round_idx + 1))

    return None, last_code or 502, last_body or "all attempts failed"

# ==================================================================
# ROUTES
# ==================================================================
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "ok",
        "service": "ff-guest-oauth",
        "endpoint": "/guest?uid=UID&password=PASSWORD",
        "post_json": {"uid": "UID", "password": "PASSWORD"},
    })

@app.route("/guest", methods=["GET", "POST"])
def guest_endpoint():
    try:
        uid = password = None
        if request.is_json:
            b = request.get_json(silent=True) or {}
            uid = b.get("uid")
            password = b.get("password")
        if not uid:
            uid = request.form.get("uid") or request.args.get("uid")
        if not password:
            password = request.form.get("password") or request.args.get("password")

        if not uid or not password:
            return jsonify({
                "status": "error",
                "message": "Both 'uid' and 'password' are required.",
                "usage": "/guest?uid=UID&password=PASSWORD",
            }), 200

        data, code, err = guest_to_token(uid.strip(), password.strip())
        if err:
            return jsonify({
                "status": "error",
                "message": "Token grant failed after all retries.",
                "oauth_status": code,
                "details": err if isinstance(err, (dict, list, str)) else str(err),
            }), 200

        if isinstance(data, dict) and "status" not in data:
            data = {"status": "success", **data}
        return jsonify(data), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Unhandled: {type(e).__name__}: {e}",
        }), 200

# ==================================================================
# ERROR HANDLERS — always 200 + JSON
# ==================================================================
@app.errorhandler(404)
def _404(e):
    return jsonify({"status": "error", "message": "Not found"}), 200

@app.errorhandler(405)
def _405(e):
    return jsonify({"status": "error", "message": "Method not allowed"}), 200

@app.errorhandler(500)
def _500(e):
    return jsonify({"status": "error", "message": "Internal server error"}), 200

@app.errorhandler(Exception)
def _any(e):
    return jsonify({"status": "error", "message": str(e)}), 200

# ==================================================================
# ENTRYPOINT
# ==================================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, debug=False, threaded=True)
