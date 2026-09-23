#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FF Guest → JWT — Fast, simple Flask API.
- Parallel platform race (first JWT wins)
- Live X-Ga-Sv (unix timestamp)
- Real device fingerprints
- addr derived from JWT lock_region (unknown → OTHERS)
- Never fails: always returns valid JSON
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import base64
import json
import re
import time
import uuid
import os
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import my_pb2
import output_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ==================================================================
# CONFIG
# ==================================================================
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_ID     = "100067"

OAUTH_URL       = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"

OB_VER   = "OB55"
PLAY_VER = "1.132.7"

PLATFORM_TYPES      = (4, 3, 8, 6, 5, 11, 13, 1, 2, 7, 9)
PER_ATTEMPT_TIMEOUT = 15
GLOBAL_JWT_TIMEOUT  = 60

SIGNED_RESPONSE_PREFIX_BYTES = 64

# ==================================================================
# REAL DEVICE PROFILES
# ==================================================================
DEVICE_PROFILES = [
    # ── 1. Samsung Galaxy S21 Ultra 5G (SM-G998B) ──────────
    {
        "name": "Samsung Galaxy S21 Ultra",
        "manufacturer": "samsung",
        "brand": "samsung",
        "model": "SM-G998B",
        "device": "p3s",
        "product": "p3sxxx",
        "build_id": "RP1A.200720.012",
        "build_display": "RP1A.200720.012.G998BXXU3AUB2",
        "build_fingerprint": "samsung/p3sxxx/p3s:11/RP1A.200720.012/G998BXXU3AUB2:user/release-keys",
        "build_number": "RP1A.200720.012",
        "android_version": "11",
        "sdk_int": 30,
        "security_patch": "2021-02-01",
        "cpu_info": "ARM64 FP ASIMD AES VMH | 2800 | 8",
        "cpu_model": "Exynos 2100",
        "gpu_renderer": "Mali-G78",
        "gpu_version": "OpenGL ES 3.2",
        "total_ram": 10954,
        "available_ram": 6218,
        "screen_width": 1440,
        "screen_height": 3200,
        "screen_dpi": "560",
        "screen_density": 3.5,
        "device_type": "Handheld",
        "device_form_factor": "phone",
    },
    # ── 2. Xiaomi Redmi Note 10 Pro (M2101K6G) ─────────────
    {
        "name": "Xiaomi Redmi Note 10 Pro",
        "manufacturer": "Xiaomi",
        "brand": "Redmi",
        "model": "M2101K6G",
        "device": "sweet",
        "product": "sweet_global",
        "build_id": "RKQ1.200826.002",
        "build_display": "RKQ1.200826.002.V12.5.1.0.RKFMIXM",
        "build_fingerprint": "Redmi/sweet_global/sweet:11/RKQ1.200826.002/V12.5.1.0.RKFMIXM:user/release-keys",
        "build_number": "RKQ1.200826.002",
        "android_version": "11",
        "sdk_int": 30,
        "security_patch": "2021-09-01",
        "cpu_info": "ARM64 FP ASIMD AES VMH | 2300 | 8",
        "cpu_model": "Snapdragon 732G",
        "gpu_renderer": "Adreno (TM) 618",
        "gpu_version": "OpenGL ES 3.2",
        "total_ram": 5951,
        "available_ram": 3180,
        "screen_width": 1080,
        "screen_height": 2400,
        "screen_dpi": "440",
        "screen_density": 2.75,
        "device_type": "Handheld",
        "device_form_factor": "phone",
    },
    # ── 3. OnePlus 9 Pro (LE2121) ─────────────────────────
    {
        "name": "OnePlus 9 Pro",
        "manufacturer": "OnePlus",
        "brand": "OnePlus",
        "model": "LE2121",
        "device": "lemonadep",
        "product": "lemonadep",
        "build_id": "RKQ1.201105.002",
        "build_display": "RKQ1.201105.002.2107151902",
        "build_fingerprint": "OnePlus/lemonadep/lemonadep:11/RKQ1.201105.002/2107151902:user/release-keys",
        "build_number": "RKQ1.201105.002",
        "android_version": "11",
        "sdk_int": 30,
        "security_patch": "2021-07-05",
        "cpu_info": "ARM64 FP ASIMD AES VMH | 2841 | 8",
        "cpu_model": "Snapdragon 888",
        "gpu_renderer": "Adreno (TM) 660",
        "gpu_version": "OpenGL ES 3.2",
        "total_ram": 7851,
        "available_ram": 4102,
        "screen_width": 1440,
        "screen_height": 3216,
        "screen_dpi": "525",
        "screen_density": 3.5,
        "device_type": "Handheld",
        "device_form_factor": "phone",
    },
    # ── 4. Google Pixel 6 (GB7N6) ─────────────────────────
    {
        "name": "Google Pixel 6",
        "manufacturer": "Google",
        "brand": "google",
        "model": "GB7N6",
        "device": "oriole",
        "product": "oriole",
        "build_id": "SD1A.210817.019.C2",
        "build_display": "SD1A.210817.019.C2",
        "build_fingerprint": "google/oriole/oriole:12/SD1A.210817.019.C2/7903491:user/release-keys",
        "build_number": "SD1A.210817.019.C2",
        "android_version": "12",
        "sdk_int": 31,
        "security_patch": "2021-11-05",
        "cpu_info": "ARM64 FP ASIMD AES VMH | 2802 | 8",
        "cpu_model": "Google Tensor",
        "gpu_renderer": "Mali-G78",
        "gpu_version": "OpenGL ES 3.2",
        "total_ram": 7851,
        "available_ram": 4820,
        "screen_width": 1080,
        "screen_height": 2400,
        "screen_dpi": "420",
        "screen_density": 2.625,
        "device_type": "Handheld",
        "device_form_factor": "phone",
    },
    # ── 5. Realme 8 Pro (RMX3081) ─────────────────────────
    {
        "name": "Realme 8 Pro",
        "manufacturer": "realme",
        "brand": "realme",
        "model": "RMX3081",
        "device": "RMX3081L1",
        "product": "RMX3081",
        "build_id": "RP1A.200720.011",
        "build_display": "RP1A.200720.011",
        "build_fingerprint": "realme/RMX3081/RMX3081L1:11/RP1A.200720.011/1626671360:user/release-keys",
        "build_number": "RP1A.200720.011",
        "android_version": "11",
        "sdk_int": 30,
        "security_patch": "2021-07-05",
        "cpu_info": "ARM64 FP ASIMD AES VMH | 2300 | 8",
        "cpu_model": "Snapdragon 720G",
        "gpu_renderer": "Adreno (TM) 618",
        "gpu_version": "OpenGL ES 3.2",
        "total_ram": 5951,
        "available_ram": 2950,
        "screen_width": 1080,
        "screen_height": 2400,
        "screen_dpi": "410",
        "screen_density": 2.625,
        "device_type": "Handheld",
        "device_form_factor": "phone",
    },
]

# ==================================================================
# REGION BUCKETS + ALIASES
# ==================================================================
REGION_BUCKETS = {
    "IND":     "https://client.ind.freefiremobile.com/",
    "AMERICA": "https://client.us.freefiremobile.com/",
    "OTHERS":  "https://clientbp.ppmainecoonghj.com/",
}

REGION_ALIASES = {
    # IND
    "IND": "IND", "INDIA": "IND", "IN": "IND",
    # AMERICA
    "AMERICA": "AMERICA", "BR": "AMERICA", "BRAZIL": "AMERICA",
    "NA": "AMERICA", "US": "AMERICA", "USA": "AMERICA", "USNA": "AMERICA",
    "LATAM": "AMERICA", "MX": "AMERICA", "AR": "AMERICA",
    "CO": "AMERICA", "SAC": "AMERICA",
    # OTHERS
    "OTHERS": "OTHERS", "OTHER": "OTHERS", "REST": "OTHERS", "ROW": "OTHERS",
    "GLOBAL": "OTHERS", "ME": "OTHERS", "VN": "OTHERS", "BD": "OTHERS",
    "PK": "OTHERS", "SG": "OTHERS", "ID": "OTHERS", "RU": "OTHERS",
    "TH": "OTHERS", "TW": "OTHERS", "MY": "OTHERS", "PH": "OTHERS",
    "EG": "OTHERS", "SA": "OTHERS", "AE": "OTHERS", "CIS": "OTHERS",
    "EU": "OTHERS", "EUROPE": "OTHERS", "HK": "OTHERS", "MO": "OTHERS",
    "KH": "OTHERS", "MM": "OTHERS", "LA": "OTHERS", "NP": "OTHERS",
    "LK": "OTHERS", "QA": "OTHERS", "KW": "OTHERS", "BH": "OTHERS",
    "OM": "OTHERS", "JO": "OTHERS", "LB": "OTHERS", "IQ": "OTHERS",
    "IR": "OTHERS", "TR": "OTHERS", "KZ": "OTHERS", "UZ": "OTHERS",
    "UA": "OTHERS", "BY": "OTHERS", "JP": "OTHERS", "KR": "OTHERS",
    "AU": "OTHERS", "NZ": "OTHERS",
}

DEFAULT_REGION = "IND"
UNKNOWN_BUCKET = "OTHERS"

# ==================================================================
# THREAD-LOCAL POOLED SESSIONS
# ==================================================================
_thread_local = threading.local()

def _make_session():
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=256, pool_maxsize=512,
        max_retries=Retry(total=2, backoff_factor=0.1,
                          status_forcelist=(500, 502, 503, 504),
                          allowed_methods=frozenset(["GET", "POST"])),
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
# FAST AES (thread-local cipher reuse)
# ==================================================================
_tl_cipher = threading.local()

def _get_encrypt_cipher():
    c = getattr(_tl_cipher, "enc", None)
    if c is None:
        c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        _tl_cipher.enc = c
    return c

def encrypt_message(plaintext):
    return _get_encrypt_cipher().encrypt(pad(plaintext, AES.block_size))

def decrypt_message(ct):
    if not ct or len(ct) % 16 != 0:
        return ct
    try:
        c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(c.decrypt(ct), AES.block_size)
    except Exception:
        return ct

# ==================================================================
# HEADERS
# ==================================================================
def _new_headers(dev=None):
    ua = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
    if dev:
        ua = f"Dalvik/2.1.0 (Linux; U; Android {dev['android_version']}; {dev['model']} Build/{dev['build_number']})"
    return {
        "User-Agent": ua,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": str(int(time.time())),
        "Authorization": "Bearer",
        "X-Ga": "v1 1",
        "ReleaseVersion": OB_VER,
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2018.4.12f1",
        "Connection": "Keep-Alive",
    }

OAUTH_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

# ==================================================================
# JWT EXTRACTION + ENVELOPE STRIP
# ==================================================================
_JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')

def _extract_jwt(body):
    if not body:
        return None
    try:
        m = output_pb2.Garena_420()
        m.ParseFromString(body)
        tok = getattr(m, "token", None)
        if tok:
            return tok
    except Exception:
        pass
    m = _JWT_RE.search(body)
    return m.group(0).decode("ascii") if m else None

def _strip_envelope(body, headers):
    try:
        if headers.get("x-ga-rv") == "1" and len(body) > SIGNED_RESPONSE_PREFIX_BYTES:
            return body[SIGNED_RESPONSE_PREFIX_BYTES:]
    except Exception:
        pass
    return body

def _parse_jwt_payload(token):
    try:
        p = token.split('.')[1]
        p += '=' * ((4 - len(p) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(p).decode('utf-8'))
    except Exception:
        return {}

# ==================================================================
# GAME DATA (with real device fingerprint)
# ==================================================================
def _build_game_data(access_token, open_id, platform_type):
    g = my_pb2.GameData()
    dev = random.choice(DEVICE_PROFILES)

    g.timestamp           = time.strftime("%Y-%m-%d %H:%M:%S")
    g.game_name           = "free fire"
    g.game_version        = 1
    g.version_code        = PLAY_VER

    # OS info — real build fingerprint
    g.os_info             = f"Android OS {dev['android_version']} / API-{dev['sdk_int']} ({dev['build_display']})"
    g.os_architecture     = "arm64-v8a"
    g.build_number        = dev["build_number"]
    g.device_type         = dev["device_type"]
    g.device_form_factor  = dev["device_form_factor"]
    g.device_model        = dev["model"]

    # Network
    g.network_provider    = "Verizon Wireless"
    g.connection_type     = "WIFI"

    # Screen
    g.screen_width        = dev["screen_width"]
    g.screen_height       = dev["screen_height"]
    g.dpi                 = dev["screen_dpi"]

    # CPU / GPU
    g.cpu_info            = dev["cpu_info"]
    g.total_ram           = dev["total_ram"]
    g.gpu_name            = dev["gpu_renderer"]
    g.gpu_version         = dev["gpu_version"]

    # Device IDs — real UUID4 + random hex
    g.user_id             = f"Google|{uuid.uuid4()}"
    g.unique_id           = os.urandom(16).hex()
    g.ip_address          = "172.190.111.97"
    g.language            = "en"

    # Account
    g.open_id             = open_id
    g.access_token        = access_token
    g.platform_type       = platform_type
    g.field_99            = str(platform_type)
    g.field_100           = str(platform_type)

    # Additional fields
    g.apk_info            = "com.dts.freefireth"
    g.library_path        = "/data/app/com.dts.freefireth-xxxxxxxxxxxx==/lib/arm64"
    g.graphics_backend    = "OpenGLES2"
    g.rendering_api       = 2
    g.marketplace         = "Google"
    g.total_storage       = 108000
    g.max_texture_units   = 16384

    return g

# ==================================================================
# SINGLE PLATFORM ATTEMPT
# ==================================================================
def _attempt(access_token, open_id, platform_type):
    try:
        g   = _build_game_data(access_token, open_id, platform_type)
        enc = encrypt_message(g.SerializeToString())
        r = get_session().post(MAJOR_LOGIN_URL, data=enc,
                               headers=_new_headers(),
                               timeout=PER_ATTEMPT_TIMEOUT)
        if r.status_code != 200:
            return None
        body = _strip_envelope(decrypt_message(r.content), r.headers)
        return _extract_jwt(body)
    except Exception:
        return None

# ==================================================================
# PARALLEL PLATFORM RACE
# ==================================================================
def get_jwt(access_token, open_id):
    with ThreadPoolExecutor(max_workers=len(PLATFORM_TYPES),
                            thread_name_prefix="ff") as pool:
        futures = [pool.submit(_attempt, access_token, open_id, p)
                   for p in PLATFORM_TYPES]
        deadline = time.time() + GLOBAL_JWT_TIMEOUT
        try:
            for fut in as_completed(futures, timeout=max(0.1, deadline - time.time())):
                try:
                    tok = fut.result()
                except Exception:
                    continue
                if tok:
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    return tok
        except Exception:
            pass
    return None

# ==================================================================
# OAUTH (guest only)
# ==================================================================
def guest_to_token(uid, password):
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': CLIENT_SECRET,
        'client_id': CLIENT_ID,
    }
    try:
        r = get_session().post(OAUTH_URL, data=payload,
                               headers=OAUTH_HEADERS, timeout=30)
        if r.status_code != 200:
            try:
                return None, r.json()
            except Exception:
                return None, {"status": "error", "message": r.text}
        j = r.json()
        if 'access_token' not in j or 'open_id' not in j:
            return None, {"status": "error", "message": "OAuth missing fields", "details": j}
        return j, None
    except Exception as e:
        return None, {"status": "error", "message": f"OAuth exception: {e}"}

# ==================================================================
# REGION RESOLVER
# ==================================================================
def _resolve_bucket(region):
    if not region:
        return DEFAULT_REGION
    return REGION_ALIASES.get(str(region).strip().upper(), DEFAULT_REGION)

def _bucket_from_lock_region(raw_lock_region, fallback_bucket):
    if raw_lock_region is not None and str(raw_lock_region).strip() != "":
        key = str(raw_lock_region).strip().upper()
        bucket = REGION_ALIASES.get(key)
        if bucket is not None:
            return bucket, "lock_region"
        return UNKNOWN_BUCKET, "lock_region_unknown"
    if fallback_bucket in REGION_BUCKETS:
        return fallback_bucket, "request"
    return DEFAULT_REGION, "default"

# ==================================================================
# ROUTES
# ==================================================================
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "ok",
        "service": "ff-jwt-guest",
        "endpoint": "/guest?uid=UID&password=PASSWORD",
        "post_json": {"uid": "UID", "password": "PASSWORD"},
        "buckets": list(REGION_BUCKETS.keys()),
        "devices": [d["name"] for d in DEVICE_PROFILES],
    })

@app.route("/guest", methods=["GET", "POST"])
def guest_endpoint():
    region_hint_raw = None
    try:
        uid = password = None
        if request.is_json:
            try:
                b = request.get_json(silent=True) or {}
                uid = b.get("uid"); password = b.get("password")
                region_hint_raw = b.get("region")
            except Exception:
                pass
        if not uid:
            uid = request.form.get("uid") or request.args.get("uid")
        if not password:
            password = request.form.get("password") or request.args.get("password")
        if not region_hint_raw:
            region_hint_raw = request.form.get("region") or request.args.get("region")

        hint_bucket = _resolve_bucket(region_hint_raw) if region_hint_raw else DEFAULT_REGION
        hint_addr = REGION_BUCKETS[hint_bucket]

        if not uid or not password:
            return jsonify({
                "status": "error",
                "message": "Both 'uid' and 'password' are required.",
                "addr": hint_addr,
                "region": hint_bucket,
                "usage": "/guest?uid=UID&password=PASSWORD",
            }), 400

        oauth, err = guest_to_token(uid.strip(), password.strip())
        if err or not oauth:
            e = dict(err or {"status": "error", "message": "OAuth failed"})
            e["status"] = "error"
            e["addr"] = hint_addr
            e["region"] = hint_bucket
            return jsonify(e), 400

        access_token = oauth["access_token"]
        open_id = oauth["open_id"]

        jwt_token = get_jwt(access_token, open_id)
        if not jwt_token:
            return jsonify({
                "status": "error",
                "message": "All platforms failed.",
                "addr": hint_addr,
                "region": hint_bucket,
                "access_token": access_token,
                "open_id": open_id,
            }), 502

        p = _parse_jwt_payload(jwt_token)
        lock_region_raw = p.get("lock_region")
        final_bucket, region_source = _bucket_from_lock_region(lock_region_raw, hint_bucket)
        addr = REGION_BUCKETS[final_bucket]

        return jsonify({
            "status": "success",
            "addr": addr,
            "region": final_bucket,
            "region_source": region_source,
            "lock_region": lock_region_raw,
            "token": jwt_token,
            "access_token": access_token,
            "open_id": open_id,
            "account_id": p.get("account_id"),
            "platform": p.get("external_type"),
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Unhandled: {type(e).__name__}: {e}",
            "addr": REGION_BUCKETS[UNKNOWN_BUCKET],
        }), 200

# ==================================================================
# ERROR HANDLERS
# ==================================================================
@app.errorhandler(404)
def _404(e):
    return jsonify({"status": "error", "message": "Not found",
                    "addr": REGION_BUCKETS[UNKNOWN_BUCKET]}), 404

@app.errorhandler(405)
def _405(e):
    return jsonify({"status": "error", "message": "Method not allowed",
                    "addr": REGION_BUCKETS[UNKNOWN_BUCKET]}), 405

@app.errorhandler(500)
def _500(e):
    return jsonify({"status": "error", "message": "Internal server error",
                    "addr": REGION_BUCKETS[UNKNOWN_BUCKET]}), 500

@app.errorhandler(Exception)
def _any(e):
    return jsonify({"status": "error", "message": str(e),
                    "addr": REGION_BUCKETS[UNKNOWN_BUCKET]}), 200

# ==================================================================
# ENTRYPOINT
# ==================================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, debug=False, threaded=True)
