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

OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"

OB_VER   = "OB55"
PLAY_VER = "1.132.1"

X_GA_SV = "1789534056"          # static; swap to str(int(time.time())) if server rejects
SIGNED_RESPONSE_PREFIX_BYTES = 64

# Platform race settings
PLATFORM_TYPES      = (3, 4, 5, 6, 8, 11, 13)   # most-common first
PER_PLATFORM_TIMEOUT = 6

# ==================================================================
# THREAD-LOCAL POOLED SESSIONS
# ==================================================================
_thread_local = threading.local()

def _make_session():
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=128, pool_maxsize=256,
        max_retries=Retry(total=1, backoff_factor=0.05,
                          status_forcelist=(502, 503, 504),
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
# FAST AES HELPERS  (reuse cipher objects per-thread)
# ==================================================================
_tl_cipher = threading.local()

def _get_encrypt_cipher():
    c = getattr(_tl_cipher, "enc", None)
    if c is None:
        c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        _tl_cipher.enc = c
    return c

def encrypt_message(plaintext: bytes) -> bytes:
    return _get_encrypt_cipher().encrypt(pad(plaintext, AES.block_size))

def decrypt_message(ct: bytes) -> bytes:
    if len(ct) % 16 != 0 or not ct:
        return ct
    try:
        c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(c.decrypt(ct), AES.block_size)
    except Exception:
        return ct

# ==================================================================
# REQUEST HEADERS  (prebuilt, no per-call dict rebuild)
# ==================================================================
GAME_HEADERS = {
    "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "Accept": "*/*",
    "Accept-Encoding": "deflate, gzip",
    "X-Ga-Sv": X_GA_SV,
    "Authorization": "Bearer",
    "X-Ga": "v1 1",
    "ReleaseVersion": OB_VER,
    "Content-Type": "application/octet-stream",
    "X-Unity-Version": "2018.4.12f1",
    "Connection": "Keep-Alive",
    "Host": "loginbp.ppmainecoonghj.com",
}

OAUTH_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

# ==================================================================
# JWT SCRAPE (regex, no protobuf parse if not needed)
# ==================================================================
_JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')

def _extract_jwt(body: bytes):
    """Return JWT string from body, or None. Tries protobuf first, then regex."""
    # 1) Try protobuf
    try:
        m = output_pb2.Garena_420()
        m.ParseFromString(body)
        tok = getattr(m, "token", None)
        if tok:
            return tok
    except Exception:
        pass
    # 2) Regex scrape
    m = _JWT_RE.search(body)
    return m.group(0).decode("ascii") if m else None

def _strip_envelope(body: bytes, headers) -> bytes:
    if headers.get("x-ga-rv") == "1" and len(body) > SIGNED_RESPONSE_PREFIX_BYTES:
        return body[SIGNED_RESPONSE_PREFIX_BYTES:]
    return body

def _parse_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification. No PyJWT dep needed."""
    try:
        p = token.split('.')[1]
        p += '=' * ((4 - len(p) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(p).decode('utf-8'))
    except Exception:
        return {}

# ==================================================================
# PLATFORM ATTEMPT  (single request, minimal work)
# ==================================================================
def _attempt(access_token: str, open_id: str, platform_type: int):
    try:
        g = my_pb2.GameData()
        g.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        g.game_name = "free fire"
        g.game_version = 1
        g.version_code = PLAY_VER
        g.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        g.device_type = "Handheld"
        g.network_provider = "Verizon Wireless"
        g.connection_type = "WIFI"
        g.screen_width = 1280
        g.screen_height = 960
        g.dpi = "240"
        g.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        g.total_ram = 5951
        g.gpu_name = "Adreno (TM) 640"
        g.gpu_version = "OpenGL ES 3.0"
        g.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        g.ip_address = "172.190.111.97"
        g.language = "en"
        g.open_id = open_id
        g.access_token = access_token
        g.platform_type = platform_type
        g.field_99  = str(platform_type)
        g.field_100 = str(platform_type)

        enc = encrypt_message(g.SerializeToString())

        r = get_session().post(MAJOR_LOGIN_URL, data=enc,
                               headers=GAME_HEADERS, timeout=PER_PLATFORM_TIMEOUT)
        if r.status_code != 200:
            return None

        body = _strip_envelope(decrypt_message(r.content), r.headers)
        jwt_token = _extract_jwt(body)
        if not jwt_token:
            return None

        return jwt_token
    except Exception:
        return None

# ==================================================================
# PARALLEL RACE  — first valid JWT wins
# ==================================================================
def get_jwt(access_token: str, open_id: str) -> str:
    with ThreadPoolExecutor(max_workers=len(PLATFORM_TYPES),
                            thread_name_prefix="ff") as pool:
        futures = [pool.submit(_attempt, access_token, open_id, p)
                   for p in PLATFORM_TYPES]
        deadline = time.time() + PER_PLATFORM_TIMEOUT + 1
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
    return None

# ==================================================================
# OAUTH: guest uid+password → access_token + open_id
# ==================================================================
def guest_to_token(uid: str, password: str):
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': CLIENT_SECRET,
        'client_id': CLIENT_ID,
    }
    r = get_session().post(OAUTH_URL, data=payload, headers=OAUTH_HEADERS, timeout=8)
    if r.status_code != 200:
        try:
            return None, r.json()
        except Exception:
            return None, {"status": "error", "message": r.text}
    try:
        j = r.json()
    except Exception:
        return None, {"status": "error", "message": "Invalid JSON from OAuth"}
    if 'access_token' not in j or 'open_id' not in j:
        return None, {"status": "error", "message": "OAuth missing fields", "details": j}
    return j, None

# ==================================================================
# ROUTES
# ==================================================================
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "status": "success",
        "message": "FF Guest → JWT. Ultra-fast.",
        "endpoint": "/guest?uid=UID&password=PASSWORD",
        "post": {"uid": "UID", "password": "PASSWORD"},
    })

@app.route('/guest', methods=['GET', 'POST'])
def guest_endpoint():
    if request.is_json and request.json:
        uid = request.json.get('uid')
        password = request.json.get('password')
    else:
        uid = request.form.get('uid') or request.args.get('uid')
        password = request.form.get('password') or request.args.get('password')

    if not uid or not password:
        return jsonify({
            "status": "error",
            "message": "Both 'uid' and 'password' are required.",
            "usage": "/guest?uid=UID&password=PASSWORD"
        }), 400

    oauth_data, err = guest_to_token(uid, password)
    if err:
        err["status"] = "error"
        return jsonify(err), 400

    access_token = oauth_data['access_token']
    open_id      = oauth_data['open_id']

    jwt_token = get_jwt(access_token, open_id)
    if not jwt_token:
        return jsonify({
            "status": "error",
            "message": "All platform attempts failed.",
            "access_token": access_token,
            "open_id": open_id,
        }), 502

    p = _parse_jwt_payload(jwt_token)

    return jsonify({
        "status": "success",
        "token": jwt_token,
        "access_token": access_token,
        "open_id": open_id,
        "account_id": p.get("account_id"),
        "region": p.get("lock_region"),
        "platform": p.get("external_type"),
    }), 200

# ==================================================================
# ENTRYPOINT
# ==================================================================
if __name__ == '__main__':
    # dev server, threaded
    app.run(host='0.0.0.0', port=1080, debug=False, threaded=True)

# PROD (recommended):
#   gunicorn -w 4 -k gthread --threads 64 --timeout 20 -b 0.0.0.0:1080 app:app
