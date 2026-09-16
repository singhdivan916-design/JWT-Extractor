from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import jwt
import urllib3
import base64
import json
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urljoin
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

# --- OB55 / new endpoint config ---
PLAY_VER     = "1.132.1"
OB_VER       = "OB55"
LOGIN_URL    = "https://loginbp.ppmainecoonghj.com"
MAJOR_LOGIN_URL = f"{LOGIN_URL}/MajorLogin"

# X-Ga-Sv: send as static value (or set MODE="time" for now-timestamp)
X_GA_SV_STATIC = "1789534056"
X_GA_SV_MODE   = "static"     # "static" | "time"

# Signed response envelope (x-ga-rv: 1 -> strip N bytes before protobuf)
SIGNED_RESPONSE_PREFIX_BYTES = 64

# Parallel platform brute-force
PLATFORM_RANGE      = range(1, 10)   # platforms 1..9
PLATFORM_WORKERS    = 9              # one thread per platform
PER_PLATFORM_TIMEOUT = 8             # seconds

# Threadpool for /token, /guest, /eat requests
REQUEST_POOL_WORKERS = 32

PLATFORM_MAP = {
    3: "Facebook",
    4: "Guest",
    5: "VK",
    6: "Huawei",
    8: "Google",
    11: "X (Twitter)",
    13: "AppleId",
}

# ==================================================================
# SHARED SESSION POOL (thread-safe, connection-pooled)
# ==================================================================
def _make_session():
    s = requests.Session()
    retries = Retry(
        total=2, backoff_factor=0.1,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    adapter = HTTPAdapter(
        pool_connections=64,
        pool_maxsize=128,
        max_retries=retries,
        pool_block=False,
    )
    s.mount("https://", adapter)
    s.mount("http://",  adapter)
    s.verify = False
    return s

# Thread-local session so each worker thread reuses its own connections
_thread_local = threading.local()

def get_session() -> requests.Session:
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = _make_session()
        _thread_local.session = s
    return s

def _current_x_ga_sv() -> str:
    if X_GA_SV_MODE == "time":
        return str(int(time.time()))
    return X_GA_SV_STATIC

# ==================================================================
# HELPERS
# ==================================================================
def decode_ff_name(b64_str):
    try:
        if not b64_str:
            return ""
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip()
        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        decrypted_bytes = bytearray()
        for i, byte in enumerate(encrypted_bytes):
            key_byte = key[i % len(key)]
            decrypted_bytes.append(byte ^ key_byte)
        return decrypted_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error decoding: {str(e)}"

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def decrypt_message(ciphertext):
    if len(ciphertext) % 16 != 0:
        return ciphertext
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except Exception:
        return ciphertext

def _looks_like_major_login_res(data: bytes) -> bool:
    """Try to parse as MajorLoginRes; return True if it looks valid."""
    if not data or len(data) < 2:
        return False
    try:
        msg = output_pb2.Garena_420()
        msg.ParseFromString(data)
        # Heuristic: valid protobuf parses cleanly + has a token field-ish
        return True
    except Exception:
        return False

def strip_signed_envelope(content: bytes, headers) -> bytes:
    """x-ga-rv: 1 → body has a fixed-size signature prefix before real protobuf."""
    if headers.get("x-ga-rv") != "1":
        return content
    if len(content) <= SIGNED_RESPONSE_PREFIX_BYTES:
        return content
    return content[SIGNED_RESPONSE_PREFIX_BYTES:]

def try_parse_with_offsets(content: bytes, check_fn) -> bytes:
    """Scan candidate offsets for a parseable protobuf."""
    for off in (0, 64, 32, 16, 8, 128):
        if off >= len(content):
            continue
        if check_fn(content[off:]):
            return content[off:]
    return content

def extract_eat_token(user_input):
    if "http" in user_input or "?" in user_input:
        parsed_url = urlparse(user_input)
        qs = parse_qs(parsed_url.query)
        if 'eat' in qs:
            return qs['eat'][0]
        return None
    return user_input.strip()

def get_access_token_from_eat(eat_token):
    url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    }
    session = get_session()
    resp = session.get(url, headers=headers, allow_redirects=False, timeout=10)
    redirect_count = 0
    max_redirects = 10
    while 300 <= resp.status_code < 400 and redirect_count < max_redirects:
        location = resp.headers.get('location')
        if not location:
            break
        next_url = location if location.startswith('http') else urljoin(url, location)
        resp = session.get(next_url, headers=headers, allow_redirects=False, timeout=10)
        redirect_count += 1

    final_url = resp.url
    parsed = urlparse(final_url)
    qs = parse_qs(parsed.query)
    access_token = qs.get('access_token', [None])[0]
    if access_token:
        return access_token

    if resp.text:
        try:
            data = json.loads(resp.text)
            access_token = data.get('access_token') or data.get('token')
            if access_token:
                return access_token
        except Exception:
            pass
        match = re.search(r'[a-fA-F0-9]{64,}', resp.text)
        if match:
            return match.group(0)
    return None

def inspect_token(access_token):
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    headers = {'User-Agent': 'GarenaMSDK/4.0.19P9'}
    try:
        resp = get_session().get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('open_id')
    except Exception:
        pass
    return None

# ==================================================================
# NEW GAME-SERVER HEADERS  (UnityPlayer/2018.4.12f1 + X-Ga-Sv)
# ==================================================================
def game_headers(host="loginbp.ppmainecoonghj.com"):
    return {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": _current_x_ga_sv(),
        "Authorization": "Bearer",
        "X-Ga": "v1 1",
        "ReleaseVersion": OB_VER,
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2018.4.12f1",
        "Connection": "Keep-Alive",
        "Host": host,
    }

# ==================================================================
# SINGLE-PLATFORM LOGIN ATTEMPT
# ==================================================================
def _attempt_platform(access_token, open_id, platform_type):
    """
    One MajorLogin attempt for a given platform_type.
    Returns a result dict on success, else None.
    """
    try:
        game_data = my_pb2.GameData()
        game_data.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = PLAY_VER
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = platform_type
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)

        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data)

        headers = game_headers()
        resp = get_session().post(
            MAJOR_LOGIN_URL,
            data=encrypted_data,
            headers=headers,
            timeout=PER_PLATFORM_TIMEOUT,
        )
        if resp.status_code != 200:
            return None

        # 1) Decrypt the AES-CBC body
        decrypted_data = decrypt_message(resp.content)

        # 2) Strip signed envelope if server marked it
        decrypted_data = strip_signed_envelope(decrypted_data, resp.headers)

        # 3) If parsing fails, scan candidate offsets
        def _ok(b):
            try:
                m = output_pb2.Garena_420()
                m.ParseFromString(b)
                return True
            except Exception:
                return False
        decrypted_data = try_parse_with_offsets(decrypted_data, _ok)

        # 4) Try protobuf parse first
        token_value = None
        try:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(decrypted_data)
            token_value = getattr(example_msg, "token", None)
        except Exception:
            token_value = None

        # 5) Fallback: scrape the raw text for a JWT
        if not token_value:
            text = decrypted_data.decode('utf-8', errors='ignore')
            start = text.find("eyJ")
            if start != -1:
                end = start
                while end < len(text) and text[end] not in ['"', ' ', '\n', '\r', '\t', '\x00']:
                    end += 1
                candidate = text[start:end]
                if candidate.count('.') >= 2:
                    token_value = candidate

        if not token_value:
            return None

        # 6) Decode JWT payload
        try:
            decoded_token = jwt.decode(token_value, options={"verify_signature": False})
        except AttributeError:
            payload_b64 = token_value.split('.')[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            decoded_token = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))

        p_id = decoded_token.get("external_type")
        p_name = PLATFORM_MAP.get(p_id, f"Unknown ({p_id})")
        raw_nickname = decoded_token.get("nickname", "")
        account_name = decode_ff_name(raw_nickname)
        if "Error decoding" in account_name or not account_name:
            account_name = requests.utils.unquote(raw_nickname)

        return {
            "access_token": access_token,
            "account_id": decoded_token.get("account_id"),
            "account_name": account_name,
            "open_id": open_id,
            "platform": p_name,
            "region": decoded_token.get("lock_region"),
            "status": "success",
            "token": token_value,
        }
    except Exception:
        return None

# ==================================================================
# PARALLEL JWT GENERATOR  (tries all platforms concurrently)
# ==================================================================
def internal_generate_jwt(access_token, open_id=None):
    if not open_id:
        open_id = inspect_token(access_token)
        if not open_id:
            return {"status": "error",
                    "message": "Failed to retrieve open_id from access token."}, 400

    # Fire all platform attempts in parallel; first success wins.
    with ThreadPoolExecutor(max_workers=PLATFORM_WORKERS,
                            thread_name_prefix="fflogin") as pool:
        futures = {
            pool.submit(_attempt_platform, access_token, open_id, p): p
            for p in PLATFORM_RANGE
        }
        # Use as_completed with a global deadline
        deadline = time.time() + PER_PLATFORM_TIMEOUT + 2
        for fut in as_completed(futures, timeout=max(0.1, deadline - time.time())):
            try:
                result = fut.result()
            except Exception:
                continue
            if result:
                # Cancel the rest
                for f in futures:
                    if not f.done():
                        f.cancel()
                return result, 200

    return {"status": "error",
            "message": "No valid platform found or all authentication attempts failed."}, 400

# ==================================================================
# REQUEST PARAM HELPER
# ==================================================================
def get_request_param(param_name):
    if request.is_json and request.json and param_name in request.json:
        return request.json.get(param_name)
    if request.form and param_name in request.form:
        return request.form.get(param_name)
    return request.args.get(param_name)

# ==================================================================
# ERROR HANDLERS
# ==================================================================
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "error",
        "message": "Endpoint not found.",
        "hint": "Try /guest, /token, or /eat.",
        "api_docs": "GET / for docs."
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "status": "error",
        "message": "Method not allowed for this endpoint.",
        "hint": "Supports GET (query) and POST (JSON).",
        "api_docs": "GET / for docs."
    }), 405

# ==================================================================
# DOCS
# ==================================================================
@app.route('/', methods=['GET'])
@app.route('/api', methods=['GET'])
def api_docs():
    documentation = {
        "status": "success",
        "message": "FF JWT Generator API (OB55 / 1.132.1). Extracts decoded names, account details, and JWT tokens.",
        "endpoints": {
            "/guest": {
                "methods": ["GET", "POST"],
                "description": "Generate JWT using Free Fire Guest Login credentials.",
                "parameters": {
                    "uid": "String (Required) - Guest Account UID",
                    "password": "String (Required) - Guest Account Password"
                },
                "examples": {
                    "GET": "/guest?uid=12345678&password=your_password_here",
                    "POST_JSON": {"uid": "12345678", "password": "your_password_here"}
                }
            },
            "/token": {
                "methods": ["GET", "POST"],
                "description": "Generate JWT using a valid Garena Access Token.",
                "parameters": {
                    "access_token": "String (Required) - Active Free Fire Access Token"
                },
                "examples": {
                    "GET": "/token?access_token=YOUR_ACCESS_TOKEN",
                    "POST_JSON": {"access_token": "YOUR_ACCESS_TOKEN"}
                }
            },
            "/eat": {
                "methods": ["GET", "POST"],
                "description": "Resolve an EAT token or Callback URL into a JWT Token.",
                "parameters": {
                    "eat_token": "String (Required) - Full callback URL with ?eat=, or raw EAT token."
                },
                "examples": {
                    "GET": "/eat?eat_token=YOUR_EAT_TOKEN_OR_URL",
                    "POST_JSON": {"eat_token": "YOUR_EAT_TOKEN_OR_URL"}
                }
            }
        },
        "response_formats": {
            "success": {
                "access_token": "99240db750...",
                "account_id": 13857576530,
                "account_name": "DecodedPlayerName",
                "open_id": "cccb9b040e6...",
                "platform": "Guest",
                "region": "IND",
                "status": "success",
                "token": "eyJhbGciOi..."
            },
            "error": {
                "status": "error",
                "message": "Detailed error explanation here."
            }
        }
    }
    return jsonify(documentation), 200

# ==================================================================
# ENDPOINTS
# ==================================================================
@app.route('/token', methods=['GET', 'POST'])
def token_endpoint():
    access_token = get_request_param('access_token')
    if not access_token or access_token.strip() == "":
        return jsonify({
            "status": "error",
            "message": "The 'access_token' parameter is missing or empty!",
            "correct_usage": {
                "GET": "/token?access_token=YOUR_ACCESS_TOKEN",
                "POST": {"access_token": "YOUR_ACCESS_TOKEN"}
            }
        }), 400

    result, status_code = internal_generate_jwt(access_token)
    return jsonify(result), status_code

@app.route('/guest', methods=['GET', 'POST'])
def guest_endpoint():
    uid = get_request_param('uid')
    password = get_request_param('password')

    if not uid or not password:
        return jsonify({
            "status": "error",
            "message": "Both 'uid' and 'password' parameters are required!",
            "correct_usage": {
                "GET": "/guest?uid=YOUR_UID&password=YOUR_PASSWORD",
                "POST": {"uid": "YOUR_UID", "password": "YOUR_PASSWORD"}
            }
        }), 400

    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }

    try:
        oauth_response = get_session().post(oauth_url, data=payload, headers=headers, timeout=10)
    except requests.RequestException as e:
        return jsonify({"status": "error", "message": f"Connection failed: {str(e)}"}), 500

    if oauth_response.status_code != 200:
        try:
            err_data = oauth_response.json()
            err_data["status"] = "error"
            return jsonify(err_data), oauth_response.status_code
        except ValueError:
            return jsonify({"status": "error", "message": oauth_response.text}), oauth_response.status_code

    try:
        oauth_data = oauth_response.json()
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid JSON response from OAuth service"}), 500

    if 'access_token' not in oauth_data or 'open_id' not in oauth_data:
        return jsonify({
            "status": "error",
            "message": "OAuth response missing access_token or open_id",
            "details": oauth_data
        }), 500

    result, status_code = internal_generate_jwt(oauth_data['access_token'], oauth_data['open_id'])
    return jsonify(result), status_code

@app.route('/eat', methods=['GET', 'POST'])
def eat_endpoint():
    eat_input = get_request_param('eat_token')
    if not eat_input or eat_input.strip() == "":
        return jsonify({
            "status": "error",
            "message": "The 'eat_token' parameter is missing or empty!",
            "correct_usage": {
                "GET": "/eat?eat_token=YOUR_EAT_TOKEN_OR_URL",
                "POST": {"eat_token": "YOUR_EAT_TOKEN_OR_URL"}
            }
        }), 400

    eat_token = extract_eat_token(eat_input)
    if not eat_token:
        return jsonify({"status": "error",
                        "message": "Invalid EAT format or could not extract 'eat' parameter."}), 400

    access_token = get_access_token_from_eat(eat_token)
    if not access_token:
        return jsonify({"status": "error",
                        "message": "Failed to resolve EAT to an Access Token. Token may be expired."}), 400

    result, status_code = internal_generate_jwt(access_token)
    return jsonify(result), status_code

# ==================================================================
# ENTRYPOINT  (threaded Flask)
# ==================================================================
if __name__ == '__main__':
    # threaded=True lets each incoming request run on its own thread.
    # For serious load, run behind gunicorn:
    #   gunicorn -w 4 -k gthread --threads 32 -b 0.0.0.0:1080 app:app
    app.run(host='0.0.0.0', port=1080, debug=False, threaded=True)
