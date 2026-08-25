from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
import jwt
import urllib3
import base64
import json
import re
import time
from urllib.parse import urlparse, parse_qs, urljoin
import my_pb2
import output_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

PLATFORM_MAP = {
    3: "Facebook",
    4: "Guest",
    5: "VK",
    6: "Huawei",
    8: "Google",
    11: "X (Twitter)",
    13: "AppleId",
}

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
        name = decrypted_bytes.decode('utf-8', errors='ignore')
        return name
    except Exception as e:
        return f"Error decoding: {str(e)}"

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def decrypt_message(ciphertext):
    """Decrypt and unpad response data (matches main.py)."""
    if len(ciphertext) % 16 != 0:
        return ciphertext
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except:
        return ciphertext

def extract_eat_token(user_input):
    if "http" in user_input or "?" in user_input:
        parsed_url = urlparse(user_input)
        query_params = parse_qs(parsed_url.query)
        if 'eat' in query_params:
            return query_params['eat'][0]
        return None
    return user_input.strip()

def get_access_token_from_eat(eat_token):
    """Manually follow redirects to extract access_token (improved from main.py)."""
    url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    }
    session = requests.Session()
    resp = session.get(url, headers=headers, allow_redirects=False, verify=False, timeout=10)
    redirect_count = 0
    max_redirects = 10
    while 300 <= resp.status_code < 400 and redirect_count < max_redirects:
        location = resp.headers.get('location')
        if not location:
            break
        next_url = location if location.startswith('http') else urljoin(url, location)
        resp = session.get(next_url, headers=headers, allow_redirects=False, verify=False)
        redirect_count += 1

    final_url = resp.url
    parsed = urlparse(final_url)
    qs = parse_qs(parsed.query)
    access_token = qs.get('access_token', [None])[0]
    if access_token:
        return access_token

    # Try to parse JSON body
    if resp.text:
        try:
            data = json.loads(resp.text)
            access_token = data.get('access_token') or data.get('token')
            if access_token:
                return access_token
        except:
            pass
        # Fallback: search for hex token in body
        match = re.search(r'[a-fA-F0-9]{64,}', resp.text)
        if match:
            return match.group(0)
    return None

def inspect_token(access_token):
    """Get open_id from Garena token inspect endpoint (more reliable)."""
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    headers = {'User-Agent': 'GarenaMSDK/4.0.19P9'}
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('open_id')
    except:
        pass
    return None

def internal_generate_jwt(access_token, open_id=None):
    if not open_id:
        open_id = inspect_token(access_token)
        if not open_id:
            return {"status": "error", "message": "Failed to retrieve open_id from access token."}, 400

    MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"  # working endpoint

    # Try platforms 1 through 9 (inclusive)
    for platform_type in range(1, 10):
        try:
            game_data = my_pb2.GameData()
            game_data.timestamp = "2024-12-05 18:15:32"
            game_data.game_name = "free fire"
            game_data.game_version = 1
            game_data.version_code = "1.108.3"
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

            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip",
                "Content-Type": "application/octet-stream",
                "Expect": "100-continue",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB54"
            }

            response = requests.post(MAJOR_LOGIN_URL, data=encrypted_data, headers=headers, verify=False, timeout=5)
            if response.status_code == 200:
                # Decrypt the response (important!)
                decrypted_data = decrypt_message(response.content)

                # Try protobuf parsing
                try:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(decrypted_data)
                    token_value = getattr(example_msg, "token", None)
                except:
                    token_value = None

                # If token not found, fallback to text search
                if not token_value:
                    text = decrypted_data.decode('utf-8', errors='ignore')
                    start = text.find("eyJ")
                    if start != -1:
                        end = start
                        while end < len(text) and text[end] not in ['"', ' ', '\n', '\r', '\t', '\x00']:
                            end += 1
                        token_value = text[start:end]
                        if token_value.count('.') < 2:
                            token_value = None

                if token_value:
                    # Decode JWT (without verification)
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

                    result = {
                        "access_token": access_token,
                        "account_id": decoded_token.get("account_id"),
                        "account_name": account_name,
                        "open_id": open_id,
                        "platform": p_name,
                        "region": decoded_token.get("lock_region"),
                        "status": "success",
                        "token": token_value
                    }
                    return result, 200
        except Exception as e:
            # silently continue to next platform
            pass
        time.sleep(0.1)

    return {"status": "error", "message": "No valid platform found or all authentication attempts failed."}, 400

def get_request_param(param_name):
    if request.is_json and request.json and param_name in request.json:
        return request.json.get(param_name)
    if request.form and param_name in request.form:
        return request.form.get(param_name)
    return request.args.get(param_name)

# -------------------------------------------------------------
# ERROR HANDLERS - Returns JSON explanation for invalid requests
# -------------------------------------------------------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "error",
        "message": "Endpoint not found.",
        "hint": "Make sure you are calling /guest, /token, or /eat.",
        "api_docs": "Send a GET request to / for documentation."
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "status": "error",
        "message": "Method not allowed for this endpoint.",
        "hint": "This API supports GET (Query Parameters) and POST (JSON Body).",
        "api_docs": "Send a GET request to / for documentation."
    }), 405

# -------------------------------------------------------------
# ROOT ENDPOINT - Returns JSON API Documentation
# -------------------------------------------------------------
@app.route('/', methods=['GET'])
@app.route('/api', methods=['GET'])
def api_docs():
    documentation = {
        "status": "success",
        "message": "Welcome to the FF JWT Generator API. This API allows you to extract Decoded Account Names, Details, and JWT Tokens.",
        "endpoints": {
            "/guest": {
                "methods": ["GET", "POST"],
                "description": "Generate JWT using Free Fire Guest Login credentials.",
                "parameters": {
                    "uid": "String (Required) - The Guest Account UID",
                    "password": "String (Required) - The Guest Account Password"
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
                "description": "Automatically resolve an EAT Token or Callback URL into a JWT Token.",
                "parameters": {
                    "eat_token": "String (Required) - Full callback URL containing ?eat= or the raw EAT token."
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
                "message": "Detailed error explanation here.",
                "correct_usage": "Instruction on how to fix the error."
            }
        }
    }
    return jsonify(documentation), 200

# -------------------------------------------------------------
# API ENDPOINTS
# -------------------------------------------------------------
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
        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=10)
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
        return jsonify({"status": "error", "message": "Invalid EAT format or could not extract 'eat' parameter from the URL provided."}), 400

    access_token = get_access_token_from_eat(eat_token)
    if not access_token:
        return jsonify({"status": "error", "message": "Failed to resolve EAT to an Access Token. The token may be expired or invalid."}), 400

    result, status_code = internal_generate_jwt(access_token)
    return jsonify(result), status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1080, debug=False)
