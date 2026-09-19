import json
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler

SPINNER_API = "https://ff-spinner.vercel.app/api/spin"


class handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        uid = params.get("uid", [None])[0]
        pwd = params.get("password", [None])[0] or params.get("pass", [None])[0]

        if not uid or not pwd:
            self._send(400, {"success": False, "error": "missing uid or password"})
            return

        url = f"{SPINNER_API}?{urllib.parse.urlencode({'uid': uid, 'pass': pwd})}"
        try:
            with urllib.request.urlopen(url, timeout=40) as r:
                self._send(r.status, json.loads(r.read()))
        except urllib.error.HTTPError as e:
            try:
                self._send(e.code, json.loads(e.read()))
            except Exception:
                self._send(e.code, {"success": False, "error": f"http_{e.code}"})
        except Exception as e:
            self._send(502, {"success": False, "error": str(e)})
