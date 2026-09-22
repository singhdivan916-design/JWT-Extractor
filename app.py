#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FF Guest → JWT — Production-grade, ultra-fast, never-fail Flask API.

Changes vs previous version:
  • FIXED: _Noop now implements dec() and info(); every metrics call is
           wrapped so a metrics failure can never block a semaphore release.
  • FIXED: semaphore release happens BEFORE metrics decrement.
  • FIXED: the JWT race now launches ALL (endpoint × header × platform)
           combinations in parallel — single wave, first success wins.
           No more sequential waves.
  • FIXED: dedicated per-attempt race timeout so a hung endpoint cannot
           hold a pool thread for the full user-facing timeout.
  • No rate limiting, no user-facing 429/503.
"""

import os
import sys
import time
import json
import base64
import re
import signal
import logging
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from flask import Flask, request, jsonify, make_response, g
from flask_cors import CORS

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- optional deps ----------
try:
    import orjson
    from flask.json.provider import DefaultJSONProvider
    _HAS_ORJSON = True
except ImportError:
    _HAS_ORJSON = False

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST,
    )
    _HAS_PROM = True
except ImportError:
    _HAS_PROM = False

try:
    import my_pb2
    import output_pb2
except ImportError:
    my_pb2 = output_pb2 = None


# ==================================================================
# CONFIG
# ==================================================================
def _env_int(n, d):
    try: return int(os.environ.get(n, d))
    except Exception: return d

def _env_float(n, d):
    try: return float(os.environ.get(n, d))
    except Exception: return d

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_ID     = "100067"

SERVER_URL  = os.environ.get("FF_SERVER_URL", "https://loginbp.ppmainecoonghj.com/")
LISTEN_HOST = os.environ.get("FF_HOST", "0.0.0.0")
LISTEN_PORT = _env_int("FF_PORT", 1080)

# User-facing timeouts (generous)
_TO_C = _env_float("FF_TO_CONNECT", 15.0)
_TO_R = _env_float("FF_TO_READ", 120.0)
TIMEOUT_OAUTH = (_TO_C, _TO_R)

# Per-attempt race timeout — short, so a hung endpoint fails fast and
# lets another combo win. This does NOT cap the user-facing request.
RACE_TO_C = _env_float("FF_RACE_CONNECT", 5.0)
RACE_TO_R = _env_float("FF_RACE_READ", 12.0)
TIMEOUT_RACE = (RACE_TO_C, RACE_TO_R)

# Platform order (most likely to succeed first)
PLATFORM_TYPES = (4, 3, 8, 6, 5, 11, 13, 1, 2, 7, 9)
GLOBAL_JWT_TIMEOUT = _env_float("FF_JWT_DEADLINE", 60.0)

# Cache
JWT_CACHE_TTL = _env_int("FF_CACHE_TTL", 300)
JWT_CACHE_MAX = _env_int("FF_CACHE_MAX", 50000)

# Bulkheads (high — practically never fire)
GLOBAL_CONCURRENCY       = _env_int("FF_GLOBAL_CONC", 4000)
PER_ENDPOINT_CONCURRENCY = _env_int("FF_EP_CONC", 1000)
OAuth_CONCURRENCY        = _env_int("FF_OAUTH_CONC", 1000)
BULKHEAD_WAIT            = _env_float("FF_BULKHEAD_WAIT", 60.0)

# Circuit breaker
CB_FAIL_THRESHOLD = _env_int("FF_CB_FAILS", 30)
CB_COOLDOWN       = _env_float("FF_CB_COOLDOWN", 20.0)
CB_HALF_OPEN_MAX  = _env_int("FF_CB_HALF_OPEN_MAX", 5)

LOG_LEVEL = os.environ.get("FF_LOG_LEVEL", "INFO").upper()


# ==================================================================
# REGIONS
# ==================================================================
REGION_BUCKETS = {
    "IND":     {"client_url": "https://client.ind.freefiremobile.com/",
                "release_version": "OB55", "client_version": "1.132.7"},
    "AMERICA": {"client_url": "https://client.us.freefiremobile.com/",
                "release_version": "OB55", "client_version": "1.132.7"},
    "OTHERS":  {"client_url": "https://clientbp.ppmainecoonghj.com/",
                "release_version": "OB55", "client_version": "1.132.7"},
}
REGION_ALIASES = {
    "IND":"IND","INDIA":"IND","IN":"IND",
    "AMERICA":"AMERICA","BR":"AMERICA","BRAZIL":"AMERICA","NA":"AMERICA",
    "US":"AMERICA","USA":"AMERICA","USNA":"AMERICA","LATAM":"AMERICA",
    "MX":"AMERICA","AR":"AMERICA","CO":"AMERICA",
    "OTHERS":"OTHERS","OTHER":"OTHERS","REST":"OTHERS","ROW":"OTHERS",
    "GLOBAL":"OTHERS","ME":"OTHERS","VN":"OTHERS","BD":"OTHERS","PK":"OTHERS",
    "SG":"OTHERS","ID":"OTHERS","RU":"OTHERS","TH":"OTHERS","MY":"OTHERS",
    "PH":"OTHERS","EG":"OTHERS","SA":"OTHERS","AE":"OTHERS",
}
DEFAULT_REGION = "IND"

def _resolve_bucket(region):
    if not region: return DEFAULT_REGION
    return REGION_ALIASES.get(str(region).strip().upper(), DEFAULT_REGION)

def _bucket_cfg(b): return REGION_BUCKETS[b]

def _bucket_from_lock_region(raw, fallback):
    if raw:
        k = str(raw).strip().upper()
        if k in REGION_ALIASES:
            return REGION_ALIASES[k], "lock_region"
    if fallback in REGION_BUCKETS:
        return fallback, "request"
    return DEFAULT_REGION, "default"


# ==================================================================
# LOGGING
# ==================================================================
class _JsonFmt(logging.Formatter):
    def format(self, r):
        d = {"ts": datetime.utcnow().isoformat(timespec="milliseconds")+"Z",
             "lvl": r.levelname, "msg": r.getMessage(), "logger": r.name}
        for k in ("rid","ip","path","status","ms"):
            v = getattr(r, k, None)
            if v is not None: d[k] = v
        if r.exc_info: d["exc"] = self.formatException(r.exc_info)
        return json.dumps(d, separators=(",", ":"))

logger = logging.getLogger("ff")
logger.setLevel(LOG_LEVEL)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(_JsonFmt())
logger.addHandler(_h)
logger.propagate = False


# ==================================================================
# METRICS  — no-op fallback fully implements the full API
# ==================================================================
class _Noop:
    """No-op metrics object. Implements EVERY method prometheus_client
    exposes (including dec) so a missing dependency can NEVER crash the
    request path."""
    def labels(self, *a, **k): return self
    def inc(self, *a, **k): return self
    def dec(self, *a, **k): return self      # ← the missing method
    def observe(self, *a, **k): return self
    def set(self, *a, **k): return self
    def set_to_current_time(self, *a, **k): return self
    def info(self, *a, **k): return self
    def track_inprogress(self, *a, **k): return self
    def __enter__(self): return self
    def __exit__(self, *a): return False

if _HAS_PROM:
    M_REQ          = Counter("ff_requests_total", "Total requests",
                             ["endpoint","status"])
    M_REQ_MS       = Histogram("ff_request_duration_ms", "Request latency",
                               ["endpoint"],
                               buckets=(5,10,25,50,100,250,500,1000,2500,5000,10000,30000,60000))
    M_CACHE_HIT    = Counter("ff_cache_hits_total", "JWT cache hits")
    M_CACHE_MISS   = Counter("ff_cache_misses_total", "JWT cache misses")
    M_SF_JOIN      = Counter("ff_singleflight_joins_total", "Singleflight joins")
    M_OAUTH_FAIL   = Counter("ff_oauth_failures_total", "OAuth failures")
    M_JWT_FAIL     = Counter("ff_jwt_failures_total", "JWT race failures")
    M_INFLIGHT     = Gauge("ff_inflight_requests", "In-flight requests")
    M_INFLIGHT_EP  = Gauge("ff_inflight_endpoint", "In-flight per endpoint",
                           ["endpoint"])
    M_CB_STATE     = Gauge("ff_circuit_state", "Circuit state 0=closed 1=half 2=open",
                           ["endpoint"])
    M_BULK_TIMEOUT = Counter("ff_bulkhead_timeouts_total", "Bulkhead timeouts",
                             ["kind"])
else:
    M_REQ = M_REQ_MS = M_CACHE_HIT = M_CACHE_MISS = _Noop()
    M_SF_JOIN = M_OAUTH_FAIL = M_JWT_FAIL = _Noop()
    M_INFLIGHT = M_INFLIGHT_EP = M_CB_STATE = M_BULK_TIMEOUT = _Noop()

# Every metrics call goes through these wrappers so a broken metrics
# backend can never crash a request or skip a semaphore release.
def _m_inc(m, *a, **k):
    try: m.inc(*a, **k)
    except Exception: pass

def _m_dec(m, *a, **k):
    try: m.dec(*a, **k)
    except Exception: pass

def _m_obs(m, v, *a, **k):
    try: m.observe(v, *a, **k)
    except Exception: pass


# ==================================================================
# BULKHEADS
# ==================================================================
_global_sem   = threading.BoundedSemaphore(GLOBAL_CONCURRENCY)
_oauth_sem    = threading.BoundedSemaphore(OAuth_CONCURRENCY)
_ep_sems_lock = threading.Lock()
_ep_sems      = {}

def _ep_sem(endpoint):
    with _ep_sems_lock:
        s = _ep_sems.get(endpoint)
        if s is None:
            s = threading.BoundedSemaphore(PER_ENDPOINT_CONCURRENCY)
            _ep_sems[endpoint] = s
        return s

def _acquire(sem, kind):
    ok = sem.acquire(timeout=BULKHEAD_WAIT)
    if not ok:
        _m_inc(M_BULK_TIMEOUT.labels(kind))
    return ok


# ==================================================================
# CIRCUIT BREAKER
# ==================================================================
class CircuitBreaker:
    CLOSED, HALF_OPEN, OPEN = 0, 1, 2
    __slots__ = ("fail_threshold","cooldown","half_open_max",
                 "state","fails","opened_at","half_probes","lock")
    def __init__(self, ft, cd, hm):
        self.fail_threshold = ft; self.cooldown = cd; self.half_open_max = hm
        self.state = self.CLOSED; self.fails = 0
        self.opened_at = 0.0; self.half_probes = 0
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            if self.state == self.CLOSED: return True
            if self.state == self.OPEN:
                if time.monotonic() - self.opened_at >= self.cooldown:
                    self.state = self.HALF_OPEN; self.half_probes = 1; return True
                return False
            if self.half_probes < self.half_open_max:
                self.half_probes += 1; return True
            return False

    def on_success(self):
        with self.lock:
            if self.state == self.HALF_OPEN:
                self.state = self.CLOSED; self.fails = 0; self.half_probes = 0
            else:
                self.fails = 0

    def on_failure(self):
        with self.lock:
            self.fails += 1
            if self.state == self.HALF_OPEN:
                self.state = self.OPEN; self.opened_at = time.monotonic()
            elif self.fails >= self.fail_threshold and self.state == self.CLOSED:
                self.state = self.OPEN; self.opened_at = time.monotonic()

_cb_lock = threading.Lock(); _cbs = {}
def _cb_for(ep):
    with _cb_lock:
        cb = _cbs.get(ep)
        if cb is None:
            cb = CircuitBreaker(CB_FAIL_THRESHOLD, CB_COOLDOWN, CB_HALF_OPEN_MAX)
            _cbs[ep] = cb
        return cb


# ==================================================================
# CACHE
# ==================================================================
class TTLCache:
    def __init__(self, maxsize, ttl):
        self.maxsize = maxsize; self.ttl = ttl
        self.d = OrderedDict(); self.lock = threading.Lock()
    def get(self, k):
        now = time.monotonic()
        with self.lock:
            e = self.d.get(k)
            if e is None: return None
            ts, v = e
            if now - ts > self.ttl:
                self.d.pop(k, None); return None
            self.d.move_to_end(k); return v
    def set(self, k, v):
        now = time.monotonic()
        with self.lock:
            self.d[k] = (now, v); self.d.move_to_end(k)
            while len(self.d) > self.maxsize:
                self.d.popitem(last=False)
    def __len__(self): return len(self.d)

_jwt_cache = TTLCache(JWT_CACHE_MAX, JWT_CACHE_TTL)


# ==================================================================
# SINGLEFLIGHT
# ==================================================================
_sf_lock = threading.Lock(); _sf_inflight = {}

def _sf_acquire(key):
    with _sf_lock:
        e = _sf_inflight.get(key)
        if e is not None:
            e[1][0] += 1
            return e[0], False
        ev = threading.Event()
        _sf_inflight[key] = (ev, [1])
        return ev, True

def _sf_release(key):
    with _sf_lock:
        e = _sf_inflight.pop(key, None)
    if e: e[0].set()


# ==================================================================
# HTTP SESSIONS
# ==================================================================
_thread_local = threading.local()

def _make_session():
    s = requests.Session()
    a = HTTPAdapter(
        pool_connections=1024, pool_maxsize=2048,
        max_retries=Retry(
            total=3, connect=3, read=3, backoff_factor=0.2,
            backoff_max=3.0, status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            respect_retry_after_header=True,
        ),
        pool_block=False,
    )
    s.mount("https://", a); s.mount("http://", a); s.verify = False
    return s

def get_session():
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = _make_session(); _thread_local.session = s
    return s


# ==================================================================
# AES
# ==================================================================
_tl_cipher = threading.local()
def _get_encrypt_cipher():
    c = getattr(_tl_cipher, "enc", None)
    if c is None:
        c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV); _tl_cipher.enc = c
    return c

def encrypt_message(pt): return _get_encrypt_cipher().encrypt(pad(pt, AES.block_size))

def decrypt_message(ct):
    if not ct or len(ct) % 16 != 0: return ct
    try:
        c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(c.decrypt(ct), AES.block_size)
    except Exception: return ct


# ==================================================================
# HEADERS
# ==================================================================
def _new_headers(cfg):
    return {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": str(int(time.time())), "Authorization": "Bearer",
        "X-Ga": "v1 1", "ReleaseVersion": cfg["release_version"],
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2018.4.12f1", "Connection": "Keep-Alive",
    }

def _legacy_headers(cfg):
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue", "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1", "ReleaseVersion": cfg["release_version"],
    }

OAUTH_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
    "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
}


# ==================================================================
# JWT EXTRACTION
# ==================================================================
_JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')
SIGNED_RESPONSE_PREFIX_BYTES = 64

def _extract_jwt(body):
    if not body: return None
    if output_pb2 is not None:
        try:
            m = output_pb2.Garena_420(); m.ParseFromString(body)
            t = getattr(m, "token", None)
            if t: return t
        except Exception: pass
    m = _JWT_RE.search(body)
    return m.group(0).decode("ascii") if m else None

def _strip_envelope(body, hdrs):
    try:
        if hdrs.get("x-ga-rv") == "1" and len(body) > SIGNED_RESPONSE_PREFIX_BYTES:
            return body[SIGNED_RESPONSE_PREFIX_BYTES:]
    except Exception: pass
    return body

def _parse_jwt_payload(tok):
    try:
        p = tok.split('.')[1]
        p += '=' * ((4 - len(p) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(p).decode('utf-8'))
    except Exception: return {}


# ==================================================================
# GAME DATA
# ==================================================================
def _build_game_data(access_token, open_id, platform_type, cfg):
    g = my_pb2.GameData()
    g.timestamp        = time.strftime("%Y-%m-%d %H:%M:%S")
    g.game_name        = "free fire"
    g.game_version     = 1
    g.version_code     = cfg["client_version"]
    g.os_info          = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    g.device_type      = "Handheld"
    g.network_provider = "Verizon Wireless"
    g.connection_type  = "WIFI"
    g.screen_width     = 1280
    g.screen_height    = 960
    g.dpi              = "240"
    g.cpu_info         = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    g.total_ram        = 5951
    g.gpu_name         = "Adreno (TM) 640"
    g.gpu_version      = "OpenGL ES 3.0"
    g.user_id          = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    g.ip_address       = "172.190.111.97"
    g.language         = "en"
    g.open_id          = open_id
    g.access_token     = access_token
    g.platform_type    = platform_type
    g.field_99         = str(platform_type)
    g.field_100        = str(platform_type)
    return g


# ==================================================================
# SINGLE ATTEMPT
#   CRITICAL: semaphore release happens FIRST in finally, then the
#   metrics dec — so a metrics failure can never leak a permit.
# ==================================================================
def _attempt(access_token, open_id, platform_type, endpoint, header_kind, cfg):
    cb = _cb_for(endpoint)
    if not cb.allow(): return None
    sem = _ep_sem(endpoint)
    if not _acquire(sem, "endpoint"): return None
    _m_inc(M_INFLIGHT_EP.labels(endpoint))
    try:
        g = _build_game_data(access_token, open_id, platform_type, cfg)
        enc = encrypt_message(g.SerializeToString())
        hdrs = _new_headers(cfg) if header_kind == "new" else _legacy_headers(cfg)
        r = get_session().post(endpoint, data=enc, headers=hdrs, timeout=TIMEOUT_RACE)
        if r.status_code != 200:
            cb.on_failure(); return None
        body = _strip_envelope(decrypt_message(r.content), r.headers)
        tok = _extract_jwt(body)
        if tok: cb.on_success()
        else:   cb.on_failure()
        return tok
    except Exception:
        cb.on_failure(); return None
    finally:
        # Order matters: release resources first, then touch metrics.
        sem.release()
        _m_dec(M_INFLIGHT_EP.labels(endpoint))


# ==================================================================
# JWT RACE — single parallel wave, no sequential phases
# ==================================================================
FALLBACK_LOGIN_HOSTS = [
    "https://loginbp.ppmainecoonghj.com",
    "https://loginbp.ggblueshark.com",
    "https://loginbp.ggpolarbear.com",
]

def _do_jwt_fetch(access_token, open_id, hint_bucket):
    cfg = _bucket_cfg(hint_bucket)
    deadline = time.monotonic() + GLOBAL_JWT_TIMEOUT

    endpoints = [f"{SERVER_URL.rstrip('/')}/MajorLogin"]
    for h in FALLBACK_LOGIN_HOSTS:
        ep = f"{h}/MajorLogin"
        if ep not in endpoints:
            endpoints.append(ep)

    # Build all combinations ordered by likelihood:
    #   primary + new      (all platforms)
    #   primary + legacy   (top 6 platforms)
    #   fallback1 + new    (top 6)
    #   fallback2 + new    (top 6)
    combos = []
    for p in PLATFORM_TYPES:
        combos.append((endpoints[0], "new", p))
    for p in PLATFORM_TYPES[:6]:
        combos.append((endpoints[0], "legacy", p))
    for ep in endpoints[1:]:
        for p in PLATFORM_TYPES[:6]:
            combos.append((ep, "new", p))

    result_box  = [None]
    result_lock = threading.Lock()
    done_event  = threading.Event()

    def _worker(ep, hk, platform):
        if done_event.is_set(): return
        tok = _attempt(access_token, open_id, platform, ep, hk, cfg)
        if tok:
            with result_lock:
                if result_box[0] is None:
                    result_box[0] = tok
                    done_event.set()

    max_workers = min(48, max(8, len(combos)))
    pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ff")
    try:
        futures = [pool.submit(_worker, ep, hk, p) for ep, hk, p in combos]
        pending = set(futures)
        while pending and result_box[0] is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0: break
            try:
                _, pending = wait(pending, timeout=min(remaining, 5.0),
                                  return_when=FIRST_COMPLETED)
            except Exception:
                break
        for f in pending:
            f.cancel()
    finally:
        done_event.set()
        pool.shutdown(wait=False)
    return result_box[0]


def get_jwt(access_token, open_id, hint_bucket=DEFAULT_REGION):
    # 1) cache
    cached = _jwt_cache.get(access_token)
    if cached is not None:
        _m_inc(M_CACHE_HIT); return cached
    _m_inc(M_CACHE_MISS)

    # 2) singleflight
    ev, is_leader = _sf_acquire(access_token)
    if not is_leader:
        _m_inc(M_SF_JOIN)
        ev.wait(GLOBAL_JWT_TIMEOUT + 10)
        return _jwt_cache.get(access_token)

    try:
        cached = _jwt_cache.get(access_token)
        if cached is not None: return cached
        tok = _do_jwt_fetch(access_token, open_id, hint_bucket)
        if tok:
            _jwt_cache.set(access_token, tok)
        return tok
    finally:
        _sf_release(access_token)


# ==================================================================
# OAUTH
# ==================================================================
OAUTH_URLS = [
    "https://100067.connect.garena.com/oauth/guest/token/grant",
    "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant",
]

def guest_to_token(uid, password):
    payload = {
        'uid': uid, 'password': password,
        'response_type': "token", 'client_type': "2",
        'client_secret': CLIENT_SECRET, 'client_id': CLIENT_ID,
    }
    last_err = None
    for url in OAUTH_URLS:
        cb = _cb_for(url)
        if not cb.allow():
            last_err = {"status": "error", "message": "OAuth endpoint skipped"}
            continue
        if not _acquire(_oauth_sem, "oauth"):
            last_err = {"status": "error", "message": "OAuth queue timeout"}
            continue
        try:
            r = get_session().post(url, data=payload,
                                   headers=OAUTH_HEADERS, timeout=TIMEOUT_OAUTH)
            if r.status_code != 200:
                cb.on_failure()
                try: last_err = r.json()
                except Exception:
                    last_err = {"status": "error",
                                "message": r.text or f"HTTP {r.status_code}"}
                continue
            try: j = r.json()
            except Exception:
                cb.on_failure()
                last_err = {"status": "error", "message": "Invalid OAuth JSON"}
                continue
            if 'access_token' not in j or 'open_id' not in j:
                cb.on_failure()
                last_err = {"status": "error", "message": "OAuth missing fields",
                            "details": j}
                continue
            cb.on_success()
            return j, None
        except Exception as e:
            cb.on_failure()
            last_err = {"status": "error", "message": f"OAuth exception: {e}"}
        finally:
            # Order matters — release first, then metrics (defensive).
            _oauth_sem.release()
    return None, last_err or {"status": "error", "message": "OAuth failed"}


# ==================================================================
# FLASK APP
# ==================================================================
app = Flask(__name__)
CORS(app)

if _HAS_ORJSON:
    class _OrProvider(DefaultJSONProvider):
        def dumps(self, obj, **kw):
            return orjson.dumps(obj, option=orjson.OPT_NON_STR_KEYS).decode()
        def loads(self, s, **kw): return orjson.loads(s)
    app.json = _OrProvider(app)

@app.before_request
def _before():
    g.rid = request.headers.get("X-Request-ID") or os.urandom(8).hex()
    g.t0 = time.monotonic()

@app.after_request
def _after(resp):
    try:
        resp.headers["X-Request-ID"] = g.rid
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Server"] = "ff-jwt"
        path = (request.path or "/")[:64]
        ms = (time.monotonic() - g.t0) * 1000.0
        _m_inc(M_REQ.labels(path, str(resp.status_code)))
        _m_obs(M_REQ_MS.labels(path), ms)
    except Exception:
        pass
    return resp


# ==================================================================
# INFO
# ==================================================================
@app.route("/health", methods=["GET"])
def health(): return jsonify({"status": "ok"}), 200

@app.route("/ready", methods=["GET"])
def ready():
    return jsonify({"status": "ready",
                    "cache_size": len(_jwt_cache),
                    "inflight_keys": len(_sf_inflight)}), 200

@app.route("/metrics", methods=["GET"])
def metrics():
    if _HAS_PROM:
        return make_response(generate_latest(), 200,
                             {"Content-Type": CONTENT_TYPE_LATEST})
    return jsonify({"status": "ok", "cache_size": len(_jwt_cache)})

@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "ok", "service": "ff-jwt-guest",
        "buckets": list(REGION_BUCKETS.keys()),
        "default_region": DEFAULT_REGION,
        "note": "addr is always derived from JWT lock_region",
        "endpoint": "/guest?uid=UID&password=PASSWORD",
    })

@app.route("/regions", methods=["GET"])
def regions():
    out = {}
    for b, cfg in REGION_BUCKETS.items():
        aliases = [a for a, x in REGION_ALIASES.items() if x == b]
        out[b] = {**cfg, "server_url": SERVER_URL, "aliases": aliases}
    return jsonify({"status": "success", "default": DEFAULT_REGION,
                    "regions": out})


# ==================================================================
# VALIDATION
# ==================================================================
_UID_RE = re.compile(r'^\d{6,20}$')

def _valid_input(uid, password):
    if not isinstance(uid, str) or not isinstance(password, str):
        return False, "uid and password must be strings"
    if not _UID_RE.match(uid.strip()):
        return False, "uid must be 6–20 digits"
    if len(password) < 16 or len(password) > 256:
        return False, "password length out of range"
    if not re.match(r'^[A-Za-z0-9+/=_\-]+$', password.strip()):
        return False, "password has invalid characters"
    return True, None


# ==================================================================
# MAIN
# ==================================================================
@app.route("/guest", methods=["GET", "POST"])
def guest_endpoint():
    if not _acquire(_global_sem, "global"):
        return jsonify({
            "status": "error",
            "message": "Server under extreme load. Please retry.",
            "addr": REGION_BUCKETS[DEFAULT_REGION]["client_url"],
        }), 200

    _m_inc(M_INFLIGHT)
    region_hint_raw = None
    try:
        # ---- parse ----
        uid = password = None
        if request.is_json:
            try:
                b = request.get_json(silent=True) or {}
                uid = b.get("uid"); password = b.get("password")
                region_hint_raw = b.get("region")
            except Exception: pass
        if uid is None:
            uid = request.form.get("uid") or request.args.get("uid")
        if password is None:
            password = request.form.get("password") or request.args.get("password")
        if region_hint_raw is None:
            region_hint_raw = request.form.get("region") or request.args.get("region")

        hint_bucket = _resolve_bucket(region_hint_raw) if region_hint_raw else DEFAULT_REGION
        hint_cfg = _bucket_cfg(hint_bucket)
        hint_addr = hint_cfg["client_url"]

        if not uid or not password:
            return jsonify({
                "status": "error",
                "message": "Both 'uid' and 'password' are required.",
                "addr": hint_addr, "region": hint_bucket,
                "usage": "/guest?uid=UID&password=PASSWORD",
            }), 400

        ok, msg = _valid_input(uid, password)
        if not ok:
            return jsonify({"status": "error", "message": msg,
                            "addr": hint_addr, "region": hint_bucket}), 400

        # ---- OAuth ----
        oauth, err = guest_to_token(uid.strip(), password.strip())
        if err or not oauth:
            _m_inc(M_OAUTH_FAIL)
            e = dict(err or {"status": "error", "message": "OAuth failed"})
            e["status"] = "error"
            e["addr"] = hint_addr
            e["region"] = hint_bucket
            e["region_source"] = "request"
            return jsonify(e), 400

        access_token = oauth["access_token"]
        open_id = oauth["open_id"]

        # ---- JWT race ----
        jwt_token = get_jwt(access_token, open_id, hint_bucket)
        if not jwt_token:
            _m_inc(M_JWT_FAIL)
            return jsonify({
                "status": "error",
                "message": "All endpoints & platforms exhausted.",
                "addr": hint_addr, "region": hint_bucket,
                "region_source": "request",
                "access_token": access_token,
                "open_id": open_id,
            }), 502

        p = _parse_jwt_payload(jwt_token)
        lock_region_raw = p.get("lock_region")
        final_bucket, region_source = _bucket_from_lock_region(lock_region_raw, hint_bucket)
        final_cfg = _bucket_cfg(final_bucket)

        return jsonify({
            "status": "success",
            "addr": final_cfg["client_url"],
            "region": final_bucket,
            "region_source": region_source,
            "lock_region": lock_region_raw,
            "client_url": final_cfg["client_url"],
            "server_url": SERVER_URL,
            "release_version": final_cfg["release_version"],
            "client_version": final_cfg["client_version"],
            "token": jwt_token,
            "access_token": access_token,
            "open_id": open_id,
            "account_id": p.get("account_id"),
            "platform": p.get("external_type"),
        }), 200

    except Exception as e:
        logger.exception("guest_unhandled")
        try:
            b = _resolve_bucket(region_hint_raw or DEFAULT_REGION)
            addr = _bucket_cfg(b)["client_url"]
        except Exception:
            b = DEFAULT_REGION
            addr = REGION_BUCKETS[DEFAULT_REGION]["client_url"]
        return jsonify({
            "status": "error",
            "message": f"Unhandled: {type(e).__name__}: {e}",
            "addr": addr, "region": b, "region_source": "fallback",
        }), 200
    finally:
        # ORDER MATTERS — release the semaphore first, then decrement metrics.
        _global_sem.release()
        _m_dec(M_INFLIGHT)


# ==================================================================
# ERROR HANDLERS
# ==================================================================
def _def_addr(): return REGION_BUCKETS[DEFAULT_REGION]["client_url"]

@app.errorhandler(404)
def _404(e): return jsonify({"status":"error","message":"Not found",
                             "addr":_def_addr()}), 404

@app.errorhandler(405)
def _405(e): return jsonify({"status":"error","message":"Method not allowed",
                             "addr":_def_addr()}), 405

@app.errorhandler(500)
def _500(e): return jsonify({"status":"error","message":"Internal server error",
                             "addr":_def_addr()}), 500

@app.errorhandler(Exception)
def _any(e): return jsonify({"status":"error","message":str(e),
                             "addr":_def_addr()}), 200


# ==================================================================
# WARMUP + SHUTDOWN
# ==================================================================
def _warmup():
    try:
        for u in [OAUTH_URLS[0], SERVER_URL.rstrip("/")]:
            try: get_session().head(u, timeout=(5, 10))
            except Exception: pass
    except Exception: pass

threading.Thread(target=_warmup, daemon=True).start()

_SHUTDOWN = threading.Event()
def _on_signal(signum, frame):
    logger.info(f"signal_received sig={signum}")
    _SHUTDOWN.set()

try:
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
except Exception: pass


if __name__ == "__main__":
    logger.info(f"starting host={LISTEN_HOST} port={LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True)
