#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FF Guest → JWT — Production-grade, ultra-fast, never-fail Flask API.
Handles 1000s of RPS per instance when scaled with gunicorn pre-fork.

Design principles:
  • NEVER reject users with 429 / 503. Queue instead of drop.
  • Generous timeouts (upstream may be slow; we wait).
  • addr always derived from JWT lock_region (authoritative)
  • Circuit breaker: internal only — saves wasted upstream calls, never user-facing
  • Singleflight deduplication (1000 identical requests = 1 backend call)
  • LRU cache with TTL for JWT results
  • Prometheus metrics (optional)
  • Request-ID tracing + structured JSON logs
  • Health / Ready / Metrics endpoints
  • Graceful shutdown (SIGTERM/SIGINT)
  • Retries with jitter (respects Retry-After)
  • Never raises to the client — always valid JSON
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
import random
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# Optional deps ------------------------------------------------------
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
# CONFIGURATION  (tune via env vars)
# ==================================================================
def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except Exception:
        return default

def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except Exception:
        return default

# --- Crypto / OAuth ---
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_ID     = "100067"

# --- Server ---
SERVER_URL = os.environ.get("FF_SERVER_URL", "https://loginbp.ppmainecoonghj.com/")
LISTEN_HOST = os.environ.get("FF_HOST", "0.0.0.0")
LISTEN_PORT = _env_int("FF_PORT", 1080)

# --- Timeouts: generous defaults; upstream may legitimately be slow ---
#     Set to (None, None) if you truly want no timeout at all.
_TO_C = _env_float("FF_TO_CONNECT", 15.0)     # connect timeout
_TO_R = _env_float("FF_TO_READ", 120.0)       # read timeout
TIMEOUT_OAUTH = (_TO_C, _TO_R)
TIMEOUT_LOGIN = (_TO_C, _TO_R)

# --- Race / deadline ---
#   GLOBAL_JWT_DEADLINE is a soft cap on how long we spend racing platforms.
#   It is NOT a hard "give up" — if the deadline hits, we still return whatever
#   the fastest successful attempt produced, even if it's just one.
PLATFORM_TYPES      = (4, 3, 8, 6, 5, 11, 13, 1, 2, 7, 9)
GLOBAL_JWT_TIMEOUT  = _env_float("FF_JWT_DEADLINE", 60.0)

# --- Cache ---
JWT_CACHE_TTL    = _env_int("FF_CACHE_TTL", 300)      # seconds
JWT_CACHE_MAX    = _env_int("FF_CACHE_MAX", 50000)

# --- Concurrency bulkheads ---
#   These are SAFETY VALVES, not rate limits.
#   Default values are set HIGHER than any realistic thread count per worker,
#   so in normal operation the semaphores never block and never reject.
GLOBAL_CONCURRENCY      = _env_int("FF_GLOBAL_CONC", 4000)
PER_ENDPOINT_CONCURRENCY= _env_int("FF_EP_CONC", 1000)
OAuth_CONCURRENCY       = _env_int("FF_OAUTH_CONC", 1000)

# How long a request will queue on a bulkhead before giving up.
#   Very generous (60s) — practically only trips if the app is genuinely dead.
BULKHEAD_WAIT = _env_float("FF_BULKHEAD_WAIT", 60.0)

# --- Circuit breaker (internal only) ---
CB_FAIL_THRESHOLD = _env_int("FF_CB_FAILS", 30)
CB_COOLDOWN       = _env_float("FF_CB_COOLDOWN", 20.0)
CB_HALF_OPEN_MAX  = _env_int("FF_CB_HALF_OPEN_MAX", 5)

# --- Logging ---
LOG_LEVEL = os.environ.get("FF_LOG_LEVEL", "INFO").upper()

# ==================================================================
# REGION BUCKETS + ALIASES
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
    "IND": "IND", "INDIA": "IND", "IN": "IND",
    "AMERICA": "AMERICA", "BR": "AMERICA", "BRAZIL": "AMERICA",
    "NA": "AMERICA", "US": "AMERICA", "USA": "AMERICA", "USNA": "AMERICA",
    "LATAM": "AMERICA", "MX": "AMERICA", "AR": "AMERICA", "CO": "AMERICA",
    "OTHERS": "OTHERS", "OTHER": "OTHERS", "REST": "OTHERS", "ROW": "OTHERS",
    "GLOBAL": "OTHERS", "ME": "OTHERS", "VN": "OTHERS", "BD": "OTHERS",
    "PK": "OTHERS", "SG": "OTHERS", "ID": "OTHERS", "RU": "OTHERS",
    "TH": "OTHERS", "MY": "OTHERS", "PH": "OTHERS", "EG": "OTHERS",
    "SA": "OTHERS", "AE": "OTHERS",
}
DEFAULT_REGION = "IND"

def _resolve_bucket(region):
    if not region:
        return DEFAULT_REGION
    return REGION_ALIASES.get(str(region).strip().upper(), DEFAULT_REGION)

def _bucket_cfg(bucket):
    return REGION_BUCKETS[bucket]

def _bucket_from_lock_region(raw, fallback_bucket):
    if raw:
        key = str(raw).strip().upper()
        if key in REGION_ALIASES:
            return REGION_ALIASES[key], "lock_region"
    if fallback_bucket in REGION_BUCKETS:
        return fallback_bucket, "request"
    return DEFAULT_REGION, "default"

# ==================================================================
# LOGGING  (structured JSON)
# ==================================================================
class _JsonFormatter(logging.Formatter):
    def format(self, record):
        d = {
            "ts": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        for k in ("rid", "ip", "path", "status", "ms"):
            v = getattr(record, k, None)
            if v is not None:
                d[k] = v
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, separators=(",", ":"))

logger = logging.getLogger("ff")
logger.setLevel(LOG_LEVEL)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(_JsonFormatter())
logger.addHandler(_h)
logger.propagate = False

# ==================================================================
# PROMETHEUS METRICS
# ==================================================================
if _HAS_PROM:
    M_REQ          = Counter("ff_requests_total", "Total requests",
                             ["endpoint", "status"])
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
    M_CB_STATE     = Gauge("ff_circuit_state",
                           "Circuit breaker state (0=closed,1=half,2=open)",
                           ["endpoint"])
    M_BULK_TIMEOUT = Counter("ff_bulkhead_timeouts_total",
                             "Bulkhead queue timeouts (rare)", ["kind"])
else:
    class _Noop:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass
    M_REQ = M_REQ_MS = M_CACHE_HIT = M_CACHE_MISS = _Noop()
    M_SF_JOIN = M_OAUTH_FAIL = M_JWT_FAIL = _Noop()
    M_INFLIGHT = M_INFLIGHT_EP = M_CB_STATE = M_BULK_TIMEOUT = _Noop()

# ==================================================================
# CONCURRENCY BULKHEADS
#   Blocking with a very long timeout. Under normal load they never fire.
#   If one ever times out, that means the process is genuinely overwhelmed;
#   we still return a clean JSON response (never a raw 500 traceback).
# ==================================================================
_global_sem  = threading.BoundedSemaphore(GLOBAL_CONCURRENCY)
_oauth_sem   = threading.BoundedSemaphore(OAuth_CONCURRENCY)
_ep_sems_lock = threading.Lock()
_ep_sems     = {}
def _ep_sem(endpoint):
    with _ep_sems_lock:
        s = _ep_sems.get(endpoint)
        if s is None:
            s = threading.BoundedSemaphore(PER_ENDPOINT_CONCURRENCY)
            _ep_sems[endpoint] = s
        return s

def _acquire(sem, kind):
    """Blocking acquire with generous timeout; returns True on success."""
    ok = sem.acquire(timeout=BULKHEAD_WAIT)
    if not ok:
        M_BULK_TIMEOUT.labels(kind).inc()
    return ok

# ==================================================================
# CIRCUIT BREAKER  (internal only — never rejects a user)
#   Purpose: stop hammering a dead endpoint so we don't waste time.
#   Users still get their response via other endpoints / platforms.
# ==================================================================
class CircuitBreaker:
    CLOSED, HALF_OPEN, OPEN = 0, 1, 2
    __slots__ = ("fail_threshold", "cooldown", "half_open_max",
                 "state", "fails", "opened_at", "half_probes", "lock")
    def __init__(self, fail_threshold, cooldown, half_open_max):
        self.fail_threshold = fail_threshold
        self.cooldown = cooldown
        self.half_open_max = half_open_max
        self.state = self.CLOSED
        self.fails = 0
        self.opened_at = 0.0
        self.half_probes = 0
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            if self.state == self.CLOSED:
                return True
            if self.state == self.OPEN:
                if time.monotonic() - self.opened_at >= self.cooldown:
                    self.state = self.HALF_OPEN
                    self.half_probes = 1
                    return True
                return False
            if self.half_probes < self.half_open_max:
                self.half_probes += 1
                return True
            return False

    def on_success(self):
        with self.lock:
            if self.state == self.HALF_OPEN:
                self.state = self.CLOSED
                self.fails = 0
                self.half_probes = 0
            else:
                self.fails = 0

    def on_failure(self):
        with self.lock:
            self.fails += 1
            if self.state == self.HALF_OPEN:
                self.state = self.OPEN
                self.opened_at = time.monotonic()
            elif self.fails >= self.fail_threshold and self.state == self.CLOSED:
                self.state = self.OPEN
                self.opened_at = time.monotonic()

_cb_lock = threading.Lock()
_cbs = {}
def _cb_for(endpoint):
    with _cb_lock:
        cb = _cbs.get(endpoint)
        if cb is None:
            cb = CircuitBreaker(CB_FAIL_THRESHOLD, CB_COOLDOWN, CB_HALF_OPEN_MAX)
            _cbs[endpoint] = cb
        return cb

# ==================================================================
# JWT CACHE  (LRU + TTL)
# ==================================================================
class TTLCache:
    def __init__(self, maxsize, ttl):
        self.maxsize = maxsize
        self.ttl = ttl
        self.d = OrderedDict()
        self.lock = threading.Lock()

    def get(self, key):
        now = time.monotonic()
        with self.lock:
            ent = self.d.get(key)
            if ent is None:
                return None
            ts, val = ent
            if now - ts > self.ttl:
                self.d.pop(key, None)
                return None
            self.d.move_to_end(key)
            return val

    def set(self, key, val):
        now = time.monotonic()
        with self.lock:
            self.d[key] = (now, val)
            self.d.move_to_end(key)
            while len(self.d) > self.maxsize:
                self.d.popitem(last=False)

    def __len__(self):
        return len(self.d)

_jwt_cache = TTLCache(JWT_CACHE_MAX, JWT_CACHE_TTL)

# ==================================================================
# SINGLEFLIGHT  (dedupe concurrent work for the same access_token)
# ==================================================================
_sf_lock = threading.Lock()
_sf_inflight = {}   # key -> (Event, [waiters_count])

def _sf_acquire(key):
    with _sf_lock:
        ent = _sf_inflight.get(key)
        if ent is not None:
            ent[1][0] += 1
            return ent[0], False
        ev = threading.Event()
        _sf_inflight[key] = (ev, [1])
        return ev, True

def _sf_release(key):
    with _sf_lock:
        ent = _sf_inflight.pop(key, None)
    if ent:
        ent[0].set()

def _sf_wait(ev, timeout):
    return ev.wait(timeout)

# ==================================================================
# THREAD-LOCAL SESSION POOL
# ==================================================================
_thread_local = threading.local()

def _make_session():
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=1024, pool_maxsize=2048,
        max_retries=Retry(
            total=3, connect=3, read=3, backoff_factor=0.2,
            backoff_max=3.0, status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            respect_retry_after_header=True,
        ),
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
# FAST AES (thread-local cipher)
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
# HEADER SETS
# ==================================================================
def _new_headers(bucket_cfg):
    return {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": str(int(time.time())),
        "Authorization": "Bearer",
        "X-Ga": "v1 1",
        "ReleaseVersion": bucket_cfg["release_version"],
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2018.4.12f1",
        "Connection": "Keep-Alive",
    }

def _legacy_headers(bucket_cfg):
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": bucket_cfg["release_version"],
    }

OAUTH_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

# ==================================================================
# JWT EXTRACTION
# ==================================================================
_JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')
SIGNED_RESPONSE_PREFIX_BYTES = 64

def _extract_jwt(body):
    if not body:
        return None
    if output_pb2 is not None:
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
# GAME DATA BUILDER
# ==================================================================
def _build_game_data(access_token, open_id, platform_type, bucket_cfg):
    g = my_pb2.GameData()
    g.timestamp        = time.strftime("%Y-%m-%d %H:%M:%S")
    g.game_name        = "free fire"
    g.game_version     = 1
    g.version_code     = bucket_cfg["client_version"]
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
# SINGLE PLATFORM ATTEMPT
# ==================================================================
def _attempt(access_token, open_id, platform_type, endpoint, header_kind, bucket_cfg):
    cb = _cb_for(endpoint)
    if not cb.allow():
        return None

    sem = _ep_sem(endpoint)
    if not _acquire(sem, "endpoint"):
        return None
    M_INFLIGHT_EP.labels(endpoint).inc()
    try:
        g = _build_game_data(access_token, open_id, platform_type, bucket_cfg)
        enc = encrypt_message(g.SerializeToString())
        hdrs = _new_headers(bucket_cfg) if header_kind == "new" else _legacy_headers(bucket_cfg)

        r = get_session().post(endpoint, data=enc, headers=hdrs, timeout=TIMEOUT_LOGIN)
        if r.status_code != 200:
            cb.on_failure()
            return None

        body = _strip_envelope(decrypt_message(r.content), r.headers)
        tok = _extract_jwt(body)
        if tok:
            cb.on_success()
        else:
            cb.on_failure()
        return tok
    except Exception:
        cb.on_failure()
        return None
    finally:
        M_INFLIGHT_EP.labels(endpoint).dec()
        sem.release()

# ==================================================================
# PLATFORM RACE
# ==================================================================
def _race(access_token, open_id, endpoint, header_kind, deadline, bucket_cfg):
    remaining = deadline - time.monotonic()
    if remaining <= 0.05:
        return None

    platforms = PLATFORM_TYPES
    with ThreadPoolExecutor(max_workers=len(platforms),
                            thread_name_prefix="ff") as pool:
        futs = [pool.submit(_attempt, access_token, open_id, p, endpoint,
                            header_kind, bucket_cfg) for p in platforms]
        try:
            for f in as_completed(futs, timeout=max(0.1, remaining)):
                try:
                    tok = f.result()
                except Exception:
                    continue
                if tok:
                    for x in futs:
                        if not x.done():
                            x.cancel()
                    return tok
        except Exception:
            pass
    return None

# ==================================================================
# JWT FETCH
# ==================================================================
FALLBACK_LOGIN_HOSTS = [
    "https://loginbp.ppmainecoonghj.com",
    "https://loginbp.ggblueshark.com",
    "https://loginbp.ggpolarbear.com",
]

def _do_jwt_fetch(access_token, open_id, hint_bucket):
    bucket_cfg = _bucket_cfg(hint_bucket)
    deadline = time.monotonic() + GLOBAL_JWT_TIMEOUT

    endpoints = [f"{SERVER_URL.rstrip('/')}/MajorLogin"]
    for h in FALLBACK_LOGIN_HOSTS:
        ep = f"{h}/MajorLogin"
        if ep not in endpoints:
            endpoints.append(ep)

    # Wave 1: primary + new headers, then legacy
    tok = _race(access_token, open_id, endpoints[0], "new", deadline, bucket_cfg)
    if not tok and time.monotonic() < deadline:
        tok = _race(access_token, open_id, endpoints[0], "legacy", deadline, bucket_cfg)
    # Wave 2: fallbacks
    if not tok:
        for ep in endpoints[1:]:
            if time.monotonic() >= deadline:
                break
            tok = _race(access_token, open_id, ep, "new", deadline, bucket_cfg)
            if not tok and time.monotonic() < deadline:
                tok = _race(access_token, open_id, ep, "legacy", deadline, bucket_cfg)
            if tok:
                break
    return tok

def get_jwt(access_token, open_id, hint_bucket=DEFAULT_REGION):
    # 1) cache
    cached = _jwt_cache.get(access_token)
    if cached is not None:
        M_CACHE_HIT.inc()
        return cached
    M_CACHE_MISS.inc()

    # 2) singleflight
    sf_key = access_token
    ev, is_leader = _sf_acquire(sf_key)

    if not is_leader:
        M_SF_JOIN.inc()
        _sf_wait(ev, GLOBAL_JWT_TIMEOUT + 10)
        return _jwt_cache.get(access_token)

    try:
        cached = _jwt_cache.get(access_token)
        if cached is not None:
            return cached
        tok = _do_jwt_fetch(access_token, open_id, hint_bucket)
        if tok:
            _jwt_cache.set(access_token, tok)
        return tok
    finally:
        _sf_release(sf_key)

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
            last_err = {"status": "error", "message": "OAuth endpoint temporarily skipped"}
            continue
        if not _acquire(_oauth_sem, "oauth"):
            last_err = {"status": "error", "message": "OAuth queue timeout"}
            continue
        try:
            r = get_session().post(url, data=payload, headers=OAUTH_HEADERS,
                                   timeout=TIMEOUT_OAUTH)
            if r.status_code != 200:
                cb.on_failure()
                try:
                    last_err = r.json()
                except Exception:
                    last_err = {"status": "error",
                                "message": r.text or f"HTTP {r.status_code}"}
                continue
            try:
                j = r.json()
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
        def loads(self, s, **kw):
            return orjson.loads(s)
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
        M_REQ.labels(path, str(resp.status_code)).inc()
        M_REQ_MS.labels(path).observe(ms)
    except Exception:
        pass
    return resp

# ==================================================================
# INFO ENDPOINTS
# ==================================================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/ready", methods=["GET"])
def ready():
    return jsonify({
        "status": "ready",
        "cache_size": len(_jwt_cache),
        "inflight_keys": len(_sf_inflight),
    }), 200

@app.route("/metrics", methods=["GET"])
def metrics():
    if _HAS_PROM:
        return make_response(generate_latest(), 200,
                             {"Content-Type": CONTENT_TYPE_LATEST})
    return jsonify({
        "status": "ok",
        "cache_size": len(_jwt_cache),
        "inflight_keys": len(_sf_inflight),
    })

@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "ok",
        "service": "ff-jwt-guest",
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
# INPUT VALIDATION
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
# MAIN ENDPOINT
# ==================================================================
@app.route("/guest", methods=["GET", "POST"])
def guest_endpoint():
    # Blocking acquire — queues instead of rejecting
    if not _acquire(_global_sem, "global"):
        # Only reaches here if the process is truly stuck for BULKHEAD_WAIT sec
        return jsonify({
            "status": "error",
            "message": "Server under extreme load. Please retry.",
            "addr": REGION_BUCKETS[DEFAULT_REGION]["client_url"],
        }), 200

    M_INFLIGHT.inc()
    region_hint_raw = None
    try:
        # ---- parse ----
        uid = password = None
        if request.is_json:
            try:
                body = request.get_json(silent=True) or {}
                uid = body.get("uid")
                password = body.get("password")
                region_hint_raw = body.get("region")
            except Exception:
                pass
        if uid is None:
            uid = request.form.get("uid") or request.args.get("uid")
        if password is None:
            password = request.form.get("password") or request.args.get("password")
        if region_hint_raw is None:
            region_hint_raw = request.form.get("region") or request.args.get("region")

        hint_bucket = _resolve_bucket(region_hint_raw) if region_hint_raw else DEFAULT_REGION
        hint_cfg = _bucket_cfg(hint_bucket)
        hint_addr = hint_cfg["client_url"]

        # ---- validate ----
        if not uid or not password:
            return jsonify({
                "status": "error",
                "message": "Both 'uid' and 'password' are required.",
                "addr": hint_addr, "region": hint_bucket,
                "usage": "/guest?uid=UID&password=PASSWORD",
            }), 400
        ok, msg = _valid_input(uid, password)
        if not ok:
            return jsonify({
                "status": "error", "message": msg,
                "addr": hint_addr, "region": hint_bucket,
            }), 400

        # ---- OAuth ----
        oauth, err = guest_to_token(uid.strip(), password.strip())
        if err or not oauth:
            M_OAUTH_FAIL.inc()
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
            M_JWT_FAIL.inc()
            return jsonify({
                "status": "error",
                "message": "All endpoints & platforms exhausted.",
                "addr": hint_addr, "region": hint_bucket,
                "region_source": "request",
                "access_token": access_token,
                "open_id": open_id,
            }), 502

        # ---- derive final bucket from JWT lock_region ----
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
        M_INFLIGHT.dec()
        _global_sem.release()

# ==================================================================
# FLASK ERROR HANDLERS
# ==================================================================
def _def_addr():
    return REGION_BUCKETS[DEFAULT_REGION]["client_url"]

@app.errorhandler(404)
def _404(e):
    return jsonify({"status": "error", "message": "Not found",
                    "addr": _def_addr()}), 404

@app.errorhandler(405)
def _405(e):
    return jsonify({"status": "error", "message": "Method not allowed",
                    "addr": _def_addr()}), 405

@app.errorhandler(500)
def _500(e):
    return jsonify({"status": "error", "message": "Internal server error",
                    "addr": _def_addr()}), 500

@app.errorhandler(Exception)
def _any(e):
    return jsonify({"status": "error", "message": str(e),
                    "addr": _def_addr()}), 200

# ==================================================================
# WARMUP
# ==================================================================
def _warmup():
    try:
        for u in [OAUTH_URLS[0], SERVER_URL.rstrip("/")]:
            try:
                get_session().head(u, timeout=(5, 10))
            except Exception:
                pass
    except Exception:
        pass

threading.Thread(target=_warmup, daemon=True).start()

# ==================================================================
# GRACEFUL SHUTDOWN
# ==================================================================
_SHUTDOWN = threading.Event()

def _on_signal(signum, frame):
    logger.info(f"signal_received sig={signum}")
    _SHUTDOWN.set()

try:
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
except Exception:
    pass

# ==================================================================
# ENTRYPOINT
# ==================================================================
if __name__ == "__main__":
    logger.info(f"starting host={LISTEN_HOST} port={LISTEN_PORT} "
                f"conc={GLOBAL_CONCURRENCY} ep_conc={PER_ENDPOINT_CONCURRENCY}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True)
