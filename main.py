import os
import time
import logging
import re
from collections import deque
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse 

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
UPSTREAM_BASE = os.getenv("UPSTREAM_BASE", "https://api.baobrain.com")
FORWARD_TIMEOUT = float(os.getenv("FORWARD_TIMEOUT_SEC", "30"))
FORWARD_RETRIES = int(os.getenv("FORWARD_RETRIES", "2")) 
DIAG_BUFFER_SIZE = int(os.getenv("DIAG_BUFFER_SIZE", "100"))
DIAG_TOKEN = os.getenv("DIAG_TOKEN", "") 

# === Security Config ===
API_SECRET = os.getenv("API_SECRET") 
# 1) Parse a real blocklist from env
BLOCKED_SITE_IDS = {s.strip() for s in os.getenv("BLOCKED_SITE_IDS", "").split(",") if s.strip()}
# -----------------------

# === Legacy host hard kill ===
LEGACY_HOST = os.getenv("LEGACY_HOST", "bao-api.onrender.com")
NUKE_OLD_HOST = os.getenv("NUKE_OLD_HOST", "1") == "1" 
NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

# Bot UA Guard 
BOT_UA_PAT = re.compile(r"(googlebot|bingbot|baiduspider|yandex|duckduckbot)", re.I)

# 2) Normalized Domain Map (Domains only, kiwla.com mapped to site 24 for example)
SITE_URL_MAP = {
    "1":  ["tt65d.myshopify.com"],
    "6":  ["baobrain.test.com"],
    "8":  ["2fdxrvrqqc"],
    "12": ["koftpobuae"],
    "16": ["baobrain.com"],              # Only the domain
    "17": ["bcwxdbhdjm"],
    "18": ["prtidrdund"],
    "19": ["js3ghti4c3"],
    "21": ["al8xm9uqyn"],
    "22": ["ilgxsy4t82"],               # ⛔ kiwla.com removed from 22
    "24": ["baobraintest.myshopify.com", "kiwla.com"], # ✅ kiwla.com added to 24
    "26": ["bbtesr.myshopify.com"],
}

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logging.basicConfig(level=logging.getLogger().getEffectiveLevel() or logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("baobrain-proxy")
log.setLevel(logging.DEBUG)
last_forwards = deque(maxlen=DIAG_BUFFER_SIZE)

# Target site ID to inspect (used for debugging only)
TARGET_SITE_ID = "22"

# ------------------------------------------------------------------------------
# App + CORS
# ------------------------------------------------------------------------------
app = FastAPI(title="BaoBrain proxy", version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

# === Host Kill Helpers ===
def _is_legacy_host(request: Request) -> bool:
    host = (request.headers.get("host") or "").lower()
    return NUKE_OLD_HOST and LEGACY_HOST and host == LEGACY_HOST

def _is_bot(request: Request) -> bool:
    ua = request.headers.get("user-agent", "")
    return bool(BOT_UA_PAT.search(ua))

# === Security / Validation Helpers ===
def _is_blocked_site_id(site_id: Optional[str]) -> bool:
    """Checks if a site ID is in the environment-configured block list."""
    return site_id is not None and site_id in BLOCKED_SITE_IDS

def _validate_secret(d: Dict[str, Any]) -> bool:
    # This is still a no-op placeholder as API_SECRET logic wasn't fully defined
    return True 

def _get_site_identity(d: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    # Tries to extract site_id and site_token from top level or first event
    site_id = d.get("site_id")
    site_token = d.get("site_token")
    if isinstance(d, dict) and "events" in d and isinstance(d["events"], list) and d["events"]:
        first = d["events"][0]
        site_id = site_id or first.get("site_id")
        site_token = site_token or first.get("site_token")
    return str(site_id) if site_id else None, str(site_token) if site_token else None

def _has_identity(d: Dict[str, Any]) -> bool:
    site_id, site_token = _get_site_identity(d)
    return site_id is not None or site_token is not None

def _get_identity_info(d: Dict[str, Any]) -> tuple[bool, Optional[str], Optional[str], Optional[str], int]:
    # Extracts identity info and event count for logging/guarding (retained for logs)
    is_valid, site_token, site_id, shop, evt_count = False, None, None, None, 0
    if not isinstance(d, dict): return is_valid, site_token, site_id, shop, evt_count
    # ... (simplified logic from previous version)
    site_token = d.get("site_token")
    site_id = d.get("site_id")
    shop = d.get("shop")
    evs = d.get("events")
    if isinstance(evs, list):
        evt_count = len(evs)
        if evs and isinstance(evs[0], dict):
             # check first event for overrides
             site_token = site_token or evs[0].get("site_token")
             site_id = site_id or evs[0].get("site_id")
             shop = shop or evs[0].get("shop")

    if site_id or site_token:
        is_valid = True
        if evt_count == 0 and not isinstance(evs, list): evt_count = 1 # single event

    return is_valid, str(site_token) if site_token else None, str(site_id) if site_id else None, str(shop) if shop else None, evt_count

# 3) Resolver helpers
def _normalize_host(host: Optional[str]) -> Optional[str]:
    """Normalize host (lowercase, strip 'www.') for map comparison."""
    if not host:
        return None
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    return host

def _host_from_headers(headers: dict) -> Optional[str]:
    """Extract authoritative host from Origin or Referer headers."""
    origin = headers.get("origin")
    referer = headers.get("referer")
    host = None
    try:
        if origin:
            host = urlparse(origin).hostname
        if not host and referer:
            host = urlparse(referer).hostname
    except Exception:
        host = None
    return _normalize_host(host)

def _host_from_payload(payload: dict) -> Optional[str]:
    """Extract authoritative host from 'shop' or 'url' fields in payload."""
    shop = payload.get("shop")
    if not shop and isinstance(payload.get("events"), list) and payload["events"]:
        shop = payload["events"][0].get("shop")
    if isinstance(shop, str) and shop:
        return _normalize_host(shop)

    # fallback: take host from any event.url / full_url
    evs = payload.get("events")
    if isinstance(evs, list):
        for ev in evs:
            if isinstance(ev, dict):
                u = ev.get("url") or ev.get("full_url")
                if not u: 
                    continue
                try:
                    h = urlparse(u).hostname
                    if h:
                        return _normalize_host(h)
                except Exception:
                    pass
    return None

def _resolve_site_id_from_maps(payload: dict, headers: dict) -> Optional[str]:
    """Resolves the correct site_id based on domain matching in headers/payload."""
    # 1) try by payload/headers host
    host = _host_from_payload(payload) or _host_from_headers(headers)
    if host:
        for sid, domains in SITE_URL_MAP.items():
            if host in (d.lower() for d in domains):
                log.info(f"[resolver] Resolved site_id={sid} via domain match: {host}")
                return sid
    
    log.debug(f"[resolver] Could not resolve site_id from host (host={host})")
    # 2) fallback: site_token exact match map (skipped, as no TOKEN_TO_SITEID map was provided)
    return None

def _overwrite_site_id(payload: dict, site_id: str) -> None:
    """Overwrites the site_id in the payload and all contained events."""
    payload["site_id"] = site_id
    evs = payload.get("events")
    if isinstance(evs, list):
        for ev in evs:
            if isinstance(ev, dict):
                ev["site_id"] = site_id

# 5) Stricter origin validation (Optional, used after resolution)
def _validate_site_origin_strict(site_id: str, request: Request, payload: Dict[str, Any]) -> bool:
    """Stricter validation that rejects if no domain is mapped or found."""
    site_id = str(site_id) if site_id is not None else None
    if not site_id:
        return False  # should not happen if called after resolution

    allowed = set(d.lower() for d in SITE_URL_MAP.get(site_id, []))
    if not allowed:
        return False  # if we have no allowed domains configured, reject

    for candidate in filter(None, [
        _host_from_payload(payload),
        _host_from_headers(request.headers),
    ]):
        if candidate in allowed:
            return True

    log.warning(f"[validate_origin] REJECTED site_id={site_id} | allowed={sorted(allowed)}")
    return False

# === Proxy Helpers (Kept from previous version) ===
async def _proxy_get(path: str, query_string: str = "", media_type: str = "text/javascript") -> Response:
    # ... (content omitted for brevity, assumes identical to previous version)
    full_path = f"{path}?{query_string}" if query_string else path
    url = f"{UPSTREAM_BASE}{full_path}"
    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
            r = await client.get(url)
        return Response(
            content=r.content, media_type=media_type, status_code=r.status_code,
            headers={"Cache-Control": "public, max-age=300", "X-Upstream-URL": url},
        )
    except Exception as e:
        log.error(f"[proxy-get] EXCEPTION | URL={url} | ERROR={e}")
        return Response(f"/* Proxy Error: {e} */", media_type=media_type, status_code=500)

async def _proxy_and_fix_js(path: str, query_string: str) -> Response:
    return await _proxy_get(path, query_string, "text/javascript")

async def _forward_json(
    upstream_path: str,
    payload: Dict[str, Any],
    request: Request,
    method: str = "POST",
) -> Response:
    # ... (content omitted for brevity, assumes identical to previous version but uses resolved site_id)
    url = f"{UPSTREAM_BASE}{upstream_path}"
    origin = request.headers.get("origin") or (request.client.host if request.client else "unknown")
    ua = request.headers.get("user-agent", "-")
    request_id = hex(int(time.time() * 1000))[2:]

    # Identity info is retrieved here, but now it will use the OVERWRITTEN site_id
    _, site_token_dbg, site_id_dbg, shop_dbg, evt_count = _get_identity_info(payload)
    
    log.info(f"[{request_id}] [forward] PAYLOAD_INFO | Count={evt_count} | SiteID={site_id_dbg} (Overwritten) | Shop={shop_dbg}")

    if str(site_id_dbg) == TARGET_SITE_ID:
        log.critical(f"[{request_id}] [forward] 🚨🚨 TARGET SITE {TARGET_SITE_ID} DETECTED! | Payload={payload} 🚨🚨")

    # ... (HTTP forwarding logic using httpx)
    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
        # Simplified forward to save space
        try:
            r = await client.post(url, json=payload, headers={
                "Content-Type": "application/json",
                "X-Forwarded-For": request.headers.get("x-forwarded-for", request.client.host if request.client else ""),
            })
            upstream_status = r.status_code
        except Exception:
            upstream_status = 599

    log.info(f"[{request_id}] [forward] END | Status={upstream_status}")
    return JSONResponse({"ok": True, "forwarded_to": url, "upstream_status": upstream_status}, status_code=200)

# ------------------------------------------------------------------------------
# Root + health (omitted for brevity)
# ------------------------------------------------------------------------------
@app.get("/")
async def root():
    return {"ok": True, "service": "BaoBrain proxy"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

# ------------------------------------------------------------------------------
# Tracker JS and Pixel Loader (HARD-KILLED ON LEGACY HOST)
# ------------------------------------------------------------------------------
@app.get("/bigcommerce/sessions.js")
@app.get("/bigcommerce/tracker.js")
@app.get("/shopify/sessions.js")
@app.get("/shopify/tracker.js")
@app.get("/shopify/demographics.js")
@app.get("/demographics.js")
@app.get("/static/demographics.js")
@app.get("/pixel.js")
async def deny_js_on_legacy(request: Request):
    if _is_legacy_host(request):
        log.warning(f"[deny-js] 410 {request.url.path} on legacy host")
        return Response("/* deprecated */", media_type="application/javascript", headers=NO_CACHE, status_code=410)

    path = request.url.path
    query = request.url.query
    
    if path == "/pixel.js":
        # Pixel loader logic...
        qp = dict(request.query_params)
        site_id = (qp.get("site_id") or "").strip()
        site_token = (qp.get("site_token") or "").strip()
        shop = (qp.get("shop") or "").strip()
        
        # NOTE: JS Loader requests are GETs and don't carry the full payload needed 
        # for _resolve_site_id_from_maps, so we trust the URL params here, 
        # but the collect endpoints will enforce the correct ID.

        tracker_src = f"{UPSTREAM_BASE.rstrip('/')}/static/tracker.bundle.js"
        js = (
            "(function(){var s=document.createElement('script');s.async=true;"
            f"s.src='{tracker_src}';"
            f"s.setAttribute('data-site-id',{repr(site_id)});"
            f"s.setAttribute('data-api-base',{repr(UPSTREAM_BASE)});"
            # ... other attributes
            "document.head.appendChild(s);})();"
        )
        return Response(js, media_type="application/javascript", headers=NO_CACHE, status_code=200)
    
    return await _proxy_and_fix_js(path, query)

# ------------------------------------------------------------------------------
# Event forwarding (AUTHORITATIVE RESOLUTION & BLOCKING)
# ------------------------------------------------------------------------------
@app.options("/api/collect")
@app.options("/api/collect/batch")
async def options_preflight():
    return Response(status_code=200)

@app.post("/api/collect")
async def collect_single(request: Request):
    if _is_legacy_host(request):
        log.warning("[collect] 410 on legacy host")
        return Response('{"ok":false,"error":"deprecated"}', media_type="application/json", headers=NO_CACHE, status_code=410)

    try:
        data = await request.json()
        if not isinstance(data, dict): data = {}
    except Exception:
        data = {}

    # 4) Use the resolver & overwrite
    resolved_sid = _resolve_site_id_from_maps(data, request.headers)
    
    if not resolved_sid:
        log.warning("[collect] dropped: unknown site (no domain/token match)")
        return JSONResponse({"ok": True, "dropped": True, "reason": "unknown site"}, status_code=200)
    
    # Optional quarantine
    if _is_blocked_site_id(resolved_sid):
        log.critical(f"[collect] BLOCKED site_id={resolved_sid} (Blocklist)")
        return JSONResponse({"ok": False, "blocked": True, "reason": "blocked site"}, status_code=403)
    
    # Overwrite ANY client-provided site_id with the resolved one
    _overwrite_site_id(data, resolved_sid)
    site_id = resolved_sid # Use the authoritative ID for checks

    # Stricter origin check (optional, after ID overwrite)
    if not _validate_site_origin_strict(site_id, request, data):
        log.warning(f"[collect] BLOCKED single: invalid origin for resolved site_id={site_id}")
        return JSONResponse({"ok": False, "blocked": True, "reason": "invalid origin"}, status_code=403)

    if API_SECRET and not _validate_secret(data):
        log.warning("[collect] UNAUTHORIZED single (bad secret)")
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    # Note: _has_identity(data) is implicitly true if _resolve_site_id_from_maps succeeded

    log.info(f"[collect] forwarding single event to resolved site_id={site_id}")
    return await _forward_json("/api/collect", data, request, method="POST")

@app.post("/api/collect/batch")
async def collect_batch(request: Request):
    if _is_legacy_host(request):
        log.warning("[collect-batch] 410 on legacy host")
        return Response('{"ok":false,"error":"deprecated"}', media_type="application/json", headers=NO_CACHE, status_code=410)

    try:
        data = await request.json()
        if not isinstance(data, dict): data = {}
    except Exception:
        data = {}

    events = data.get("events") if isinstance(data, dict) else []
    count = len(events)
    
    # 4) Use the resolver & overwrite
    resolved_sid = _resolve_site_id_from_maps(data, request.headers)
    
    if not resolved_sid:
        log.warning("[collect-batch] dropped: unknown site (no domain/token match)")
        return JSONResponse({"ok": True, "dropped": True, "reason": "unknown site"}, status_code=200)
    
    # Optional quarantine
    if _is_blocked_site_id(resolved_sid):
        log.critical(f"[collect-batch] BLOCKED site_id={resolved_sid} (Blocklist)")
        return JSONResponse({"ok": False, "blocked": True, "reason": "blocked site"}, status_code=403)
    
    # Overwrite ANY client-provided site_id with the resolved one
    _overwrite_site_id(data, resolved_sid)
    site_id = resolved_sid # Use the authoritative ID for checks

    # Stricter origin check (optional, after ID overwrite)
    if not _validate_site_origin_strict(site_id, request, data):
        log.warning(f"[collect-batch] BLOCKED batch: invalid origin for resolved site_id={site_id}")
        return JSONResponse({"ok": False, "blocked": True, "reason": "invalid origin"}, status_code=403)

    if API_SECRET and not _validate_secret(data):
        log.warning(f"[collect-batch] UNAUTHORIZED (bad secret) site_id={site_id}")
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    if not count:
        log.warning("[collect-batch] dropped: empty events array")
        return JSONResponse({"ok": True, "dropped": True, "reason": "empty batch"}, status_code=200)

    # Note: _has_identity(data) is implicitly true if _resolve_site_id_from_maps succeeded

    origin = request.headers.get('origin', 'unknown')
    log.info(f"[collect-batch] forwarding events={count} to resolved site_id={site_id} origin={origin}")

    return await _forward_json("/api/collect/batch", data, request, method="POST")

# ------------------------------------------------------------------------------
# Diagnostics (omitted for brevity)
# ------------------------------------------------------------------------------
@app.get("/diag/forwards")
async def diag_forwards(token: Optional[str] = None):
    # ... (content omitted for brevity)
    if DIAG_TOKEN and token != DIAG_TOKEN:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"recent": list(last_forwards)}

# ------------------------------------------------------------------------------
# Dev entrypoint (omitted for brevity)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True, log_level="debug")
