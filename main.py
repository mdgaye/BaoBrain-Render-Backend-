import os
import time
import logging
import re
from collections import deque
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse # <-- New import for origin validation

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
UPSTREAM_BASE = os.getenv("UPSTREAM_BASE", "https://api.baobrain.com")
FORWARD_TIMEOUT = float(os.getenv("FORWARD_TIMEOUT_SEC", "30"))
FORWARD_RETRIES = int(os.getenv("FORWARD_RETRIES", "2"))  # retries on 5xx
DIAG_BUFFER_SIZE = int(os.getenv("DIAG_BUFFER_SIZE", "100"))
DIAG_TOKEN = os.getenv("DIAG_TOKEN", "")  # require ?token=... if set

# === Placeholder Configs (Required by the patch) ===
API_SECRET = os.getenv("API_SECRET") # Used for _validate_secret
# ---------------------------------------------------

# === Legacy host hard kill ===
LEGACY_HOST = os.getenv("LEGACY_HOST", "bao-api.onrender.com")
NUKE_OLD_HOST = os.getenv("NUKE_OLD_HOST", "1") == "1"  # set to 1 to kill, 0 to allow
NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

# Bot UA Guard (Optional, but included in patch)
BOT_UA_PAT = re.compile(r"(googlebot|bingbot|baiduspider|yandex|duckduckbot)", re.I)
# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
# Set level to DEBUG for maximum output
logging.basicConfig(level=logging.getLogger().getEffectiveLevel() or logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("baobrain-proxy")
log.setLevel(logging.DEBUG) # Ensure this logger is set to DEBUG
last_forwards = deque(maxlen=DIAG_BUFFER_SIZE)  # ring buffer of recent forwards

# Target site ID to inspect (used for debugging only)
TARGET_SITE_ID = "22"

# Site ID to URL mapping cache (load from DB or config)
SITE_URL_MAP = {
    # Populated mapping based on provided data
    "1": ["tt65d.myshopify.com"],
    "6": ["baobrain.test.com"],
    "8": ["2fdxrvrqqc"],
    "12": ["koftpobuae"],
    "16": ["baobrain.com", "https://baobrain.com/"], # Including full URL just in case
    "17": ["bcwxdbhdjm"],
    "18": ["prtidrdund"],
    "19": ["js3ghti4c3"],
    "21": ["al8xm9uqyn"],
    # Site 22: Added the domain from the prompt's context (`kiwla.com`) and the shop domain (`ilgxsy4t82`)
    "22": ["kiwla.com", "ilgxsy4t82"], 
    "24": ["baobraintest.myshopify.com"],
    "26": ["bbtesr.myshopify.com"],
}

# ------------------------------------------------------------------------------
# App + CORS
# ------------------------------------------------------------------------------
app = FastAPI(title="BaoBrain proxy", version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],            # tighten for production if needed
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

# === Identity Helpers ===
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
    """Extracts identity info and event count for logging/guarding."""
    is_valid = False
    site_token = None
    site_id = None
    shop = None
    evt_count = 0

    if not isinstance(d, dict):
        return is_valid, site_token, site_id, shop, evt_count

    site_token = d.get("site_token")
    site_id = d.get("site_id")
    shop = d.get("shop")

    if site_token or site_id:
        is_valid = True
        if "events" not in d: # Single event format without 'events' array
            evt_count = 1
        
    evs = d.get("events")
    if isinstance(evs, list):
        evt_count = len(evs)
        if evs:
            first = evs[0]
            if isinstance(first, dict):
                site_token = site_token or first.get("site_token")
                site_id = site_id or first.get("site_id")
                shop = shop or first.get("shop")
                if site_token or site_id:
                    is_valid = True
    
    # Ensure site_id is a string for consistent logging/comparison
    site_id = str(site_id) if site_id is not None else None
    site_token = str(site_token) if site_token is not None else None
    shop = str(shop) if shop is not None else None

    return is_valid, site_token, site_id, shop, evt_count

# === Security / Validation Helpers ===
def _is_blocked_site(d: Dict[str, Any]) -> bool:
    # Placeholder: Add real blocked site logic if needed
    return False

def _validate_secret(d: Dict[str, Any]) -> bool:
    # Placeholder: Add real API secret validation if API_SECRET is set
    return True # Assume valid if API_SECRET is not set

def _validate_site_origin(site_id: str, request: Request, payload: Dict[str, Any]) -> bool:
    """Validate that the request origin matches the registered site URL."""
    site_id = str(site_id) if site_id is not None else None
    
    if not site_id or site_id not in SITE_URL_MAP:
        return True # Allow if no mapping exists (backward compatible)
    
    allowed_domains = SITE_URL_MAP[site_id]
    
    # 1. Check Origin header
    origin = request.headers.get("origin", "")
    if origin:
        origin_domain = urlparse(origin).netloc.lower()
        if origin_domain in allowed_domains:
            log.debug(f"[validate_origin] ALLOWED by ORIGIN for site_id={site_id} | domain={origin_domain}")
            return True
            
    # 2. Check Referer header as fallback
    referer = request.headers.get("referer", "")
    if referer:
        referer_domain = urlparse(referer).netloc.lower()
        if referer_domain in allowed_domains:
            log.debug(f"[validate_origin] ALLOWED by REFERER for site_id={site_id} | domain={referer_domain}")
            return True
            
    # 3. Check URL in payload
    events = payload.get("events", [])
    if events and isinstance(events, list):
        for event in events:
            if isinstance(event, dict):
                event_url = event.get("url") or event.get("full_url", "")
                if event_url:
                    event_domain = urlparse(event_url).netloc.lower()
                    if event_domain in allowed_domains:
                        log.debug(f"[validate_origin] ALLOWED by PAYLOAD URL for site_id={site_id} | domain={event_domain}")
                        return True
                        
    log.warning(f"[validate_origin] REJECTED site_id={site_id} | origin={origin} | referer={referer} | allowed={allowed_domains}")
    return False

# === Proxy Helpers ===
async def _proxy_get(path: str, query_string: str = "", media_type: str = "text/javascript") -> Response:
    """GET a file from the upstream and stream it back as-is."""
    full_path = f"{path}?{query_string}" if query_string else path
    url = f"{UPSTREAM_BASE}{full_path}"
    log.info(f"[proxy-get] START | URL={url}")
    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
            r = await client.get(url)
        log.info(f"[proxy-get] END | STATUS={r.status_code} | URL={url}")
        return Response(
            content=r.content,
            media_type=media_type,
            headers={
                "Cache-Control": "public, max-age=300",
                "X-Upstream-URL": url,
                "X-Forwarded-Status": str(r.status_code),
            },
            status_code=200 if r.status_code == 200 else r.status_code,
        )
    except Exception as e:
        log.error(f"[proxy-get] EXCEPTION | URL={url} | ERROR={e}")
        return Response(f"/* Proxy Error: {e} */", media_type=media_type, status_code=500)

async def _proxy_and_fix_js(path: str, query_string: str) -> Response:
    # Simple proxy-get wrapper for the combined JS handler
    return await _proxy_get(path, query_string, "text/javascript")

async def _forward_json(
    upstream_path: str,
    payload: Dict[str, Any],
    request: Request,
    method: str = "POST",
) -> Response:
    """
    Forward JSON to upstream with simple retries on 5xx.
    Includes extensive debugging and Site 22 inspection.
    """
    url = f"{UPSTREAM_BASE}{upstream_path}"
    origin = request.headers.get("origin") or (request.client.host if request.client else "unknown")
    ua = request.headers.get("user-agent", "-")
    request_id = hex(int(time.time() * 1000))[2:]

    log.debug(f"[{request_id}] [forward] START | URL={url} | METHOD={method}")
    log.debug(f"[{request_id}] [forward] REQUEST_ORIGIN | Host={request.client.host if request.client else 'N/A'} | OriginHeader={origin} | XFF={request.headers.get('x-forwarded-for', '-')}")
    
    headers = {
        "Content-Type": "application/json",
        "X-Forwarded-For": request.headers.get("x-forwarded-for", request.client.host if request.client else ""),
        "X-Original-Origin": origin,
        "X-Original-User-Agent": ua,
    }

    upstream_status: Optional[int] = None
    upstream_body: Any = None
    err_text: Optional[str] = None

    site_token_dbg = None
    site_id_dbg = None
    shop_dbg = None
    evt_count = 0

    try:
        is_valid, site_token_dbg, site_id_dbg, shop_dbg, evt_count = _get_identity_info(payload)

        log.info(f"[{request_id}] [forward] PAYLOAD_INFO | Count={evt_count} | SiteID={site_id_dbg} | SiteToken={site_token_dbg[:4]}... | Shop={shop_dbg}")

        # CRITICAL INSPECTION: Site ID 22 check
        if str(site_id_dbg) == TARGET_SITE_ID:
            log.critical(f"[{request_id}] [forward] 🚨🚨 TARGET SITE {TARGET_SITE_ID} DETECTED! | Payload={payload} 🚨🚨")

    except Exception as e:
        log.error(f"[{request_id}] [forward] PAYLOAD_PARSING_ERROR | Error={e}")
        pass

    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
        attempts = FORWARD_RETRIES + 1
        for i in range(attempts):
            try:
                if method.upper() == "POST":
                    r = await client.post(url, json=payload, headers=headers)
                else:
                    r = await client.request(method.upper(), url, json=payload, headers=headers)
                
                upstream_status = r.status_code
                
                log.debug(f"[{request_id}] [forward] UPSTREAM_RESPONSE | Attempt={i+1}/{attempts} | Status={upstream_status}")
                
                try:
                    upstream_body = r.json()
                    log.debug(f"[{request_id}] [forward] UPSTREAM_BODY_JSON | Body={upstream_body}")
                except Exception:
                    upstream_body = r.text
                    log.debug(f"[{request_id}] [forward] UPSTREAM_BODY_TEXT | Body={upstream_body[:100]}...")
                    
                if r.status_code < 500:
                    break
                log.warning(f"[{request_id}] [forward] 5xx from upstream (attempt {i+1}/{attempts}) code={r.status_code} | URL={url}")
            except Exception as e:
                err_text = str(e)
                log.error(f"[{request_id}] [forward] EXCEPTION on attempt {i+1}/{attempts}: {err_text}")
                if i == attempts - 1:
                    upstream_status = 599

    try:
        last_forwards.append(
            {
                "ts": int(time.time()),
                "path": upstream_path,
                "upstream": upstream_status,
                "events": evt_count,
                "site_token": site_token_dbg,
                "site_id": site_id_dbg,
                "shop": shop_dbg,
                "err": err_text,
                "req_id": request_id,
            }
        )
        log.debug(f"[{request_id}] [forward] DIAG_BUFFER_APPENDED | Status={upstream_status} | SiteID={site_id_dbg}")
    except Exception as e:
        log.error(f"[{request_id}] [forward] DIAG_BUFFER_ERROR | Error={e}")

    body = {
        "ok": True,
        "forwarded_to": url,
        "upstream_status": upstream_status,
    }
    log.info(f"[{request_id}] [forward] END | Status={upstream_status} | FinalResponse=200")
    return JSONResponse(
        content=body,
        headers={"X-Forwarded-Status": str(upstream_status or 0), "X-Upstream-URL": url},
        status_code=200,
    )

# ------------------------------------------------------------------------------
# Root + health
# ------------------------------------------------------------------------------
@app.get("/")
async def root():
    log.debug("[root] Endpoint hit.")
    return {"ok": True, "service": "BaoBrain proxy", "docs": "/docs"}

@app.get("/health")
async def health():
    log.debug("[health] Endpoint hit.")
    return {"status": "healthy"}

# ------------------------------------------------------------------------------
# Tracker JS and Pixel Loader (COMBINED AND HARD-KILLED ON LEGACY HOST)
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
    # --- STEP 1: Hard-kill on legacy host ---
    if _is_legacy_host(request):
        log.warning(f"[deny-js] 410 {request.url.path} on legacy host")
        return Response("/* deprecated */", media_type="application/javascript", headers=NO_CACHE, status_code=410)

    # --- Step 2: Fall through for non-legacy hosts (current host is good) ---
    path = request.url.path
    query = request.url.query
    
    # Handle the special case for /pixel.js (which generates JS, not proxies)
    if path == "/pixel.js":
        qp = dict(request.query_params)
        site_id = (qp.get("site_id") or "").strip()
        site_token = (qp.get("site_token") or "").strip()
        shop = (qp.get("shop") or "").strip()
        
        log.info(f"[pixel] loader hit (non-legacy) | SiteID={site_id} | Shop={shop} | Query={query}")
        
        # CRITICAL INSPECTION: Check for Target Site ID on loader
        if site_id == TARGET_SITE_ID:
            log.critical(f"[pixel] 🚨🚨 TARGET SITE {TARGET_SITE_ID} LOADER HIT! (non-legacy) 🚨🚨")

        # Optional: enforce at least site_token
        if not site_token:
            log.warning("[pixel] missing site_token")
            return Response("/* missing site_token */", media_type="application/javascript", status_code=200)

        tracker_src = f"{UPSTREAM_BASE.rstrip('/')}/static/tracker.bundle.js"
        js = (
            "(function(){var s=document.createElement('script');s.async=true;"
            f"s.src='{tracker_src}';"
            f"s.setAttribute('data-site-id',{repr(site_id)});"
            f"s.setAttribute('data-site-token',{repr(site_token)});"
            f"s.setAttribute('data-shop',{repr(shop)});"
            f"s.setAttribute('data-api-base',{repr(UPSTREAM_BASE)});"
            "document.head.appendChild(s);})();"
        )
        return Response(js, media_type="application/javascript", headers=NO_CACHE, status_code=200)
    
    # All other JS endpoints proxy from upstream
    log.debug(f"[deny-js] Proxying {path} on current host.")
    return await _proxy_and_fix_js(path, query)

# ------------------------------------------------------------------------------
# Static JS and GA4 (Proxy only)
# ------------------------------------------------------------------------------
@app.get("/static/tracker.bundle.js")
async def tracker_bundle_js(request: Request):
    log.debug(f"[tracker_bundle_js] Request received | Query={request.url.query}")
    return await _proxy_get("/static/tracker.bundle.js", request.url.query, "application/javascript")

@app.get("/integrations/assets/ga4-loader-{site_id}.js")
async def ga4_loader_js(site_id: str, request: Request):
    log.debug(f"[ga4_loader_js] Request received | SiteID={site_id} | Query={request.url.query}")
    # CRITICAL INSPECTION: Check for Target Site ID on GA4 loader
    if site_id == TARGET_SITE_ID:
        log.critical(f"[ga4_loader_js] 🚨🚨 TARGET SITE {TARGET_SITE_ID} GA4 LOADER HIT! 🚨🚨")
    return await _proxy_get(f"/integrations/assets/ga4-loader-{site_id}.js", request.url.query, "text/javascript")

# ------------------------------------------------------------------------------
# Event forwarding (HARD-KILLED ON LEGACY HOST + ORIGIN VALIDATION)
# ------------------------------------------------------------------------------
@app.options("/api/collect")
@app.options("/api/collect/batch")
async def options_preflight():
    log.debug("[options] Preflight request received.")
    return Response(status_code=200)

@app.post("/api/collect")
async def collect_single(request: Request):
    # Kill the old Render host immediately
    if _is_legacy_host(request):
        log.warning("[collect] 410 on legacy host")
        return Response('{"ok":false,"error":"deprecated"}', media_type="application/json", headers=NO_CACHE, status_code=410)

    # Safe parse
    try:
        data = await request.json()
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}

    # --- Debug/Logging ---
    _, site_token_dbg, site_id_dbg, shop_dbg, _ = _get_identity_info(data)
    log.info(f"[collect] single request | SiteID={site_id_dbg} | Shop={shop_dbg} | URL={request.url}")
    # --- End Debug/Logging ---

    if API_SECRET and not _validate_secret(data):
        log.warning("[collect] UNAUTHORIZED single (bad secret)")
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    if _is_blocked_site(data):
        site_id, _ = _get_site_identity(data)
        log.warning(f"[collect] BLOCKED single: site_id={site_id}")
        return JSONResponse({"ok": False, "blocked": True, "reason": "blocked site"}, status_code=403)

    if not _has_identity(data):
        log.warning("[collect] dropped single: missing site identity")
        return JSONResponse({"ok": True, "dropped": True, "reason": "missing site identity"}, status_code=200)

    # ORIGIN VALIDATION CHECK:
    site_id, _ = _get_site_identity(data)
    if not _validate_site_origin(site_id, request, data):
        log.warning(f"[collect] BLOCKED single: invalid origin for site_id={site_id}")
        return JSONResponse({"ok": False, "blocked": True, "reason": "invalid origin"}, status_code=403)
    
    # CRITICAL INSPECTION: Check for Target Site ID on collect
    if site_id == TARGET_SITE_ID:
        log.critical(f"[collect] 🚨🚨 TARGET SITE {TARGET_SITE_ID} SINGLE EVENT! 🚨🚨")

    log.info("[collect] single event received (passed validation)")
    return await _forward_json("/api/collect", data, request, method="POST")

@app.post("/api/collect/batch")
async def collect_batch(request: Request):
    # Kill the old Render host immediately
    if _is_legacy_host(request):
        log.warning("[collect-batch] 410 on legacy host")
        return Response('{"ok":false,"error":"deprecated"}', media_type="application/json", headers=NO_CACHE, status_code=410)

    # Safe parse
    try:
        data = await request.json()
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}

    events = data.get("events") if isinstance(data, dict) else []
    if not isinstance(events, list):
        events = []
    count = len(events)
    
    # --- Debug/Logging ---
    _, site_token_dbg, site_id_dbg, shop_dbg, _ = _get_identity_info(data)
    log.info(f"[collect-batch] received events={count} site_id={site_id_dbg} shop={shop_dbg} URL={request.url}")
    # --- End Debug/Logging ---

    if API_SECRET and not _validate_secret(data):
        site_id, _ = _get_site_identity(data)
        log.warning(f"[collect-batch] UNAUTHORIZED (bad secret) site_id={site_id}")
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    if _is_blocked_site(data):
        site_id, _ = _get_site_identity(data)
        log.warning(f"[collect-batch] BLOCKED site_id={site_id}")
        return JSONResponse({"ok": False, "blocked": True, "reason": "blocked site"}, status_code=403)

    if not count:
        log.warning("[collect-batch] dropped: empty events array")
        return JSONResponse({"ok": True, "dropped": True, "reason": "empty batch"}, status_code=200)

    if not _has_identity(data):
        log.warning("[collect-batch] dropped: missing site identity")
        return JSONResponse({"ok": True, "dropped": True, "reason": "missing site identity"}, status_code=200)

    # ORIGIN VALIDATION CHECK:
    site_id, _ = _get_site_identity(data)
    if not _validate_site_origin(site_id, request, data):
        log.warning(f"[collect-batch] BLOCKED batch: invalid origin for site_id={site_id}")
        return JSONResponse({"ok": False, "blocked": True, "reason": "invalid origin"}, status_code=403)
    
    site_id, _ = _get_site_identity(data)
    origin = request.headers.get('origin', 'unknown')
    
    # CRITICAL INSPECTION: Check for Target Site ID on batch collect
    if site_id == TARGET_SITE_ID:
        log.critical(f"[collect-batch] 🚨🚨 TARGET SITE {TARGET_SITE_ID} BATCH EVENT! | Events={count} 🚨🚨")

    log.info(f"[collect-batch] forwarding events={count} site_id={site_id} origin={origin} (passed validation)")

    return await _forward_json("/api/collect/batch", data, request, method="POST")

# ------------------------------------------------------------------------------
# Diagnostics
# ------------------------------------------------------------------------------
@app.get("/diag/forwards")
async def diag_forwards(token: Optional[str] = None):
    log.debug("[diag_forwards] Request received.")
    if DIAG_TOKEN and token != DIAG_TOKEN:
        log.warning("[diag_forwards] Unauthorized access attempt.")
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"recent": list(last_forwards)}

# ------------------------------------------------------------------------------
# Dev entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    # Use log_level="debug" for maximum visibility of all debug statements
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=bool(os.getenv("DEV_RELOAD", "0") == "1"),
        log_level="debug",
    )
