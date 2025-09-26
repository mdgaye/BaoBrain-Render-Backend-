import os
import time
import logging
import re # Import regex for advanced fixing
from collections import deque
from typing import Any, Dict, Optional, Set

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
# --- Security Fixes ---
# Blocked Site IDs (use a Set for fast lookups)
BLOCKED_SITE_IDS: Set[str] = set(os.getenv("BLOCKED_SITE_IDS", "22").split(","))
API_SECRET = os.getenv("API_SECRET", "")  # Require a secret key in payload if set

# Define the old URL to be replaced. Ensure it's the exact URL clients are calling.
OLD_PROXY_URL = os.getenv("OLD_PROXY_URL", "https://bao-api.onrender.com")

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("baobrain-proxy")
last_forwards = deque(maxlen=DIAG_BUFFER_SIZE)  # ring buffer of recent forwards

# ------------------------------------------------------------------------------
# App + CORS
# ------------------------------------------------------------------------------
app = FastAPI(title="BaoBrain proxy (Rewriting Fix)", version="1.3.0") # Updated version
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

def _get_site_identity(data: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Extracts site_id and site_token from payload or first event."""
    site_id = data.get("site_id")
    site_token = data.get("site_token")
    
    evs = data.get("events")
    if isinstance(evs, list) and evs and isinstance(evs[0], dict):
        first = evs[0]
        site_id = site_id or first.get("site_id")
        site_token = site_token or first.get("site_token")

    return (str(site_id) if site_id else None, str(site_token) if site_token else None)

def _has_identity(d: Dict[str, Any]) -> bool:
    """Checks if site_id or site_token is present."""
    if not isinstance(d, dict):
        return False
    site_id, site_token = _get_site_identity(d)
    return bool(site_token or site_id)

def _is_blocked_site(data: Dict[str, Any]) -> bool:
    """Check if this site should be blocked by ID."""
    site_id, _ = _get_site_identity(data)
    # Check if a non-empty site_id is in the blocked list
    return site_id is not None and site_id in BLOCKED_SITE_IDS

def _validate_secret(data: Dict[str, Any]) -> bool:
    """Validate API secret if configured."""
    if not API_SECRET:
        return True  # No validation if not configured

    provided_secret = data.get("api_secret", "")
    return provided_secret == API_SECRET


# --- CRITICAL NEW JS PROXY/REWRITE HELPER ---
async def _proxy_and_fix_js(path: str, query_string: str = "") -> Response:
    """GET JS from upstream (api.baobrain.com) and fix any wrong URLs in it."""
    full_path = f"{path}?{query_string}" if query_string else path
    url = f"{UPSTREAM_BASE}{full_path}"
    log.info(f"[proxy-get-fix] fetching {url}")

    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
        r = await client.get(url)

        if r.status_code == 200:
            js_content = r.text
            
            # --- The Core Rewrite Logic ---
            replaced = False
            
            # 1. Replace the full old proxy URL (e.g., https://bao-api.onrender.com)
            if OLD_PROXY_URL in js_content:
                js_content = js_content.replace(OLD_PROXY_URL, UPSTREAM_BASE)
                replaced = True
            
            # 2. Replace the old proxy domain (e.g., bao-api.onrender.com)
            # Use regex to replace the bare domain name safely
            old_domain = OLD_PROXY_URL.split('//')[-1]
            new_domain = UPSTREAM_BASE.split('//')[-1]
            
            if old_domain in js_content:
                js_content = js_content.replace(old_domain, new_domain)
                replaced = True

            # 3. Replace common localhost/dev URLs (optional but good hygiene)
            if 'localhost' in js_content:
                 # Note: This is an over-simplification. A full fix requires knowing the dev URLs.
                 js_content = re.sub(r'https?://localhost:\d+', UPSTREAM_BASE, js_content)
                 replaced = True

            if replaced:
                log.warning(f"[FIX] Found and replaced old URLs in {path}. Proxy: {OLD_PROXY_URL} -> {UPSTREAM_BASE}")

            return Response(
                content=js_content,
                media_type="application/javascript", # Correct media type for all these files
                headers={
                    # Set aggressive no-cache headers to ensure customers reload the fixed file
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                    "X-Upstream-URL": url,
                    "X-Forwarded-Status": str(r.status_code),
                },
                status_code=200,
            )
        
        # Fallback for non-200 status codes
        return Response(
            content=r.content, 
            status_code=r.status_code, 
            headers={"X-Upstream-URL": url, "X-Forwarded-Status": str(r.status_code)}
        )
        
# --- END NEW HELPER ---

# The original _proxy_get is no longer used for JS files, but kept for reference
async def _proxy_get(path: str, query_string: str = "", media_type: str = "text/javascript") -> Response:
    """Original GET helper, kept as a template but replaced by _proxy_and_fix_js for all JS."""
    full_path = f"{path}?{query_string}" if query_string else path
    url = f"{UPSTREAM_BASE}{full_path}"
    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
        r = await client.get(url)
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

async def _forward_json(
    upstream_path: str,
    payload: Dict[str, Any],
    request: Request,
    method: str = "POST",
) -> Response:
    """
    Forward JSON to upstream with simple retries on 5xx.
    (This function remains largely the same, but uses updated helpers)
    """
    url = f"{UPSTREAM_BASE}{upstream_path}"
    origin = request.headers.get("origin") or (request.client.host if request.client else "unknown")
    ua = request.headers.get("user-agent", "-")

    headers = {
        "Content-Type": "application/json",
        "X-Forwarded-For": request.headers.get("x-forwarded-for", request.client.host if request.client else ""),
        "X-Original-Origin": origin,
        "X-Original-User-Agent": ua,
    }

    upstream_status: Optional[int] = None
    upstream_body: Any = None
    err_text: Optional[str] = None

    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
        attempts = FORWARD_RETRIES + 1
        for i in range(attempts):
            try:
                if method.upper() == "POST":
                    r = await client.post(url, json=payload, headers=headers)
                else:
                    r = await client.request(method.upper(), url, json=payload, headers=headers)
                upstream_status = r.status_code
                try:
                    upstream_body = r.json()
                except Exception:
                    upstream_body = r.text
                if r.status_code < 500:
                    break
                log.warning(f"[forward] 5xx from upstream (attempt {i+1}/{attempts}) code={r.status_code}")
            except Exception as e:
                err_text = str(e)
                log.error(f"[forward] exception on attempt {i+1}/{attempts}: {err_text}")
                if i == attempts - 1:
                    upstream_status = 599

    try:
        site_id_dbg, site_token_dbg = _get_site_identity(payload)

        evt_count = 0
        shop_dbg = None
        if isinstance(payload, dict):
            if "events" in payload and isinstance(payload["events"], list):
                evt_count = len(payload["events"])
                if payload["events"] and isinstance(payload["events"][0], dict):
                    shop_dbg = payload["events"][0].get("shop") or payload.get("shop")
            else:
                evt_count = 1
                shop_dbg = payload.get("shop")

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
            }
        )
    except Exception:
        pass

    body = {
        "ok": True,
        "forwarded_to": url,
        "upstream_status": upstream_status,
    }
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
    return {"ok": True, "service": "BaoBrain proxy", "docs": "/docs", "version": app.version}

@app.get("/health")
async def health():
    return {"status": "healthy"}

# ------------------------------------------------------------------------------
# Tracker JS (NOW USING THE REWRITE HELPER)
# ------------------------------------------------------------------------------
@app.get("/bigcommerce/sessions.js")
async def bc_sessions_js(request: Request):
    return await _proxy_and_fix_js("/bigcommerce/sessions.js", request.url.query)

@app.get("/bigcommerce/tracker.js")
async def bc_tracker_js(request: Request):
    return await _proxy_and_fix_js("/bigcommerce/tracker.js", request.url.query)

@app.get("/shopify/sessions.js")
async def shopify_sessions_js(request: Request):
    return await _proxy_and_fix_js("/shopify/sessions.js", request.url.query)

@app.get("/shopify/tracker.js")
async def shopify_tracker_js(request: Request):
    return await _proxy_and_fix_js("/shopify/tracker.js", request.url.query)

@app.get("/shopify/demographics.js")
async def shopify_demographics_js(request: Request):
    return await _proxy_and_fix_js("/shopify/demographics.js", request.url.query)

@app.get("/demographics.js")
async def demographics_js(request: Request):
    return await _proxy_and_fix_js("/demographics.js", request.url.query)

@app.get("/static/demographics.js")
async def demographics_static_js(request: Request):
    return await _proxy_and_fix_js("/static/demographics.js", request.url.query)

# ------------------------------------------------------------------------------
# Pixel loader (CRITICAL: now points directly to UPSTREAM for the bundle)
# ------------------------------------------------------------------------------
@app.get("/pixel.js")
async def pixel_js(request: Request):
    qp = dict(request.query_params)
    site_id = (qp.get("site_id") or "").strip()
    site_token = (qp.get("site_token") or "").strip()
    shop = (qp.get("shop") or "").strip()

    log.info(f"[pixel.js] Request from site_id={site_id}, token={site_token}, shop={shop}")

    if not site_token:
        log.warning("[pixel] missing site_token")
        return Response("/* missing site_token */", media_type="application/javascript", status_code=200)

    # CRITICAL FIX: Point the bundle source directly to the new backend
    tracker_src = f"{UPSTREAM_BASE.rstrip('/')}/static/tracker.bundle.js"

    js = (
        "(function(){"
        "var s=document.createElement('script');"
        "s.async=true;"
        f"s.src='{tracker_src}';"
        f"s.setAttribute('data-site-id', {repr(site_id)});"
        f"s.setAttribute('data-site-token', {repr(site_token)});"
        f"s.setAttribute('data-shop', {repr(shop)});"
        # OPTIONAL: Pass the API base for the tracker bundle to use internally
        f"s.setAttribute('data-api-base', {repr(UPSTREAM_BASE)});"
        "document.head.appendChild(s);"
        "})();"
    )

    return Response(
        content=js,
        media_type="application/javascript",
        # Use no-cache headers here too, just to be sure clients reload the loader
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
        status_code=200,
    )

@app.get("/static/tracker.bundle.js")
async def tracker_bundle_js(request: Request):
    # Use the fixer for the bundle as well, in case it contains internal URLs
    return await _proxy_and_fix_js("/static/tracker.bundle.js", request.url.query)

@app.get("/integrations/assets/ga4-loader-{site_id}.js")
async def ga4_loader_js(site_id: str, request: Request):
    return await _proxy_and_fix_js(f"/integrations/assets/ga4-loader-{site_id}.js", request.url.query)

# ------------------------------------------------------------------------------
# Event forwarding (Now includes Blocked Site ID check)
# ------------------------------------------------------------------------------
@app.options("/api/collect")
@app.options("/api/collect/batch")
async def options_preflight():
    return Response(status_code=200)

@app.post("/api/collect")
async def collect_single(request: Request):
    data = await request.json()
    
    # 1. Secret Check
    if API_SECRET and not _validate_secret(data):
        log.warning(f"[collect] UNAUTHORIZED single: Invalid secret from site_id={data.get('site_id')}")
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        
    # 2. Block Site ID Check
    if _is_blocked_site(data):
        site_id, _ = _get_site_identity(data)
        log.warning(f"[collect] BLOCKED single: site_id={site_id}")
        return JSONResponse({"ok": False, "blocked": True, "reason": "blocked site"}, status_code=403)
    
    # 3. Identity Check
    if not _has_identity(data):
        log.warning("[collect] dropped single: missing site identity")
        return JSONResponse({"ok": True, "dropped": True, "reason": "missing site identity"}, status_code=200)
        
    log.info("[collect] single event received")
    return await _forward_json("/api/collect", data, request, method="POST")

@app.post("/api/collect/batch")
async def collect_batch(request: Request):
    data = await request.json()
    events = data.get("events") if isinstance(data, dict) else []
    count = len(events) if isinstance(events, list) else 0
    
    # 1. Secret Check
    if API_SECRET and not _validate_secret(data):
        site_id, _ = _get_site_identity(data)
        log.warning(f"[collect] UNAUTHORIZED batch: Invalid secret from site_id={site_id}")
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    # 2. Block Site ID Check
    if _is_blocked_site(data):
        site_id, _ = _get_site_identity(data)
        log.warning(f"[collect] BLOCKED batch: site_id={site_id}")
        return JSONResponse({"ok": False, "blocked": True, "reason": "blocked site"}, status_code=403)

    if not count:
        log.warning("[collect] dropped batch: empty events array")
        return JSONResponse({"ok": True, "dropped": True, "reason": "empty batch"}, status_code=200)
        
    # 3. Identity Check
    if not _has_identity(data):
        log.warning("[collect] dropped batch: missing site identity")
        return JSONResponse({"ok": True, "dropped": True, "reason": "missing site identity"}, status_code=200)
    
    site_id, _ = _get_site_identity(data)
    origin = request.headers.get('origin', 'unknown')
    log.info(f"[collect] batch received events={count} site_id={site_id} origin={origin}")
    
    return await _forward_json("/api/collect/batch", data, request, method="POST")

# ------------------------------------------------------------------------------
# Diagnostics and Debugging
# ------------------------------------------------------------------------------
@app.get("/diag/forwards")
async def diag_forwards(token: Optional[str] = None):
    if DIAG_TOKEN and token != DIAG_TOKEN:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"recent": list(last_forwards)}

@app.get("/debug/inspect")
async def debug_inspect(file: str, token: Optional[str] = None):
    """Check what URLs are in the JS files from api.baobrain.com (without rewriting)."""
    if DIAG_TOKEN and token != DIAG_TOKEN:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    if file not in ["sessions.js", "tracker.js", "demographics.js", "tracker.bundle.js"]:
        return JSONResponse({"error": "specify file=sessions.js, tracker.js, demographics.js, or tracker.bundle.js"}, status_code=400)
    
    path = f"/shopify/{file}" if "shopify" in file else f"/{file}" if ".js" in file else f"/static/{file}"

    url = f"{UPSTREAM_BASE}{path}"
    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
        r = await client.get(url)
        
        if r.status_code == 200:
            content = r.text
            all_urls = re.findall(r'(https?://[^\s\'"]+)', content)
            
            return {
                "file": path,
                "upstream_url": url,
                "status": r.status_code,
                "contains_old_proxy": OLD_PROXY_URL in content,
                "contains_localhost": "localhost" in content,
                "contains_new_backend": UPSTREAM_BASE in content,
                "all_urls_found": all_urls,
                "first_1000_chars": content[:1000],
            }
        
        return JSONResponse({"error": f"Failed to fetch {url}: Status {r.status_code}"}, status_code=500)

# ------------------------------------------------------------------------------
# Dev entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=bool(os.getenv("DEV_RELOAD", "0") == "1"),
    )
