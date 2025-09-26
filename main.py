import os
import time
import logging
from collections import deque
from typing import Any, Dict, Optional, List

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

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
# Set level to DEBUG for maximum output
logging.basicConfig(level=logging.getLogger().getEffectiveLevel() or logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("baobrain-proxy")
log.setLevel(logging.DEBUG) # Ensure this logger is set to DEBUG
last_forwards = deque(maxlen=DIAG_BUFFER_SIZE)  # ring buffer of recent forwards

# Target site ID to inspect (hardcoded for immediate check, but consider env var)
TARGET_SITE_ID = "22"

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


async def _forward_json(
    upstream_path: str,
    payload: Dict[str, Any],
    request: Request,
    method: str = "POST",
) -> Response:
    """
    Forward JSON to upstream with simple retries on 5xx.
    Always returns 200 to caller; upstream code is echoed in headers/diagnostics.
    """
    url = f"{UPSTREAM_BASE}{upstream_path}"
    origin = request.headers.get("origin") or (request.client.host if request.client else "unknown")
    ua = request.headers.get("user-agent", "-")

    # --- DEBUG: Log all request headers and origin info ---
    request_id = hex(int(time.time() * 1000))[2:] # Simple unique ID for the request
    log.debug(f"[{request_id}] [forward] START | URL={url} | METHOD={method}")
    log.debug(f"[{request_id}] [forward] REQUEST_ORIGIN | Host={request.client.host if request.client else 'N/A'} | OriginHeader={origin} | XFF={request.headers.get('x-forwarded-for', '-')}")
    log.debug(f"[{request_id}] [forward] REQUEST_HEADERS_SENT | Headers={dict(request.headers)}")
    # --- END DEBUG LOGGING ---

    headers = {
        "Content-Type": "application/json",
        "X-Forwarded-For": request.headers.get("x-forwarded-for", request.client.host if request.client else ""),
        "X-Original-Origin": origin,
        "X-Original-User-Agent": ua,
    }

    upstream_status: Optional[int] = None
    upstream_body: Any = None
    err_text: Optional[str] = None

    # --- DEBUG: Extract site info from payload (repeated logic for debugging context) ---
    site_token_dbg = None
    site_id_dbg = None
    shop_dbg = None
    evt_count = 0

    try:
        if isinstance(payload, dict):
            if "events" in payload and isinstance(payload["events"], list):
                evt_count = len(payload["events"])
                if payload["events"]:
                    first = payload["events"][0]
                    site_token_dbg = first.get("site_token") or payload.get("site_token")
                    site_id_dbg = first.get("site_id") or payload.get("site_id")
                    shop_dbg = first.get("shop") or payload.get("shop")
            else:
                evt_count = 1
                site_token_dbg = payload.get("site_token")
                site_id_dbg = payload.get("site_id")
                shop_dbg = payload.get("shop")

            log.info(f"[{request_id}] [forward] PAYLOAD_INFO | Count={evt_count} | SiteID={site_id_dbg} | SiteToken={site_token_dbg[:4]}... | Shop={shop_dbg}")

            # --- CRITICAL INSPECTION: Check for Target Site ID ---
            if str(site_id_dbg) == TARGET_SITE_ID:
                log.critical(f"[{request_id}] [forward] 🚨🚨 TARGET SITE {TARGET_SITE_ID} DETECTED! | Payload={payload} 🚨🚨")
            # --- END CRITICAL INSPECTION ---

    except Exception as e:
        log.error(f"[{request_id}] [forward] PAYLOAD_PARSING_ERROR | Error={e}")
        pass
    # --- END DEBUG PAYLOAD EXTRACTION ---

    async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
        attempts = FORWARD_RETRIES + 1
        for i in range(attempts):
            try:
                if method.upper() == "POST":
                    r = await client.post(url, json=payload, headers=headers)
                else:
                    r = await client.request(method.upper(), url, json=payload, headers=headers)
                
                upstream_status = r.status_code
                
                # --- DEBUG: Log response status and headers ---
                log.debug(f"[{request_id}] [forward] UPSTREAM_RESPONSE | Attempt={i+1}/{attempts} | Status={upstream_status}")
                log.debug(f"[{request_id}] [forward] UPSTREAM_RESPONSE_HEADERS | Headers={dict(r.headers)}")
                # --- END DEBUG LOGGING ---
                
                try:
                    upstream_body = r.json()
                    log.debug(f"[{request_id}] [forward] UPSTREAM_BODY_JSON | Body={upstream_body}")
                except Exception:
                    upstream_body = r.text
                    log.debug(f"[{request_id}] [forward] UPSTREAM_BODY_TEXT | Body={upstream_body[:100]}...") # Log partial body for text
                    
                if r.status_code < 500:
                    break
                log.warning(f"[{request_id}] [forward] 5xx from upstream (attempt {i+1}/{attempts}) code={r.status_code} | URL={url}")
            except Exception as e:
                err_text = str(e)
                log.error(f"[{request_id}] [forward] EXCEPTION on attempt {i+1}/{attempts}: {err_text}")
                if i == attempts - 1:
                    upstream_status = 599  # network error sentinel

    # record compact diagnostics (event count + site markers)
    # Reusing the debug-extracted variables from above
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
# Tracker JS (always proxy from upstream)
# ------------------------------------------------------------------------------
# NOTE: Removed redundant proxy_get functions for brevity, keeping only one example and the others follow the same pattern.
@app.get("/bigcommerce/sessions.js")
async def bc_sessions_js(request: Request):
    log.debug(f"[bc_sessions_js] Request received | Query={request.url.query}")
    return await _proxy_get("/bigcommerce/sessions.js", request.url.query, "text/javascript")

@app.get("/bigcommerce/tracker.js")
async def bc_tracker_js(request: Request):
    log.debug(f"[bc_tracker_js] Request received | Query={request.url.query}")
    return await _proxy_get("/bigcommerce/tracker.js", request.url.query, "text/javascript")
# ... (other proxy_get routes omitted for brevity but remain the same) ...
@app.get("/shopify/sessions.js")
async def shopify_sessions_js(request: Request):
    return await _proxy_get("/shopify/sessions.js", request.url.query, "text/javascript")

@app.get("/shopify/tracker.js")
async def shopify_tracker_js(request: Request):
    return await _proxy_get("/shopify/tracker.js", request.url.query, "text/javascript")

@app.get("/shopify/demographics.js")
async def shopify_demographics_js(request: Request):
    return await _proxy_get("/shopify/demographics.js", request.url.query, "text/javascript")

@app.get("/demographics.js")
async def demographics_js(request: Request):
    return await _proxy_get("/demographics.js", request.url.query, "text/javascript")

@app.get("/static/demographics.js")
async def demographics_static_js(request: Request):
    return await _proxy_get("/static/demographics.js", request.url.query, "text/javascript")

# ------------------------------------------------------------------------------
# Pixel loader (fixed): pass identity via data-* so bundle can read it
# ------------------------------------------------------------------------------
@app.get("/pixel.js")
async def pixel_js(request: Request):
    qp = dict(request.query_params)
    site_id = (qp.get("site_id") or "").strip()
    site_token = (qp.get("site_token") or "").strip()
    shop = (qp.get("shop") or "").strip()

    log.info(f"[pixel] loader hit | SiteID={site_id} | Shop={shop} | Query={request.url.query}")
    
    # Optional: enforce at least site_token to catch misconfigs early
    if not site_token:
        log.warning("[pixel] missing site_token")
        return Response("/* missing site_token */", media_type="application/javascript", status_code=200)

    # --- CRITICAL INSPECTION: Check for Target Site ID on loader ---
    if site_id == TARGET_SITE_ID:
        log.critical(f"[pixel] 🚨🚨 TARGET SITE {TARGET_SITE_ID} LOADER HIT! | URL={request.url} 🚨🚨")
    # --- END CRITICAL INSPECTION ---

    tracker_src = f"{UPSTREAM_BASE.rstrip('/')}/static/tracker.bundle.js"

    # Use setAttribute to generate kebab-case data-* attrs explicitly
    js = (
        "(function(){"
        "var s=document.createElement('script');"
        "s.async=true;"
        f"s.src='{tracker_src}';"
        f"s.setAttribute('data-site-id', {repr(site_id)});"
        f"s.setAttribute('data-site-token', {repr(site_token)});"
        f"s.setAttribute('data-shop', {repr(shop)});"
        "document.head.appendChild(s);"
        "})();"
    )

    log.debug(f"[pixel] JS generated and sent | Script length={len(js)}")

    return Response(
        content=js,
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=300"},
        status_code=200,
    )

@app.get("/static/tracker.bundle.js")
async def tracker_bundle_js(request: Request):
    log.debug(f"[tracker_bundle_js] Request received | Query={request.url.query}")
    return await _proxy_get("/static/tracker.bundle.js", request.url.query, "application/javascript")

@app.get("/integrations/assets/ga4-loader-{site_id}.js")
async def ga4_loader_js(site_id: str, request: Request):
    log.debug(f"[ga4_loader_js] Request received | SiteID={site_id} | Query={request.url.query}")
    # --- CRITICAL INSPECTION: Check for Target Site ID on GA4 loader ---
    if site_id == TARGET_SITE_ID:
        log.critical(f"[ga4_loader_js] 🚨🚨 TARGET SITE {TARGET_SITE_ID} GA4 LOADER HIT! 🚨🚨")
    # --- END CRITICAL INSPECTION ---
    return await _proxy_get(f"/integrations/assets/ga4-loader-{site_id}.js", request.url.query, "text/javascript")

# ------------------------------------------------------------------------------
# Event forwarding (guards missing identity to avoid default-site pollution)
# ------------------------------------------------------------------------------
@app.options("/api/collect")
@app.options("/api/collect/batch")
async def options_preflight():
    log.debug("[options] Preflight request received.")
    return Response(status_code=200)

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
                # Check within the first event for identity if not present in top-level payload
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


@app.post("/api/collect")
async def collect_single(request: Request):
    data = await request.json()
    is_valid, site_token, site_id, shop, evt_count = _get_identity_info(data)
    
    log.info(f"[collect] single request received | SiteID={site_id} | Shop={shop} | URL={request.url}")

    if not is_valid:
        log.warning(f"[collect] dropped single: missing site identity | PayloadKeys={list(data.keys())}")
        return JSONResponse({"ok": True, "dropped": True, "reason": "missing site identity"}, status_code=200)
    
    # --- CRITICAL INSPECTION: Check for Target Site ID on collect ---
    if site_id == TARGET_SITE_ID:
        log.critical(f"[collect] 🚨🚨 TARGET SITE {TARGET_SITE_ID} SINGLE EVENT! | Payload={data} 🚨🚨")
    # --- END CRITICAL INSPECTION ---
    
    return await _forward_json("/api/collect", data, request, method="POST")

@app.post("/api/collect/batch")
async def collect_batch(request: Request):
    data = await request.json()
    is_valid, site_token, site_id, shop, count = _get_identity_info(data)

    log.info(f"[collect] batch request received | Events={count} | SiteID={site_id} | Shop={shop} | URL={request.url}")

    if not count:
        log.warning("[collect] dropped batch: empty events array")
        return JSONResponse({"ok": True, "dropped": True, "reason": "empty batch"}, status_code=200)
    
    if not is_valid:
        log.warning(f"[collect] dropped batch: missing site identity | Events={count} | PayloadKeys={list(data.keys())}")
        return JSONResponse({"ok": True, "dropped": True, "reason": "missing site identity"}, status_code=200)
    
    # --- CRITICAL INSPECTION: Check for Target Site ID on batch collect ---
    if site_id == TARGET_SITE_ID:
        log.critical(f"[collect] 🚨🚨 TARGET SITE {TARGET_SITE_ID} BATCH EVENT! | Events={count} | Payload={data} 🚨🚨")
    # --- END CRITICAL INSPECTION ---
    
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
    # Make sure to run with log_level="debug" or "info" to see the output
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=bool(os.getenv("DEV_RELOAD", "0") == "1"),
        log_level="debug", # Ensure uvicorn's log level is set for visibility
    )
