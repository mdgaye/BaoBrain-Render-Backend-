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
# ⚠️ CRITICAL DEBUG NOTE: If other sites are not forwarding, check this ENV VAR!
BLOCKED_SITE_IDS = {s.strip() for s in os.getenv("BLOCKED_SITE_IDS", "").split(",") if s.strip()}
# -----------------------

# === Legacy host hard kill ===
LEGACY_HOST = os.getenv("LEGACY_HOST", "bao-api.onrender.com")
# EDITED: Default changed to "0" (off) for safe migration
NUKE_OLD_HOST = os.getenv("NUKE_OLD_HOST", "0") == "1"
NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

# Bot UA Guard
BOT_UA_PAT = re.compile(r"(googlebot|bingbot|baiduspider|yandex|duckduckbot)", re.I)

# 2) Normalized Domain Map (Domains, Shopify hashes, and BigCommerce hashes)
# EDITED: Updated SITE_URL_MAP with new BigCommerce domains (site IDs 8, 12, 19, 27).
SITE_URL_MAP = {
    "1":  ["tt65d.myshopify.com"],
    "6":  ["baobrain.test.com"],
    "8":  ["2fdxrvrqqc", "baobrain-r7.mybigcommerce.com"],
    "12": ["koftpobuae", "store-koftpobuae.mybigcommerce.com"],
    "16": ["baobrain.com"],
    "17": ["versare.com", "bcwxdbhdjm"],
    "18": ["mavoli.com", "prtidrdund"],
    "19": ["js3ghti4c3", "store-js3ghti4c3.mybigcommerce.com"],
    "21": ["gandjbaby.co.uk", "al8xm9uqyn"],
    "22": ["kiwla.com", "ilgxsy4t82"],
    "24": ["baobraintest.myshopify.com"],
    "26": ["bbtesr.myshopify.com"],
    "27": ["eywisirpku", "test3.mybigcommerce.com"],
}
# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logging.basicConfig(level=logging.getLogger().getEffectiveLevel() or logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("baobrain-proxy")
log.setLevel(logging.DEBUG) # Enforce DEBUG level for max logs
last_forwards = deque(maxlen=DIAG_BUFFER_SIZE)

# FIX 3a: Target site ID is used only for enhanced logging (as int)
TARGET_SITE_ID = 22
log.debug(f"[config] UPSTREAM_BASE={UPSTREAM_BASE}, FORWARD_TIMEOUT={FORWARD_TIMEOUT}")
log.debug(f"[config] LEGACY_HOST={LEGACY_HOST}, NUKE_OLD_HOST={NUKE_OLD_HOST}")
log.debug(f"[config] Blocked Site IDs: {BLOCKED_SITE_IDS}")
log.debug(f"[config] Target Debug Site: {TARGET_SITE_ID}")
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
log.debug("[startup] FastAPI app initialized with CORS middleware.")

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

# === Host Kill Helpers ===
def _is_legacy_host(request: Request) -> bool:
    host = (request.headers.get("host") or "").lower()
    is_legacy = NUKE_OLD_HOST and LEGACY_HOST and host == LEGACY_HOST
    log.debug(f"[legacy_check] Host: {host}, Is Legacy: {is_legacy}")
    return is_legacy

def _is_bot(request: Request) -> bool:
    ua = request.headers.get("user-agent", "")
    is_bot = bool(BOT_UA_PAT.search(ua))
    log.debug(f"[bot_check] User-Agent: {ua[:50]}..., Is Bot: {is_bot}")
    return is_bot

# === Security / Validation Helpers ===
def _is_blocked_site_id(site_id: Optional[str]) -> bool:
    """Checks if a site ID (string) is in the environment-configured block list."""
    is_blocked = site_id is not None and site_id in BLOCKED_SITE_IDS
    log.debug(f"[block_check] Site ID: {site_id} (Checking against {BLOCKED_SITE_IDS}), Is Blocked: {is_blocked}")
    return is_blocked

def _validate_secret(d: Dict[str, Any]) -> bool:
    log.debug("[secret_check] Placeholder secret validation returning True.")
    # This is still a no-op placeholder as API_SECRET logic wasn't fully defined
    return True

def _get_site_identity(d: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    # Tries to extract site_id and site_token from top level or first event
    site_id_raw = d.get("site_id")
    site_token = d.get("site_token")
    log.debug(f"[_get_site_identity] Initial: site_id={site_id_raw}, site_token={site_token}")
    if isinstance(d, dict) and "events" in d and isinstance(d["events"], list) and d["events"]:
        first = d["events"][0]
        site_id_raw = site_id_raw or first.get("site_id")
        site_token = site_token or first.get("site_token")
        log.debug(f"[_get_site_identity] From first event: site_id={site_id_raw}, site_token={site_token}")
    
    # We must normalize to string here because we are only extracting identity info
    final_site_id = str(site_id_raw) if site_id_raw else None
    final_site_token = str(site_token) if site_token else None
    log.debug(f"[_get_site_identity] Final extracted: site_id={final_site_id}, site_token={final_site_token}")
    return final_site_id, final_site_token

def _has_identity(d: Dict[str, Any]) -> bool:
    site_id, site_token = _get_site_identity(d)
    has_identity = site_id is not None or site_token is not None
    log.debug(f"[_has_identity] Result: {has_identity}")
    return has_identity

def _get_identity_info(d: Dict[str, Any]) -> tuple[bool, Optional[str], Optional[Any], Optional[str], int]:
    # Extracts identity info and event count for logging/guarding (retained for logs)
    is_valid, site_token, site_id_raw, shop, evt_count = False, None, None, None, 0
    if not isinstance(d, dict):
        log.debug("[_get_identity_info] Input not a dict.")
        return is_valid, site_token, site_id_raw, shop, evt_count
    
    # site_id will be whatever type it is in the payload (str or int or None)
    site_token = d.get("site_token")
    site_id_raw = d.get("site_id")
    shop = d.get("shop")
    evs = d.get("events")
    
    log.debug(f"[_get_identity_info] Payload fields: site_id={site_id_raw}, site_token={site_token}, shop={shop}")

    if isinstance(evs, list):
        evt_count = len(evs)
        if evs and isinstance(evs[0], dict):
              # check first event for overrides
              site_token = site_token or evs[0].get("site_token")
              site_id_raw = site_id_raw or evs[0].get("site_id")
              shop = shop or evs[0].get("shop")
              log.debug(f"[_get_identity_info] After first event override: site_id={site_id_raw}, site_token={site_token}, shop={shop}")

    if site_id_raw or site_token:
        is_valid = True
        if evt_count == 0 and not isinstance(evs, list):
             evt_count = 1 # single event
             log.debug("[_get_identity_info] Assumed single event.")

    final_site_token = str(site_token) if site_token else None
    # site_id_raw can now be an int or None/str if it was overwritten by _overwrite_site_id
    final_site_id = site_id_raw
    final_shop = str(shop) if shop else None
    
    log.debug(f"[_get_identity_info] Final: Valid={is_valid}, SiteID={final_site_id}, Shop={final_shop}, Count={evt_count}")
    return is_valid, final_site_token, final_site_id, final_shop, evt_count

# 3) Resolver helpers
def _normalize_host(host: Optional[str]) -> Optional[str]:
    """Normalize host (lowercase, strip 'www.') for map comparison."""
    if not host:
        log.debug("[_normalize_host] Host is None/empty.")
        return None
    
    original_host = host
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    log.debug(f"[_normalize_host] Original: {original_host}, Normalized: {host}")
    return host

def _host_from_headers(headers: dict) -> Optional[str]:
    """Extract authoritative host from Origin or Referer headers."""
    origin = headers.get("origin")
    referer = headers.get("referer")
    host = None
    
    log.debug(f"[_host_from_headers] Origin: {origin}, Referer: {referer}")

    try:
        if origin:
            host = urlparse(origin).hostname
            log.debug(f"[_host_from_headers] Host from Origin: {host}")
        if not host and referer:
            host = urlparse(referer).hostname
            log.debug(f"[_host_from_headers] Host from Referer: {host}")
    except Exception as e:
        log.error(f"[_host_from_headers] EXCEPTION during URL parse: {e}")
        host = None
    
    final_host = _normalize_host(host)
    log.debug(f"[_host_from_headers] Final normalized host: {final_host}")
    return final_host

def _host_from_payload(payload: dict) -> Optional[str]:
    """Extract authoritative host from 'shop' or 'url' fields in payload."""
    shop = payload.get("shop")
    log.debug(f"[_host_from_payload] Initial shop: {shop}")
    
    if not shop and isinstance(payload.get("events"), list) and payload["events"]:
        shop = payload["events"][0].get("shop")
        log.debug(f"[_host_from_payload] Shop from first event: {shop}")

    if isinstance(shop, str) and shop:
        normalized_shop_host = _normalize_host(shop)
        log.debug(f"[_host_from_payload] Host from 'shop' field: {normalized_shop_host}")
        return normalized_shop_host

    # fallback: take host from any event.url / full_url
    evs = payload.get("events")
    if isinstance(evs, list):
        log.debug(f"[_host_from_payload] Checking {len(evs)} events for URL fallback.")
        for i, ev in enumerate(evs):
            if isinstance(ev, dict):
                u = ev.get("url") or ev.get("full_url")
                if not u:
                    log.debug(f"[_host_from_payload] Event {i} has no URL.")
                    continue
                try:
                    h = urlparse(u).hostname
                    if h:
                        normalized_host = _normalize_host(h)
                        log.debug(f"[_host_from_payload] Host from event {i} URL: {normalized_host}")
                        return normalized_host
                except Exception as e:
                    log.warning(f"[_host_from_payload] EXCEPTION parsing URL in event {i}: {e}")
                    pass
    log.debug("[_host_from_payload] No host found in payload.")
    return None

def _resolve_site_id_from_maps(payload: dict, headers: dict) -> Optional[str]:
    """Resolves the correct site_id (string) based on domain matching in headers/payload."""
    log.debug("[resolver] Starting site_id resolution.")
    
    # 1) try by payload/headers host
    payload_host = _host_from_payload(payload)
    header_host = _host_from_headers(headers)
    host = payload_host or header_host
    log.debug(f"[resolver] Candidate hosts: Payload={payload_host}, Header={header_host}, Used={host}")
    
    host_candidates: List[str] = []
    if host:
        host_candidates.append(host)

    # 2) Also include any shop hash from payload as a candidate (it's normalized in _host_from_payload)
    shop_from_payload = payload.get("shop")
    if isinstance(shop_from_payload, str) and len(shop_from_payload) < 20 and shop_from_payload not in host_candidates: # Short string is likely a hash
        host_candidates.append(shop_from_payload.lower())
        log.debug(f"[resolver] Added shop hash as candidate: {shop_from_payload.lower()}")
    
    for candidate in host_candidates:
        for sid, domains in SITE_URL_MAP.items():
            normalized_domains = {d.lower() for d in domains}
            log.debug(f"[resolver] Checking site_id {sid} against domains: {normalized_domains}")
            if candidate in normalized_domains:
                log.info(f"[resolver] ✅ Resolved site_id={sid} via domain match: {candidate}")
                return sid
    
    log.warning(f"[resolver] Could not resolve site_id from host candidates: {host_candidates}")
    # 3) fallback: site_token exact match map (skipped, as no TOKEN_TO_SITEID map was provided)
    return None

# FIX 1: Implement int coercion for site_id before writing to payload
def _overwrite_site_id(payload: dict, site_id: str) -> bool:
    """
    Overwrites the site_id in the payload and all contained events.
    The resolved site_id (str) is coerced to an int for upstream compatibility.
    Returns True if successful, False if coercion failed (e.g., site_id is not a number).
    """
    try:
        # Coerce the string site_id to an integer
        sid = int(site_id)
    except (TypeError, ValueError):
        # if we somehow got a bad value, log and do not proceed with overwrite
        log.error(f"[_overwrite_site_id] Invalid site_id '{site_id}' (not coercible to int).")
        return False

    original_sid = payload.get("site_id")
    payload["site_id"] = sid
    log.info(f"[_overwrite_site_id] Payload site_id overwritten from {original_sid} to {sid} (as int)")
    
    evs = payload.get("events")
    if isinstance(evs, list):
        log.debug(f"[_overwrite_site_id] Overwriting site_id in {len(evs)} events.")
        for i, ev in enumerate(evs):
            if isinstance(ev, dict):
                original_ev_sid = ev.get("site_id")
                ev["site_id"] = sid
                if original_ev_sid != sid:
                    log.debug(f"[_overwrite_site_id] Event {i} site_id changed from {original_ev_sid} to {sid}")
            else:
                log.warning(f"[_overwrite_site_id] Event {i} is not a dict: {type(ev)}")
    
    return True

# FIX 2: Coerce site_id back to string before looking up in SITE_URL_MAP
def _validate_site_origin_strict(site_id: Any, request: Request, payload: Dict[str, Any]) -> bool:
    """Stricter validation that rejects if no domain is mapped or found."""
    # Ensure site_id is treated as a string for SITE_URL_MAP lookup
    site_id_str = str(site_id) if site_id is not None else None
    log.debug(f"[validate_origin] Starting strict check for resolved site_id={site_id_str} (as string for map lookup)")
    
    if not site_id_str:
        log.error("[validate_origin] Rejecting due to missing site_id after resolution.")
        return False  # should not happen if called after resolution

    # FIX 2: Use str(site_id) for map lookup
    allowed = set(d.lower() for d in SITE_URL_MAP.get(site_id_str, []))
    log.debug(f"[validate_origin] Allowed domains for {site_id_str}: {sorted(allowed)}")
    
    if not allowed:
        log.warning(f"[validate_origin] REJECTED site_id={site_id_str}: No allowed domains configured in SITE_URL_MAP.")
        return False  # if we have no allowed domains configured, reject

    candidate_hosts = list(filter(None, [
        _host_from_payload(payload),
        _host_from_headers(request.headers),
    ]))
    log.debug(f"[validate_origin] Candidate hosts for validation: {candidate_hosts}")

    for candidate in candidate_hosts:
        if candidate in allowed:
            log.info(f"[validate_origin] ✅ ACCEPTED site_id={site_id_str} via domain match: {candidate}")
            return True

    log.warning(f"[validate_origin] ❌ REJECTED site_id={site_id_str} | No candidate host matched allowed: {sorted(allowed)}")
    return False

# === Proxy Helpers (Kept from previous version) ===
# EDITED: Changed default media_type to application/javascript for ORB safety
async def _proxy_get(path: str, query_string: str = "", media_type: str = "application/javascript") -> Response:
    full_path = f"{path}?{query_string}" if query_string else path
    url = f"{UPSTREAM_BASE}{full_path}"
    log.info(f"[proxy-get] START | URL={url}")
    
    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
            r = await client.get(url)
            log.info(f"[proxy-get] END | Status={r.status_code} | URL={url}")
        
        # EDITED: Ensure content is non-empty and set correct Content-Type for JS
        content = r.content if r.content else b"/* empty upstream */"
        
        headers = dict(NO_CACHE)
        headers["X-Upstream-URL"] = url
        # Overwrite cache control for GETs that are meant to be cached (like JS)
        if media_type == "text/javascript" or media_type == "application/javascript":
             headers["Cache-Control"] = "public, max-age=300"
        
        # RESTORED: Response return block
        return Response(
            content=content, media_type=media_type, status_code=r.status_code,
            headers=headers,
        )
    except httpx.TimeoutException:
        log.error(f"[proxy-get] TIMEOUT | URL={url}")
        return Response(f"/* Proxy Error: Timeout */", media_type=media_type, status_code=504)
    except httpx.HTTPError as e:
        log.error(f"[proxy-get] HTTP_ERROR | URL={url} | ERROR={e}")
        return Response(f"/* Proxy Error: HTTP Error {e} */", media_type=media_type, status_code=500)
    except Exception as e:
        log.error(f"[proxy-get] UNEXPECTED EXCEPTION | URL={url} | ERROR={e}", exc_info=True)
        return Response(f"/* Proxy Error: {e} */", media_type=media_type, status_code=500)

async def _proxy_and_fix_js(path: str, query_string: str) -> Response:
    log.debug(f"[_proxy_and_fix_js] Path: {path}, Query: {query_string}")
    return await _proxy_get(path, query_string, "application/javascript")

async def _forward_json(
    upstream_path: str,
    payload: Dict[str, Any],
    request: Request,
    method: str = "POST",
) -> Response:
    url = f"{UPSTREAM_BASE}{upstream_path}"
    origin = request.headers.get("origin") or (request.client.host if request.client else "unknown")
    ua = request.headers.get("user-agent", "-")
    request_id = hex(int(time.time() * 1000))[2:]

    # Identity info is retrieved here, after the site_id has been coerced to int
    is_valid, site_token_dbg, site_id_dbg, shop_dbg, evt_count = _get_identity_info(payload)
    
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    log.info(f"[{request_id}] [forward] START | Method={method} | Path={upstream_path} | IP={client_ip} | Origin={origin}")
    log.debug(f"[{request_id}] [forward] PAYLOAD_INFO | Count={evt_count} | SiteID={site_id_dbg} (Overwritten) | Shop={shop_dbg} | Token={site_token_dbg}")

    # FIX 3b: Check target site ID as int (or safely cast to int) - This is for LOGGING ONLY
    try:
        if site_id_dbg is not None and int(site_id_dbg) == TARGET_SITE_ID:
            log.critical(f"[{request_id}] [forward] 🚨🚨 TARGET SITE {TARGET_SITE_ID} DETECTED! | Payload={payload} 🚨🚨")
    except (TypeError, ValueError):
        pass

    upstream_status = 599
    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT) as client:
            headers = {
                "Content-Type": "application/json",
                # Pass client IP for better upstream logging/analytics
                "X-Forwarded-For": client_ip,
                # Optionally pass User-Agent or Origin
                "User-Agent": ua,
                "Origin": origin,
            }
            log.debug(f"[{request_id}] [forward] HTTPX Headers: {headers}")
            
            r = await client.post(url, json=payload, headers=headers)
            upstream_status = r.status_code
            log.info(f"[{request_id}] [forward] HTTPX SUCCESS | Upstream Status={upstream_status}")
            
            # Record in diagnostics buffer
            last_forwards.appendleft({
                "ts": time.time(),
                "rid": request_id,
                "sid": site_id_dbg,
                "count": evt_count,
                "status": upstream_status,
                "url": url,
            })
            
    except httpx.TimeoutException:
        log.error(f"[{request_id}] [forward] TIMEOUT | URL={url}")
        upstream_status = 504
    except httpx.ConnectError as e:
        log.error(f"[{request_id}] [forward] CONNECT_ERROR | URL={url} | ERROR={e}")
        upstream_status = 503
    except httpx.HTTPError as e:
        log.error(f"[{request_id}] [forward] HTTP_ERROR | URL={url} | ERROR={e}")
        upstream_status = 500
    except Exception as e:
        log.error(f"[{request_id}] [forward] UNEXPECTED_EXCEPTION | URL={url} | ERROR={e}", exc_info=True)
        upstream_status = 599

    log.info(f"[{request_id}] [forward] END | Final Status={upstream_status}")
    
    # Return 200 even if upstream failed (client side wants success acknowledgement)
    return JSONResponse({"ok": True, "forwarded_to": url, "upstream_status": upstream_status, "request_id": request_id}, status_code=200)

# ------------------------------------------------------------------------------
# Root + health
# ------------------------------------------------------------------------------
@app.get("/")
async def root():
    log.debug("[root] root endpoint accessed.")
    return {"ok": True, "service": "BaoBrain proxy"}

@app.get("/health")
async def health():
    log.debug("[health] health check accessed.")
    return {"status": "healthy"}

# ------------------------------------------------------------------------------
# Tracker JS and Pixel Loader (REDIRECT/PROXY LOGIC) - EDITED
# ------------------------------------------------------------------------------
@app.get("/bigcommerce/sessions.js")
@app.get("/bigcommerce/tracker.js")
@app.get("/shopify/sessions.js")
@app.get("/shopify/tracker.js")
@app.get("/shopify/demographics.js")
@app.get("/demographics.js")
@app.get("/static/demographics.js")
@app.get("/pixel.js")
# ADDED: The missing GA4 loader path
@app.get("/integrations/assets/ga4-loader-1.js")
async def legacy_js(request: Request):
    path = request.url.path
    query = request.url.query
    log.info(f"[js_loader] START | Path={path}")
    
    # EDITED: Legacy host check now triggers a redirect, not a hard-kill (410)
    if _is_legacy_host(request):
        log.info(f"[js_loader] Legacy host detected. Redirecting JS: {path}")
        # OPTION A: 302 redirect to new host’s equivalent JS
        upstream_js = f"{UPSTREAM_BASE.rstrip('/')}{path}"
        if query:
            upstream_js += f"?{query}"
        
        # Use short cache max-age (300s) to help traffic migrate faster
        return Response(
            status_code=302,
            headers={
                "Location": upstream_js,
                # Set a short cache max-age to ensure browsers update quickly
                "Cache-Control": "public, max-age=300",
            },
            media_type="application/javascript",
            content=b"// redirecting to new tracker\n",
        )
        
    # Non-legacy host: proxy or generate dynamic pixel loader
    if path == "/pixel.js":
        log.debug("[js_loader] Handling /pixel.js loader logic for new host.")
        qp = dict(request.query_params)
        site_id = (qp.get("site_id") or "").strip()
        site_token = (qp.get("site_token") or "").strip()
        shop = (qp.get("shop") or "").strip()

        tracker_src = f"{UPSTREAM_BASE.rstrip('/')}/static/tracker.bundle.js"
        log.debug(f"[js_loader] Injecting tracker src: {tracker_src}")
        
        js = (
            "(function(){var s=document.createElement('script');s.async=true;"
            f"s.src='{tracker_src}';"
            f"s.setAttribute('data-site-id',{repr(site_id)});"
            f"s.setAttribute('data-api-base',{repr(UPSTREAM_BASE)});"
            f"s.setAttribute('data-shop',{repr(shop)});"
            "document.head.appendChild(s);})();"
        )
        return Response(js, media_type="application/javascript", headers=NO_CACHE, status_code=200)
    
    log.debug(f"[js_loader] Proxying JS path: {path}")
    return await _proxy_and_fix_js(path, query)

# ------------------------------------------------------------------------------
# Event forwarding (AUTHORITATIVE RESOLUTION & BLOCKING) - EDITED
# ------------------------------------------------------------------------------
@app.options("/api/collect")
@app.options("/api/collect/batch")
async def options_preflight(request: Request):
    log.debug(f"[options] Preflight request received for {request.url.path}")
    return Response(status_code=200, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400",
    })

@app.post("/api/collect")
async def collect_single(request: Request):
    log.info("[collect] START single event processing.")
    
    try:
        data = await request.json()
        if not isinstance(data, dict):
            data = {}
            log.warning("[collect] Invalid JSON payload type (not dict).")
    except Exception as e:
        data = {}
        log.error(f"[collect] Failed to parse JSON payload: {e}")

    # 4) Use the resolver
    resolved_sid = _resolve_site_id_from_maps(data, request.headers)
    
    if not resolved_sid:
        log.warning("[collect] dropped: unknown site (no domain/token match).")
        return JSONResponse({"ok": True, "dropped": True, "reason": "unknown site"}, status_code=200)
    
    # FIX 4: Validate at the boundary/Check int coercion before proceeding
    try:
        site_id_int = int(resolved_sid)
    except (TypeError, ValueError):
        log.warning(f"[collect] invalid resolved site_id '{resolved_sid}' (not int); dropping.")
        return JSONResponse({"ok": True, "dropped": True, "reason": "invalid resolved site_id"}, status_code=200)

    # 🛑 CRITICAL CHECK: The reason other sites are not forwarding is likely here.
    if _is_blocked_site_id(resolved_sid): 
        log.critical(f"[collect] BLOCKED site_id={resolved_sid} (Blocklist) 🛑 CHECK ENV VAR: BLOCKED_SITE_IDS")
        return JSONResponse({"ok": False, "blocked": True, "reason": "blocked site"}, status_code=403)
    
    # Overwrite ANY client-provided site_id with the resolved one (coerced to int)
    if not _overwrite_site_id(data, resolved_sid):
        return JSONResponse({"ok": True, "dropped": True, "reason": "internal site_id error"}, status_code=200)

    site_id_str = resolved_sid 

    # EDITED: Stricter origin check is skipped on legacy host for migration safety
    is_legacy = _is_legacy_host(request)
    if not is_legacy:
        # Pass the string version for map lookup validation
        if not _validate_site_origin_strict(site_id_str, request, data):
            log.warning(f"[collect] BLOCKED single: invalid origin for resolved site_id={site_id_str}")
            return JSONResponse({"ok": False, "blocked": True, "reason": "invalid origin"}, status_code=403)
    else:
        # On legacy host during migration, log & allow (pass-through mode)
        log.info(f"[collect] legacy host pass-through accepted for site_id={site_id_str}")


    if API_SECRET and not _validate_secret(data):
        log.warning(f"[collect] UNAUTHORIZED single (bad secret) site_id={site_id_str}")
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    
    log.info(f"[collect] forwarding single event to resolved site_id={site_id_str}")
    return await _forward_json("/api/collect", data, request, method="POST")

@app.post("/api/collect/batch")
async def collect_batch(request: Request):
    log.info("[collect-batch] START batch event processing.")
    
    try:
        data = await request.json()
        if not isinstance(data, dict):
            data = {}
            log.warning("[collect-batch] Invalid JSON payload type (not dict).")
    except Exception as e:
        data = {}
        log.error(f"[collect-batch] Failed to parse JSON payload: {e}")

    events = data.get("events") if isinstance(data, dict) else []
    count = len(events)
    log.debug(f"[collect-batch] Initial event count: {count}")
    
    # 4) Use the resolver
    resolved_sid = _resolve_site_id_from_maps(data, request.headers)
    
    if not resolved_sid:
        log.warning("[collect-batch] dropped: unknown site (no domain/token match).")
        return JSONResponse({"ok": True, "dropped": True, "reason": "unknown site"}, status_code=200)
    
    # FIX 4: Validate at the boundary/Check int coercion before proceeding
    try:
        site_id_int = int(resolved_sid)
    except (TypeError, ValueError):
        log.warning(f"[collect-batch] invalid resolved site_id '{resolved_sid}' (not int); dropping.")
        return JSONResponse({"ok": True, "dropped": True, "reason": "invalid resolved site_id"}, status_code=200)

    # 🛑 CRITICAL CHECK: The reason other sites are not forwarding is likely here.
    if _is_blocked_site_id(resolved_sid):
        log.critical(f"[collect-batch] BLOCKED site_id={resolved_sid} (Blocklist) 🛑 CHECK ENV VAR: BLOCKED_SITE_IDS")
        return JSONResponse({"ok": False, "blocked": True, "reason": "blocked site"}, status_code=403)
    
    # Overwrite ANY client-provided site_id with the resolved one (coerced to int)
    if not _overwrite_site_id(data, resolved_sid):
        return JSONResponse({"ok": True, "dropped": True, "reason": "internal site_id error"}, status_code=200)

    site_id_str = resolved_sid
    
    # EDITED: Stricter origin check is skipped on legacy host for migration safety
    is_legacy = _is_legacy_host(request)
    if not is_legacy:
        # Pass the string version for map lookup validation
        if not _validate_site_origin_strict(site_id_str, request, data):
            log.warning(f"[collect-batch] BLOCKED batch: invalid origin for resolved site_id={site_id_str}")
            return JSONResponse({"ok": False, "blocked": True, "reason": "invalid origin"}, status_code=403)
    else:
        # On legacy host during migration, log & allow (pass-through mode)
        log.info(f"[collect-batch] legacy host pass-through accepted for site_id={site_id_str}")

    if API_SECRET and not _validate_secret(data):
        log.warning(f"[collect-batch] UNAUTHORIZED (bad secret) site_id={site_id_str}")
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    if not count:
        log.warning("[collect-batch] dropped: empty events array.")
        return JSONResponse({"ok": True, "dropped": True, "reason": "empty batch"}, status_code=200)
    
    origin = request.headers.get('origin', 'unknown')
    log.info(f"[collect-batch] forwarding events={count} to resolved site_id={site_id_str} origin={origin}")

    return await _forward_json("/api/collect/batch", data, request, method="POST")

# ------------------------------------------------------------------------------
# Diagnostics
# ------------------------------------------------------------------------------
@app.get("/diag/forwards")
async def diag_forwards(token: Optional[str] = None):
    log.debug("[diag_forwards] Diagnostics accessed.")
    if DIAG_TOKEN and token != DIAG_TOKEN:
        log.warning("[diag_forwards] Unauthorized access attempt.")
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    log.info(f"[diag_forwards] Returning {len(last_forwards)} recent forward logs.")
    return {"recent": list(last_forwards)}

# ------------------------------------------------------------------------------
# Dev entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    log.info("Starting Uvicorn server in debug mode.")
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True, log_level="debug")
