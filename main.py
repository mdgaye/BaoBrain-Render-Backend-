import os
import time
import logging
from collections import deque
from typing import Any, Dict, Optional

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
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("baobrain-proxy")
last_forwards = deque(maxlen=DIAG_BUFFER_SIZE)  # ring buffer of recent forwards

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
    log.info(f"[proxy-get] {url}")
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
    Always returns 200 to caller; upstream code is echoed in headers/diagnostics.
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
                    upstream_status = 599  # network error sentinel

    # record compact diagnostics (event count + site markers)
    try:
        evt_count = 0
        site_token_dbg = None
        site_id_dbg = None
        shop_dbg = None
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
    return {"ok": True, "service": "BaoBrain proxy", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

# ------------------------------------------------------------------------------
# Tracker JS (always proxy from upstream)
# ------------------------------------------------------------------------------
@app.get("/bigcommerce/sessions.js")
async def bc_sessions_js(request: Request):
    return await _proxy_get("/bigcommerce/sessions.js", request.url.query, "text/javascript")

@app.get("/bigcommerce/tracker.js")
async def bc_tracker_js(request: Request):
    return await _proxy_get("/bigcommerce/tracker.js", request.url.query, "text/javascript")

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

    # Optional: enforce at least site_token to catch misconfigs early
    if not site_token:
        log.warning("[pixel] missing site_token")
        return Response("/* missing site_token */", media_type="application/javascript", status_code=200)

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

    return Response(
        content=js,
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=300"},
        status_code=200,
    )

@app.get("/static/tracker.bundle.js")
async def tracker_bundle_js(request: Request):
    return await _proxy_get("/static/tracker.bundle.js", request.url.query, "application/javascript")

@app.get("/integrations/assets/ga4-loader-{site_id}.js")
async def ga4_loader_js(site_id: str, request: Request):
    return await _proxy_get(f"/integrations/assets/ga4-loader-{site_id}.js", request.url.query, "text/javascript")

# ------------------------------------------------------------------------------
# Event forwarding (guards missing identity to avoid default-site pollution)
# ------------------------------------------------------------------------------
@app.options("/api/collect")
@app.options("/api/collect/batch")
async def options_preflight():
    return Response(status_code=200)

def _has_identity(d: Dict[str, Any]) -> bool:
    if not isinstance(d, dict):
        return False
    if d.get("site_token") or d.get("site_id"):
        return True
    evs = d.get("events")
    if isinstance(evs, list) and evs:
        first = evs[0]
        if isinstance(first, dict) and (first.get("site_token") or first.get("site_id")):
            return True
    return False

@app.post("/api/collect")
async def collect_single(request: Request):
    data = await request.json()
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
    if not count:
        log.warning("[collect] dropped batch: empty events array")
        return JSONResponse({"ok": True, "dropped": True, "reason": "empty batch"}, status_code=200)
    if not _has_identity(data):
        log.warning("[collect] dropped batch: missing site identity")
        return JSONResponse({"ok": True, "dropped": True, "reason": "missing site identity"}, status_code=200)
    log.info(f"[collect] batch received events={count}")
    return await _forward_json("/api/collect/batch", data, request, method="POST")

# ------------------------------------------------------------------------------
# Diagnostics
# ------------------------------------------------------------------------------
@app.get("/diag/forwards")
async def diag_forwards(token: Optional[str] = None):
    if DIAG_TOKEN and token != DIAG_TOKEN:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"recent": list(last_forwards)}

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
