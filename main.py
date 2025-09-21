from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
import httpx
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NEW_BACKEND = os.getenv("NEW_BACKEND", "https://api.baobrain.com")

app = FastAPI(title="BaoBrain Proxy")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ---- Simple home + health ----
@app.get("/")
async def home():
    return {"ok": True, "service": "BaoBrain proxy", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

# ---- Track endpoints (both batch and non-batch) ----
@app.post("/api/collect")
async def forward_collect(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = await request.body()
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(f"{NEW_BACKEND}/api/collect", json=payload if isinstance(payload, dict) else None, content=None if isinstance(payload, dict) else payload)
    return JSONResponse(status_code=r.status_code, content=(r.json() if r.headers.get("content-type","").startswith("application/json") else {"status": r.status_code}))

@app.post("/api/collect/batch")
async def forward_collect_batch(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = await request.body()
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(f"{NEW_BACKEND}/api/collect/batch", json=payload if isinstance(payload, dict) else None, content=None if isinstance(payload, dict) else payload)
    return JSONResponse(status_code=r.status_code, content=(r.json() if r.headers.get("content-type","").startswith("application/json") else {"status": r.status_code}))

# ---- Static proxy (no need to ship files here) ----
@app.get("/static/{path:path}")
async def proxy_static(path: str):
    url = f"{NEW_BACKEND}/static/{path}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(url)
    return Response(content=r.content, status_code=r.status_code, headers={"content-type": r.headers.get("content-type","application/octet-stream")})

# BigCommerce tracker path compatibility
@app.get("/bigcommerce/{path:path}")
async def proxy_bc_static(path: str):
    url = f"{NEW_BACKEND}/bigcommerce/{path}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(url)
    return Response(content=r.content, status_code=r.status_code, headers={"content-type": r.headers.get("content-type","application/octet-stream")})

# Root-served files compatibility (e.g., /demographics.js)
@app.get("/{file}.js")
async def proxy_root_js(file: str):
    url = f"{NEW_BACKEND}/{file}.js"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(url)
    return Response(content=r.content, status_code=r.status_code, headers={"content-type": r.headers.get("content-type","application/javascript")})

# ---- Optional: catch-all proxy for other API routes ----
@app.api_route("/api/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
async def proxy_api(path: str, request: Request):
    target = f"{NEW_BACKEND}/api/{path}"
    method = request.method
    headers = dict(request.headers)
    # strip hop-by-hop headers
    for h in ["host", "content-length", "connection", "accept-encoding", "x-forwarded-for", "x-forwarded-proto"]:
        headers.pop(h, None)
    body = await request.body()
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.request(method, target, headers=headers, content=body)
    return Response(content=r.content, status_code=r.status_code, headers={"content-type": r.headers.get("content-type","application/octet-stream")})

if __name__ == "__main__":
    import uvicorn, os
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
