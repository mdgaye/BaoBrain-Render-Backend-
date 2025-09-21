from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import httpx
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS middleware (same as your current setup)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Forward events to your new backend
@app.post("/api/collect/batch")
async def forward_events(request: Request):
    try:
        data = await request.json()
        logger.info(f"Forwarding event data to baobrain.com backend")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.baobrain.com/api/collect/batch",
                json=data,
                timeout=30.0
            )
            
        logger.info(f"Forward response: {response.status_code}")
        return {"status": "forwarded", "code": response.status_code}
        
    except Exception as e:
        logger.error(f"Forward error: {str(e)}")
        return {"status": "error", "message": str(e)}, 500

# Serve your tracker files (keep existing functionality)
@app.get("/static/{file_path}")
async def serve_static(file_path: str):
    return FileResponse(f"static/{file_path}")

@app.get("/bigcommerce/{file_path}")
async def serve_bigcommerce(file_path: str):
    return FileResponse(f"static/{file_path}")

@app.get("/demographics.js")
async def serve_demographics():
    return FileResponse("static/demographics.js")

@app.get("/{file_path}")
async def serve_root_files(file_path: str):
    # For files served directly from root like demographics.js
    return FileResponse(f"static/{file_path}")

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))