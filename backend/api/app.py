"""
backend/api/app.py
Master Web Server & Host for Project Fjord Agent.
Serves the modern Fjord Agent frontend from frontend/ and mounts static assets.
"""

from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from backend.api.router import router

app = FastAPI(
    title="Project Fjord: Cloud & Container Security Posture & Remediation Agent",
    description="FalkorDB Hackathon Track 1: Agents That Act on Connected Data. Posture Prioritization, Exploit Plane Compilation, Cutting-Plane ILP, and Counterfactual Sandboxing.",
    version="1.0.0",
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Mount API v1 router
app.include_router(router)

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
INDEX_HTML = FRONTEND_DIR / "index.html"

# Mount static files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def get_command_center_ui():
    """
    Renders the Fjord Agent Attack-Path Remediation Workspace.
    Serves from frontend/index.html.
    """
    if INDEX_HTML.exists():
        return HTMLResponse(content=INDEX_HTML.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Fjord Agent Frontend Not Found</h1>", status_code=404)
