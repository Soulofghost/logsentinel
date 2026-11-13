import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.database import init_db
from app.routers import logs, alerts

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="LogSentinel SIEM & Threat Analysis Platform",
    description="Security Information and Event Management (SIEM) log correlation and intrusion detection engine.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")

@app.get("/api/v1/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "LogSentinel SIEM Engine",
        "version": "1.0.0",
        "mitre_framework": "ATT&CK v14.1"
    }

# Static files
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
