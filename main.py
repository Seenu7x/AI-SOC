"""
Main FastAPI application
AI-SOC Anomaly Detection System - Phase 1
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import logging
import time
from pathlib import Path
from datetime import datetime

from app.core.config import get_settings
from app.core.rate_limit import RateLimitMiddleware
from app.db.session import init_db
from app.api import events, alerts, models, compliance
from app.core import auth as auth_module

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events
    """
    # Startup
    logger.info("Starting AI-SOC Anomaly Detection System")
    init_db()
    logger.info("Database initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down AI-SOC Anomaly Detection System")


# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description=settings.api_description,
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware (added after CORS so CORS headers still reach 429 responses)
app.add_middleware(RateLimitMiddleware)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests"""
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate processing time
    process_time = time.time() - start_time
    
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.3f}s"
    )
    
    # Add processing time header
    response.headers["X-Process-Time"] = str(process_time)
    
    return response


# Include routers
app.include_router(
    auth_module.router,
    tags=["Authentication"]
)

app.include_router(
    events.router,
    prefix="/api/v1/events",
    tags=["Events"]
)

app.include_router(
    alerts.router,
    prefix="/api/v1/alerts",
    tags=["Alerts"]
)

app.include_router(
    models.router,
    prefix="/api/v1/models",
    tags=["ML Models"]
)

app.include_router(
    compliance.router,
    prefix="/api/v1/compliance",
    tags=["Compliance"]
)


# ── Serve the dashboard as static files ────────────────────────────
_dashboard_dir = Path(__file__).parent / "dashboard"
if _dashboard_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(_dashboard_dir), html=True), name="dashboard")


@app.get("/ui", include_in_schema=False)
async def ui_redirect():
    """Redirect /ui to the dashboard"""
    return RedirectResponse(url="/dashboard/index.html")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": settings.api_title,
        "version": settings.api_version,
        "description": settings.api_description,
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "events": "/api/v1/events",
            "alerts": "/api/v1/alerts",
            "models": "/api/v1/models",
            "compliance": "/api/v1/compliance",
            "dashboard": "/dashboard/index.html",
            "health": "/health",
            "docs": "/docs"
        }
    }


# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring
    """
    from app.services.anomaly_detection import anomaly_service
    
    model_info = anomaly_service.get_model_info()
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "ai-soc-anomaly-detection",
        "version": settings.api_version,
        "model": {
            "loaded": model_info is not None,
            "version": model_info["model_version"] if model_info else None
        }
    }


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": type(exc).__name__,
            "timestamp": datetime.now().isoformat()
        }
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level.lower()
    )
