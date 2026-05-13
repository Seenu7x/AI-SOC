"""
Rate Limiting Middleware for AI-SOC
=====================================
In-memory sliding-window rate limiter — no Redis required.

Limits:
  /auth/*  and  /health   →  20 requests / minute  per IP
  /api/*                  → 300 requests / minute  per IP
  everything else         → 60  requests / minute  per IP

Returns HTTP 429 with Retry-After header when a client exceeds its quota.
"""
import time
import threading
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


# (max_requests, window_seconds) per route prefix
RATE_LIMITS: list[Tuple[str, int, int]] = [
    ("/auth",   20,  60),   # login attempts — tight
    ("/health", 60,  60),   # health polling — relaxed
    ("/api",    300, 60),   # API (dashboard + bulk log posts)
]
DEFAULT_LIMIT = (60, 60)    # fallback for all other paths


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter.

    Each entry in _windows is a deque of request timestamps (float).
    Old timestamps outside the current window are pruned on each request.
    """

    def __init__(self, app):
        super().__init__(app)
        # key → deque of timestamps
        self._windows: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _get_limit(self, path: str) -> Tuple[int, int]:
        for prefix, max_req, window in RATE_LIMITS:
            if path.startswith(prefix):
                return max_req, window
        return DEFAULT_LIMIT

    def _client_ip(self, request: Request) -> str:
        # Respect X-Forwarded-For when behind Nginx
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        ip = self._client_ip(request)
        path = request.url.path
        max_req, window = self._get_limit(path)

        key = f"{ip}:{path.split('/')[1]}"   # group by top-level prefix
        now = time.monotonic()

        with self._lock:
            dq = self._windows[key]
            # Prune timestamps outside the window
            cutoff = now - window
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= max_req:
                oldest = dq[0]
                retry_after = int(window - (now - oldest)) + 1
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Please slow down.",
                        "retry_after_seconds": retry_after,
                    },
                    headers={"Retry-After": str(retry_after)},
                )

            dq.append(now)

        return await call_next(request)
