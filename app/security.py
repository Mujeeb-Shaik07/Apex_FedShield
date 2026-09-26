"""
Basic security headers middleware.

NOTE: These headers reduce certain classes of browser-based attacks
(MIME-type sniffing, clickjacking via framing, referrer leakage) but do
NOT by themselves make the application secure - see README.md
"Security assumptions" and "Limitations" for the full picture (TLS,
secret management, rate limiting, etc. are still required in
production).
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attaches a small set of standard, low-risk security headers to every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
