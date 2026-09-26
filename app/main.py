"""
FastAPI application entry point for the Privacy-Preserving Threat
Intelligence Network.

Pipeline implemented by POST /api/ingest-log (see README.md "Exact data
flow" for the full diagram):

    validate (Pydantic) -> mock AI analysis -> privacy engine
        -> SanitizedReport -> SQLite (sanitized only) -> sanitized response

On startup:
    - Database tables are created.
    - If no MAIN_ADMIN exists, one is bootstrapped from environment
      variables (BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD).
      The password is hashed with Argon2 immediately; the plaintext is
      never stored anywhere.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Query, Request, status, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import ai_engine, privacy_engine
from app.admin_router import router as admin_router
from app.auth import require_api_key
from app.config import settings
from app.database import get_db, init_db
from app.db_models import Admin, AdminRole, ThreatReport
from app.schemas import (
    HealthResponse,
    RawLog,
    SanitizedReport,
    StatsResponse,
    ThreatFeedResponse,
    ClientLoginRequest,
    ClientResponse,
)
from app.security import SecurityHeadersMiddleware
from fastapi.responses import FileResponse
import os as _os

# ---------------------------------------------------------------------------
# Safe logging configuration.
#
# Logs may include ONLY: request_id, endpoint, HTTP status, processing
# time, and report_id. Raw request bodies, company names, internal IPs,
# API keys, passwords, tokens, and the privacy secret are NEVER logged.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("threat_intel")


def _bootstrap_main_admin() -> None:
    """
    Seed the MAIN_ADMIN account on first startup.

    Rules:
      - If no MAIN_ADMIN exists, create one from bootstrap credentials.
      - If MAIN_ADMIN already exists, do nothing.
      - The bootstrap password is hashed with Argon2 immediately.
      - The plaintext password is NEVER stored or logged.

    This runs synchronously at startup, before any request is served.
    """
    from app.admin_auth import hash_password
    from app.database import SessionLocal

    with SessionLocal() as db:
        existing = db.query(Admin).filter(Admin.role == AdminRole.MAIN_ADMIN).first()
        if existing:
            logger.info("[Bootstrap] MAIN_ADMIN already exists — skipping bootstrap.")
            return

        logger.info("[Bootstrap] No MAIN_ADMIN found — creating from bootstrap credentials.")
        now = dt.datetime.now(dt.timezone.utc)
        main_admin = Admin(
            admin_id=uuid.uuid4().hex,
            name="Main Administrator",
            email=settings.bootstrap_admin_email,
            # Hash immediately — plaintext is NOT stored anywhere
            password_hash=hash_password(settings.bootstrap_admin_password),
            role=AdminRole.MAIN_ADMIN,
            is_active=True,
            created_at=now,
            updated_at=now,
            token_version=0,
            force_password_change=False,
        )
        db.add(main_admin)
        db.commit()
        # SECURITY: Log the email only — NEVER log the password or its hash.
        logger.info(
            "[Bootstrap] MAIN_ADMIN created for email: %s",
            settings.bootstrap_admin_email,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database and bootstrap the MAIN_ADMIN on start-up."""
    init_db()
    _bootstrap_main_admin()
    yield


app = FastAPI(
    title="Privacy-Preserving Threat Intelligence Network",
    description=(
        "Sanitized threat-intelligence feed built on HMAC-SHA256 "
        "pseudonymization and data minimization. See README.md."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend to communicate with backend (adjust origins for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SecurityHeadersMiddleware)

# ---------------------------------------------------------------------------
# Static asset serving (UI redesign only — no API behavior below is touched).
# Serves purely-visual background assets (e.g. /static/assets/*.mp4) used by
# the frontend. If the directory or a given file is missing, StaticFiles
# returns a normal 404 and the frontend's video-failure fallback (a CSS-only
# background) takes over automatically — this never affects auth, API
# requests, or page rendering.
# ---------------------------------------------------------------------------
_static_dir = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "static")
_os.makedirs(_os.path.join(_static_dir, "assets"), exist_ok=True)
app.mount("/static", StaticFiles(directory=_static_dir), name="static")

# Mount the admin API router
app.include_router(admin_router)

@app.get("/", include_in_schema=False)
async def serve_frontend():
    """Serve the frontend admin portal."""
    file_path = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "index.html")
    return FileResponse(file_path, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


@app.middleware("http")
async def _log_requests(request: Request, call_next):
    """Attach a request_id and log only safe, non-sensitive request metadata."""
    request_id = uuid.uuid4().hex
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info(
        "request_id=%s endpoint=%s status=%s elapsed_ms=%s",
        request_id,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    response.headers["X-Request-ID"] = request_id
    return response


# ---------------------------------------------------------------------------
# Safe exception handling: never leak stack traces, SQL, file paths,
# secrets, or raw input back to the client.
# ---------------------------------------------------------------------------


@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Pydantic/FastAPI validation errors describe which field failed and
    why, but never echo back the submitted values - a submitted value
    could itself be sensitive (e.g. an oversized company_name).
    """
    safe_errors = [
        {"field": ".".join(str(part) for part in err["loc"]), "message": err["msg"]}
        for err in exc.errors()
    ]
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": safe_errors})


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler: never return a stack trace, file path, or raw input to the client."""
    logger.error("Unhandled exception on %s: %s", request.url.path, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# ---------------------------------------------------------------------------
# Public / Client Endpoints
# ---------------------------------------------------------------------------


@app.post("/api/client/login", response_model=ClientResponse, tags=["client"])
def client_login(
    req: ClientLoginRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> ClientResponse:
    from app.auth import hash_api_key
    from app.db_models import Client, ClientStatus, AuditLog
    import datetime as dt
    import uuid

    key_hash = hash_api_key(req.api_key)
    client = db.query(Client).filter(Client.api_key_hash == key_hash).first()
    
    if not client or client.display_name.strip().casefold() != req.display_name.casefold():
        raise HTTPException(status_code=401, detail="Invalid organization name or API key")
        
    if client.status != ClientStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Client account is suspended or revoked")

    now = dt.datetime.now(dt.timezone.utc)
    client.last_seen_at = now
    client.last_login_ip = request.client.host
    
    audit = AuditLog(
        event_id=uuid.uuid4().hex,
        action="CLIENT_LOGIN",
        target_id=client.client_id,
        target_type="CLIENT",
        success=True,
        created_at=now,
        metadata_summary=f"IP: {request.client.host}"
    )
    db.add(audit)
    db.commit()
    db.refresh(client)
    
    return client


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    """Liveness check. Exposes no internal secrets or database credentials."""
    return HealthResponse(status="healthy")


@app.post(
    "/api/ingest-log",
    response_model=SanitizedReport,
    status_code=status.HTTP_201_CREATED,
    tags=["ingest"],
)
def ingest_log(
    raw_log: RawLog,
    db: Annotated[Session, Depends(get_db)],
    client_id: Annotated[str, Depends(require_api_key)],
) -> SanitizedReport:
    """
    Ingest a raw security event, run the local mock AI analysis, run the
    privacy engine, store ONLY the sanitized record, and return ONLY the
    sanitized report to the submitting organization.

    `raw_log` (containing company_name and internal_ip) exists only in
    this function's local scope and in the privacy-engine functions it
    calls directly. It is never logged, never stored, and never
    returned - see app/privacy_engine.py.
    """
    analysis = ai_engine.analyze_threat(raw_log)
    internal_record = privacy_engine.create_sanitized_report(raw_log, analysis)

    db_row = ThreatReport(
        report_id=internal_record.report_id,
        created_at=internal_record.created_at,
        organization_token=internal_record.organization_token,
        indicator_token=internal_record.indicator_token,
        indicator_type=internal_record.indicator_type,
        threat_type=internal_record.threat_type,
        severity=internal_record.severity,
        impact_percentage=internal_record.impact_percentage,
        confidence=internal_record.confidence,
        attack_pattern=internal_record.attack_pattern,
        mitigation=internal_record.mitigation,
        target_service=internal_record.target_service,
    )
    db.add(db_row)
    db.commit()
    db.refresh(db_row)

    # Explicit mapping from the ORM row to the external response model -
    # the ORM row (which we could add internal-only fields to later) is
    # never returned directly.
    return privacy_engine.to_external_report(db_row)


@app.get("/api/threat-feed", response_model=ThreatFeedResponse, tags=["feed"])
def threat_feed(
    db: Annotated[Session, Depends(get_db)],
    client_id: Annotated[str, Depends(require_api_key)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ThreatFeedResponse:
    """
    Return sanitized threat intelligence reports to an authenticated
    external client. Never returns raw company identity or internal IPs
    - only SanitizedReport objects, explicitly mapped from the database
    rows.
    """
    stmt = (
        select(ThreatReport)
        .order_by(ThreatReport.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = db.execute(stmt).scalars().all()
    reports = [privacy_engine.to_external_report(row) for row in rows]
    return ThreatFeedResponse(count=len(reports), reports=reports)


@app.get("/api/stats", response_model=StatsResponse, tags=["system"])
def stats(db: Annotated[Session, Depends(get_db)]) -> StatsResponse:
    """Safe aggregate statistics. Never returns organization names or internal identifiers."""
    total = db.execute(select(func.count()).select_from(ThreatReport)).scalar_one()

    def _count_for(severity: str) -> int:
        stmt = select(func.count()).select_from(ThreatReport).where(ThreatReport.severity == severity)
        return db.execute(stmt).scalar_one()

    return StatsResponse(
        total_reports=total,
        critical_reports=_count_for("CRITICAL"),
        high_reports=_count_for("HIGH"),
        medium_reports=_count_for("MEDIUM"),
        low_reports=_count_for("LOW"),
    )
