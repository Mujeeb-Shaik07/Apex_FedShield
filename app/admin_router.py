"""
Admin API router — all endpoints under /api/admin/.

Provides:
  Authentication:
    POST   /api/admin/login
    POST   /api/admin/logout
    POST   /api/admin/change-password

  Dashboard (ADMIN + MAIN_ADMIN):
    GET    /api/admin/dashboard
    GET    /api/admin/stats
    GET    /api/admin/threat-feed

  Client management (ADMIN + MAIN_ADMIN):
    GET    /api/admin/clients
    POST   /api/admin/clients
    PATCH  /api/admin/clients/{client_id}/suspend
    PATCH  /api/admin/clients/{client_id}/activate
    POST   /api/admin/clients/{client_id}/regenerate-key
    DELETE /api/admin/clients/{client_id}

  Admin management (MAIN_ADMIN only):
    GET    /api/admin/admins
    POST   /api/admin/admins
    PATCH  /api/admin/admins/{admin_id}/deactivate
    PATCH  /api/admin/admins/{admin_id}/activate
    DELETE /api/admin/admins/{admin_id}

  Audit logs (ADMIN + MAIN_ADMIN):
    GET    /api/admin/audit-logs

AUTHORIZATION RULES (enforced server-side, regardless of frontend UI):
  - All endpoints require a valid, non-expired JWT with correct token_version.
  - Admin management endpoints require MAIN_ADMIN role.
  - MAIN_ADMIN cannot be deleted, deactivated, or stripped of role.
  - Secondary ADMINs cannot promote themselves or others to MAIN_ADMIN.
  - A removed/deactivated ADMIN's token is immediately rejected.

SECURITY:
  - Passwords are hashed with Argon2 before storage.
  - API keys are SHA-256 hashed before storage.
  - No plaintext password, api_key, or hash ever appears in responses
    (except the one-time api_key in the client creation response).
  - Audit log entries are created for all significant actions.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.admin_auth import (
    create_access_token,
    create_audit_log,
    get_current_admin,
    hash_password,
    require_main_admin,
    verify_password,
)
from app.auth import generate_api_key
from app.database import get_db
from app.db_models import Admin, AdminRole, AuditLog, Client, ClientStatus, ThreatReport
from app.schemas import (
    AdminCreateRequest,
    AdminListResponse,
    AdminLoginRequest,
    AdminResponse,
    AdminTokenResponse,
    AuditLogListResponse,
    AuditLogResponse,
    ClientCreateRequest,
    ClientCreateResponse,
    ClientKeyRegenerateResponse,
    ClientListResponse,
    ClientResponse,
    DashboardResponse,
    PasswordChangeRequest,
    SanitizedReport,
    StatsResponse,
    ThreatFeedResponse,
)
from app.privacy_engine import to_external_report

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Authentication endpoints
# ---------------------------------------------------------------------------


@router.post("/login", response_model=AdminTokenResponse)
def admin_login(
    credentials: AdminLoginRequest,
    db: Session = Depends(get_db),
) -> AdminTokenResponse:
    """
    Authenticate an admin with email + password.

    Returns a short-lived JWT access token on success.
    NEVER logs the submitted password.
    NEVER includes the password or password_hash in the response.
    """
    admin: Admin | None = db.query(Admin).filter(Admin.email == credentials.email).first()

    # Verify both existence and password in a timing-safe manner.
    # If admin is None, we still call verify_password with a dummy hash
    # to prevent user enumeration via timing.
    _DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$dGVzdA$dGVzdA"  # never matches
    stored_hash = admin.password_hash if admin else _DUMMY_HASH
    password_ok = verify_password(credentials.password, stored_hash)

    if not admin or not password_ok:
        # Audit login failure without exposing which check failed.
        create_audit_log(
            db,
            actor_admin_id=None,
            actor_role=None,
            action="ADMIN_LOGIN_FAILURE",
            target_type="ADMIN",
            target_id=None,
            success=False,
            metadata_summary=f"Failed login attempt for email: {credentials.email[:50]}",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not admin.is_active:
        create_audit_log(
            db,
            actor_admin_id=admin.admin_id,
            actor_role=admin.role,
            action="ADMIN_LOGIN_FAILURE",
            target_type="ADMIN",
            target_id=admin.admin_id,
            success=False,
            metadata_summary="Login attempt by inactive admin",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin account is not active",
        )

    # Update last_login_at
    admin.last_login_at = dt.datetime.now(dt.timezone.utc)
    admin.updated_at = dt.datetime.now(dt.timezone.utc)

    token = create_access_token(admin.admin_id, admin.role, admin.token_version)

    create_audit_log(
        db,
        actor_admin_id=admin.admin_id,
        actor_role=admin.role,
        action="ADMIN_LOGIN_SUCCESS",
        target_type="ADMIN",
        target_id=admin.admin_id,
        success=True,
    )
    db.commit()

    return AdminTokenResponse(
        access_token=token,
        token_type="bearer",
        role=admin.role,
        admin_id=admin.admin_id,
        name=admin.name,
        force_password_change=admin.force_password_change,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def admin_logout(
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> None:
    """
    Logout: increment token_version to invalidate this and all other
    existing tokens for this admin (stateless JWT invalidation).
    """
    current_admin.token_version += 1
    current_admin.updated_at = dt.datetime.now(dt.timezone.utc)
    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="ADMIN_LOGOUT",
        target_type="ADMIN",
        target_id=current_admin.admin_id,
        success=True,
    )
    db.commit()


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    request: PasswordChangeRequest,
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> None:
    """Allow an admin to change their own password."""
    if not verify_password(request.current_password, current_admin.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    current_admin.password_hash = hash_password(request.new_password)
    current_admin.force_password_change = False
    current_admin.token_version += 1  # Invalidate all existing tokens
    current_admin.updated_at = dt.datetime.now(dt.timezone.utc)
    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="ADMIN_PASSWORD_CHANGED",
        target_type="ADMIN",
        target_id=current_admin.admin_id,
        success=True,
    )
    db.commit()


# ---------------------------------------------------------------------------
# Dashboard endpoint (ADMIN + MAIN_ADMIN)
# ---------------------------------------------------------------------------


@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard(
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> DashboardResponse:
    """Return aggregate dashboard statistics for the admin portal."""

    def _count_threat(severity: str) -> int:
        return db.execute(
            select(func.count()).select_from(ThreatReport).where(ThreatReport.severity == severity)
        ).scalar_one()

    def _count_clients(st: str) -> int:
        return db.execute(
            select(func.count()).select_from(Client).where(Client.status == st)
        ).scalar_one()

    total_reports = db.execute(select(func.count()).select_from(ThreatReport)).scalar_one()
    total_clients = db.execute(select(func.count()).select_from(Client)).scalar_one()
    total_admins = db.execute(select(func.count()).select_from(Admin)).scalar_one()
    active_admins = db.execute(
        select(func.count()).select_from(Admin).where(Admin.is_active == True)  # noqa: E712
    ).scalar_one()

    return DashboardResponse(
        total_reports=total_reports,
        critical_reports=_count_threat("CRITICAL"),
        high_reports=_count_threat("HIGH"),
        medium_reports=_count_threat("MEDIUM"),
        low_reports=_count_threat("LOW"),
        total_clients=total_clients,
        active_clients=_count_clients(ClientStatus.ACTIVE),
        suspended_clients=_count_clients(ClientStatus.SUSPENDED),
        revoked_clients=_count_clients(ClientStatus.REVOKED),
        total_admins=total_admins,
        active_admins=active_admins,
    )


@router.get("/stats", response_model=StatsResponse)
def admin_stats(
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> StatsResponse:
    """Aggregate threat statistics (admin view)."""

    def _count(severity: str) -> int:
        return db.execute(
            select(func.count()).select_from(ThreatReport).where(ThreatReport.severity == severity)
        ).scalar_one()

    total = db.execute(select(func.count()).select_from(ThreatReport)).scalar_one()
    return StatsResponse(
        total_reports=total,
        critical_reports=_count("CRITICAL"),
        high_reports=_count("HIGH"),
        medium_reports=_count("MEDIUM"),
        low_reports=_count("LOW"),
    )


@router.get("/threat-feed", response_model=ThreatFeedResponse)
def admin_threat_feed(
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ThreatFeedResponse:
    """
    Admin view of the sanitized threat intelligence feed.
    Returns SanitizedReport objects — never raw company names or IPs.
    """
    stmt = (
        select(ThreatReport)
        .order_by(ThreatReport.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = db.execute(stmt).scalars().all()
    reports = [to_external_report(row) for row in rows]
    return ThreatFeedResponse(count=len(reports), reports=reports)


# ---------------------------------------------------------------------------
# Client management endpoints (ADMIN + MAIN_ADMIN)
# ---------------------------------------------------------------------------


@router.get("/clients", response_model=ClientListResponse)
def list_clients(
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> ClientListResponse:
    """
    Return all client organizations.
    SECURITY: Never returns api_key or api_key_hash.
    """
    clients = db.query(Client).order_by(Client.created_at.desc()).all()
    return ClientListResponse(
        count=len(clients),
        clients=[ClientResponse.model_validate(c) for c in clients],
    )


@router.post("/clients", response_model=ClientCreateResponse, status_code=status.HTTP_201_CREATED)
def create_client(
    request: ClientCreateRequest,
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> ClientCreateResponse:
    """
    Create a new client organization and generate their API key.

    The plaintext API key is returned ONCE in this response.
    It is NEVER stored in the database and NEVER retrievable again.
    """
    plaintext_key, key_hash = generate_api_key()
    now = dt.datetime.now(dt.timezone.utc)
    client = Client(
        client_id=uuid.uuid4().hex,
        display_name=request.display_name,
        contact_email=request.contact_email,
        api_key_hash=key_hash,
        status=ClientStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    db.add(client)

    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="CLIENT_CREATED",
        target_type="CLIENT",
        target_id=client.client_id,
        success=True,
        metadata_summary=f"Client created: {request.display_name}",
    )
    db.commit()
    db.refresh(client)

    return ClientCreateResponse(
        client_id=client.client_id,
        display_name=client.display_name,
        contact_email=client.contact_email,
        status=client.status,
        created_at=client.created_at,
        api_key=plaintext_key,  # ONE-TIME only
    )


@router.patch("/clients/{client_id}/suspend", response_model=ClientResponse)
def suspend_client(
    client_id: str,
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> ClientResponse:
    """Suspend a client (prevents API access; preserves history)."""
    client = _get_client_or_404(db, client_id)
    if client.status == ClientStatus.REVOKED:
        raise HTTPException(status_code=400, detail="Cannot suspend a revoked client")
    client.status = ClientStatus.SUSPENDED
    client.updated_at = dt.datetime.now(dt.timezone.utc)
    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="CLIENT_SUSPENDED",
        target_type="CLIENT",
        target_id=client.client_id,
        success=True,
        metadata_summary=f"Client suspended: {client.display_name}",
    )
    db.commit()
    db.refresh(client)
    return ClientResponse.model_validate(client)


@router.patch("/clients/{client_id}/activate", response_model=ClientResponse)
def activate_client(
    client_id: str,
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> ClientResponse:
    """Reactivate a suspended client."""
    client = _get_client_or_404(db, client_id)
    if client.status == ClientStatus.REVOKED:
        raise HTTPException(status_code=400, detail="Cannot reactivate a revoked client; regenerate key instead")
    client.status = ClientStatus.ACTIVE
    client.revoked_at = None
    client.updated_at = dt.datetime.now(dt.timezone.utc)
    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="CLIENT_ACTIVATED",
        target_type="CLIENT",
        target_id=client.client_id,
        success=True,
        metadata_summary=f"Client activated: {client.display_name}",
    )
    db.commit()
    db.refresh(client)
    return ClientResponse.model_validate(client)


@router.post("/clients/{client_id}/regenerate-key", response_model=ClientKeyRegenerateResponse)
def regenerate_client_key(
    client_id: str,
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> ClientKeyRegenerateResponse:
    """
    Regenerate the API key for a client.

    The new plaintext key is returned ONCE in this response.
    The old key is immediately invalidated.
    """
    client = _get_client_or_404(db, client_id)
    plaintext_key, key_hash = generate_api_key()
    client.api_key_hash = key_hash
    client.status = ClientStatus.ACTIVE  # Reactivate if revoked
    client.revoked_at = None
    client.updated_at = dt.datetime.now(dt.timezone.utc)
    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="CLIENT_API_KEY_REGENERATED",
        target_type="CLIENT",
        target_id=client.client_id,
        success=True,
        metadata_summary=f"API key regenerated for client: {client.display_name}",
    )
    db.commit()
    db.refresh(client)

    return ClientKeyRegenerateResponse(
        client_id=client.client_id,
        display_name=client.display_name,
        api_key=plaintext_key,  # ONE-TIME only
    )


@router.delete("/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_client(
    client_id: str,
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> None:
    """
    Revoke client access (soft delete).

    Sets status=REVOKED and revoked_at=now. Preserves audit history.
    The client's API key immediately stops working.
    """
    client = _get_client_or_404(db, client_id)
    now = dt.datetime.now(dt.timezone.utc)
    client.status = ClientStatus.REVOKED
    client.revoked_at = now
    client.updated_at = now
    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="CLIENT_REVOKED",
        target_type="CLIENT",
        target_id=client.client_id,
        success=True,
        metadata_summary=f"Client access revoked: {client.display_name}",
    )
    db.commit()


# ---------------------------------------------------------------------------
# Admin management endpoints (MAIN_ADMIN only)
# ---------------------------------------------------------------------------


@router.get("/admins", response_model=AdminListResponse)
def list_admins(
    current_admin: Admin = Depends(require_main_admin),
    db: Session = Depends(get_db),
) -> AdminListResponse:
    """
    List all administrator accounts.
    SECURITY: Never returns password_hash.
    Only accessible to MAIN_ADMIN.
    """
    admins = db.query(Admin).order_by(Admin.created_at).all()
    return AdminListResponse(
        count=len(admins),
        admins=[AdminResponse.model_validate(a) for a in admins],
    )


@router.post("/admins", response_model=AdminResponse, status_code=status.HTTP_201_CREATED)
def create_admin(
    request: AdminCreateRequest,
    current_admin: Admin = Depends(require_main_admin),
    db: Session = Depends(get_db),
) -> AdminResponse:
    """
    Create a new secondary ADMIN account. MAIN_ADMIN only.

    The temporary_password is hashed immediately and NEVER stored as plaintext.
    The new admin will be required to change their password on first login.
    """
    # Prevent email conflicts
    existing = db.query(Admin).filter(Admin.email == request.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="An admin with that email already exists")

    now = dt.datetime.now(dt.timezone.utc)
    new_admin = Admin(
        admin_id=uuid.uuid4().hex,
        name=request.name,
        email=request.email,
        password_hash=hash_password(request.temporary_password),
        role=AdminRole.ADMIN,  # New admins always get ADMIN role, never MAIN_ADMIN
        is_active=True,
        created_at=now,
        updated_at=now,
        token_version=0,
        force_password_change=True,
    )
    db.add(new_admin)

    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="ADMIN_CREATED",
        target_type="ADMIN",
        target_id=new_admin.admin_id,
        success=True,
        metadata_summary=f"New ADMIN created: {request.name} ({request.email})",
    )
    db.commit()
    db.refresh(new_admin)
    return AdminResponse.model_validate(new_admin)


@router.patch("/admins/{admin_id}/deactivate", response_model=AdminResponse)
def deactivate_admin(
    admin_id: str,
    current_admin: Admin = Depends(require_main_admin),
    db: Session = Depends(get_db),
) -> AdminResponse:
    """
    Deactivate a secondary ADMIN. MAIN_ADMIN only.
    Increments token_version so all existing tokens are immediately rejected.
    MAIN_ADMIN cannot be deactivated.
    """
    target = _get_admin_or_404(db, admin_id)
    _guard_main_admin_immutability(target)

    target.is_active = False
    target.token_version += 1  # Immediately invalidate all tokens
    target.updated_at = dt.datetime.now(dt.timezone.utc)

    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="ADMIN_DEACTIVATED",
        target_type="ADMIN",
        target_id=target.admin_id,
        success=True,
        metadata_summary=f"Admin deactivated: {target.name}",
    )
    db.commit()
    db.refresh(target)
    return AdminResponse.model_validate(target)


@router.patch("/admins/{admin_id}/activate", response_model=AdminResponse)
def activate_admin(
    admin_id: str,
    current_admin: Admin = Depends(require_main_admin),
    db: Session = Depends(get_db),
) -> AdminResponse:
    """Reactivate a deactivated ADMIN. MAIN_ADMIN only."""
    target = _get_admin_or_404(db, admin_id)

    target.is_active = True
    target.updated_at = dt.datetime.now(dt.timezone.utc)

    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="ADMIN_ACTIVATED",
        target_type="ADMIN",
        target_id=target.admin_id,
        success=True,
        metadata_summary=f"Admin activated: {target.name}",
    )
    db.commit()
    db.refresh(target)
    return AdminResponse.model_validate(target)


@router.delete("/admins/{admin_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_admin(
    admin_id: str,
    current_admin: Admin = Depends(require_main_admin),
    db: Session = Depends(get_db),
) -> None:
    """
    Remove a secondary ADMIN. MAIN_ADMIN only.

    Deactivates the account and increments token_version to immediately
    invalidate all outstanding tokens. Historical audit entries are preserved.
    MAIN_ADMIN cannot be removed.
    """
    target = _get_admin_or_404(db, admin_id)
    _guard_main_admin_immutability(target)

    target.is_active = False
    target.token_version += 1
    target.updated_at = dt.datetime.now(dt.timezone.utc)

    create_audit_log(
        db,
        actor_admin_id=current_admin.admin_id,
        actor_role=current_admin.role,
        action="ADMIN_REMOVED",
        target_type="ADMIN",
        target_id=target.admin_id,
        success=True,
        metadata_summary=f"Admin removed: {target.name}",
    )
    db.commit()


# ---------------------------------------------------------------------------
# Audit logs (ADMIN + MAIN_ADMIN)
# ---------------------------------------------------------------------------


@router.get("/audit-logs", response_model=AuditLogListResponse)
def get_audit_logs(
    current_admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> AuditLogListResponse:
    """
    Return recent audit log entries.
    SECURITY: metadata_summary is stored without secrets; this is enforced
    at write time in create_audit_log().
    """
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return AuditLogListResponse(
        count=len(logs),
        logs=[AuditLogResponse.model_validate(log) for log in logs],
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _get_client_or_404(db: Session, client_id: str) -> Client:
    client = db.query(Client).filter(Client.client_id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


def _get_admin_or_404(db: Session, admin_id: str) -> Admin:
    admin = db.query(Admin).filter(Admin.admin_id == admin_id).first()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return admin


def _guard_main_admin_immutability(target: Admin) -> None:
    """Raise 403 if the target admin is MAIN_ADMIN (immutable)."""
    if target.role == AdminRole.MAIN_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The MAIN_ADMIN account cannot be modified through this endpoint",
        )
