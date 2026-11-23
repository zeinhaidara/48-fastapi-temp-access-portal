"""Temporary IAM role access: request, approve or deny, then fetch a short session."""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from portal.audit import AuditLog
from portal.granter import Granter
from portal.settings import Settings

Clock = Callable[[], datetime]
IDENTITY = re.compile(r"^[\w+=,.@-]{2,64}$")  # also valid as an STS SourceIdentity


class AccessRequestIn(BaseModel):
    role: str
    justification: str
    duration_seconds: int = Field(gt=0)


class Decision(BaseModel):
    reason: str = ""


@dataclass
class AccessRequest:
    id: str
    requester: str
    role: str
    justification: str
    duration_seconds: int
    created_at: datetime
    status: str = "pending"  # pending, approved, denied
    decided_by: str | None = None
    decided_at: datetime | None = None
    expires_at: datetime | None = None

    def view(self, now: datetime) -> dict:
        status = self.status
        if status == "approved" and now >= self.expires_at:
            status = "expired"
        return {
            "id": self.id,
            "requester": self.requester,
            "role": self.role,
            "justification": self.justification,
            "duration_seconds": self.duration_seconds,
            "status": status,
            "created_at": self.created_at.isoformat(),
            "decided_by": self.decided_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


def create_app(settings: Settings, granter: Granter, clock: Clock | None = None) -> FastAPI:
    clock = clock or (lambda: datetime.now(UTC))
    audit = AuditLog(settings.audit_log_path)
    requests: dict[str, AccessRequest] = {}  # in memory; lost on restart
    # Sync routes run in a thread pool, so two approvers could race on one request.
    decision_lock = threading.Lock()
    app = FastAPI(title="Temporary access portal")

    def identity(x_forwarded_user: str | None = Header(default=None)) -> str:
        # Set by the trusted auth proxy in front of this service; see README.
        if not x_forwarded_user or not IDENTITY.match(x_forwarded_user):
            raise HTTPException(401, "missing or malformed X-Forwarded-User")
        return x_forwarded_user

    def find(request_id: str) -> AccessRequest:
        if request_id not in requests:
            raise HTTPException(404, "no such request")
        return requests[request_id]

    @app.post("/requests", status_code=201)
    def create(body: AccessRequestIn, user: str = Depends(identity)):
        if body.role not in settings.roles:
            raise HTTPException(422, f"role {body.role!r} is not requestable")
        if len(body.justification.strip()) < settings.min_justification_chars:
            raise HTTPException(
                422, f"justification needs at least {settings.min_justification_chars} characters"
            )
        if (
            not settings.min_duration_seconds
            <= body.duration_seconds
            <= settings.max_duration_seconds
        ):
            raise HTTPException(
                422,
                f"duration_seconds must be {settings.min_duration_seconds}"
                f"-{settings.max_duration_seconds}",
            )
        now = clock()
        req = AccessRequest(
            uuid.uuid4().hex,
            user,
            body.role,
            body.justification.strip(),
            body.duration_seconds,
            now,
        )
        requests[req.id] = req
        audit.write(
            now,
            event="request_created",
            request_id=req.id,
            actor=user,
            requester=user,
            role=req.role,
            duration_seconds=req.duration_seconds,
            justification=req.justification,
        )
        return req.view(now)

    @app.get("/requests")
    def list_requests(user: str = Depends(identity)):
        now = clock()
        visible = [
            r
            for r in requests.values()
            if user in settings.approvers_for(r.role) or r.requester == user
        ]
        return [r.view(now) for r in sorted(visible, key=lambda r: r.created_at)]

    def decide(request_id: str, user: str, approve: bool, reason: str) -> dict:
        with decision_lock:
            return decide_locked(request_id, user, approve, reason)

    def decide_locked(request_id: str, user: str, approve: bool, reason: str) -> dict:
        req = find(request_id)
        now = clock()
        action = "approve" if approve else "deny"
        if user not in settings.approvers_for(req.role):
            audit.write(
                now,
                event="decision_refused",
                request_id=req.id,
                actor=user,
                reason="not an approver for this role",
            )
            raise HTTPException(403, f"only approvers for {req.role} can approve or deny")
        if user == req.requester:
            audit.write(
                now,
                event="decision_refused",
                request_id=req.id,
                actor=user,
                reason="approver is the requester",
            )
            raise HTTPException(403, f"you cannot {action} your own request")
        if req.status != "pending":
            raise HTTPException(409, f"request is already {req.status}")
        req.status = "approved" if approve else "denied"
        req.decided_by, req.decided_at = user, now
        if approve:
            req.expires_at = now + timedelta(seconds=req.duration_seconds)
        audit.write(
            now,
            event=f"request_{req.status}",
            request_id=req.id,
            actor=user,
            requester=req.requester,
            role=req.role,
            reason=reason,
        )
        return req.view(now)

    @app.post("/requests/{request_id}/approve")
    def approve(request_id: str, body: Decision | None = None, user: str = Depends(identity)):
        return decide(request_id, user, True, body.reason if body else "")

    @app.post("/requests/{request_id}/deny")
    def deny(request_id: str, body: Decision | None = None, user: str = Depends(identity)):
        return decide(request_id, user, False, body.reason if body else "")

    @app.post("/requests/{request_id}/credentials")
    def credentials(request_id: str, user: str = Depends(identity)):
        req = find(request_id)
        now = clock()
        if user != req.requester:
            raise HTTPException(403, "only the requester can fetch credentials")
        if req.status != "approved":
            raise HTTPException(409, f"request is {req.status}")
        remaining = int((req.expires_at - now).total_seconds())
        if remaining <= 0:
            raise HTTPException(410, "approval window has expired")
        if remaining < settings.min_duration_seconds:
            # STS would issue a session that outlives the approval.
            raise HTTPException(409, "less than 15 minutes left; request access again")
        session_name = f"portal-{req.id[:12]}"
        grant = granter.grant(settings.roles[req.role], session_name, req.requester, remaining)
        # Credentials go back to the requester only, never into the audit log.
        audit.write(
            now,
            event="credentials_issued",
            request_id=req.id,
            actor=user,
            role=req.role,
            session_name=session_name,
            session_expires_at=grant.expires_at.isoformat(),
        )
        return {
            "access_key_id": grant.access_key_id,
            "secret_access_key": grant.secret_access_key,
            "session_token": grant.session_token,
            "expires_at": grant.expires_at.isoformat(),
        }

    return app
