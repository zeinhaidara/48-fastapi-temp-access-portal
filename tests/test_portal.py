import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.app import create_app
from portal.audit import AuditLog
from portal.granter import Grant, StsGranter
from portal.settings import Settings

DEV, OTHER_DEV = "dev@example.com", "dev2@example.com"
LEAD = "lead@example.com"
SECRET = "fake-secret-must-never-be-logged"
TOKEN = "fake-session-token-must-never-be-logged"


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


class FakeGranter:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []

    def grant(self, role_arn, session_name, source_identity, duration_seconds):
        self.calls.append((role_arn, session_name, source_identity, duration_seconds))
        return Grant(
            "ASIAEXAMPLE", SECRET, TOKEN, self.clock() + timedelta(seconds=duration_seconds)
        )


@pytest.fixture
def env(tmp_path):
    clock = FakeClock()
    granter = FakeGranter(clock)
    settings = Settings(audit_log_path=str(tmp_path / "audit.jsonl"))
    client = TestClient(create_app(settings, granter, clock))
    return client, clock, granter, tmp_path / "audit.jsonl"


def as_user(user):
    return {"X-Forwarded-User": user}


def new_request(client, user=DEV, **overrides):
    body = {
        "role": "prod-readonly",
        "justification": "INC-1234 investigate errors",
        "duration_seconds": 3600,
        **overrides,
    }
    return client.post("/requests", json=body, headers=as_user(user))


def audit_events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- requesting --------------------------------------------------------------------


def test_create_request(env):
    client, _, _, audit = env
    r = new_request(client)
    assert r.status_code == 201
    assert r.json()["status"] == "pending"
    [event] = audit_events(audit)
    assert event["event"] == "request_created"
    assert event["requester"] == DEV
    assert event["justification"] == "INC-1234 investigate errors"


def test_identity_header_required(env):
    client = env[0]
    assert client.post("/requests", json={}).status_code == 401
    assert client.get("/requests", headers=as_user("bad user!")).status_code == 401


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"justification": "   "}, "justification"),
        ({"justification": "because"}, "justification"),
        ({"duration_seconds": 3601}, "duration_seconds"),
        ({"duration_seconds": 600}, "duration_seconds"),
        ({"role": "AdministratorAccess"}, "not requestable"),
    ],
)
def test_request_rules(env, overrides, message):
    client, _, _, audit = env
    r = new_request(client, **overrides)
    assert r.status_code == 422
    assert message in r.text
    assert not audit.exists()


# --- approving -----------------------------------------------------------------------


def test_requester_cannot_approve_own_request(tmp_path):
    clock = FakeClock()
    # The lead is an approver, but still can't approve their own request.
    client = TestClient(
        create_app(Settings(audit_log_path=str(tmp_path / "a.jsonl")), FakeGranter(clock), clock)
    )
    rid = new_request(client, user=LEAD).json()["id"]
    r = client.post(f"/requests/{rid}/approve", headers=as_user(LEAD))
    assert r.status_code == 403
    assert "own request" in r.text
    assert audit_events(tmp_path / "a.jsonl")[-1]["reason"] == "approver is the requester"


def test_non_approver_cannot_approve(env):
    client = env[0]
    rid = new_request(client).json()["id"]
    assert client.post(f"/requests/{rid}/approve", headers=as_user(OTHER_DEV)).status_code == 403


def test_approve_sets_expiry_from_clock(env):
    client, clock, _, audit = env
    rid = new_request(client).json()["id"]
    clock.advance(minutes=5)
    r = client.post(f"/requests/{rid}/approve", json={"reason": "on call"}, headers=as_user(LEAD))
    assert r.status_code == 200
    assert r.json()["expires_at"] == "2026-11-20T10:05:00+00:00"
    assert audit_events(audit)[-1]["event"] == "request_approved"


def test_cannot_decide_twice(env):
    client = env[0]
    rid = new_request(client).json()["id"]
    assert client.post(f"/requests/{rid}/deny", headers=as_user(LEAD)).status_code == 200
    r = client.post(f"/requests/{rid}/approve", headers=as_user(LEAD))
    assert r.status_code == 409
    assert "denied" in r.text


def test_unknown_request_404(env):
    assert env[0].post("/requests/nope/approve", headers=as_user(LEAD)).status_code == 404


# --- credentials and expiry ------------------------------------------------------------


def approved(client, clock):
    rid = new_request(client).json()["id"]
    client.post(f"/requests/{rid}/approve", headers=as_user(LEAD))
    return rid


def test_requester_gets_credentials_for_remaining_window(env):
    client, clock, granter, _ = env
    rid = approved(client, clock)
    clock.advance(minutes=20)
    r = client.post(f"/requests/{rid}/credentials", headers=as_user(DEV))
    assert r.status_code == 200
    assert r.json()["secret_access_key"] == SECRET
    [(arn, session, source, seconds)] = granter.calls
    assert arn == "arn:aws:iam::123456789012:role/prod-readonly"
    assert source == DEV
    assert seconds == 2400  # 60 minutes approved, 20 used
    assert session.startswith("portal-")


def test_only_requester_gets_credentials(env):
    client, clock, granter, _ = env
    rid = approved(client, clock)
    assert client.post(f"/requests/{rid}/credentials", headers=as_user(LEAD)).status_code == 403
    assert granter.calls == []


def test_pending_or_denied_gives_no_credentials(env):
    client, _, granter, _ = env
    rid = new_request(client).json()["id"]
    assert client.post(f"/requests/{rid}/credentials", headers=as_user(DEV)).status_code == 409
    client.post(f"/requests/{rid}/deny", headers=as_user(LEAD))
    assert client.post(f"/requests/{rid}/credentials", headers=as_user(DEV)).status_code == 409
    assert granter.calls == []


def test_expired_after_window(env):
    client, clock, granter, _ = env
    rid = approved(client, clock)
    clock.advance(minutes=60)
    assert client.post(f"/requests/{rid}/credentials", headers=as_user(DEV)).status_code == 410
    [view] = client.get("/requests", headers=as_user(DEV)).json()
    assert view["status"] == "expired"
    assert granter.calls == []


def test_too_little_time_left_for_sts_minimum(env):
    client, clock, granter, _ = env
    rid = approved(client, clock)
    clock.advance(minutes=50)  # 10 minutes left, STS minimum is 15
    r = client.post(f"/requests/{rid}/credentials", headers=as_user(DEV))
    assert r.status_code == 409
    assert granter.calls == []


def test_credentials_never_reach_the_audit_log(env):
    client, clock, _, audit = env
    rid = approved(client, clock)
    client.post(f"/requests/{rid}/credentials", headers=as_user(DEV))
    text = audit.read_text()
    assert "credentials_issued" in text
    assert SECRET not in text and TOKEN not in text and "ASIAEXAMPLE" not in text


def test_audit_log_rejects_unknown_fields(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    with pytest.raises(ValueError, match="secret_access_key"):
        log.write(datetime.now(UTC), event="x", secret_access_key=SECRET)
    assert not (tmp_path / "a.jsonl").exists()


def test_audit_log_only_grows(env):
    client, clock, _, audit = env
    approved(client, clock)
    first = audit.read_text()
    new_request(client, user=OTHER_DEV)
    assert audit.read_text().startswith(first)
    assert len(audit_events(audit)) == 3


def test_no_route_can_change_or_read_the_audit_log(env):
    client = env[0]
    for route in client.app.routes:
        methods = getattr(route, "methods", set()) or set()
        assert not methods & {"PUT", "PATCH", "DELETE"}, route.path
        assert "audit" not in route.path


# --- listing ------------------------------------------------------------------------------


def test_list_visibility(env):
    client = env[0]
    new_request(client, user=DEV)
    new_request(client, user=OTHER_DEV)
    assert len(client.get("/requests", headers=as_user(DEV)).json()) == 1
    assert len(client.get("/requests", headers=as_user(LEAD)).json()) == 2


# --- STS granter -------------------------------------------------------------------------


def test_sts_granter_passes_duration_and_source_identity():
    class FakeSTS:
        def assume_role(self, **kw):
            self.kw = kw
            return {
                "Credentials": {
                    "AccessKeyId": "ASIA",
                    "SecretAccessKey": "s",
                    "SessionToken": "t",
                    "Expiration": datetime(2026, 11, 20, 10, tzinfo=UTC),
                }
            }

    sts = FakeSTS()
    grant = StsGranter(sts).grant("arn:aws:iam::123456789012:role/r", "portal-abc", DEV, 1800)
    assert sts.kw == {
        "RoleArn": "arn:aws:iam::123456789012:role/r",
        "RoleSessionName": "portal-abc",
        "SourceIdentity": DEV,
        "DurationSeconds": 1800,
    }
    assert grant.expires_at.hour == 10


def test_settings_reject_sub_sts_minimum():
    with pytest.raises(ValueError):
        Settings(min_duration_seconds=60)


# --- concurrency ---------------------------------------------------------------------------


def test_concurrent_audit_writes_never_interleave(tmp_path):
    # Two log objects on one file (like two app instances in one process) and lines far
    # larger than a write buffer, so split writes would show up as broken JSON.
    path = tmp_path / "audit.jsonl"
    logs = [AuditLog(path), AuditLog(path)]
    at = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)

    def write_many(n):
        for i in range(50):
            logs[n % 2].write(at, event="request_created", actor=f"u{n}", reason=f"{n}-{i}" * 4000)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write_many, range(8)))

    events = audit_events(path)
    assert len(events) == 400
    assert all(e["reason"] == e["reason"][: len(e["reason"]) // 4000] * 4000 for e in events)


def test_concurrent_requests_are_all_audited(env):
    client, _, _, audit = env
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda _: new_request(client), range(40)))
    assert [r.status_code for r in responses] == [201] * 40
    events = audit_events(audit)
    assert len(events) == 40
    assert len({e["request_id"] for e in events}) == 40


def test_concurrent_approvals_decide_once(tmp_path):
    # Behaviour check: ten approvers at once, exactly one wins. The race window is too
    # small to force reliably, so this does not prove the lock on its own.
    clock = FakeClock()
    approvers = frozenset(f"approver{i}@example.com" for i in range(10))
    settings = Settings(audit_log_path=str(tmp_path / "a.jsonl"), approvers=approvers)
    client = TestClient(create_app(settings, FakeGranter(clock), clock))
    rid = new_request(client).json()["id"]

    with ThreadPoolExecutor(max_workers=10) as pool:
        codes = list(
            pool.map(
                lambda a: client.post(f"/requests/{rid}/approve", headers=as_user(a)).status_code,
                sorted(approvers),
            )
        )
    assert sorted(codes) == [200] + [409] * 9
    decided = [e for e in audit_events(tmp_path / "a.jsonl") if e["event"] == "request_approved"]
    assert len(decided) == 1


# --- per-role approvers ----------------------------------------------------------------------


SRE = "sre-oncall@example.com"


def test_role_approvers_limit_who_can_decide(tmp_path):
    clock = FakeClock()
    settings = Settings(
        audit_log_path=str(tmp_path / "a.jsonl"),
        role_approvers={"prod-deployer": frozenset({LEAD})},
    )
    client = TestClient(create_app(settings, FakeGranter(clock), clock))
    deployer = new_request(client, role="prod-deployer").json()["id"]
    readonly = new_request(client, role="prod-readonly").json()["id"]

    r = client.post(f"/requests/{deployer}/approve", headers=as_user(SRE))
    assert r.status_code == 403
    assert "prod-deployer" in r.text
    assert audit_events(tmp_path / "a.jsonl")[-1]["reason"] == "not an approver for this role"

    assert client.post(f"/requests/{readonly}/approve", headers=as_user(SRE)).status_code == 200
    assert client.post(f"/requests/{deployer}/approve", headers=as_user(LEAD)).status_code == 200
    # SRE only sees requests for roles they can decide.
    assert [r["id"] for r in client.get("/requests", headers=as_user(SRE)).json()] == [readonly]


@pytest.mark.parametrize(
    "role_approvers",
    [{"AdministratorAccess": frozenset({LEAD})}, {"prod-deployer": frozenset()}],
)
def test_settings_reject_bad_role_approvers(role_approvers):
    with pytest.raises(ValueError):
        Settings(role_approvers=role_approvers)
