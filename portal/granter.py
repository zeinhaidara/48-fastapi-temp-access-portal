"""Issue temporary credentials. STS sessions expire on their own."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class Grant:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expires_at: datetime


class Granter(Protocol):
    def grant(
        self, role_arn: str, session_name: str, source_identity: str, duration_seconds: int
    ) -> Grant: ...


class StsGranter:
    """AssumeRole with DurationSeconds, so expiry is enforced by AWS, not by us."""

    def __init__(self, sts):
        self.sts = sts

    def grant(self, role_arn, session_name, source_identity, duration_seconds) -> Grant:
        resp = self.sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            # Shows up in CloudTrail for every call made with these credentials.
            SourceIdentity=source_identity,
            DurationSeconds=duration_seconds,
        )
        c = resp["Credentials"]
        return Grant(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"], c["Expiration"])
