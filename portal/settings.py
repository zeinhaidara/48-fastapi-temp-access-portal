"""Portal policy. Placeholder account 123456789012."""

from __future__ import annotations

from dataclasses import dataclass, field

STS_MIN_SECONDS = 900  # AssumeRole will not issue a shorter session


@dataclass(frozen=True)
class Settings:
    # Only these roles can be requested. Name shown to users -> role ARN.
    roles: dict[str, str] = field(
        default_factory=lambda: {
            "prod-readonly": "arn:aws:iam::123456789012:role/prod-readonly",
            "prod-deployer": "arn:aws:iam::123456789012:role/prod-deployer",
        }
    )
    approvers: frozenset[str] = frozenset({"lead@example.com", "sre-oncall@example.com"})
    min_duration_seconds: int = STS_MIN_SECONDS
    # One hour also matches the STS cap when the portal itself runs as a role session.
    max_duration_seconds: int = 3600
    min_justification_chars: int = 10
    audit_log_path: str = "audit.jsonl"

    def __post_init__(self):
        if self.min_duration_seconds < STS_MIN_SECONDS:
            raise ValueError(f"min_duration_seconds must be >= {STS_MIN_SECONDS}")
        if self.max_duration_seconds < self.min_duration_seconds:
            raise ValueError("max_duration_seconds must be >= min_duration_seconds")
        if not self.roles or not self.approvers:
            raise ValueError("roles and approvers must not be empty")
