from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


class ScanRequest(BaseModel):
    full_name: str
    email: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    location: Optional[str] = None  # for state law routing
    use_emailrep: bool = False
    use_breachdirectory: bool = False
    use_intelx: bool = False

    @model_validator(mode="after")
    def at_least_one_identifier(self) -> ScanRequest:
        if not any([self.email, self.username, self.phone]):
            raise ValueError(
                "At least one of email, username, or phone must be provided"
            )
        return self


class Finding(BaseModel):
    source: str  # e.g., "hibp", "maigret", "holehe"
    source_url: str  # URL where the data was found
    finding_type: str  # "breach", "account_exists", "document", "phone_exposure", etc.
    data: dict = Field(default_factory=dict)  # source-specific data (flexible)
    confidence: Literal["high", "medium", "low"]
    input_used: str  # what input triggered this: "email", "username", "name", "phone"
    original_input: str  # the actual value searched
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    leads_to: list[str] = Field(
        default_factory=list
    )  # e.g. ["username:johndoe", "email:john@gmail.com"]
    severity: Literal["critical", "high", "medium", "low", "info"]


class ScanReport(BaseModel):
    scan_id: str
    status: str = "complete"
    inputs: ScanRequest
    findings: list[Finding] = Field(default_factory=list)
    exposure_score: int = Field(default=0, ge=0, le=100)
    kill_chains: list[dict] = Field(default_factory=list)  # attack path narratives
    actions: list[dict] = Field(default_factory=list)  # prioritized remediation steps
    audit_trail: list[dict] = Field(
        default_factory=list
    )  # chronological agent steps
    applicable_laws: list[dict] = Field(
        default_factory=list
    )  # based on location
    scan_duration_seconds: float = 0.0
