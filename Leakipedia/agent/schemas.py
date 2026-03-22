from __future__ import annotations

from datetime import datetime, timezone
import uuid
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
    finding_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
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


class Lead(BaseModel):
    lead_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    type: str
    value: str
    origin_kind: str
    status: Literal[
        "confirmed",
        "auto_search",
        "deferred",
        "promoted",
        "searched",
        "pending_user_confirmation",
        "rejected",
    ]
    confidence: Literal["high", "medium", "low"]
    round_discovered: int = 0
    supporting_finding_ids: list[str] = Field(default_factory=list)
    supporting_sources: list[str] = Field(default_factory=list)
    why: str = ""


class ScoreFactor(BaseModel):
    category: Literal[
        "severity",
        "breadth",
        "escalation",
        "data_exposure",
        "attack_surfaces",
        "accessibility",
    ]
    label: str
    points: int = Field(default=0, ge=0)
    detail: str = ""


class ScoreBreakdown(BaseModel):
    version: str = "deterministic_v3"
    methodology: str = (
        "Deterministic score based on deduplicated findings, confirmed sensitive data exposure, "
        "viable attack surfaces, and how discoverable the data is. No LLM-generated score is used."
    )
    total: int = Field(default=0, ge=0, le=100)
    raw_total: int = Field(default=0, ge=0)
    label: Literal["low", "medium", "high", "critical"] = "low"
    finding_count: int = Field(default=0, ge=0)
    unique_finding_count: int = Field(default=0, ge=0)
    duplicate_finding_count: int = Field(default=0, ge=0)
    section_totals: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    finding_type_counts: dict[str, int] = Field(default_factory=dict)
    factors: list[ScoreFactor] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    data_inventory: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    scan_id: str
    status: str = "complete"
    inputs: ScanRequest
    findings: list[Finding] = Field(default_factory=list)
    lead_registry: list[Lead] = Field(default_factory=list)
    exposure_score: int = Field(default=0, ge=0, le=100)
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    kill_chains: list[dict] = Field(default_factory=list)  # attack path narratives
    actions: list[dict] = Field(default_factory=list)  # prioritized remediation steps
    audit_trail: list[dict] = Field(
        default_factory=list
    )  # chronological agent steps
    applicable_laws: list[dict] = Field(
        default_factory=list
    )  # based on location
    privacy_resources: list[dict] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0
