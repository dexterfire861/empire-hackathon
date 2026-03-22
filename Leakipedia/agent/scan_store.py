from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from Leakipedia.agent.schemas import Finding, Lead, ScanReport, ScanRequest


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class EventBus:
    """Fan-out event broadcaster for WebSocket streaming."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def publish(self, event: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # drop events for slow consumers


@dataclass
class ScanState:
    scan_id: str
    request: ScanRequest
    status: ScanStatus = ScanStatus.PENDING
    findings: list[Finding] = field(default_factory=list)
    lead_registry: list[Lead] = field(default_factory=list)
    audit_trail: list[dict] = field(default_factory=list)
    report: Optional[ScanReport] = None
    lead_lookup: dict[str, str] = field(default_factory=dict, repr=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    event_bus: EventBus = field(default_factory=EventBus)
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ScanStore:
    """In-memory scan state store."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanState] = {}

    async def create(self, request: ScanRequest) -> ScanState:
        scan_id = uuid.uuid4().hex[:12]
        state = ScanState(scan_id=scan_id, request=request)
        self._scans[scan_id] = state
        return state

    def get(self, scan_id: str) -> Optional[ScanState]:
        return self._scans.get(scan_id)

    async def add_finding(self, scan_id: str, finding: Finding) -> None:
        state = self._scans.get(scan_id)
        if not state:
            return
        async with state.lock:
            state.findings.append(finding)
        await state.event_bus.publish(
            {"type": "finding", "finding": finding.model_dump(mode="json")}
        )

    async def add_audit_entry(self, scan_id: str, entry: dict) -> None:
        state = self._scans.get(scan_id)
        if not state:
            return
        async with state.lock:
            state.audit_trail.append(entry)
        await state.event_bus.publish({"type": "audit_step", "step": entry})

    async def add_or_update_lead(
        self, scan_id: str, canonical_key: str, lead: Lead
    ) -> None:
        state = self._scans.get(scan_id)
        if not state:
            return
        async with state.lock:
            lead_id = state.lead_lookup.get(canonical_key)
            if lead_id:
                for index, existing in enumerate(state.lead_registry):
                    if existing.lead_id == lead_id:
                        state.lead_registry[index] = lead
                        break
            else:
                state.lead_lookup[canonical_key] = lead.lead_id
                state.lead_registry.append(lead)

    async def update_status(self, scan_id: str, status: ScanStatus) -> None:
        state = self._scans.get(scan_id)
        if not state:
            return
        async with state.lock:
            state.status = status

    async def set_report(self, scan_id: str, report: ScanReport) -> None:
        state = self._scans.get(scan_id)
        if not state:
            return
        async with state.lock:
            state.report = report
            state.status = ScanStatus.COMPLETE
        await state.event_bus.publish(
            {"type": "scan_complete", "report": report.model_dump(mode="json")}
        )
