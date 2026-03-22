from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone

import anthropic

from specter.agent.prompts import RISK_ASSESSMENT_PROMPT, SYSTEM_PROMPT
from specter.agent.scan_store import ScanState, ScanStatus, ScanStore
from specter.agent.schemas import Finding, Lead, ScanReport
from specter.config import (
    ANTHROPIC_API_KEY,
    BREACHDIRECTORY_RAPIDAPI_KEY,
    CLAUDE_MODEL,
    MAX_SCAN_ROUNDS,
    SUBPROCESS_TIMEOUT,
)
from specter.agent.username_gen import build_username_candidate_sets
from specter.risk.actions import generate_actions, get_applicable_laws
from specter.risk.kill_chain import generate_kill_chains
from specter.risk.scorer import compute_exposure_score
from specter.sources import SOURCE_REGISTRY

logger = logging.getLogger("specter.orchestrator")

SEARCHABLE_LEAD_TYPES = {"email", "username", "phone", "domain", "url", "name"}
LEAD_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


class Orchestrator:
    """
    Core agent loop using Claude tool-calling to scan data sources,
    chain findings across rounds, and produce a risk-scored audit report.
    """

    def __init__(self, scan_state: ScanState, store: ScanStore) -> None:
        self.state = scan_state
        self.store = store
        self.client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        self.tools = self._build_tool_definitions()
        self.source_instances = self._instantiate_sources()
        self.messages: list[dict] = []
        self.step_counter = 0
        self.start_time = time.time()
        self.tool_result_cache: dict[str, dict] = {}
        self.current_round = 0

    # ── Setup ───────────────────────────────────────────────────────────

    def _build_tool_definitions(self) -> list[dict]:
        """Build Anthropic-format tool definitions from all available sources."""
        tools: list[dict] = []
        for name, source_cls in SOURCE_REGISTRY.items():
            if self._source_enabled(name, source_cls):
                tools.append(source_cls.tool_definition())
                logger.info("Tool registered: scan_%s", name)
            else:
                logger.info("Tool unavailable or disabled: scan_%s", name)
        return tools

    def _instantiate_sources(self) -> dict[str, object]:
        """Create one instance of each available source."""
        instances: dict[str, object] = {}
        for name, cls in SOURCE_REGISTRY.items():
            if not self._source_enabled(name, cls):
                continue
            instance = cls()
            setattr(instance, "scan_request", self.state.request)
            instances[name] = instance
        return instances

    def _source_enabled(self, name: str, source_cls: type) -> bool:
        """Filter sources by environment and per-scan opt-in flags."""
        if not source_cls.is_available():
            return False

        req = self.state.request
        if name == "leakcheck":
            return req.use_emailrep or (
                req.use_breachdirectory and bool(BREACHDIRECTORY_RAPIDAPI_KEY)
            )

        if name == "paste_search":
            return True

        return True

    def _initial_username_candidates(self) -> dict[str, list[str]]:
        known = [self.state.request.username] if self.state.request.username else []
        return build_username_candidate_sets(self.state.request.full_name, known)

    def _build_lead_context_summary(self) -> str:
        confirmed_inputs: list[str] = []
        auto_search: list[str] = []
        deferred: list[str] = []

        for lead in self.state.lead_registry:
            label = f"{lead.type}:{lead.value}"
            if lead.origin_kind == "user_input":
                confirmed_inputs.append(label)
            elif lead.status in {"auto_search", "promoted"}:
                auto_search.append(label)
            elif lead.status == "deferred":
                deferred.append(label)

        parts: list[str] = []
        if confirmed_inputs:
            parts.append(
                "Confirmed inputs: " + ", ".join(confirmed_inputs[:8])
            )
        if auto_search:
            parts.append(
                "Auto-search leads: " + ", ".join(auto_search[:8])
            )
        if deferred:
            parts.append(
                "Deferred leads (do not search unless promoted by evidence): "
                + ", ".join(deferred[:12])
            )
        return "\n".join(parts)

    def _build_initial_message(self) -> str:
        """Construct the first user message from the scan request."""
        req = self.state.request
        parts = ["Scan the following target for digital exposure:\n"]
        if req.full_name:
            parts.append(f"- Full Name: {req.full_name}")
        if req.email:
            parts.append(f"- Email: {req.email}")
        if req.username:
            parts.append(f"- Username (confirmed): {req.username}")
        if req.phone:
            parts.append(f"- Phone: {req.phone}")
        if req.location:
            parts.append(f"- Location: {req.location}")

        lead_context = self._build_lead_context_summary()
        if lead_context:
            parts.append(
                "\nCurrent lead registry:\n" + lead_context
            )

        parts.append(
            "\nUse all relevant tools to discover digital exposure. "
            "Chain findings across rounds — extract new leads from results and search them. "
            f"You have a maximum of {MAX_SCAN_ROUNDS} rounds."
        )
        return "\n".join(parts)

    def _normalize_lead_value(self, lead_type: str, value: str) -> str:
        cleaned = " ".join(str(value).strip().split())
        if not cleaned or lead_type not in SEARCHABLE_LEAD_TYPES:
            return ""
        if lead_type in {"email", "username", "domain"}:
            return cleaned.lower()
        if lead_type == "phone":
            return re.sub(r"\s+", "", cleaned)
        if lead_type == "url":
            return cleaned
        return cleaned

    def _lead_key(self, lead_type: str, value: str) -> str:
        normalized = self._normalize_lead_value(lead_type, value)
        if not normalized:
            return ""
        return f"{lead_type}:{normalized}"

    def _get_lead_by_key(self, canonical_key: str) -> Lead | None:
        lead_id = self.state.lead_lookup.get(canonical_key)
        if not lead_id:
            return None
        for lead in self.state.lead_registry:
            if lead.lead_id == lead_id:
                return lead
        return None

    @staticmethod
    def _lead_confidence_value(confidence: str) -> int:
        return LEAD_CONFIDENCE_ORDER.get(confidence, 0)

    @staticmethod
    def _confidence_from_value(value: int) -> str:
        for label, rank in LEAD_CONFIDENCE_ORDER.items():
            if rank == value:
                return label
        return "low"

    def _merge_lead_confidence(
        self, existing_confidence: str, incoming_confidence: str, source_count: int
    ) -> str:
        rank = max(
            self._lead_confidence_value(existing_confidence),
            self._lead_confidence_value(incoming_confidence),
        )
        if source_count >= 2 and rank < self._lead_confidence_value("high"):
            rank += 1
        return self._confidence_from_value(rank)

    def _support_reference(self, finding: Finding) -> str:
        return f"finding:{finding.source}:{finding.finding_type}"

    def _lead_searchable_from_finding(self, lead_type: str, finding: Finding) -> bool:
        if lead_type not in SEARCHABLE_LEAD_TYPES:
            return False
        if lead_type == "username":
            return finding.confidence in {"high", "medium"}
        return finding.confidence in {"high", "medium"}

    def _build_lead_registry_context(self) -> dict[str, list[str]]:
        buckets = {
            "confirmed": [],
            "auto_search": [],
            "deferred": [],
            "searched": [],
        }
        for lead in self.state.lead_registry:
            label = f"{lead.type}:{lead.value}"
            if lead.status == "confirmed":
                buckets["confirmed"].append(label)
            elif lead.status in {"auto_search", "promoted"}:
                buckets["auto_search"].append(label)
            elif lead.status == "deferred":
                buckets["deferred"].append(label)
            elif lead.status == "searched":
                buckets["searched"].append(label)
        return buckets

    def _build_round_context_text(self, round_num: int) -> str:
        registry = self._build_lead_registry_context()
        parts = [f"Structured lead registry before round {round_num}:"]
        if registry["confirmed"]:
            parts.append("Confirmed inputs: " + ", ".join(registry["confirmed"][:8]))
        if registry["auto_search"]:
            parts.append("Auto-search leads: " + ", ".join(registry["auto_search"][:8]))
        if registry["searched"]:
            parts.append("Already searched leads: " + ", ".join(registry["searched"][:8]))
        if registry["deferred"]:
            parts.append(
                "Deferred leads (do not search unless promoted by evidence): "
                + ", ".join(registry["deferred"][:12])
            )
        return "\n".join(parts)

    async def _register_seed_lead(
        self,
        lead_type: str,
        value: str,
        origin_kind: str,
        status: str,
        confidence: str,
        why: str,
        entry_type: str,
    ) -> None:
        canonical_key = self._lead_key(lead_type, value)
        if not canonical_key or self._get_lead_by_key(canonical_key):
            return

        lead = Lead(
            type=lead_type,
            value=self._normalize_lead_value(lead_type, value),
            origin_kind=origin_kind,
            status=status,
            confidence=confidence,
            round_discovered=0,
            supporting_sources=["user_input"] if origin_kind == "user_input" else [],
            why=why,
        )
        await self.store.add_or_update_lead(self.state.scan_id, canonical_key, lead)
        await self._log_audit(
            entry_type=entry_type,
            round=0,
            action=f"Registered {lead_type} lead",
            result_summary=f"{lead_type}:{lead.value}",
            reasoning=why,
            lead=lead.model_dump(mode="json"),
            supports=["user_input"] if origin_kind == "user_input" else ["generated_from_name"],
        )

    async def _seed_initial_leads(self) -> None:
        req = self.state.request
        await self._register_seed_lead(
            "name",
            req.full_name,
            "user_input",
            "confirmed",
            "high",
            "Provided directly by the user",
            "lead_generated",
        )
        if req.email:
            await self._register_seed_lead(
                "email",
                req.email,
                "user_input",
                "confirmed",
                "high",
                "Provided directly by the user",
                "lead_generated",
            )
        if req.phone:
            await self._register_seed_lead(
                "phone",
                req.phone,
                "user_input",
                "confirmed",
                "high",
                "Provided directly by the user",
                "lead_generated",
            )
        if req.username:
            await self._register_seed_lead(
                "username",
                req.username,
                "user_input",
                "confirmed",
                "high",
                "Provided directly by the user",
                "lead_generated",
            )

        username_candidates = self._initial_username_candidates()
        for username in username_candidates["auto_search"]:
            if req.username and username == req.username.strip().lower():
                continue
            await self._register_seed_lead(
                "username",
                username,
                "username_permutation",
                "auto_search",
                "medium",
                "Conservative full-name permutation selected for immediate searching",
                "lead_generated",
            )

        for username in username_candidates["deferred"]:
            await self._register_seed_lead(
                "username",
                username,
                "username_permutation",
                "deferred",
                "low",
                "Full-name permutation kept visible but deferred until evidence promotes it",
                "lead_deferred",
            )

    def _parse_lead_token(self, token: str) -> tuple[str, str] | None:
        if ":" not in token:
            return None
        lead_type, raw_value = token.split(":", 1)
        lead_type = lead_type.strip().lower()
        raw_value = raw_value.strip()
        if not raw_value or lead_type not in SEARCHABLE_LEAD_TYPES:
            return None
        return lead_type, raw_value

    async def _register_finding_leads(self, finding: Finding) -> None:
        for token in finding.leads_to:
            parsed = self._parse_lead_token(token)
            if not parsed:
                continue

            lead_type, raw_value = parsed
            canonical_key = self._lead_key(lead_type, raw_value)
            if not canonical_key:
                continue

            existing = self._get_lead_by_key(canonical_key)
            incoming_confidence = finding.confidence
            should_auto_search = self._lead_searchable_from_finding(
                lead_type, finding
            )
            support_ref = self._support_reference(finding)
            normalized_value = self._normalize_lead_value(lead_type, raw_value)
            why = (
                f"Derived from {finding.source} {finding.finding_type} "
                f"({finding.finding_id})"
            )

            if not existing:
                status = "auto_search" if should_auto_search else "deferred"
                lead = Lead(
                    type=lead_type,
                    value=normalized_value,
                    origin_kind="source_derived",
                    status=status,
                    confidence=incoming_confidence,
                    round_discovered=self.current_round,
                    supporting_finding_ids=[finding.finding_id],
                    supporting_sources=[finding.source],
                    why=why,
                )
                await self.store.add_or_update_lead(
                    self.state.scan_id, canonical_key, lead
                )
                await self._log_audit(
                    entry_type="lead_generated" if status != "deferred" else "lead_deferred",
                    round=self.current_round,
                    action=f"Derived {lead_type} lead",
                    result_summary=f"{lead_type}:{normalized_value}",
                    reasoning=why,
                    lead=lead.model_dump(mode="json"),
                    supports=[support_ref],
                    connection={
                        "from": f"finding:{finding.finding_id}",
                        "to": f"{lead_type}:{normalized_value}",
                        "why": why,
                    },
                )
                continue

            updated_sources = sorted(
                {*(existing.supporting_sources or []), finding.source}
            )
            updated_finding_ids = list(
                dict.fromkeys(
                    [*(existing.supporting_finding_ids or []), finding.finding_id]
                )
            )
            updated_confidence = self._merge_lead_confidence(
                existing.confidence,
                incoming_confidence,
                len(updated_sources),
            )
            confidence_change = None
            if updated_confidence != existing.confidence:
                confidence_change = {
                    "from": existing.confidence,
                    "to": updated_confidence,
                }

            new_status = existing.status
            promoted = False
            if existing.status == "deferred" and should_auto_search:
                new_status = "promoted"
                promoted = True
            elif existing.status == "deferred" and len(updated_sources) >= 2:
                new_status = "promoted"
                promoted = True

            updated_lead = existing.model_copy(
                update={
                    "supporting_sources": updated_sources,
                    "supporting_finding_ids": updated_finding_ids,
                    "confidence": updated_confidence,
                    "status": new_status,
                    "why": why,
                }
            )
            await self.store.add_or_update_lead(
                self.state.scan_id, canonical_key, updated_lead
            )

            await self._log_audit(
                entry_type="lead_promoted" if promoted else "connection_made",
                round=self.current_round,
                action=f"Updated {lead_type} lead",
                result_summary=f"{lead_type}:{normalized_value}",
                reasoning=why,
                lead=updated_lead.model_dump(mode="json"),
                supports=[support_ref],
                connection={
                    "from": f"finding:{finding.finding_id}",
                    "to": f"{lead_type}:{normalized_value}",
                    "why": why,
                },
                confidence_change=confidence_change,
            )

    def _extract_visible_trace(
        self, text_blocks: list[str]
    ) -> tuple[dict | None, str]:
        combined = "\n".join(block.strip() for block in text_blocks if block.strip()).strip()
        if not combined:
            return None, ""

        match = re.search(r"<trace>(.*?)</trace>", combined, re.DOTALL | re.IGNORECASE)
        if not match:
            return None, combined

        raw_json = match.group(1).strip()
        try:
            trace = json.loads(raw_json)
        except json.JSONDecodeError:
            return None, combined

        if not isinstance(trace, dict):
            return None, combined

        trace.setdefault("hypotheses", [])
        trace.setdefault("lead_decisions", [])
        trace.setdefault("connections", [])
        trace.setdefault("planned_tools", [])
        leftover = (combined[: match.start()] + combined[match.end() :]).strip()
        return trace, leftover

    async def _log_round_plan(
        self, round_num: int, trace: dict | None, raw_text: str
    ) -> None:
        if trace:
            supports: list[str] = []
            for decision in trace.get("lead_decisions", []):
                for support in decision.get("supports", []):
                    if support not in supports:
                        supports.append(support)
            summary = "; ".join(trace.get("hypotheses", [])[:2]) or (
                f"{len(trace.get('lead_decisions', []))} lead decisions"
            )
            await self._log_audit(
                entry_type="round_plan",
                round=round_num,
                action=f"Round {round_num} plan",
                result_summary=summary,
                reasoning=raw_text or "Claude emitted a structured visible planning trace",
                supports=supports[:6],
                planned_tools=trace.get("planned_tools", []),
                hypotheses=trace.get("hypotheses", []),
                lead_decisions=trace.get("lead_decisions", []),
                connections=trace.get("connections", []),
            )
            return

        if raw_text:
            await self._log_audit(
                entry_type="round_plan",
                round=round_num,
                action=f"Round {round_num} plan",
                result_summary=raw_text[:400],
                reasoning="Claude emitted an unstructured visible planning note",
            )

    def _match_input_lead(self, input_type: str, input_value: str) -> Lead | None:
        canonical_key = self._lead_key(input_type, input_value)
        if not canonical_key:
            return None
        return self._get_lead_by_key(canonical_key)

    def _lead_search_allowed(self, lead: Lead | None) -> tuple[bool, str]:
        if lead is None:
            return True, ""
        if lead.status in {"confirmed", "auto_search", "promoted", "searched"}:
            return True, ""
        if lead.status == "deferred":
            return (
                False,
                "Lead is deferred until stronger evidence promotes it",
            )
        if lead.status == "pending_user_confirmation":
            return (
                False,
                "Lead is waiting for user confirmation before searching",
            )
        if lead.status == "rejected":
            return False, "Lead was explicitly rejected"
        return False, f"Lead status {lead.status} is not searchable"

    async def _mark_lead_searched(self, lead: Lead | None) -> Lead | None:
        if lead is None:
            return None
        if lead.status in {"confirmed", "searched"}:
            return lead
        updated = lead.model_copy(update={"status": "searched"})
        await self.store.add_or_update_lead(
            self.state.scan_id,
            self._lead_key(updated.type, updated.value),
            updated,
        )
        return updated

    # ── Main loop ───────────────────────────────────────────────────────

    async def run(self) -> None:
        """Execute the full scan orchestration."""
        await self.store.update_status(self.state.scan_id, ScanStatus.RUNNING)
        await self.state.event_bus.publish(
            {
                "type": "scan_started",
                "scan_id": self.state.scan_id,
                "sources_count": len(self.tools),
            }
        )

        await self._seed_initial_leads()

        # Initial message
        user_msg = self._build_initial_message()
        self.messages.append({"role": "user", "content": user_msg})

        await self._log_audit(
            entry_type="scan_lifecycle",
            action="Scan started",
            result_summary=f"Target: {self.state.request.full_name}, {len(self.tools)} tools available",
            reasoning="Beginning multi-round OSINT scan",
        )

        # Agent loop
        round_num = 0
        for round_num in range(1, MAX_SCAN_ROUNDS + 1):
            self.current_round = round_num
            await self.state.event_bus.publish(
                {"type": "round_start", "round": round_num}
            )
            await self._log_audit(
                entry_type="round_summary",
                round=round_num,
                action=f"Round {round_num} started",
                result_summary=f"Findings so far: {len(self.state.findings)}",
                reasoning=f"Starting scan round {round_num}/{MAX_SCAN_ROUNDS}",
            )

            # Call Claude
            try:
                response = await self.client.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=4096,
                    system=SYSTEM_PROMPT,
                    tools=self.tools,
                    messages=self.messages,
                )
            except anthropic.APIError as e:
                logger.error("Anthropic API error: %s", e)
                await self._log_audit(
                    entry_type="scan_lifecycle",
                    round=round_num,
                    action="API error",
                    result_summary=str(e),
                    reasoning="Claude API call failed",
                )
                break

            # If Claude is done (no more tool calls)
            if response.stop_reason == "end_turn":
                # Extract any final text
                text_blocks = [
                    b.text for b in response.content if hasattr(b, "text")
                ]
                if text_blocks:
                    await self._log_audit(
                        entry_type="scan_lifecycle",
                        round=round_num,
                        action="Agent finished scanning",
                        result_summary=" ".join(text_blocks)[:500],
                        reasoning="Claude decided scanning is complete",
                    )
                break

            # Process tool calls
            if response.stop_reason == "tool_use":
                # Append the assistant's message (contains tool_use blocks)
                self.messages.append(
                    {
                        "role": "assistant",
                        "content": [self._serialize_block(b) for b in response.content],
                    }
                )

                # Extract tool_use blocks
                tool_uses = [
                    b for b in response.content if b.type == "tool_use"
                ]

                # Also extract any text blocks (Claude's reasoning)
                text_blocks = [
                    b.text for b in response.content if hasattr(b, "text") and b.type == "text"
                ]
                if text_blocks:
                    trace, raw_text = self._extract_visible_trace(text_blocks)
                    await self._log_round_plan(round_num, trace, raw_text)

                # Execute all tool calls in parallel
                logger.info(
                    "Round %d: executing %d tool calls in parallel",
                    round_num,
                    len(tool_uses),
                )
                results = await asyncio.gather(
                    *[self._execute_tool(tu) for tu in tool_uses],
                    return_exceptions=True,
                )

                # Build tool_result content blocks
                result_blocks: list[dict] = []
                for tu, result in zip(tool_uses, results):
                    if isinstance(result, Exception):
                        content = json.dumps(
                            {"error": str(result), "findings": []}
                        )
                        is_error = True
                    else:
                        content = json.dumps(result)
                        is_error = False

                    result_blocks.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tu.id,
                            "content": content,
                            "is_error": is_error,
                        }
                    )

                self.messages.append({"role": "user", "content": result_blocks})

                await self.state.event_bus.publish(
                    {
                        "type": "round_complete",
                        "round": round_num,
                        "findings_count": len(self.state.findings),
                        "new_leads": sum(
                            len(f.leads_to) for f in self.state.findings
                        ),
                    }
                )
                await self._log_audit(
                    entry_type="round_summary",
                    round=round_num,
                    action=f"Round {round_num} complete",
                    result_summary=(
                        f"{len(self.state.findings)} findings total, "
                        f"{sum(len(f.leads_to) for f in self.state.findings)} linked leads"
                    ),
                    reasoning="Completed visible planning and source execution for this round",
                )

        # ── Risk Assessment ─────────────────────────────────────────────
        await self._generate_risk_assessment(round_num)

    # ── Tool Execution ──────────────────────────────────────────────────

    async def _execute_tool(self, tool_use) -> dict:
        """Execute a single tool call, return results dict for Claude."""
        tool_name = tool_use.name  # e.g., "scan_hibp"
        source_name = tool_name.removeprefix("scan_")
        inputs = tool_use.input
        input_type, input_value = self._extract_input(inputs, source_name)
        cache_key = json.dumps(
            {"tool": source_name, "input": inputs},
            sort_keys=True,
            default=str,
        )
        input_lead = self._match_input_lead(input_type, input_value)
        can_search_lead, lead_block_reason = self._lead_search_allowed(input_lead)
        if can_search_lead:
            input_lead = await self._mark_lead_searched(input_lead)

        # Log the tool call
        await self.state.event_bus.publish(
            {"type": "tool_call", "tool": source_name, "input": inputs}
        )
        await self._log_audit(
            entry_type="tool_call",
            round=self.current_round,
            action=f"Calling {source_name}",
            result_summary=f"Input: {json.dumps(inputs)[:200]}",
            reasoning=f"Claude requested scan via {source_name}",
            lead=input_lead.model_dump(mode="json") if input_lead else None,
            supports=(input_lead.supporting_sources if input_lead else None),
        )

        if not can_search_lead:
            await self._log_audit(
                entry_type="lead_deferred",
                round=self.current_round,
                action=f"{source_name} skipped",
                result_summary=f"Skipped search for {input_type}:{input_value}",
                reasoning=lead_block_reason,
                lead=input_lead.model_dump(mode="json") if input_lead else None,
                supports=(input_lead.supporting_sources if input_lead else None),
            )
            await self.state.event_bus.publish(
                {
                    "type": "tool_result",
                    "tool": source_name,
                    "finding_count": 0,
                }
            )
            return {
                "findings": [],
                "count": 0,
                "skipped": True,
                "reason": lead_block_reason,
            }

        source = self.source_instances.get(source_name)
        if not source:
            return {"error": f"Unknown source: {source_name}", "findings": []}

        cached = self.tool_result_cache.get(cache_key)
        if cached is not None:
            finding_count = cached.get("count", 0)
            await self._log_audit(
                entry_type="tool_result",
                round=self.current_round,
                action=f"{source_name} reused",
                result_summary=f"Using cached result from this scan ({finding_count} findings)",
                reasoning="Skipping duplicate source call within the same run",
                lead=input_lead.model_dump(mode="json") if input_lead else None,
            )
            await self.state.event_bus.publish(
                {
                    "type": "tool_result",
                    "tool": source_name,
                    "finding_count": finding_count,
                }
            )
            return cached

        try:
            findings = await asyncio.wait_for(
                source.scan(input_type, input_value),
                timeout=SUBPROCESS_TIMEOUT,
            )
        except asyncio.TimeoutError:
            msg = f"{source_name} timed out after {SUBPROCESS_TIMEOUT}s"
            logger.warning(msg)
            await self._log_audit(
                entry_type="tool_result",
                round=self.current_round,
                action=f"{source_name} timeout",
                result_summary=msg,
                lead=input_lead.model_dump(mode="json") if input_lead else None,
            )
            return {"error": msg, "findings": []}
        except Exception as e:
            msg = f"{source_name} failed: {e}"
            logger.warning(msg, exc_info=True)
            await self._log_audit(
                entry_type="tool_result",
                round=self.current_round,
                action=f"{source_name} error",
                result_summary=msg,
                lead=input_lead.model_dump(mode="json") if input_lead else None,
            )
            return {"error": msg, "findings": []}

        # Store findings
        for f in findings:
            await self.store.add_finding(self.state.scan_id, f)
            await self._register_finding_leads(f)

        new_leads = []
        for f in findings:
            new_leads.extend(f.leads_to)

        await self._log_audit(
            entry_type="tool_result",
            round=self.current_round,
            action=f"{source_name} completed",
            result_summary=f"Found {len(findings)} findings",
            new_leads=new_leads[:10] if new_leads else None,
            reasoning=f"{source_name} scan finished successfully",
            lead=input_lead.model_dump(mode="json") if input_lead else None,
            supports=(
                [f"{finding.source}:{finding.finding_type}" for finding in findings[:5]]
                if findings
                else None
            ),
        )

        await self.state.event_bus.publish(
            {
                "type": "tool_result",
                "tool": source_name,
                "finding_count": len(findings),
            }
        )

        result = {
            "findings": [f.model_dump(mode="json") for f in findings],
            "count": len(findings),
        }
        self.tool_result_cache[cache_key] = result
        return result

    def _extract_input(
        self, inputs: dict, source_name: str
    ) -> tuple[str, str]:
        """Extract input_type and input_value from tool call inputs."""
        # Map common parameter names to input types
        for key in ("email", "username", "phone", "domain", "url", "query"):
            if key in inputs:
                input_type = key
                if key == "query":
                    # For google_search and crtsh, map query to appropriate type
                    input_type = inputs.get("query_type", "name")
                return input_type, inputs[key]

        # Fallback: use the first value
        if inputs:
            key = next(iter(inputs))
            return key, inputs[key]

        return "unknown", ""

    # ── Risk Assessment ─────────────────────────────────────────────────

    async def _generate_risk_assessment(self, rounds_completed: int) -> None:
        """Final step: produce the risk-scored audit report."""
        await self.state.event_bus.publish(
            {"type": "status", "status": "generating_report"}
        )
        await self._log_audit(
            entry_type="scan_lifecycle",
            round=rounds_completed,
            action="Generating risk assessment",
            result_summary=f"Analyzing {len(self.state.findings)} findings from {rounds_completed} rounds",
        )

        findings = self.state.findings

        # Deterministic risk scoring (fallback)
        fallback_score = compute_exposure_score(findings)
        fallback_chains = generate_kill_chains(findings)
        fallback_actions = generate_actions(findings, self.state.request.location)
        applicable_laws = get_applicable_laws(self.state.request.location)

        # Try to get Claude's assessment
        exposure_score = fallback_score
        kill_chains = fallback_chains
        actions = fallback_actions
        executive_summary = ""

        if findings:
            try:
                findings_json = json.dumps(
                    [f.model_dump(mode="json") for f in findings], indent=2
                )
                # Truncate if too long
                if len(findings_json) > 50000:
                    findings_json = findings_json[:50000] + "\n... (truncated)"

                assessment_messages = [
                    {
                        "role": "user",
                        "content": RISK_ASSESSMENT_PROMPT + findings_json,
                    }
                ]

                response = await self.client.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=4096,
                    system=SYSTEM_PROMPT,
                    messages=assessment_messages,
                )

                text = "".join(
                    b.text for b in response.content if hasattr(b, "text")
                )

                # Parse Claude's JSON response
                assessment = json.loads(text)

                exposure_score = assessment.get("exposure_score", fallback_score)
                executive_summary = assessment.get("executive_summary", "")

                if assessment.get("kill_chains"):
                    kill_chains = assessment["kill_chains"]
                if assessment.get("actions"):
                    actions = assessment["actions"]
                if assessment.get("applicable_laws"):
                    applicable_laws = assessment["applicable_laws"]

            except (json.JSONDecodeError, anthropic.APIError) as e:
                logger.warning(
                    "Failed to parse Claude's risk assessment, using fallback: %s", e
                )
                executive_summary = (
                    f"Specter scanned {len(findings)} data points across multiple sources. "
                    f"The deterministic risk score is {fallback_score}/100."
                )

        scan_duration = time.time() - self.start_time

        report = ScanReport(
            scan_id=self.state.scan_id,
            inputs=self.state.request,
            findings=findings,
            lead_registry=self.state.lead_registry,
            exposure_score=min(100, max(0, exposure_score)),
            kill_chains=kill_chains,
            actions=actions,
            audit_trail=self.state.audit_trail,
            applicable_laws=applicable_laws,
            scan_duration_seconds=round(scan_duration, 2),
        )

        await self.store.set_report(self.state.scan_id, report)

        await self.state.event_bus.publish(
            {
                "type": "risk_assessment",
                "score": report.exposure_score,
                "kill_chains": report.kill_chains,
                "actions_count": len(report.actions),
            }
        )

        await self._log_audit(
            entry_type="scan_lifecycle",
            round=rounds_completed,
            action="Scan complete",
            result_summary=f"Exposure score: {report.exposure_score}/100, "
            f"{len(report.kill_chains)} attack paths, "
            f"{len(report.actions)} remediation actions",
            reasoning=f"Completed in {scan_duration:.1f}s across {rounds_completed} rounds",
        )

        logger.info(
            "Scan %s complete: score=%d, findings=%d, duration=%.1fs",
            self.state.scan_id,
            report.exposure_score,
            len(findings),
            scan_duration,
        )

    # ── Helpers ──────────────────────────────────────────────────────────

    async def _log_audit(
        self,
        action: str,
        result_summary: str = "",
        new_leads: list[str] | None = None,
        reasoning: str = "",
        entry_type: str = "audit",
        round: int | None = None,
        lead: dict | None = None,
        supports: list[str] | None = None,
        planned_tools: list[dict] | None = None,
        connection: dict | None = None,
        confidence_change: dict | None = None,
        hypotheses: list[str] | None = None,
        lead_decisions: list[dict] | None = None,
        connections: list[dict] | None = None,
    ) -> None:
        """Add an entry to the audit trail."""
        self.step_counter += 1
        entry = {
            "step": self.step_counter,
            "entry_type": entry_type,
            "action": action,
            "result_summary": result_summary,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if round is not None:
            entry["round"] = round
        if new_leads:
            entry["new_leads"] = new_leads
        if reasoning:
            entry["reasoning"] = reasoning
        if lead:
            entry["lead"] = lead
        if supports:
            entry["supports"] = supports
        if planned_tools:
            entry["planned_tools"] = planned_tools
        if connection:
            entry["connection"] = connection
        if confidence_change:
            entry["confidence_change"] = confidence_change
        if hypotheses:
            entry["hypotheses"] = hypotheses
        if lead_decisions:
            entry["lead_decisions"] = lead_decisions
        if connections:
            entry["connections"] = connections

        await self.store.add_audit_entry(self.state.scan_id, entry)

    @staticmethod
    def _serialize_block(block) -> dict:
        """Serialize an Anthropic content block to a dict for message history."""
        if block.type == "text":
            return {"type": "text", "text": block.text}
        elif block.type == "tool_use":
            return {
                "type": "tool_use",
                "id": block.id,
                "name": block.name,
                "input": block.input,
            }
        return {"type": block.type}
