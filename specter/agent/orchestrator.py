from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import anthropic

from specter.agent.prompts import RISK_ASSESSMENT_PROMPT, SYSTEM_PROMPT
from specter.agent.scan_store import ScanState, ScanStatus, ScanStore
from specter.agent.schemas import Finding, ScanReport
from specter.config import (
    ANTHROPIC_API_KEY,
    BREACHDIRECTORY_RAPIDAPI_KEY,
    CLAUDE_MODEL,
    MAX_SCAN_ROUNDS,
    SUBPROCESS_TIMEOUT,
)
from specter.agent.username_gen import generate_username_permutations
from specter.risk.actions import generate_actions, get_applicable_laws
from specter.risk.kill_chain import generate_kill_chains
from specter.risk.scorer import compute_exposure_score
from specter.sources import SOURCE_REGISTRY

logger = logging.getLogger("specter.orchestrator")


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

        # Generate username permutations
        known = [req.username] if req.username else []
        permutations = generate_username_permutations(req.full_name, known)
        if permutations:
            parts.append(
                f"\n**Username permutations to search** (common patterns derived from name): "
                f"{', '.join(permutations)}"
            )
            parts.append(
                "Search these usernames with sherlock and maigret — they are likely "
                "Instagram, Twitter, TikTok, etc. handles. Focus on the most common "
                "patterns first (first.last, first_last, firstlast)."
            )

        parts.append(
            "\nUse all relevant tools to discover digital exposure. "
            "Chain findings across rounds — extract new leads from results and search them. "
            f"You have a maximum of {MAX_SCAN_ROUNDS} rounds."
        )
        return "\n".join(parts)

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

        # Initial message
        user_msg = self._build_initial_message()
        self.messages.append({"role": "user", "content": user_msg})

        await self._log_audit(
            action="Scan started",
            result_summary=f"Target: {self.state.request.full_name}, {len(self.tools)} tools available",
            reasoning="Beginning multi-round OSINT scan",
        )

        # Agent loop
        round_num = 0
        for round_num in range(1, MAX_SCAN_ROUNDS + 1):
            await self.state.event_bus.publish(
                {"type": "round_start", "round": round_num}
            )
            await self._log_audit(
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
                    await self._log_audit(
                        action=f"Agent reasoning (Round {round_num})",
                        result_summary=" ".join(text_blocks)[:500],
                        reasoning="Claude's plan for this round",
                    )

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

        # ── Risk Assessment ─────────────────────────────────────────────
        await self._generate_risk_assessment(round_num)

    # ── Tool Execution ──────────────────────────────────────────────────

    async def _execute_tool(self, tool_use) -> dict:
        """Execute a single tool call, return results dict for Claude."""
        tool_name = tool_use.name  # e.g., "scan_hibp"
        source_name = tool_name.removeprefix("scan_")
        inputs = tool_use.input
        cache_key = json.dumps(
            {"tool": source_name, "input": inputs},
            sort_keys=True,
            default=str,
        )

        # Log the tool call
        await self.state.event_bus.publish(
            {"type": "tool_call", "tool": source_name, "input": inputs}
        )
        await self._log_audit(
            action=f"Calling {source_name}",
            result_summary=f"Input: {json.dumps(inputs)[:200]}",
            reasoning=f"Claude requested scan via {source_name}",
        )

        source = self.source_instances.get(source_name)
        if not source:
            return {"error": f"Unknown source: {source_name}", "findings": []}

        cached = self.tool_result_cache.get(cache_key)
        if cached is not None:
            finding_count = cached.get("count", 0)
            await self._log_audit(
                action=f"{source_name} reused",
                result_summary=f"Using cached result from this scan ({finding_count} findings)",
                reasoning="Skipping duplicate source call within the same run",
            )
            await self.state.event_bus.publish(
                {
                    "type": "tool_result",
                    "tool": source_name,
                    "finding_count": finding_count,
                }
            )
            return cached

        # Determine input_type and input_value from the tool inputs
        input_type, input_value = self._extract_input(inputs, source_name)

        try:
            findings = await asyncio.wait_for(
                source.scan(input_type, input_value),
                timeout=SUBPROCESS_TIMEOUT,
            )
        except asyncio.TimeoutError:
            msg = f"{source_name} timed out after {SUBPROCESS_TIMEOUT}s"
            logger.warning(msg)
            await self._log_audit(
                action=f"{source_name} timeout", result_summary=msg
            )
            return {"error": msg, "findings": []}
        except Exception as e:
            msg = f"{source_name} failed: {e}"
            logger.warning(msg, exc_info=True)
            await self._log_audit(
                action=f"{source_name} error", result_summary=msg
            )
            return {"error": msg, "findings": []}

        # Store findings
        for f in findings:
            await self.store.add_finding(self.state.scan_id, f)

        new_leads = []
        for f in findings:
            new_leads.extend(f.leads_to)

        await self._log_audit(
            action=f"{source_name} completed",
            result_summary=f"Found {len(findings)} findings",
            new_leads=new_leads[:10] if new_leads else None,
            reasoning=f"{source_name} scan finished successfully",
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
        new_leads: Optional[list[str]] = None,
        reasoning: str = "",
    ) -> None:
        """Add an entry to the audit trail."""
        self.step_counter += 1
        entry = {
            "step": self.step_counter,
            "action": action,
            "result_summary": result_summary,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if new_leads:
            entry["new_leads"] = new_leads
        if reasoning:
            entry["reasoning"] = reasoning

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
