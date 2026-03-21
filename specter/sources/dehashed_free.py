from __future__ import annotations

import asyncio

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class LeakCheckSource(BaseSource):
    name = "leakcheck"
    description = (
        "Check if an email appears in known data leaks using free breach-check services "
        "(emailrep.io, breach directory lookups). Returns breach exposure data, email "
        "reputation, and whether credentials have been leaked."
    )
    input_types = ["email"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_leakcheck",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to check for leaked credentials",
                    }
                },
                "required": ["email"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        email = input_value.strip().lower()
        findings: list[Finding] = []

        # Run checks concurrently
        results = await asyncio.gather(
            self._check_emailrep(email),
            self._check_leak_databases(email),
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _check_emailrep(self, email: str) -> list[Finding]:
        """Check email reputation via emailrep.io (free, no key, rate limited)."""
        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(
                    f"https://emailrep.io/{email}",
                    headers={
                        "User-Agent": "Specter-Scanner",
                        "Accept": "application/json",
                    },
                )

            if resp.status_code == 429:
                # Rate limited — wait and retry once
                await asyncio.sleep(2)
                async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                    resp = await client.get(
                        f"https://emailrep.io/{email}",
                        headers={
                            "User-Agent": "Specter-Scanner",
                            "Accept": "application/json",
                        },
                    )

            if resp.status_code != 200:
                return []

            data = resp.json()
            reputation = data.get("reputation", "none")
            details = data.get("details", {})
            credentials_leaked = details.get("credentials_leaked", False)
            data_breach = details.get("data_breach", False)
            malicious_activity = details.get("malicious_activity", False)
            profiles = details.get("profiles", [])

            leads: list[str] = []
            for profile in profiles:
                leads.append(f"url:{profile}")

            severity = "info"
            if credentials_leaked:
                severity = "critical"
            elif data_breach:
                severity = "high"
            elif malicious_activity:
                severity = "medium"

            return [
                Finding(
                    source="leakcheck",
                    source_url=f"https://emailrep.io/{email}",
                    finding_type="breach" if data_breach or credentials_leaked else "account_exists",
                    data={
                        "reputation": reputation,
                        "credentials_leaked": credentials_leaked,
                        "data_breach": data_breach,
                        "malicious_activity": malicious_activity,
                        "profiles_found": profiles,
                        "domain_exists": details.get("domain_exists", True),
                        "free_provider": details.get("free_provider", False),
                        "deliverable": details.get("deliverable", False),
                        "spoofable": details.get("spoofable", False),
                        "spam": details.get("spam", False),
                        "suspicious_tld": details.get("suspicious_tld", False),
                        "days_since_domain_creation": details.get("days_since_domain_creation", 0),
                    },
                    confidence="high",
                    input_used="email",
                    original_input=email,
                    leads_to=leads,
                    severity=severity,
                )
            ]
        except (httpx.HTTPError, httpx.TimeoutException):
            return []

    async def _check_leak_databases(self, email: str) -> list[Finding]:
        """Check if email appears in known leak compilation databases."""
        findings: list[Finding] = []

        # Check multiple free breach-check services
        services = [
            {
                "name": "BreachDirectory",
                "url": f"https://breachdirectory.org/api/entries?email={email}",
            },
            {
                "name": "LeakPeek",
                "url": f"https://leakpeek.com/api/search?query={email}&type=email",
            },
        ]

        for svc in services:
            try:
                async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                    resp = await client.get(
                        svc["url"],
                        headers={"User-Agent": "Specter-Scanner"},
                    )

                if resp.status_code != 200:
                    continue

                try:
                    data = resp.json()
                except Exception:
                    continue

                # Handle different response formats
                entries = []
                if isinstance(data, dict):
                    if data.get("success") and data.get("result"):
                        entries = data["result"] if isinstance(data["result"], list) else []
                    elif data.get("results"):
                        entries = data["results"] if isinstance(data["results"], list) else []
                elif isinstance(data, list):
                    entries = data

                for entry in entries[:10]:
                    if not isinstance(entry, dict):
                        continue
                    source_name = entry.get("source", entry.get("name", svc["name"]))
                    has_password = entry.get("has_password", False)

                    findings.append(
                        Finding(
                            source="leakcheck",
                            source_url=svc["url"].split("?")[0],
                            finding_type="leaked_credential" if has_password else "breach",
                            data={
                                "service": svc["name"],
                                "breach_source": source_name,
                                "has_password": has_password,
                            },
                            confidence="high",
                            input_used="email",
                            original_input=email,
                            leads_to=[
                                f"credential_risk:password exposed in {source_name}"
                            ] if has_password else [],
                            severity="critical" if has_password else "high",
                        )
                    )

            except (httpx.HTTPError, httpx.TimeoutException):
                continue

        return findings
