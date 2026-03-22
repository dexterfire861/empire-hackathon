from __future__ import annotations

import asyncio

import httpx

from Leakipedia.agent.schemas import Finding
from Leakipedia.config import API_TIMEOUT, BREACHDIRECTORY_RAPIDAPI_KEY
from Leakipedia.sources.base import BaseSource, register_source


@register_source
class LeakCheckSource(BaseSource):
    name = "leakcheck"
    description = (
        "Check if an email appears in known data leaks using EmailRep and optional "
        "BreachDirectory lookups. Returns breach exposure data, email reputation, "
        "and whether credentials have been leaked."
    )
    input_types = ["email"]

    def __init__(self) -> None:
        self.scan_request = None

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
        checks = []

        checks.append(self._check_emailrep(email))

        if BREACHDIRECTORY_RAPIDAPI_KEY:
            checks.append(self._check_breachdirectory(email))

        if not checks:
            return findings

        results = await asyncio.gather(*checks, return_exceptions=True)

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
                        "User-Agent": "Leakipedia-Scanner",
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
                            "User-Agent": "Leakipedia-Scanner",
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

    async def _check_breachdirectory(self, email: str) -> list[Finding]:
        """Check BreachDirectory via RapidAPI."""
        findings: list[Finding] = []
        if not BREACHDIRECTORY_RAPIDAPI_KEY:
            return findings

        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(
                    "https://breachdirectory.p.rapidapi.com/",
                    params={"func": "auto", "term": email},
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Leakipedia-Scanner",
                        "x-rapidapi-host": "breachdirectory.p.rapidapi.com",
                        "x-rapidapi-key": BREACHDIRECTORY_RAPIDAPI_KEY,
                    },
                )

            if resp.status_code != 200:
                return findings

            data = resp.json()
        except (ValueError, httpx.HTTPError, httpx.TimeoutException):
            return findings

        entries = self._extract_breachdirectory_entries(data)

        if not entries and self._looks_like_positive_breachdirectory_response(data):
            entries = [data]

        for entry in entries[:10]:
            record = entry if isinstance(entry, dict) else {"value": entry}
            source_name = (
                record.get("source")
                or record.get("name")
                or record.get("breach")
                or "BreachDirectory"
            )
            has_password = any(
                bool(record.get(key))
                for key in ("password", "hash", "sha1", "sha256", "bcrypt")
            ) or bool(record.get("has_password"))

            findings.append(
                Finding(
                    source="leakcheck",
                    source_url="https://breachdirectory.p.rapidapi.com/",
                    finding_type="leaked_credential" if has_password else "breach",
                    data={
                        "service": "BreachDirectory",
                        "breach_source": source_name,
                        "has_password": has_password,
                        "result": record,
                    },
                    confidence="high" if has_password else "medium",
                    input_used="email",
                    original_input=email,
                    leads_to=[
                        f"credential_risk:password-related data exposed in {source_name}"
                    ]
                    if has_password
                    else [],
                    severity="critical" if has_password else "high",
                )
            )

        return findings

    @staticmethod
    def _extract_breachdirectory_entries(data: object) -> list:
        if isinstance(data, list):
            return data

        if not isinstance(data, dict):
            return []

        for key in ("result", "results", "data", "entries", "breaches", "matches"):
            value = data.get(key)
            if isinstance(value, list):
                return value

        return []

    @staticmethod
    def _looks_like_positive_breachdirectory_response(data: object) -> bool:
        if not isinstance(data, dict):
            return False

        positive_markers = [
            "password",
            "hash",
            "sha1",
            "sha256",
            "bcrypt",
            "source",
            "breach",
            "line",
        ]
        return any(key in data for key in positive_markers)
