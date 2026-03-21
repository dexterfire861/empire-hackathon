from __future__ import annotations

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT, HIBP_API_KEY
from specter.sources.base import BaseSource, register_source


@register_source
class HIBPSource(BaseSource):
    name = "hibp"
    description = "Check HaveIBeenPwned for data breaches associated with an email address. Returns breach names, dates, and types of data exposed (passwords, phone numbers, etc.)."
    input_types = ["email"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_hibp",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to check for data breaches",
                    }
                },
                "required": ["email"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return bool(HIBP_API_KEY)

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        email = input_value.strip().lower()
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

        headers = {
            "hibp-api-key": HIBP_API_KEY,
            "user-agent": "Specter-Scanner",
        }

        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(
                    url,
                    headers=headers,
                    params={"truncateResponse": "false"},
                )
        except (httpx.HTTPError, httpx.TimeoutException):
            return []

        if resp.status_code == 404:
            return []  # no breaches
        if resp.status_code == 401:
            return [
                Finding(
                    source="hibp",
                    source_url=url,
                    finding_type="error",
                    data={"error": "Invalid HIBP API key"},
                    confidence="high",
                    input_used="email",
                    original_input=email,
                    leads_to=[],
                    severity="info",
                )
            ]
        if resp.status_code != 200:
            return []

        try:
            breaches = resp.json()
        except ValueError:
            return []

        findings: list[Finding] = []

        for breach in breaches:
            name = breach.get("Name", "Unknown")
            breach_date = breach.get("BreachDate", "")
            data_classes = breach.get("DataClasses", [])
            domain = breach.get("Domain", "")
            description = breach.get("Description", "")
            is_verified = breach.get("IsVerified", False)
            pwn_count = breach.get("PwnCount", 0)

            # Determine severity based on data classes
            data_classes_lower = [dc.lower() for dc in data_classes]
            if any(kw in dc for dc in data_classes_lower for kw in ("password", "credential")):
                severity = "critical"
            elif any(kw in dc for dc in data_classes_lower for kw in ("phone", "physical address", "ip address")):
                severity = "high"
            elif any(kw in dc for dc in data_classes_lower for kw in ("name", "date of birth", "gender")):
                severity = "medium"
            else:
                severity = "low"

            leads: list[str] = []
            if any("password" in dc for dc in data_classes_lower):
                leads.append(
                    f"credential_risk:all accounts using {email} may be compromised"
                )

            findings.append(
                Finding(
                    source="hibp",
                    source_url=f"https://haveibeenpwned.com/api/v3/breach/{name}",
                    finding_type="breach",
                    data={
                        "breach_name": name,
                        "breach_date": breach_date,
                        "data_classes": data_classes,
                        "domain": domain,
                        "description": description,
                        "is_verified": is_verified,
                        "pwn_count": pwn_count,
                    },
                    confidence="high" if is_verified else "medium",
                    input_used="email",
                    original_input=email,
                    leads_to=leads,
                    severity=severity,
                )
            )

        return findings
