from __future__ import annotations

import httpx

from Leakipedia.agent.schemas import Finding
from Leakipedia.config import API_TIMEOUT, HUNTER_API_KEY
from Leakipedia.sources.base import BaseSource, register_source


@register_source
class HunterSource(BaseSource):
    name = "hunter"
    description = "Verify an email address using Hunter.io. Returns deliverability status, confidence score, associated organization, and public sources where the email was found."
    input_types = ["email"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_hunter",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to verify",
                    }
                },
                "required": ["email"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return bool(HUNTER_API_KEY)

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        email = input_value.strip().lower()
        url = "https://api.hunter.io/v2/email-verifier"
        params = {"email": email, "api_key": HUNTER_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(url, params=params)
        except (httpx.HTTPError, httpx.TimeoutException):
            return []

        if resp.status_code != 200:
            return []

        try:
            result = resp.json().get("data", {})
        except ValueError:
            return []

        status = result.get("result", "unknown")
        score = result.get("score", 0)
        sources = result.get("sources", [])
        organization = result.get("organization", "")

        leads: list[str] = []
        if organization:
            leads.append(f"organization:{organization}")
        for source in sources:
            source_domain = source.get("domain", "")
            if source_domain:
                leads.append(f"domain:{source_domain}")

        return [
            Finding(
                source="hunter",
                source_url="https://hunter.io",
                finding_type="data_broker_listing",
                data={
                    "status": status,
                    "score": score,
                    "disposable": result.get("disposable", False),
                    "webmail": result.get("webmail", False),
                    "organization": organization,
                    "sources": [
                        {
                            "domain": s.get("domain", ""),
                            "uri": s.get("uri", ""),
                            "extracted_on": s.get("extracted_on", ""),
                        }
                        for s in sources[:10]
                    ],
                    "sources_count": len(sources),
                },
                confidence="high",
                input_used="email",
                original_input=email,
                leads_to=leads,
                severity="low",
            )
        ]
