from __future__ import annotations

import httpx

from Leakipedia.agent.schemas import Finding
from Leakipedia.config import API_TIMEOUT, NUMVERIFY_API_KEY
from Leakipedia.sources.base import BaseSource, register_source


@register_source
class NumVerifySource(BaseSource):
    name = "numverify"
    description = "Validate a phone number using NumVerify. Returns carrier, line type (mobile/landline/VoIP), location, and whether the number is valid. Useful for SIM-swap risk assessment."
    input_types = ["phone"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_numverify",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "phone": {
                        "type": "string",
                        "description": "Phone number to validate (include country code, e.g., +14155552671)",
                    }
                },
                "required": ["phone"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return bool(NUMVERIFY_API_KEY)

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        phone = input_value.strip()
        url = "http://apilayer.net/api/validate"
        params = {
            "access_key": NUMVERIFY_API_KEY,
            "number": phone,
            "country_code": "US",
        }

        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(url, params=params)
        except (httpx.HTTPError, httpx.TimeoutException):
            return []

        if resp.status_code != 200:
            return []

        try:
            data = resp.json()
        except ValueError:
            return []

        if not data.get("valid", False):
            return [
                Finding(
                    source="numverify",
                    source_url="https://numverify.com",
                    finding_type="phone_exposure",
                    data={"valid": False, "number": phone},
                    confidence="high",
                    input_used="phone",
                    original_input=phone,
                    leads_to=[],
                    severity="info",
                )
            ]

        carrier = data.get("carrier", "")
        line_type = data.get("line_type", "")
        location = data.get("location", "")
        country_name = data.get("country_name", "")

        # Mobile numbers are higher risk for SIM swapping
        severity = "medium" if line_type == "mobile" else "low"

        return [
            Finding(
                source="numverify",
                source_url="https://numverify.com",
                finding_type="phone_exposure",
                data={
                    "valid": True,
                    "number": data.get("international_format", phone),
                    "local_format": data.get("local_format", ""),
                    "carrier": carrier,
                    "line_type": line_type,
                    "location": location,
                    "country": country_name,
                },
                confidence="high",
                input_used="phone",
                original_input=phone,
                leads_to=[],
                severity=severity,
            )
        ]
