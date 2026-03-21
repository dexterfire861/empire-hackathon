from __future__ import annotations

import httpx

from Leakipedia.agent.schemas import Finding
from Leakipedia.config import API_TIMEOUT
from Leakipedia.sources.base import BaseSource, register_source


@register_source
class HaveIBeenSoldSource(BaseSource):
    name = "haveibeensold"
    description = (
        "Check if an email address has been sold to marketers and third-party data buyers "
        "using HaveIBeenSold.app. This reveals whether your email is being traded in "
        "marketing databases and ad networks, separate from breach/hack exposure."
    )
    input_types = ["email"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_haveibeensold",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to check for marketing data sales",
                    }
                },
                "required": ["email"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        email = input_value.strip().lower()
        findings: list[Finding] = []

        # HaveIBeenSold API
        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT, follow_redirects=True) as client:
                # The site uses a form POST to check emails
                resp = await client.post(
                    "https://haveibeensold.app/api/v2/check",
                    json={"email": email},
                    headers={
                        "User-Agent": "Leakipedia-Scanner",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )

                if resp.status_code == 200:
                    data = resp.json()
                    sold = data.get("result", data.get("sold", False))

                    if sold:
                        findings.append(
                            Finding(
                                source="haveibeensold",
                                source_url="https://haveibeensold.app",
                                finding_type="data_broker_listing",
                                data={
                                    "email_sold": True,
                                    "description": "This email has been found in marketing/data broker databases, indicating it was sold to third parties",
                                    "response": data,
                                },
                                confidence="high",
                                input_used="email",
                                original_input=email,
                                leads_to=[],
                                severity="high",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                source="haveibeensold",
                                source_url="https://haveibeensold.app",
                                finding_type="data_broker_listing",
                                data={
                                    "email_sold": False,
                                    "description": "This email was not found in known marketing databases",
                                    "response": data,
                                },
                                confidence="high",
                                input_used="email",
                                original_input=email,
                                leads_to=[],
                                severity="info",
                            )
                        )

                    return findings

        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        # Fallback: try the HTML form endpoint
        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT, follow_redirects=True) as client:
                resp = await client.post(
                    "https://haveibeensold.app/check",
                    data={"email": email},
                    headers={
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

                if resp.status_code == 200:
                    text = resp.text.lower()
                    if "has been sold" in text or "your email was found" in text or "yes" in text[:500]:
                        findings.append(
                            Finding(
                                source="haveibeensold",
                                source_url="https://haveibeensold.app",
                                finding_type="data_broker_listing",
                                data={
                                    "email_sold": True,
                                    "description": "This email has been sold to marketing/data broker databases",
                                    "detection_method": "html_parse",
                                },
                                confidence="medium",
                                input_used="email",
                                original_input=email,
                                leads_to=[],
                                severity="high",
                            )
                        )
                    elif "not been sold" in text or "not found" in text or "no" in text[:500]:
                        findings.append(
                            Finding(
                                source="haveibeensold",
                                source_url="https://haveibeensold.app",
                                finding_type="data_broker_listing",
                                data={
                                    "email_sold": False,
                                    "description": "This email was not found in known marketing databases",
                                    "detection_method": "html_parse",
                                },
                                confidence="medium",
                                input_used="email",
                                original_input=email,
                                leads_to=[],
                                severity="info",
                            )
                        )

        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        return findings
