from __future__ import annotations

import re
import shutil

from specter.agent.schemas import Finding
from specter.config import SUBPROCESS_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class PhoneInfogaScanSource(BaseSource):
    name = "phoneinfoga"
    description = "Scan a phone number using PhoneInfoga for carrier info, country, line type, and Google dork results revealing where the number appears online."
    input_types = ["phone"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_phoneinfoga",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "phone": {
                        "type": "string",
                        "description": "Phone number to scan (include country code, e.g., +14155552671)",
                    }
                },
                "required": ["phone"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("phoneinfoga") is not None

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        phone = input_value.strip()

        stdout, stderr = await self.run_cli(
            ["phoneinfoga", "scan", "-n", phone],
            timeout=SUBPROCESS_TIMEOUT,
        )

        return self._parse_output(stdout, phone)

    def _parse_output(self, stdout: str, phone: str) -> list[Finding]:
        findings: list[Finding] = []

        # Extract structured info from phoneinfoga output
        carrier = ""
        country = ""
        line_type = ""
        urls_found: list[str] = []

        for line in stdout.splitlines():
            line_stripped = line.strip()

            if "carrier" in line_stripped.lower():
                carrier = line_stripped.split(":", 1)[-1].strip() if ":" in line_stripped else ""
            elif "country" in line_stripped.lower():
                country = line_stripped.split(":", 1)[-1].strip() if ":" in line_stripped else ""
            elif "line type" in line_stripped.lower() or "type" in line_stripped.lower():
                line_type = line_stripped.split(":", 1)[-1].strip() if ":" in line_stripped else ""

            # Extract any URLs from Google dork results
            url_matches = re.findall(r"https?://\S+", line_stripped)
            urls_found.extend(url_matches)

        leads = [f"url:{u}" for u in urls_found[:5]]

        if carrier or country or urls_found:
            findings.append(
                Finding(
                    source="phoneinfoga",
                    source_url="https://github.com/sundowndev/phoneinfoga",
                    finding_type="phone_exposure",
                    data={
                        "carrier": carrier,
                        "country": country,
                        "line_type": line_type,
                        "google_dork_urls": urls_found[:10],
                        "raw_output_lines": stdout.splitlines()[:30],
                    },
                    confidence="medium",
                    input_used="phone",
                    original_input=phone,
                    leads_to=leads,
                    severity="medium" if urls_found else "low",
                )
            )

        return findings
