from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from specter.agent.schemas import Finding
from specter.config import SUBPROCESS_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class MaigretScanSource(BaseSource):
    name = "maigret"
    description = "Search for a username across 500+ websites using Maigret. More comprehensive than Sherlock — parses profile data for bio text, linked URLs, and secondary emails. Best source for lead chaining."
    input_types = ["username"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_maigret",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to search across social media and web platforms",
                    }
                },
                "required": ["username"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("maigret") is not None

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        username = input_value.strip()

        tmpdir = tempfile.mkdtemp(prefix="specter_maigret_")
        output_file = Path(tmpdir) / "results.json"

        try:
            stdout, stderr = await self.run_cli(
                [
                    "maigret",
                    username,
                    "--json",
                    "simple",
                    "--top-sites",
                    "500",
                    "-o",
                    str(output_file),
                ],
                timeout=SUBPROCESS_TIMEOUT,
            )

            if output_file.exists():
                content = output_file.read_text()
                return self._parse_json(content, username)

            # Fallback: try parsing stdout
            return self._parse_stdout(stdout, username)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _parse_json(self, content: str, username: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings

        # Maigret JSON output can be a dict with site names as keys
        sites = data if isinstance(data, dict) else {}

        for site_name, site_data in sites.items():
            if not isinstance(site_data, dict):
                continue

            status = site_data.get("status", "")
            if status not in ("Claimed", "Found"):
                continue

            url = site_data.get("url_user", site_data.get("url", ""))

            # Extract any profile info for lead chaining
            leads: list[str] = []
            parsed_data = site_data.get("status_data", {})
            if isinstance(parsed_data, dict):
                # Look for emails, other usernames, URLs in parsed profile data
                for key, value in parsed_data.items():
                    if isinstance(value, str):
                        if "@" in value and "." in value:
                            leads.append(f"email:{value}")
                        elif value.startswith("http"):
                            leads.append(f"url:{value}")

            findings.append(
                Finding(
                    source="maigret",
                    source_url=url,
                    finding_type="account_exists",
                    data={
                        "site": site_name,
                        "status": status,
                        "url": url,
                        "tags": site_data.get("tags", []),
                    },
                    confidence="high",
                    input_used="username",
                    original_input=username,
                    leads_to=leads,
                    severity="low",
                )
            )

        return findings

    def _parse_stdout(self, stdout: str, username: str) -> list[Finding]:
        """Fallback parser for maigret text output."""
        findings: list[Finding] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Maigret typically outputs [+] or [*] for found accounts
            if any(marker in line for marker in ("[+]", "[*]")):
                # Try to extract URL from the line
                parts = line.split()
                url = ""
                site = ""
                for part in parts:
                    if part.startswith("http"):
                        url = part
                    elif part not in ("[+]", "[*]", "-"):
                        site = part

                if url or site:
                    findings.append(
                        Finding(
                            source="maigret",
                            source_url=url or f"https://{site.lower()}.com/{username}",
                            finding_type="account_exists",
                            data={"site": site, "url": url},
                            confidence="medium",
                            input_used="username",
                            original_input=username,
                            leads_to=[],
                            severity="low",
                        )
                    )

        return findings
