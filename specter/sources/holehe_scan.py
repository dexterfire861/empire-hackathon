from __future__ import annotations

import csv
import io
import re
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from specter.agent.schemas import Finding
from specter.config import SUBPROCESS_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class HoleheScanSource(BaseSource):
    name = "holehe"
    description = "Check which online services an email is registered on using Holehe. Returns a list of sites where the email has an account, plus any recovery email/phone info discovered."
    input_types = ["email"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_holehe",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to check for account registrations",
                    }
                },
                "required": ["email"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("holehe") is not None or _can_import_holehe()

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        email = input_value.strip().lower()

        tmpdir = tempfile.mkdtemp(prefix="specter_holehe_")
        output_file = Path(tmpdir) / "results.csv"

        try:
            stdout, stderr = await self.run_cli(
                [
                    sys.executable,
                    "-m",
                    "holehe",
                    email,
                    "--only-used",
                    "--no-color",
                    "--csv",
                    str(output_file),
                ],
                timeout=SUBPROCESS_TIMEOUT,
            )

            if not output_file.exists():
                # Try parsing stdout instead
                return self._parse_stdout(stdout, email)

            content = output_file.read_text()
            return self._parse_csv(content, email)

        finally:
            import shutil as sh
            sh.rmtree(tmpdir, ignore_errors=True)

    def _parse_csv(self, content: str, email: str) -> list[Finding]:
        findings: list[Finding] = []
        reader = csv.DictReader(io.StringIO(content))

        for row in reader:
            site = row.get("name", row.get("Name", "")).strip()
            exists = row.get("exists", row.get("Exists", "")).strip().lower()
            url = row.get("url", row.get("Url", "")).strip()
            email_recovery = row.get("emailrecovery", row.get("EmailRecovery", "")).strip()
            phone_number = row.get("phoneNumber", row.get("PhoneNumber", "")).strip()

            if exists != "true":
                continue

            leads: list[str] = []
            if email_recovery and email_recovery != "None":
                leads.append(f"email:{email_recovery}")
            if phone_number and phone_number != "None":
                leads.append(f"phone:{phone_number}")

            # Try to extract username from URL
            if url:
                parsed = urlparse(url)
                path_parts = [p for p in parsed.path.strip("/").split("/") if p]
                if path_parts and re.match(r"^[\w.-]+$", path_parts[-1]):
                    leads.append(f"username:{path_parts[-1]}")

            findings.append(
                Finding(
                    source="holehe",
                    source_url=url or f"https://{site.lower()}.com",
                    finding_type="account_exists",
                    data={
                        "site": site,
                        "email_recovery": email_recovery if email_recovery != "None" else None,
                        "phone_number": phone_number if phone_number != "None" else None,
                    },
                    confidence="high",
                    input_used="email",
                    original_input=email,
                    leads_to=leads,
                    severity="low",
                )
            )

        return findings

    def _parse_stdout(self, stdout: str, email: str) -> list[Finding]:
        """Fallback: parse holehe text output if CSV wasn't produced."""
        findings: list[Finding] = []
        for line in stdout.splitlines():
            # Holehe marks found accounts with [+]
            if "[+]" in line:
                parts = line.split("[+]")
                if len(parts) >= 2:
                    site = parts[1].strip().split()[0] if parts[1].strip() else "unknown"
                    findings.append(
                        Finding(
                            source="holehe",
                            source_url=f"https://{site.lower()}",
                            finding_type="account_exists",
                            data={"site": site},
                            confidence="high",
                            input_used="email",
                            original_input=email,
                            leads_to=[],
                            severity="low",
                        )
                    )
        return findings


def _can_import_holehe() -> bool:
    try:
        import importlib
        importlib.import_module("holehe")
        return True
    except ImportError:
        return False
