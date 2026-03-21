from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from Leakipedia.agent.schemas import Finding
from Leakipedia.config import SUBPROCESS_TIMEOUT
from Leakipedia.sources.base import BaseSource, register_source


@register_source
class SherlockScanSource(BaseSource):
    name = "sherlock"
    description = "Search for a username across social networks using Sherlock. Faster but simpler than Maigret — good for cross-validation of username existence across platforms."
    input_types = ["username"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_sherlock",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to search across social networks",
                    }
                },
                "required": ["username"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("sherlock") is not None

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        username = input_value.strip()

        tmpdir = tempfile.mkdtemp(prefix="Leakipedia_sherlock_")
        output_file = Path(tmpdir) / f"{username}.txt"

        try:
            stdout, stderr = await self.run_cli(
                [
                    "sherlock",
                    username,
                    "--output",
                    str(output_file),
                    "--print-found",
                ],
                timeout=SUBPROCESS_TIMEOUT,
            )

            # Sherlock outputs found URLs to the file, one per line
            if output_file.exists():
                content = output_file.read_text()
                return self._parse_output(content, stdout, username)

            return self._parse_stdout(stdout, username)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _parse_output(
        self, file_content: str, stdout: str, username: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        urls_seen: set[str] = set()

        # Parse the output file (contains URLs, one per line)
        for line in file_content.splitlines():
            url = line.strip()
            if url and url.startswith("http") and url not in urls_seen:
                urls_seen.add(url)
                site = self._extract_site_name(url)
                findings.append(
                    Finding(
                        source="sherlock",
                        source_url=url,
                        finding_type="account_exists",
                        data={"site": site, "url": url},
                        confidence="high",
                        input_used="username",
                        original_input=username,
                        leads_to=[],
                        severity="low",
                    )
                )

        # Also check stdout for any [+] lines that might have URLs
        if not findings:
            findings = self._parse_stdout(stdout, username)

        return findings

    def _parse_stdout(self, stdout: str, username: str) -> list[Finding]:
        findings: list[Finding] = []
        urls_seen: set[str] = set()

        for line in stdout.splitlines():
            if "[+]" not in line:
                continue

            # Extract URL from the line
            url_match = re.search(r"https?://\S+", line)
            if url_match:
                url = url_match.group(0).rstrip(")")
                if url not in urls_seen:
                    urls_seen.add(url)
                    site = self._extract_site_name(url)
                    findings.append(
                        Finding(
                            source="sherlock",
                            source_url=url,
                            finding_type="account_exists",
                            data={"site": site, "url": url},
                            confidence="high",
                            input_used="username",
                            original_input=username,
                            leads_to=[],
                            severity="low",
                        )
                    )

        return findings

    @staticmethod
    def _extract_site_name(url: str) -> str:
        """Extract a readable site name from a URL."""
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            domain = parsed.netloc.replace("www.", "")
            # Take the first part of the domain
            return domain.split(".")[0].capitalize()
        except Exception:
            return "Unknown"
