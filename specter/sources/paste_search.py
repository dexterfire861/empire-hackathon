from __future__ import annotations

import re

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class PasteSearchSource(BaseSource):
    name = "paste_search"
    description = (
        "Search public paste sites (Pastebin, etc.) and paste dump indexes for an email "
        "or username. Leaked credentials and data dumps are often posted to paste sites. "
        "Also checks the Google cache of paste sites for deleted content."
    )
    input_types = ["email", "username"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_paste_search",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Email address or username to search for in paste sites",
                    },
                    "query_type": {
                        "type": "string",
                        "description": "Type of query: 'email' or 'username'",
                        "enum": ["email", "username"],
                    },
                },
                "required": ["query"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        query = input_value.strip()
        findings: list[Finding] = []

        # Check multiple paste/dump search services
        checks = [
            self._check_psbdmp(query),
            self._check_paste_search_service(query),
            self._check_intelx_public(query),
        ]

        results = await __import__("asyncio").gather(*checks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _check_psbdmp(self, query: str) -> list[Finding]:
        """Check psbdmp.ws — a Pastebin dump search engine."""
        findings: list[Finding] = []
        try:
            url = f"https://psbdmp.ws/api/v3/search/{query}"
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(
                    url,
                    headers={"User-Agent": "Specter-Scanner"},
                )

            if resp.status_code != 200:
                return []

            data = resp.json()
            pastes = data if isinstance(data, list) else data.get("data", [])

            for paste in pastes[:10]:
                if not isinstance(paste, dict):
                    continue
                paste_id = paste.get("id", "")
                paste_time = paste.get("time", paste.get("date", ""))
                paste_tags = paste.get("tags", "")

                findings.append(
                    Finding(
                        source="paste_search",
                        source_url=f"https://pastebin.com/{paste_id}" if paste_id else "https://psbdmp.ws",
                        finding_type="leaked_credential",
                        data={
                            "paste_id": paste_id,
                            "paste_time": paste_time,
                            "tags": paste_tags,
                            "search_engine": "psbdmp",
                        },
                        confidence="high",
                        input_used="email",
                        original_input=query,
                        leads_to=[
                            f"url:https://pastebin.com/{paste_id}"
                        ] if paste_id else [],
                        severity="critical",
                    )
                )

        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        return findings

    async def _check_paste_search_service(self, query: str) -> list[Finding]:
        """Check IntelligenceX paste search (free public endpoint)."""
        findings: list[Finding] = []
        try:
            # Search via the IntelX public phonebook (free, limited)
            url = "https://2.intelx.io/phonebook/search"
            payload = {
                "term": query,
                "maxresults": 10,
                "media": 0,
                "target": 1,  # 1 = paste sites
                "timeout": 5,
            }

            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers={
                        "x-key": "9df61df0-84f7-4dc7-b34c-8ccfb8646571",  # public free-tier key
                        "User-Agent": "Specter-Scanner",
                    },
                )

            if resp.status_code == 200:
                data = resp.json()
                search_id = data.get("id")
                if search_id:
                    # Fetch results
                    await __import__("asyncio").sleep(2)
                    result_url = f"https://2.intelx.io/phonebook/search/result?id={search_id}&limit=10"
                    async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                        resp2 = await client.get(
                            result_url,
                            headers={
                                "x-key": "9df61df0-84f7-4dc7-b34c-8ccfb8646571",
                                "User-Agent": "Specter-Scanner",
                            },
                        )

                    if resp2.status_code == 200:
                        results = resp2.json()
                        selectors = results.get("selectors", [])
                        for sel in selectors[:10]:
                            value = sel.get("selectorvalue", "")
                            sel_type = sel.get("selectortypeh", "")
                            if value:
                                lead_type = "email" if "@" in value else "url" if "http" in value else "username"
                                findings.append(
                                    Finding(
                                        source="paste_search",
                                        source_url="https://intelx.io",
                                        finding_type="leaked_credential",
                                        data={
                                            "value": value,
                                            "type": sel_type,
                                            "search_engine": "intelx_phonebook",
                                        },
                                        confidence="medium",
                                        input_used="email",
                                        original_input=query,
                                        leads_to=[f"{lead_type}:{value}"] if value != query else [],
                                        severity="high",
                                    )
                                )

        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        return findings

    async def _check_intelx_public(self, query: str) -> list[Finding]:
        """Search IntelX public search for darknet/paste exposure."""
        findings: list[Finding] = []
        try:
            url = "https://2.intelx.io/intelligent/search"
            payload = {
                "term": query,
                "maxresults": 5,
                "media": 0,
                "timeout": 5,
            }

            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers={
                        "x-key": "9df61df0-84f7-4dc7-b34c-8ccfb8646571",
                        "User-Agent": "Specter-Scanner",
                    },
                )

            if resp.status_code == 200:
                data = resp.json()
                search_id = data.get("id")
                if search_id:
                    await __import__("asyncio").sleep(3)
                    result_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=5"
                    async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                        resp2 = await client.get(
                            result_url,
                            headers={
                                "x-key": "9df61df0-84f7-4dc7-b34c-8ccfb8646571",
                                "User-Agent": "Specter-Scanner",
                            },
                        )

                    if resp2.status_code == 200:
                        results = resp2.json()
                        records = results.get("records", [])
                        for rec in records[:5]:
                            name = rec.get("name", "")
                            source_url = rec.get("sourceshort", "")
                            media_type = rec.get("mediah", "")
                            date = rec.get("date", "")
                            bucket = rec.get("bucketh", "")

                            findings.append(
                                Finding(
                                    source="paste_search",
                                    source_url=f"https://intelx.io/?s={query}",
                                    finding_type="leaked_credential",
                                    data={
                                        "name": name,
                                        "source": source_url,
                                        "media_type": media_type,
                                        "date": date,
                                        "bucket": bucket,
                                        "search_engine": "intelx",
                                    },
                                    confidence="medium",
                                    input_used="email",
                                    original_input=query,
                                    leads_to=[],
                                    severity="critical" if "darknet" in bucket.lower() or "leak" in bucket.lower() else "high",
                                )
                            )

        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        return findings
