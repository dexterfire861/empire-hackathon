from __future__ import annotations

import asyncio

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT, GOOGLE_CSE_API_KEY, GOOGLE_CSE_CX, MAX_GOOGLE_QUERIES_PER_SCAN
from specter.sources.base import BaseSource, register_source


@register_source
class GoogleSearchSource(BaseSource):
    name = "google_search"
    description = "Search Google for pages containing an email, name, phone number, or username. Finds documents (PDFs, spreadsheets), social profiles, and other web mentions."
    input_types = ["email", "name", "phone", "username"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_google_search",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., an email address, full name, phone number)",
                    },
                    "query_type": {
                        "type": "string",
                        "description": "Type of query: 'email', 'name', 'phone', 'username', 'document'",
                        "enum": ["email", "name", "phone", "username", "document"],
                    },
                },
                "required": ["query", "query_type"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return bool(GOOGLE_CSE_API_KEY and GOOGLE_CSE_CX)

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        query = input_value.strip()

        # Build the actual search query based on type
        if input_type in ("email", "phone"):
            search_query = f'"{query}"'
            confidence = "high"
        elif input_type == "document":
            search_query = query  # already formatted by agent
            confidence = "medium"
        elif input_type == "username":
            search_query = f'"{query}" -site:instagram.com -site:twitter.com'
            confidence = "medium"
        else:  # name
            search_query = f'"{query}"'
            confidence = "medium"

        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "q": search_query,
            "key": GOOGLE_CSE_API_KEY,
            "cx": GOOGLE_CSE_CX,
            "num": 10,
        }

        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                # Small delay to respect rate limits
                await asyncio.sleep(0.5)
                resp = await client.get(url, params=params)
        except (httpx.HTTPError, httpx.TimeoutException):
            return []

        if resp.status_code != 200:
            return []

        try:
            data = resp.json()
        except ValueError:
            return []

        items = data.get("items", [])

        if not items:
            return []

        findings: list[Finding] = []
        for item in items:
            title = item.get("title", "")
            snippet = item.get("snippet", "")
            link = item.get("link", "")
            mime = item.get("mime", "")

            # Determine finding type
            if mime and ("pdf" in mime or "spreadsheet" in mime or "document" in mime):
                finding_type = "document"
                severity = "medium"
            else:
                finding_type = "data_broker_listing"
                severity = "low"

            leads: list[str] = []
            if mime and "pdf" in mime:
                leads.append(f"url:{link}")  # for ExifTool analysis

            findings.append(
                Finding(
                    source="google_search",
                    source_url=link,
                    finding_type=finding_type,
                    data={
                        "title": title,
                        "snippet": snippet,
                        "link": link,
                        "mime_type": mime,
                        "search_query": search_query,
                    },
                    confidence=confidence,
                    input_used=input_type,
                    original_input=query,
                    leads_to=leads,
                    severity=severity,
                )
            )

        return findings
