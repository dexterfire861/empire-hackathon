from __future__ import annotations

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class WaybackSource(BaseSource):
    name = "wayback"
    description = "Search the Wayback Machine for archived snapshots of a URL or domain. Shows how long content has been publicly cached and may reveal deleted pages."
    input_types = ["url", "domain"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_wayback",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL or domain to search for in the Wayback Machine",
                    }
                },
                "required": ["url"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        target = input_value.strip()
        api_url = f"https://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=20"

        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            resp = await client.get(api_url)

        if resp.status_code != 200:
            return []

        rows = resp.json()
        if not rows or len(rows) < 2:
            return []

        # First row is headers: ["urlkey","timestamp","original","mimetype","statuscode","digest","length"]
        headers = rows[0]
        snapshots = [dict(zip(headers, row)) for row in rows[1:]]

        if not snapshots:
            return []

        timestamps = [s.get("timestamp", "") for s in snapshots]
        earliest = min(timestamps) if timestamps else ""
        latest = max(timestamps) if timestamps else ""

        leads = [
            f"url:https://web.archive.org/web/{s['timestamp']}/{s['original']}"
            for s in snapshots[:3]
        ]

        return [
            Finding(
                source="wayback",
                source_url=f"https://web.archive.org/web/*/{target}",
                finding_type="archived_page",
                data={
                    "total_snapshots": len(snapshots),
                    "earliest_snapshot": earliest,
                    "latest_snapshot": latest,
                    "sample_snapshots": snapshots[:5],
                },
                confidence="high",
                input_used=input_type,
                original_input=target,
                leads_to=leads,
                severity="info",
            )
        ]
