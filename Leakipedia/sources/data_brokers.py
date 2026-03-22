from __future__ import annotations

import asyncio
from urllib.parse import quote_plus

import httpx

from Leakipedia.agent.schemas import Finding
from Leakipedia.config import API_TIMEOUT
from Leakipedia.sources.base import BaseSource, register_source

# People-search / data broker sites
# These aggregate public records and typically have a listing for any US resident.
# Most block direct scraping (403), so we report them as likely listings with
# the search URL and opt-out URL for the user to verify and take action.
DATA_BROKER_SITES = [
    {
        "name": "Whitepages",
        "search_url": "https://www.whitepages.com/name/{name}",
        "opt_out": "https://www.whitepages.com/suppression_requests",
        "description": "Aggregates phone, address, and family member data from public records",
        "data_types": ["name", "phone", "address", "relatives", "age"],
    },
    {
        "name": "Spokeo",
        "search_url": "https://www.spokeo.com/{name}",
        "opt_out": "https://www.spokeo.com/optout",
        "description": "Aggregates social media profiles, public records, and contact info",
        "data_types": ["name", "phone", "address", "email", "social_profiles", "photos"],
    },
    {
        "name": "FastPeopleSearch",
        "search_url": "https://www.fastpeoplesearch.com/name/{name}",
        "opt_out": "https://www.fastpeoplesearch.com/removal",
        "description": "Free people search showing name, address, phone, relatives, and neighbors",
        "data_types": ["name", "phone", "address", "relatives", "email"],
    },
    {
        "name": "BeenVerified",
        "search_url": "https://www.beenverified.com/people/{name}/",
        "opt_out": "https://www.beenverified.com/optout/",
        "description": "Background check service with criminal records, assets, and social media",
        "data_types": ["name", "phone", "address", "criminal_records", "assets", "social_profiles"],
    },
    {
        "name": "Radaris",
        "search_url": "https://radaris.com/p/{name}/",
        "opt_out": "https://radaris.com/control/privacy",
        "description": "People search with professional info, court records, and property data",
        "data_types": ["name", "phone", "address", "employment", "court_records", "property"],
    },
    {
        "name": "Intelius",
        "search_url": "https://www.intelius.com/people-search/{name}/",
        "opt_out": "https://app.intelius.com/privacy-center/?",
        "description": "Background check and people search with comprehensive public records",
        "data_types": ["name", "phone", "address", "criminal_records", "relatives"],
    },
]


def _format_name(full_name: str) -> dict[str, str]:
    """Create URL-friendly name variants."""
    parts = full_name.strip().split()
    hyphenated = "-".join(parts)
    raw = " ".join(parts)
    return {"name": hyphenated, "name_raw": quote_plus(raw)}


@register_source
class DataBrokersSource(BaseSource):
    name = "data_brokers"
    description = (
        "Check major people-search and data broker sites (Whitepages, Spokeo, FastPeopleSearch, "
        "BeenVerified, Radaris, Intelius, etc.) for listings of a person by name. "
        "These sites aggregate public records and typically list most US residents. "
        "Returns listing URLs, opt-out URLs, and what data types each broker exposes."
    )
    input_types = ["name"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_data_brokers",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "full_name": {
                        "type": "string",
                        "description": "Full name of the person to search for on data broker sites",
                    },
                    "state": {
                        "type": "string",
                        "description": "US state (e.g., 'NY', 'CA') to narrow results, optional",
                    },
                },
                "required": ["full_name"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        full_name = input_value.strip()
        name_parts = _format_name(full_name)

        # Check which sites we can actually verify (some allow HEAD/GET)
        verification_results = await asyncio.gather(
            *[self._probe_site(site, name_parts) for site in DATA_BROKER_SITES],
            return_exceptions=True,
        )

        findings: list[Finding] = []
        for site, probe_result in zip(DATA_BROKER_SITES, verification_results):
            if isinstance(probe_result, Exception):
                status = "likely_listed"
                verified = False
            else:
                status, verified = probe_result

            search_url = site["search_url"].format(**name_parts)

            findings.append(
                Finding(
                    source="data_brokers",
                    source_url=search_url,
                    finding_type="data_broker_listing",
                    data={
                        "broker_name": site["name"],
                        "description": site["description"],
                        "search_url": search_url,
                        "opt_out_url": site["opt_out"],
                        "data_types_exposed": site["data_types"],
                        "verification_status": status,
                        "verified_by_http": verified,
                    },
                    confidence="high" if verified else "medium",
                    input_used="name",
                    original_input=full_name,
                    leads_to=[],
                    severity="high",
                )
            )

        return findings

    async def _probe_site(
        self, site: dict, name_parts: dict[str, str]
    ) -> tuple[str, bool]:
        """
        Try to verify a listing via HTTP.
        Returns (status, verified_by_http).
        - 200 with content → "confirmed", True
        - 403/captcha → "likely_listed" (site exists, blocks bots), False
        - 404 → "not_found", False
        """
        check_url = site["search_url"].format(**name_parts)

        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            async with httpx.AsyncClient(
                timeout=API_TIMEOUT,
                follow_redirects=True,
                headers=headers,
            ) as client:
                resp = await client.get(check_url)

            if resp.status_code == 200:
                text_lower = resp.text.lower()
                no_result_signals = [
                    "no results found", "no records found", "we didn't find",
                    "0 results", "no matches", "person not found",
                ]
                if any(s in text_lower for s in no_result_signals):
                    return ("not_found", True)
                return ("confirmed", True)

            elif resp.status_code == 403:
                # 403 = bot protection, site exists and probably has a listing
                return ("likely_listed", False)

            elif resp.status_code == 404:
                return ("not_found", True)

            else:
                return ("likely_listed", False)

        except (httpx.HTTPError, httpx.TimeoutException):
            # Network error — assume the site exists
            return ("likely_listed", False)
