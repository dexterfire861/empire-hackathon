from __future__ import annotations

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class CrtshSource(BaseSource):
    name = "crtsh"
    description = "Search Certificate Transparency logs via crt.sh. Finds SSL certificates issued for a domain or email, revealing associated domains and subdomains."
    input_types = ["email", "domain"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_crtsh",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Domain name or email address to search for in certificate transparency logs",
                    }
                },
                "required": ["query"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        query = input_value.strip()
        url = f"https://crt.sh/?q={query}&output=json"

        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(url)
        except (httpx.HTTPError, httpx.TimeoutException):
            return []

        if resp.status_code != 200:
            return []

        try:
            certs = resp.json()
        except ValueError:
            return []

        if not certs:
            return []

        # Deduplicate domains found across certificates
        domains_seen: set[str] = set()
        cert_entries: list[dict] = []

        for cert in certs[:50]:  # limit to 50 certs
            name_value = cert.get("name_value", "")
            issuer = cert.get("issuer_name", "")
            not_before = cert.get("not_before", "")
            not_after = cert.get("not_after", "")

            for domain in name_value.split("\n"):
                domain = domain.strip().lstrip("*.")
                if domain and domain not in domains_seen:
                    domains_seen.add(domain)

            cert_entries.append(
                {
                    "common_name": cert.get("common_name", ""),
                    "name_value": name_value,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                }
            )

        leads = [f"domain:{d}" for d in domains_seen if d != query]

        return [
            Finding(
                source="crtsh",
                source_url=f"https://crt.sh/?q={query}",
                finding_type="domain_registration",
                data={
                    "certificates_found": len(certs),
                    "unique_domains": sorted(domains_seen),
                    "sample_certificates": cert_entries[:10],
                },
                confidence="high",
                input_used=input_type,
                original_input=query,
                leads_to=leads,
                severity="info" if len(domains_seen) <= 1 else "low",
            )
        ]
