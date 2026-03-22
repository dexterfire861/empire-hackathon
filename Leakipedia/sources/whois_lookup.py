from __future__ import annotations

import asyncio

import whois

from Leakipedia.agent.schemas import Finding
from Leakipedia.sources.base import BaseSource, register_source


@register_source
class WhoisSource(BaseSource):
    name = "whois"
    description = "Perform WHOIS lookup on a domain. Returns registrant name, organization, email, address, and registration/expiry dates. Many modern domains use privacy services."
    input_types = ["domain"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_whois",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to look up (e.g., example.com)",
                    }
                },
                "required": ["domain"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        domain = input_value.strip().lower()

        # python-whois is synchronous, run in thread
        try:
            w = await asyncio.to_thread(whois.whois, domain)
        except Exception:
            return []

        if not w or not w.domain_name:
            return []

        # Extract registrant info
        registrant_name = w.name or ""
        registrant_org = w.org or ""
        registrant_email = ""
        if w.emails:
            if isinstance(w.emails, list):
                registrant_email = w.emails[0]
            else:
                registrant_email = w.emails

        registrar = w.registrar or ""
        creation_date = str(w.creation_date) if w.creation_date else ""
        expiration_date = str(w.expiration_date) if w.expiration_date else ""
        name_servers = w.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]

        # Check if privacy service is in use
        privacy_keywords = ["privacy", "proxy", "redacted", "whoisguard", "domains by proxy", "contact privacy"]
        is_redacted = any(
            kw in str(registrant_name).lower() + str(registrant_org).lower() + str(registrant_email).lower()
            for kw in privacy_keywords
        )

        leads: list[str] = []
        if registrant_email and not is_redacted:
            leads.append(f"email:{registrant_email}")
        if registrant_name and not is_redacted:
            leads.append(f"name:{registrant_name}")

        severity = "info" if is_redacted else "medium"
        confidence = "low" if is_redacted else "high"

        return [
            Finding(
                source="whois",
                source_url=f"https://www.whois.com/whois/{domain}",
                finding_type="domain_registration",
                data={
                    "domain": domain,
                    "registrant_name": registrant_name if not is_redacted else "[REDACTED]",
                    "registrant_org": registrant_org if not is_redacted else "[REDACTED]",
                    "registrant_email": registrant_email if not is_redacted else "[REDACTED]",
                    "registrar": registrar,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "name_servers": list(name_servers)[:5],
                    "privacy_protected": is_redacted,
                },
                confidence=confidence,
                input_used="domain",
                original_input=domain,
                leads_to=leads,
                severity=severity,
            )
        ]
