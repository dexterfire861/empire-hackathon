from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class GravatarSource(BaseSource):
    name = "gravatar"
    description = "Look up Gravatar profile for an email address. Returns display name, bio, avatar, and linked social accounts."
    input_types = ["email"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_gravatar",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to look up",
                    }
                },
                "required": ["email"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        email = input_value.strip().lower()
        email_hash = hashlib.md5(email.encode()).hexdigest()
        url = f"https://en.gravatar.com/{email_hash}.json"

        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(url)
        except (httpx.HTTPError, httpx.TimeoutException):
            return []

        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            return []

        try:
            data = resp.json()
        except ValueError:
            return []

        entry = data.get("entry", [{}])[0]

        display_name = entry.get("displayName", "")
        profile_url = entry.get("profileUrl", "")
        about_me = entry.get("aboutMe", "")
        photos = entry.get("photos", [])
        accounts = entry.get("accounts", [])

        leads: list[str] = []
        for account in accounts:
            acct_url = account.get("url", "")
            username = account.get("username", "")
            if username:
                leads.append(f"username:{username}")
            if acct_url:
                leads.append(f"url:{acct_url}")
                # Try to extract username from URL path
                parsed = urlparse(acct_url)
                path_parts = [p for p in parsed.path.strip("/").split("/") if p]
                if path_parts and re.match(r"^[\w.-]+$", path_parts[-1]):
                    extracted = path_parts[-1]
                    if extracted != username:
                        leads.append(f"username:{extracted}")

        return [
            Finding(
                source="gravatar",
                source_url=profile_url or url,
                finding_type="account_exists",
                data={
                    "display_name": display_name,
                    "about_me": about_me,
                    "photos": [p.get("value") for p in photos],
                    "linked_accounts": [
                        {
                            "domain": a.get("domain", ""),
                            "username": a.get("username", ""),
                            "url": a.get("url", ""),
                            "shortname": a.get("shortname", ""),
                        }
                        for a in accounts
                    ],
                },
                confidence="high",
                input_used="email",
                original_input=email,
                leads_to=leads,
                severity="low",
            )
        ]
