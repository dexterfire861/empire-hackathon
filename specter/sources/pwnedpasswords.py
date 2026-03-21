from __future__ import annotations

import hashlib

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT
from specter.sources.base import BaseSource, register_source


@register_source
class PwnedPasswordsSource(BaseSource):
    name = "pwnedpasswords"
    description = (
        "Check the HaveIBeenPwned Passwords API (free, no key needed) using k-anonymity. "
        "Checks if common passwords associated with a name/email appear in known breach dumps. "
        "Also queries the free HIBP breach-check endpoint for domain-level exposure."
    )
    input_types = ["email"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_pwnedpasswords",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to check breaches (uses free paste + breach-domain endpoints)",
                    }
                },
                "required": ["email"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        email = input_value.strip().lower()
        findings: list[Finding] = []

        # ── HIBP Pastes (free, no key needed) ──
        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                # Check pastes (pastebin leaks) — this endpoint is free
                domain = email.split("@")[-1] if "@" in email else ""
                if domain:
                    resp = await client.get(
                        f"https://haveibeenpwned.com/api/v3/breaches",
                        headers={"User-Agent": "Specter-Scanner"},
                    )
                    if resp.status_code == 200:
                        all_breaches = resp.json()
                        # Filter for breaches that match the email domain
                        domain_breaches = [
                            b for b in all_breaches
                            if b.get("Domain", "").lower() == domain.lower()
                        ]
                        if domain_breaches:
                            for breach in domain_breaches[:5]:
                                data_classes = breach.get("DataClasses", [])
                                data_classes_lower = [dc.lower() for dc in data_classes]
                                has_passwords = any("password" in dc for dc in data_classes_lower)

                                findings.append(
                                    Finding(
                                        source="pwnedpasswords",
                                        source_url=f"https://haveibeenpwned.com/api/v3/breach/{breach['Name']}",
                                        finding_type="breach",
                                        data={
                                            "breach_name": breach.get("Name", ""),
                                            "breach_date": breach.get("BreachDate", ""),
                                            "domain": breach.get("Domain", ""),
                                            "data_classes": data_classes,
                                            "pwn_count": breach.get("PwnCount", 0),
                                            "is_verified": breach.get("IsVerified", False),
                                            "description": breach.get("Description", "")[:300],
                                            "note": "Your email domain was breached. Your account may be affected.",
                                        },
                                        confidence="medium",
                                        input_used="email",
                                        original_input=email,
                                        leads_to=[
                                            f"credential_risk:domain {domain} was breached with password exposure"
                                        ] if has_passwords else [],
                                        severity="high" if has_passwords else "medium",
                                    )
                                )
        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        # ── Check if common password variants are pwned ──
        # Use the k-anonymity API to check if simple passwords are in breach dumps
        # This demonstrates the risk without needing the actual password
        local_part = email.split("@")[0] if "@" in email else email
        test_passwords = [
            local_part,                    # verma.aryaan
            local_part + "123",            # verma.aryaan123
            local_part.replace(".", ""),   # vermaaryaan
        ]

        pwned_count = 0
        for pwd in test_passwords:
            count = await self._check_password_pwned(pwd)
            if count > 0:
                pwned_count += count

        if pwned_count > 0:
            findings.append(
                Finding(
                    source="pwnedpasswords",
                    source_url="https://haveibeenpwned.com/Passwords",
                    finding_type="leaked_credential",
                    data={
                        "risk": "Common password variants based on this email appear in breach dumps",
                        "variants_checked": len(test_passwords),
                        "total_appearances": pwned_count,
                        "note": "This checks if simple password patterns (based on the email local part) exist in known breaches. Real passwords are never transmitted.",
                    },
                    confidence="low",
                    input_used="email",
                    original_input=email,
                    leads_to=[
                        "credential_risk:common password variants found in breach dumps"
                    ],
                    severity="medium",
                )
            )

        return findings

    @staticmethod
    async def _check_password_pwned(password: str) -> int:
        """Check a password against HIBP Passwords API using k-anonymity."""
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={"User-Agent": "Specter-Scanner"},
                )
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        return int(parts[1])
        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        return 0
