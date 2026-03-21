from __future__ import annotations

from specter.agent.schemas import Finding

# State privacy law reference
STATE_LAWS: dict[str, list[dict]] = {
    "CA": [
        {
            "law": "California Consumer Privacy Act (CCPA)",
            "jurisdiction": "California",
            "relevance": "Grants California residents the right to know what data is collected, request deletion, and opt out of data sales",
            "user_rights": [
                "Right to know what personal data is collected",
                "Right to delete personal data",
                "Right to opt out of sale of personal data",
                "Right to non-discrimination for exercising rights",
            ],
        }
    ],
    "NY": [
        {
            "law": "SHIELD Act",
            "jurisdiction": "New York",
            "relevance": "Requires businesses to implement reasonable security safeguards for private information of NY residents",
            "user_rights": [
                "Right to breach notification within reasonable time",
                "Expanded definition of private information includes biometric data",
            ],
        }
    ],
    "VA": [
        {
            "law": "Virginia Consumer Data Protection Act (VCDPA)",
            "jurisdiction": "Virginia",
            "relevance": "Grants Virginia consumers rights over their personal data",
            "user_rights": [
                "Right to access personal data",
                "Right to correct inaccuracies",
                "Right to delete personal data",
                "Right to opt out of targeted advertising",
            ],
        }
    ],
    "CO": [
        {
            "law": "Colorado Privacy Act (CPA)",
            "jurisdiction": "Colorado",
            "relevance": "Provides Colorado residents rights regarding their personal data",
            "user_rights": [
                "Right to access and confirm personal data",
                "Right to correct inaccuracies",
                "Right to delete personal data",
                "Right to data portability",
                "Right to opt out of targeted advertising and sale of data",
            ],
        }
    ],
    "CT": [
        {
            "law": "Connecticut Data Privacy Act (CTDPA)",
            "jurisdiction": "Connecticut",
            "relevance": "Gives Connecticut consumers control over their personal data",
            "user_rights": [
                "Right to access personal data",
                "Right to correct inaccuracies",
                "Right to delete personal data",
                "Right to opt out of sale and targeted advertising",
            ],
        }
    ],
    "TX": [
        {
            "law": "Texas Data Privacy and Security Act (TDPSA)",
            "jurisdiction": "Texas",
            "relevance": "Provides Texas consumers with data privacy rights",
            "user_rights": [
                "Right to access personal data",
                "Right to correct and delete personal data",
                "Right to opt out of data sales",
            ],
        }
    ],
}

# Map of US state abbreviations from common location strings
STATE_ABBREVIATIONS: dict[str, str] = {
    "california": "CA",
    "new york": "NY",
    "virginia": "VA",
    "colorado": "CO",
    "connecticut": "CT",
    "texas": "TX",
}


def _resolve_state(location: str | None) -> str | None:
    if not location:
        return None
    loc = location.strip().upper()
    if loc in STATE_LAWS:
        return loc
    loc_lower = location.strip().lower()
    for name, abbr in STATE_ABBREVIATIONS.items():
        if name in loc_lower:
            return abbr
    return None


def generate_actions(
    findings: list[Finding], location: str | None = None
) -> list[dict]:
    """Generate prioritized remediation actions from findings."""
    actions: list[dict] = []
    priority = 1

    breach_findings = [f for f in findings if f.finding_type == "breach"]
    account_findings = [f for f in findings if f.finding_type == "account_exists"]
    phone_findings = [f for f in findings if f.finding_type == "phone_exposure"]
    document_findings = [f for f in findings if f.finding_type == "document"]
    domain_findings = [f for f in findings if f.finding_type == "domain_registration"]
    broker_findings = [f for f in findings if f.finding_type == "data_broker_listing"]

    # Password breaches — highest priority
    password_breaches = [
        f
        for f in breach_findings
        if any(
            "password" in str(dc).lower()
            for dc in f.data.get("data_classes", [])
        )
    ]
    if password_breaches:
        breach_names = [f.data.get("breach_name", "") for f in password_breaches]
        actions.append(
            {
                "priority": priority,
                "action": f"URGENT: Change passwords on all services using this email. Breaches with password exposure: {', '.join(breach_names)}. Use a unique password for each service via a password manager (1Password, Bitwarden).",
                "category": "password",
                "effort": "quick_win",
                "addresses_findings": [f"breach:{n}" for n in breach_names],
            }
        )
        priority += 1

    # Enable 2FA everywhere
    if password_breaches or len(account_findings) > 3:
        actions.append(
            {
                "priority": priority,
                "action": "Enable two-factor authentication (2FA) on all accounts, preferring authenticator apps (Authy, Google Authenticator) over SMS-based 2FA to mitigate SIM-swap risk.",
                "category": "account_security",
                "effort": "moderate",
                "addresses_findings": [
                    f"account:{f.data.get('site', f.source_url)}"
                    for f in account_findings[:5]
                ],
            }
        )
        priority += 1

    # Non-password breaches
    other_breaches = [f for f in breach_findings if f not in password_breaches]
    if other_breaches:
        actions.append(
            {
                "priority": priority,
                "action": f"Monitor accounts associated with {len(other_breaches)} data breaches for suspicious activity. Consider enrolling in a credit monitoring service.",
                "category": "monitoring",
                "effort": "moderate",
                "addresses_findings": [
                    f"breach:{f.data.get('breach_name', '')}" for f in other_breaches
                ],
            }
        )
        priority += 1

    # Unused/forgotten accounts
    if len(account_findings) > 5:
        actions.append(
            {
                "priority": priority,
                "action": f"Review and close {len(account_findings)} discovered accounts. Each dormant account is an attack surface. Delete accounts you no longer use.",
                "category": "privacy",
                "effort": "significant",
                "addresses_findings": [
                    f"account:{f.data.get('site', f.source_url)}"
                    for f in account_findings
                ],
            }
        )
        priority += 1

    # Phone exposure
    if phone_findings:
        mobile = [f for f in phone_findings if f.data.get("line_type") == "mobile"]
        if mobile:
            actions.append(
                {
                    "priority": priority,
                    "action": "Contact your mobile carrier and set up a SIM lock/PIN to prevent SIM-swap attacks. Consider switching SMS-based 2FA to app-based 2FA.",
                    "category": "account_security",
                    "effort": "quick_win",
                    "addresses_findings": [f"phone:{f.original_input}" for f in mobile],
                }
            )
            priority += 1

    # Document metadata
    gps_docs = [f for f in document_findings if f.data.get("has_gps")]
    if gps_docs:
        actions.append(
            {
                "priority": priority,
                "action": "Remove GPS metadata from publicly accessible documents and images. Use ExifTool or your OS's built-in metadata removal before uploading files.",
                "category": "privacy",
                "effort": "moderate",
                "addresses_findings": [f"document:{f.source_url}" for f in gps_docs],
            }
        )
        priority += 1

    # Data broker listings
    if broker_findings:
        actions.append(
            {
                "priority": priority,
                "action": f"Request data removal from {len(broker_findings)} sites where your information appears. Use opt-out pages or services like DeleteMe/Kanary.",
                "category": "privacy",
                "effort": "significant",
                "addresses_findings": [f.source_url for f in broker_findings[:5]],
            }
        )
        priority += 1

    # Domain registration
    exposed_domains = [
        f for f in domain_findings if not f.data.get("privacy_protected", True)
    ]
    if exposed_domains:
        actions.append(
            {
                "priority": priority,
                "action": "Enable WHOIS privacy protection on your domain registrations to hide personal contact information.",
                "category": "privacy",
                "effort": "quick_win",
                "addresses_findings": [
                    f"domain:{f.data.get('domain', '')}" for f in exposed_domains
                ],
            }
        )
        priority += 1

    # Google results
    google_findings = [f for f in findings if f.source == "google_search"]
    if google_findings:
        actions.append(
            {
                "priority": priority,
                "action": "Set up Google Alerts for your name, email, and phone number to monitor for new exposures. Request removal of sensitive results via Google's removal tool.",
                "category": "monitoring",
                "effort": "quick_win",
                "addresses_findings": [f.source_url for f in google_findings[:3]],
            }
        )
        priority += 1

    return actions


def get_applicable_laws(location: str | None) -> list[dict]:
    """Return applicable privacy laws based on user's location."""
    state = _resolve_state(location)
    if state and state in STATE_LAWS:
        return STATE_LAWS[state]

    # Default: mention CCPA as the most well-known
    return [
        {
            "law": "General Data Privacy Guidance",
            "jurisdiction": "Federal (US)",
            "relevance": "While no comprehensive federal privacy law exists, multiple state laws may apply. Check your state's specific privacy legislation.",
            "user_rights": [
                "Right to breach notification (all 50 states)",
                "Right to request data deletion (varies by state)",
                "Right to opt out of data sales (varies by state)",
            ],
        }
    ]
