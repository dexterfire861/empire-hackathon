from __future__ import annotations

from Leakipedia.agent.schemas import Finding


def generate_kill_chains(findings: list[Finding]) -> list[dict]:
    """
    Generate attack path narratives based on finding combinations.
    Template-based: matches findings against known attack patterns.
    """
    chains: list[dict] = []

    breach_findings = [f for f in findings if f.finding_type == "breach"]
    account_findings = [f for f in findings if f.finding_type == "account_exists"]
    phone_findings = [f for f in findings if f.finding_type == "phone_exposure"]
    document_findings = [f for f in findings if f.finding_type == "document"]
    domain_findings = [f for f in findings if f.finding_type == "domain_registration"]

    password_breaches = [
        f
        for f in breach_findings
        if any(
            "password" in str(dc).lower()
            for dc in f.data.get("data_classes", [])
        )
    ]

    # 1. Credential Stuffing Chain
    if password_breaches and account_findings:
        breach_names = [f.data.get("breach_name", f.source) for f in password_breaches[:3]]
        account_sites = [f.data.get("site", f.source_url) for f in account_findings[:5]]
        chains.append(
            {
                "name": "Credential Stuffing Attack",
                "steps": [
                    f"Attacker obtains breached credentials from: {', '.join(breach_names)}",
                    f"Credentials tested against {len(account_findings)} discovered accounts: {', '.join(account_sites[:3])}...",
                    "Successful login grants access to personal data, financial info, or enables further social engineering",
                ],
                "likelihood": "high" if len(password_breaches) >= 2 else "medium",
                "impact": "critical",
                "enabling_findings": [
                    f"breach:{f.data.get('breach_name', '')}" for f in password_breaches[:3]
                ]
                + [f"account:{f.data.get('site', '')}" for f in account_findings[:3]],
            }
        )

    # 2. Social Engineering Chain
    if account_findings and (phone_findings or breach_findings):
        chains.append(
            {
                "name": "Social Engineering / Phishing Attack",
                "steps": [
                    f"Attacker builds target profile from {len(account_findings)} discovered social accounts",
                    "Personal details from profiles used to craft convincing phishing messages",
                    "Phishing email/SMS sent using known email/phone, referencing real accounts to build trust",
                    "Victim clicks link or provides credentials, granting account access",
                ],
                "likelihood": "medium",
                "impact": "high",
                "enabling_findings": [
                    f"account:{f.data.get('site', f.source_url)}"
                    for f in account_findings[:5]
                ],
            }
        )

    # 3. Account Takeover via Recovery
    recovery_findings = [
        f
        for f in findings
        if f.data.get("email_recovery") or f.data.get("phone_number")
    ]
    if recovery_findings and password_breaches:
        chains.append(
            {
                "name": "Account Takeover via Recovery Bypass",
                "steps": [
                    "Attacker identifies account recovery options (backup email/phone) exposed by Holehe",
                    "Compromised email from breach used to receive recovery codes",
                    "Password reset completed on target accounts using compromised recovery email",
                    "Attacker gains full control of accounts",
                ],
                "likelihood": "high",
                "impact": "critical",
                "enabling_findings": [
                    f"recovery:{f.data.get('site', '')}" for f in recovery_findings[:3]
                ]
                + [f"breach:{f.data.get('breach_name', '')}" for f in password_breaches[:2]],
            }
        )

    # 4. SIM Swapping
    if phone_findings and account_findings:
        mobile_phones = [
            f for f in phone_findings if f.data.get("line_type") == "mobile"
        ]
        if mobile_phones:
            chains.append(
                {
                    "name": "SIM Swap Attack",
                    "steps": [
                        f"Attacker identifies mobile number ({mobile_phones[0].original_input}) and carrier",
                        "Personal information from social accounts used to pass carrier identity verification",
                        "Carrier transfers phone number to attacker's SIM",
                        "Attacker receives all SMS-based 2FA codes, completing account takeover",
                    ],
                    "likelihood": "medium",
                    "impact": "critical",
                    "enabling_findings": [
                        f"phone:{f.original_input}" for f in mobile_phones[:1]
                    ]
                    + [
                        f"account:{f.data.get('site', '')}"
                        for f in account_findings[:3]
                    ],
                }
            )

    # 5. Identity Theft via Document Metadata
    gps_docs = [f for f in document_findings if f.data.get("has_gps")]
    author_docs = [f for f in document_findings if f.data.get("has_author")]
    if (gps_docs or author_docs) and (breach_findings or account_findings):
        chains.append(
            {
                "name": "Identity Theft via Data Aggregation",
                "steps": [
                    "Attacker collects personal documents with embedded metadata (GPS, author name)",
                    "GPS coordinates reveal home/work addresses",
                    "Combined with breach data and social profiles, attacker has full identity package",
                    "Identity used for fraud: credit applications, tax filing, or impersonation",
                ],
                "likelihood": "low" if not gps_docs else "medium",
                "impact": "critical",
                "enabling_findings": [f"document:{f.source_url}" for f in (gps_docs + author_docs)[:3]],
            }
        )

    return chains
