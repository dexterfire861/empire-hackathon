from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from Leakipedia.agent.schemas import Finding

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
    "utah": "UT",
    "oregon": "OR",
    "montana": "MT",
    "delaware": "DE",
    "new jersey": "NJ",
    "new hampshire": "NH",
    "maryland": "MD",
    "minnesota": "MN",
    "nebraska": "NE",
    "kentucky": "KY",
    "rhode island": "RI",
    "tennessee": "TN",
    "indiana": "IN",
    "iowa": "IA",
    "florida": "FL",
}

STATE_PRIVACY_COMPLAINTS: dict[str, dict] = {
    "CA": {"label": "California (CPPA)", "url": "https://cppa.ca.gov/webapplications/complaint"},
    "TX": {"label": "Texas (TDPSA)", "url": "https://www.texasattorneygeneral.gov/consumer-protection/file-consumer-complaint/consumer-privacy-rights"},
    "CO": {"label": "Colorado (CPA)", "url": "https://coag.gov/resources/colorado-privacy-act/"},
    "VA": {"label": "Virginia (VCDPA)", "url": "https://www.oag.state.va.us/consumer-protection/index.php/file-a-complaint"},
    "CT": {"label": "Connecticut (CTDPA)", "url": "https://www.dir.ct.gov/ag/complaint/"},
    "UT": {"label": "Utah (UCPA)", "url": "https://attorneygeneral.utah.gov/contact/complaint-form/"},
    "OR": {"label": "Oregon (OCPA)", "url": "https://justice.oregon.gov/consumercomplaints/"},
    "MT": {"label": "Montana (MCDPA)", "url": "https://dojmt.gov/office-of-consumer-protection/consumer-complaints/"},
    "DE": {"label": "Delaware (DPDPA)", "url": "https://attorneygeneral.delaware.gov/fraud/cmu/complaint/"},
    "NJ": {"label": "New Jersey (NJDPA)", "url": "https://www.njconsumeraffairs.gov/Pages/Consumer-Complaints.aspx"},
    "NH": {"label": "New Hampshire (NHPA)", "url": "https://www.doj.nh.gov/consumer/complaints/index.htm"},
    "MD": {"label": "Maryland (MODPA)", "url": "https://www.marylandattorneygeneral.gov/Pages/CPD/Complaint.aspx"},
    "MN": {"label": "Minnesota (MCDPA)", "url": "https://www.ag.state.mn.us/Office/Forms/ConsumerAssistanceRequest.asp"},
    "NE": {"label": "Nebraska (NDPA)", "url": "https://www.nebraska.gov/apps-ago-complaints/?preSelect=CP_COMPLAINT"},
    "KY": {"label": "Kentucky (KCDPA)", "url": "https://www.ag.ky.gov/Resources/Consumer-Resources/Consumers/Pages/Consumer-Complaints.aspx"},
    "RI": {"label": "Rhode Island (RI-DTPPA)", "url": "https://riag.ri.gov/forms/consumer-complaint"},
    "TN": {"label": "Tennessee (TIPA)", "url": "https://www.tn.gov/attorneygeneral/working-for-tennessee/consumer/file-a-complaint.html"},
    "IN": {"label": "Indiana (INCDPA)", "url": "https://www.in.gov/attorneygeneral/consumer-protection-division/file-a-complaint/"},
    "IA": {"label": "Iowa (ICDPA)", "url": "https://www.iowaattorneygeneral.gov/for-consumers/file-a-consumer-complaint"},
    "FL": {"label": "Florida (FDBR / consumer complaint)", "url": "https://www.myfloridalegal.com/how-to-contact-us/file-a-complaint"},
}

PASSWORD_GUIDANCE_LINKS = [
    {"label": "NIST Password Guidance", "url": "https://pages.nist.gov/800-63-3/sp800-63b.html"},
    {"label": "CISA Password Best Practices", "url": "https://www.cisa.gov/secure-our-world/use-strong-passwords"},
]

MFA_GUIDANCE_LINKS = [
    {"label": "CISA MFA Guide", "url": "https://www.cisa.gov/mfa"},
    {"label": "NIST Digital Identity Guidelines", "url": "https://pages.nist.gov/800-63-3/"},
]

CREDIT_FREEZE_LINKS = [
    {"label": "FTC Credit Freeze Guide", "url": "https://consumer.ftc.gov/articles/what-know-about-credit-freezes-fraud-alerts"},
    {"label": "CFPB Credit Freeze Guide", "url": "https://www.consumerfinance.gov/ask-cfpb/what-is-a-credit-freeze-or-security-freeze-on-my-credit-report-en-1341/"},
]

GOOGLE_REMOVAL_LINKS = [
    {"label": "Google Results About You", "url": "https://support.google.com/websearch/answer/12719076"},
    {"label": "Google Removal Request Form", "url": "https://support.google.com/websearch/troubleshooter/3111061"},
]

EMAIL_ALIAS_LINKS = [
    {"label": "Apple Hide My Email", "url": "https://support.apple.com/en-us/HT210425"},
    {"label": "SimpleLogin Alias Guide", "url": "https://simplelogin.io/docs/"},
]

BROWSER_PRIVACY_LINKS = [
    {"label": "Global Privacy Control", "url": "https://globalprivacycontrol.org/"},
    {"label": "Privacy Badger", "url": "https://privacybadger.org/"},
]

MARKETING_OPT_OUT_LINKS = [
    {"label": "Acxiom Opt-Out", "url": "https://isapps.acxiom.com/optout/optout.aspx"},
    {"label": "Epsilon Opt-Out", "url": "https://legal.epsilon.com/optout"},
    {"label": "Oracle Advertising Privacy Choices", "url": "https://www.oracle.com/legal/privacy/privacy-choices/"},
]

BROKER_HELPER_LINKS = [
    {"label": "Consumer Reports Permission Slip", "url": "https://permissionslipcr.com/"},
    {"label": "EPIC Data Broker Resources", "url": "https://epic.org/issues/consumer-privacy/data-brokers/"},
]


def _resolve_state(location: Optional[str]) -> Optional[str]:
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


def _dedupe_links(links: list[dict]) -> list[dict]:
    seen: set[str] = set()
    unique: list[dict] = []
    for link in links:
        url = str(link.get("url", "")).strip()
        label = str(link.get("label", "")).strip()
        if not url or not label or url in seen:
            continue
        seen.add(url)
        unique.append({"label": label, "url": url})
    return unique


def _broker_label(finding: Finding) -> str:
    broker_name = str(finding.data.get("broker_name", "")).strip()
    if broker_name:
        return broker_name
    source_url = str(finding.source_url or "").strip()
    if source_url.startswith("http"):
        hostname = urlparse(source_url).netloc.replace("www.", "")
        if hostname:
            return hostname
    return finding.source


def _collect_broker_opt_out_links(findings: list[Finding]) -> list[dict]:
    links: list[dict] = []
    for finding in findings:
        opt_out_url = str(finding.data.get("opt_out_url", "")).strip()
        if not opt_out_url.startswith("http"):
            continue
        links.append(
            {
                "label": f"{_broker_label(finding)} Opt-Out",
                "url": opt_out_url,
            }
        )
    return _dedupe_links(links)


def _breach_has_sensitive_identity_data(finding: Finding) -> bool:
    data_classes = [str(dc).lower() for dc in finding.data.get("data_classes", [])]
    sensitive_keywords = (
        "password",
        "credential",
        "physical address",
        "phone",
        "date of birth",
        "dob",
        "government",
        "ssn",
        "social security",
        "driver",
        "identity",
    )
    return any(keyword in dc for dc in data_classes for keyword in sensitive_keywords)


def generate_actions(
    findings: list[Finding], location: Optional[str] = None
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
    google_findings = [f for f in findings if f.source == "google_search"]
    state = _resolve_state(location)
    complaint_portal = STATE_PRIVACY_COMPLAINTS.get(state or "")
    broker_opt_out_links = _collect_broker_opt_out_links(broker_findings)
    marketing_sale_findings = [
        f
        for f in broker_findings
        if f.source == "haveibeensold" and f.data.get("email_sold") is True
    ]
    sensitive_identity_findings = [
        f
        for f in findings
        if (
            f.finding_type == "breach"
            and _breach_has_sensitive_identity_data(f)
        )
        or (f.finding_type == "data_broker_listing" and f.severity == "high")
        or (f.finding_type == "document" and f.data.get("has_gps"))
    ]

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
                "links": PASSWORD_GUIDANCE_LINKS,
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
                "links": MFA_GUIDANCE_LINKS,
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
                "links": CREDIT_FREEZE_LINKS,
            }
        )
        priority += 1

    if sensitive_identity_findings:
        actions.append(
            {
                "priority": priority,
                "action": "Freeze your credit and review fraud-alert options to reduce identity-theft risk from exposed address, phone, password, or public-record data.",
                "category": "monitoring",
                "effort": "moderate",
                "addresses_findings": [f.source_url for f in sensitive_identity_findings[:5]],
                "links": CREDIT_FREEZE_LINKS,
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
                "links": _dedupe_links(broker_opt_out_links + BROKER_HELPER_LINKS),
            }
        )
        priority += 1

    if marketing_sale_findings:
        actions.append(
            {
                "priority": priority,
                "action": "Opt out of major marketing-data aggregators and ad-tech brokers linked to email resale activity.",
                "category": "privacy",
                "effort": "moderate",
                "addresses_findings": [f.source_url for f in marketing_sale_findings[:3]],
                "links": _dedupe_links(MARKETING_OPT_OUT_LINKS + BROKER_HELPER_LINKS),
            }
        )
        priority += 1

    if complaint_portal and broker_findings:
        actions.append(
            {
                "priority": priority,
                "action": f"File a {complaint_portal['label']} privacy complaint if a broker ignores your opt-out or continues exposing your data after removal requests.",
                "category": "legal",
                "effort": "moderate",
                "addresses_findings": [f.source_url for f in broker_findings[:5]],
                "links": [
                    {
                        "label": f"Open {complaint_portal['label']} complaint form",
                        "url": complaint_portal["url"],
                    }
                ],
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
    if google_findings:
        actions.append(
            {
                "priority": priority,
                "action": "Set up Google Alerts for your name, email, and phone number to monitor for new exposures. Request removal of sensitive results via Google's removal tool.",
                "category": "monitoring",
                "effort": "quick_win",
                "addresses_findings": [f.source_url for f in google_findings[:3]],
                "links": GOOGLE_REMOVAL_LINKS,
            }
        )
        priority += 1

    if breach_findings or marketing_sale_findings or account_findings:
        actions.append(
            {
                "priority": priority,
                "action": "Use email aliases for future signups so new exposures do not reveal your primary inbox.",
                "category": "privacy",
                "effort": "quick_win",
                "addresses_findings": [f"email:{f.original_input}" for f in findings if f.input_used == "email"][:5],
                "links": EMAIL_ALIAS_LINKS,
            }
        )
        priority += 1

    if broker_findings or marketing_sale_findings or google_findings:
        actions.append(
            {
                "priority": priority,
                "action": "Enable browser privacy controls like Global Privacy Control and tracker blocking to reduce future data sale and advertising exposure.",
                "category": "privacy",
                "effort": "quick_win",
                "addresses_findings": [f.source_url for f in (broker_findings[:3] or google_findings[:3])],
                "links": BROWSER_PRIVACY_LINKS,
            }
        )
        priority += 1

    return actions


def get_applicable_laws(location: Optional[str]) -> list[dict]:
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
