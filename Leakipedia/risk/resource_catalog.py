from __future__ import annotations

from copy import deepcopy
from typing import Optional

from Leakipedia.agent.schemas import Finding, ScanRequest

COMMON_PRIVACY_RIGHTS = [
    "Right to access personal data held about you",
    "Right to request deletion of personal data",
    "Right to correct inaccurate personal data",
    "Right to opt out of sale or sharing of personal data",
]

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

STATE_PRIVACY_PORTALS: dict[str, dict] = {
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

STATE_PRIVACY_LAWS: dict[str, dict] = {
    "CA": {
        "law": "California Consumer Privacy Act (CCPA)",
        "jurisdiction": "California",
        "relevance": "California residents can request access, deletion, and opt-out of sale or sharing of personal information.",
        "user_rights": COMMON_PRIVACY_RIGHTS + ["Right to limit use of sensitive personal information"],
    },
    "NY": {
        "law": "New York SHIELD Act",
        "jurisdiction": "New York",
        "relevance": "New York requires reasonable safeguards for private information and breach notification for impacted residents.",
        "user_rights": [
            "Right to breach notification within a reasonable time",
            "Right to expect reasonable safeguards for private information",
        ],
    },
    "VA": {
        "law": "Virginia Consumer Data Protection Act (VCDPA)",
        "jurisdiction": "Virginia",
        "relevance": "Virginia gives residents rights over access, correction, deletion, and opt-out for personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "CO": {
        "law": "Colorado Privacy Act (CPA)",
        "jurisdiction": "Colorado",
        "relevance": "Colorado residents can access, correct, delete, and opt out of sale or targeted advertising.",
        "user_rights": COMMON_PRIVACY_RIGHTS + ["Right to data portability"],
    },
    "CT": {
        "law": "Connecticut Data Privacy Act (CTDPA)",
        "jurisdiction": "Connecticut",
        "relevance": "Connecticut residents can request access, deletion, correction, and opt-out of sale or advertising uses.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "TX": {
        "law": "Texas Data Privacy and Security Act (TDPSA)",
        "jurisdiction": "Texas",
        "relevance": "Texas residents can access, delete, correct, and opt out of sale of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "UT": {
        "law": "Utah Consumer Privacy Act (UCPA)",
        "jurisdiction": "Utah",
        "relevance": "Utah residents can access, delete, and opt out of targeted advertising and sale of personal data.",
        "user_rights": [
            "Right to access personal data held about you",
            "Right to request deletion of personal data",
            "Right to opt out of sale or targeted advertising",
        ],
    },
    "OR": {
        "law": "Oregon Consumer Privacy Act (OCPA)",
        "jurisdiction": "Oregon",
        "relevance": "Oregon residents can access, correct, delete, and opt out of sale or profiling uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS + ["Right to opt out of profiling in furtherance of significant decisions"],
    },
    "MT": {
        "law": "Montana Consumer Data Privacy Act (MCDPA)",
        "jurisdiction": "Montana",
        "relevance": "Montana residents can access, correct, delete, and opt out of sale or targeted advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "DE": {
        "law": "Delaware Personal Data Privacy Act (DPDPA)",
        "jurisdiction": "Delaware",
        "relevance": "Delaware residents can access, delete, correct, and opt out of sale or targeted advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "NJ": {
        "law": "New Jersey Data Privacy Act (NJDPA)",
        "jurisdiction": "New Jersey",
        "relevance": "New Jersey residents can access, correct, delete, and opt out of sale or targeted advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "NH": {
        "law": "New Hampshire Privacy Act (NHPA)",
        "jurisdiction": "New Hampshire",
        "relevance": "New Hampshire residents can access, correct, delete, and opt out of sale or advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "MD": {
        "law": "Maryland Online Data Privacy Act (MODPA)",
        "jurisdiction": "Maryland",
        "relevance": "Maryland residents can exercise rights over access, deletion, and opt-out of certain uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "MN": {
        "law": "Minnesota Consumer Data Privacy Act (MCDPA)",
        "jurisdiction": "Minnesota",
        "relevance": "Minnesota residents can access, correct, delete, and opt out of sale or targeted advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "NE": {
        "law": "Nebraska Data Privacy Act (NDPA)",
        "jurisdiction": "Nebraska",
        "relevance": "Nebraska residents can access, delete, and opt out of sale or advertising uses of personal data.",
        "user_rights": [
            "Right to access personal data held about you",
            "Right to request deletion of personal data",
            "Right to opt out of sale or targeted advertising",
        ],
    },
    "KY": {
        "law": "Kentucky Consumer Data Protection Act (KCDPA)",
        "jurisdiction": "Kentucky",
        "relevance": "Kentucky residents can access, correct, delete, and opt out of sale or targeted advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "RI": {
        "law": "Rhode Island Data Transparency and Privacy Protection Act (RI-DTPPA)",
        "jurisdiction": "Rhode Island",
        "relevance": "Rhode Island residents can access, correct, delete, and opt out of sale or targeted advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "TN": {
        "law": "Tennessee Information Protection Act (TIPA)",
        "jurisdiction": "Tennessee",
        "relevance": "Tennessee residents can access, correct, delete, and opt out of sale or targeted advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "IN": {
        "law": "Indiana Consumer Data Protection Act (INCDPA)",
        "jurisdiction": "Indiana",
        "relevance": "Indiana residents can access, correct, delete, and opt out of sale or targeted advertising uses of personal data.",
        "user_rights": COMMON_PRIVACY_RIGHTS,
    },
    "IA": {
        "law": "Iowa Consumer Data Protection Act (ICDPA)",
        "jurisdiction": "Iowa",
        "relevance": "Iowa residents can access, delete, and opt out of sale of personal data.",
        "user_rights": [
            "Right to access personal data held about you",
            "Right to request deletion of personal data",
            "Right to opt out of sale of personal data",
        ],
    },
    "FL": {
        "law": "Florida Digital Bill of Rights (partial law)",
        "jurisdiction": "Florida",
        "relevance": "Florida has limited privacy rights for qualifying large platforms and general consumer complaint pathways for data misuse.",
        "user_rights": [
            "Right to pursue consumer complaint channels for privacy-related misuse",
            "Some platform-specific privacy rights may apply depending on the entity involved",
        ],
    },
}

GENERIC_LAW = {
    "law": "General Data Privacy Guidance",
    "jurisdiction": "United States",
    "relevance": "Privacy rights vary by state. If no exact state match is available, use the consumer-protection or attorney-general complaint path in your jurisdiction.",
    "user_rights": [
        "Right to breach notification in all 50 states",
        "Possible rights to request deletion or opt out depending on your state",
        "Right to escalate persistent privacy violations through state consumer-protection channels",
    ],
}

PRIVACY_RESOURCE_CATALOG = [
    {
        "id": "google_removal",
        "title": "Google Search Removal",
        "blurb": "Use Google’s tools to request removal of public search results that expose personal data.",
        "links": [
            {"label": "Google Results About You", "url": "https://support.google.com/websearch/answer/12719076"},
            {"label": "Google Removal Request Form", "url": "https://support.google.com/websearch/troubleshooter/3111061"},
        ],
    },
    {
        "id": "credit_freeze",
        "title": "Credit Freeze",
        "blurb": "Freeze credit and review fraud-alert guidance when the scan found sensitive identity exposures.",
        "links": [
            {"label": "FTC Credit Freeze Guide", "url": "https://consumer.ftc.gov/articles/what-know-about-credit-freezes-fraud-alerts"},
            {"label": "CFPB Credit Freeze Guide", "url": "https://www.consumerfinance.gov/ask-cfpb/what-is-a-credit-freeze-en-349/"},
        ],
    },
    {
        "id": "mfa",
        "title": "Enable 2FA",
        "blurb": "Prioritize email, banking, and social accounts first, and prefer authenticator apps over SMS where possible.",
        "links": [
            {"label": "CISA MFA Guide", "url": "https://www.cisa.gov/mfa"},
            {"label": "NIST Digital Identity Guidelines", "url": "https://pages.nist.gov/800-63-3/"},
        ],
    },
    {
        "id": "password_rotation",
        "title": "Password Rotation",
        "blurb": "Rotate passwords immediately for breached accounts and any credentials you have reused elsewhere.",
        "links": [
            {"label": "NIST Password Guidance", "url": "https://pages.nist.gov/800-63-3/sp800-63b.html"},
            {"label": "CISA Password Best Practices", "url": "https://www.cisa.gov/secure-our-world/use-strong-passwords"},
        ],
    },
    {
        "id": "email_aliases",
        "title": "Email Aliases",
        "blurb": "Use aliases for future signups so new exposures do not reveal your primary inbox.",
        "links": [
            {"label": "Apple Hide My Email", "url": "https://support.apple.com/en-us/HT210425"},
            {"label": "SimpleLogin Alias Guide", "url": "https://simplelogin.io/docs/"},
        ],
    },
    {
        "id": "browser_privacy",
        "title": "Browser Privacy",
        "blurb": "Turn on Global Privacy Control and tracker blocking to reduce future sale and advertising exposure.",
        "links": [
            {"label": "Global Privacy Control", "url": "https://globalprivacycontrol.org/"},
            {"label": "Privacy Badger", "url": "https://privacybadger.org/"},
        ],
    },
    {
        "id": "data_broker_help",
        "title": "Data Broker Help",
        "blurb": "Use broker-removal helper services and advocacy resources if manual removals become time-consuming.",
        "links": [
            {"label": "Consumer Reports Permission Slip", "url": "https://permissionslipcr.com/"},
            {"label": "EPIC Data Broker Resources", "url": "https://epic.org/issues/consumer-privacy/data-brokers/"},
        ],
    },
    {
        "id": "periodic_rescan",
        "title": "Periodic Re-Scan",
        "blurb": "Rerun the scan after removals so you can confirm exposed data stayed down and catch reappearance early.",
        "links": [],
    },
]


def resolve_state(location: Optional[str]) -> Optional[str]:
    if not location:
        return None
    loc = location.strip().upper()
    if loc in STATE_PRIVACY_LAWS or loc in STATE_PRIVACY_PORTALS:
        return loc
    loc_lower = location.strip().lower()
    for name, abbr in STATE_ABBREVIATIONS.items():
        if name in loc_lower:
            return abbr
    return None


def _summarize_exposure_counts(findings: list[Finding]) -> list[str]:
    broker_count = sum(1 for f in findings if f.finding_type == "data_broker_listing")
    breach_count = sum(1 for f in findings if f.finding_type == "breach")
    google_count = sum(1 for f in findings if f.source == "google_search")
    account_count = sum(1 for f in findings if f.finding_type == "account_exists")

    summary: list[str] = []
    if broker_count:
        summary.append(f"{broker_count} broker or public-record listing(s)")
    if breach_count:
        summary.append(f"{breach_count} breach exposure(s)")
    if google_count:
        summary.append(f"{google_count} Google-indexed result(s)")
    if account_count:
        summary.append(f"{account_count} account or profile hit(s)")
    return summary


def _evidence_lines(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    for finding in findings:
        if len(lines) >= 4:
            break
        if finding.finding_type == "data_broker_listing":
            label = finding.data.get("broker_name") or finding.source
            lines.append(f"- Broker/public-record listing on {label}: {finding.source_url}")
        elif finding.finding_type == "breach":
            breach_name = finding.data.get("breach_name") or finding.source
            lines.append(f"- Breach exposure in {breach_name}: {finding.source_url}")
        elif finding.source == "google_search":
            title = finding.data.get("title") or "Search result"
            lines.append(f"- Google-indexed result ({title}): {finding.source_url}")
        elif finding.finding_type == "document":
            lines.append(f"- Public document exposure: {finding.source_url}")
    return lines


def build_complaint_template(
    law: dict, findings: list[Finding], request: ScanRequest
) -> str:
    exposure_summary = _summarize_exposure_counts(findings)
    evidence_lines = _evidence_lines(findings)
    rights = ", ".join(law.get("user_rights", [])[:3])
    summary_text = ", ".join(exposure_summary) if exposure_summary else "public exposure of my personal data"

    body = [
        f"Hello, I am {request.full_name} and I am submitting a privacy complaint under the {law.get('law', 'applicable state privacy law')}.",
        f"My scan identified {summary_text}.",
    ]

    if request.location:
        body.append(f"I am located in {request.location}.")

    if evidence_lines:
        body.append("Examples from the scan:")
        body.extend(evidence_lines)

    if rights:
        body.append(
            f"I am requesting assistance enforcing my privacy rights, including {rights}."
        )

    body.append(
        "Please review these exposures, investigate the entities involved, and advise on the most effective next steps for removal or enforcement."
    )
    return "\n".join(body)


def build_applicable_laws(
    location: Optional[str], findings: list[Finding], request: ScanRequest
) -> list[dict]:
    state = resolve_state(location)
    if state and state in STATE_PRIVACY_LAWS:
        law = deepcopy(STATE_PRIVACY_LAWS[state])
        portal = STATE_PRIVACY_PORTALS.get(state)
        if portal:
            law["complaint_portal"] = deepcopy(portal)
            law["complaint_template"] = build_complaint_template(
                law, findings, request
            )
        return [law]

    generic = deepcopy(GENERIC_LAW)
    generic["complaint_template"] = build_complaint_template(
        generic, findings, request
    )
    return [generic]


def _has_password_exposure(findings: list[Finding]) -> bool:
    for finding in findings:
        if finding.finding_type != "breach":
            continue
        data_classes = [str(value).lower() for value in finding.data.get("data_classes", [])]
        if any("password" in data_class for data_class in data_classes):
            return True
    return False


def _has_sensitive_identity_exposure(findings: list[Finding]) -> bool:
    for finding in findings:
        if finding.finding_type == "phone_exposure":
            return True
        if finding.finding_type == "document" and finding.data.get("has_gps"):
            return True
        if finding.finding_type == "data_broker_listing" and finding.severity in {"high", "critical"}:
            return True
        if finding.finding_type == "breach":
            data_classes = [str(value).lower() for value in finding.data.get("data_classes", [])]
            if any(
                keyword in data_class
                for data_class in data_classes
                for keyword in ("password", "phone", "address", "dob", "social", "ssn", "driver")
            ):
                return True
    return False


def build_privacy_resources(findings: list[Finding]) -> list[dict]:
    google_findings = [f for f in findings if f.source == "google_search"]
    broker_findings = [f for f in findings if f.finding_type == "data_broker_listing"]
    breach_findings = [f for f in findings if f.finding_type == "breach"]
    account_findings = [f for f in findings if f.finding_type == "account_exists"]

    resources: list[dict] = []
    for entry in PRIVACY_RESOURCE_CATALOG:
        resource = deepcopy(entry)
        resource["recommended"] = False
        resource["reason"] = ""

        if resource["id"] == "google_removal" and google_findings:
            resource["recommended"] = True
            resource["reason"] = "Google-indexed results appeared in this scan."
        elif resource["id"] == "credit_freeze" and _has_sensitive_identity_exposure(findings):
            resource["recommended"] = True
            resource["reason"] = "The scan found sensitive identity exposures that raise fraud risk."
        elif resource["id"] == "mfa" and (_has_password_exposure(findings) or len(account_findings) > 3):
            resource["recommended"] = True
            resource["reason"] = "The scan found password exposure or enough account hits to justify tightening account security."
        elif resource["id"] == "password_rotation" and _has_password_exposure(findings):
            resource["recommended"] = True
            resource["reason"] = "At least one breach exposure included password-related data."
        elif resource["id"] == "email_aliases" and (breach_findings or account_findings):
            resource["recommended"] = True
            resource["reason"] = "Email-linked findings suggest aliases would reduce future exposure."
        elif resource["id"] == "browser_privacy" and (broker_findings or google_findings):
            resource["recommended"] = True
            resource["reason"] = "Broker or search-result findings make browser privacy controls worth enabling."
        elif resource["id"] == "data_broker_help" and broker_findings:
            resource["recommended"] = True
            resource["reason"] = "Broker listings were found in this scan."
        elif resource["id"] == "periodic_rescan" and findings:
            resource["recommended"] = True
            resource["reason"] = "Use re-scans after removals to verify the data stays down."

        resources.append(resource)

    return resources
