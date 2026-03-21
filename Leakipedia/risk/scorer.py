from __future__ import annotations

from Leakipedia.agent.schemas import Finding


def compute_exposure_score(findings: list[Finding]) -> int:
    """
    Deterministic risk score (0-100) based on finding severity distribution.
    Used as fallback if Claude's LLM-based score can't be parsed.
    """
    if not findings:
        return 0

    severity_weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 1,
    }

    total = 0.0
    for f in findings:
        total += severity_weights.get(f.severity, 1)

    # Bonus for breach-specific dangers
    breach_findings = [f for f in findings if f.finding_type == "breach"]
    password_breaches = [
        f
        for f in breach_findings
        if any(
            "password" in str(dc).lower()
            for dc in f.data.get("data_classes", [])
        )
    ]
    total += len(password_breaches) * 10

    # Bonus for high account exposure (many accounts found)
    account_findings = [f for f in findings if f.finding_type == "account_exists"]
    if len(account_findings) > 10:
        total += 15
    elif len(account_findings) > 5:
        total += 8

    # Bonus for GPS/document metadata exposure
    metadata_findings = [
        f
        for f in findings
        if f.finding_type == "document" and f.data.get("has_gps")
    ]
    total += len(metadata_findings) * 15

    # Cap at 100
    return min(100, int(total))
