from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Iterable, Optional
from urllib.parse import urlparse

from Leakipedia.agent.schemas import Finding, ScoreBreakdown

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEARCH_INDEX_SOURCES = {"google_search", "duckduckgo_search", "wayback"}
UNVERIFIED_LISTING_STATUSES = {
    "",
    "search_result_only",
    "likely_listing",
    "manual_verification_needed",
    "indexed_match",
}

FLAG_PRIORITY = [
    "identity_ambiguity",
    "low_confidence_evidence",
    "medium_confidence_evidence",
    "broker_listing_not_fully_verified",
    "search_index_evidence",
    "limited_evidence",
    "generic_preventive_guidance",
    "location_not_state_specific",
    "external_submission_required",
]

FLAG_NOTES = {
    "identity_ambiguity": "Some person-level details conflict across sources, so this conclusion should be reviewed before acting on it as confirmed identity evidence.",
    "low_confidence_evidence": "At least one supporting source is low confidence, so this conclusion should be treated as unverified until a human confirms it.",
    "medium_confidence_evidence": "Some supporting evidence is only medium confidence, so this conclusion should be treated as likely rather than confirmed.",
    "broker_listing_not_fully_verified": "At least one broker or public-record listing was inferred or only partially verified, so manual confirmation is still warranted.",
    "search_index_evidence": "Some supporting evidence comes from indexed search results, which can point to exposure but may still require manual validation at the source.",
    "limited_evidence": "Only a small amount of evidence supports this conclusion, so it should be treated cautiously.",
    "generic_preventive_guidance": "This appears as preventive guidance rather than a scan-specific mandate, so it is included as a low-confidence hardening step.",
    "location_not_state_specific": "No exact state-law match was found, so this is general privacy guidance rather than a confirmed state-specific complaint path.",
    "external_submission_required": "Any regulator complaint or third-party submission still requires human review and manual submission.",
}


def _normalize_text(value: object) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _hostname(url: str) -> str:
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return ""
    try:
        return urlparse(url).netloc.replace("www.", "").lower()
    except ValueError:
        return ""


def finding_source_label(finding: Finding) -> str:
    data = finding.data or {}
    for key in ("broker_name", "service", "site", "site_name", "search_engine"):
        value = str(data.get(key, "")).strip()
        if value:
            return value
    return finding.source


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER.get(finding.severity, 0),
            -CONFIDENCE_ORDER.get(finding.confidence, 0),
            finding.timestamp,
        ),
    )


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen_ids: set[str] = set()
    for finding in findings:
        if finding.finding_id in seen_ids:
            continue
        seen_ids.add(finding.finding_id)
        deduped.append(finding)
    return deduped


def top_findings(findings: Iterable[Finding], limit: int = 4) -> list[Finding]:
    return sort_findings(dedupe_findings(findings))[:limit]


def summarize_support(findings: Iterable[Finding]) -> str:
    supporting_findings = dedupe_findings(findings)
    if not supporting_findings:
        return "No direct supporting findings were captured for this conclusion."

    type_counts = Counter(f.finding_type for f in supporting_findings)
    ordered_types = sorted(
        type_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )
    segments = [
        f"{count} {finding_type.replace('_', ' ')} finding(s)"
        for finding_type, count in ordered_types[:3]
    ]
    return "Supported by " + ", ".join(segments) + "."


def _identity_signatures(findings: Iterable[Finding]) -> dict[str, set[str]]:
    addresses: set[str] = set()
    ages: set[str] = set()
    relatives: set[str] = set()

    for finding in findings:
        data = finding.data or {}
        if finding.finding_type != "data_broker_listing":
            continue

        for key in ("current_address", "address", "location", "location_summary"):
            value = _normalize_text(data.get(key))
            if value:
                addresses.add(value)

        for key in ("age", "age_summary"):
            value = _normalize_text(data.get(key))
            if value:
                ages.add(value)

        relatives_value = data.get("relatives")
        if isinstance(relatives_value, list):
            for relative in relatives_value[:5]:
                normalized = _normalize_text(relative)
                if normalized:
                    relatives.add(normalized)

    return {"addresses": addresses, "ages": ages, "relatives": relatives}


def has_identity_conflict(findings: Iterable[Finding]) -> bool:
    signatures = _identity_signatures(findings)
    return len(signatures["addresses"]) > 1 or len(signatures["ages"]) > 1


def infer_uncertainty_flags(findings: Iterable[Finding]) -> list[str]:
    supporting_findings = dedupe_findings(findings)
    flags: set[str] = set()

    if not supporting_findings:
        flags.add("limited_evidence")
    elif len(supporting_findings) == 1 and supporting_findings[0].confidence != "high":
        flags.add("limited_evidence")
    if any(finding.confidence == "low" for finding in supporting_findings):
        flags.add("low_confidence_evidence")
    elif any(finding.confidence == "medium" for finding in supporting_findings):
        flags.add("medium_confidence_evidence")
    if any(finding.source in SEARCH_INDEX_SOURCES for finding in supporting_findings):
        flags.add("search_index_evidence")
    if any(
        finding.finding_type == "data_broker_listing"
        and _normalize_text(finding.data.get("verification_status"))
        in UNVERIFIED_LISTING_STATUSES
        for finding in supporting_findings
    ):
        flags.add("broker_listing_not_fully_verified")
    if has_identity_conflict(supporting_findings):
        flags.add("identity_ambiguity")

    return [flag for flag in FLAG_PRIORITY if flag in flags]


def _degrade_confidence(confidence: str) -> str:
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return "low"


def derive_confidence(
    supporting_findings: Iterable[Finding],
    uncertainty_flags: Optional[Iterable[str]] = None,
) -> str:
    findings_list = dedupe_findings(supporting_findings)
    if not findings_list:
        return "low"

    if any(finding.confidence == "low" for finding in findings_list):
        confidence = "low"
    elif any(finding.confidence == "medium" for finding in findings_list):
        confidence = "medium"
    else:
        confidence = "high"

    flags = set(uncertainty_flags or [])
    if "identity_ambiguity" in flags or "broker_listing_not_fully_verified" in flags:
        confidence = _degrade_confidence(confidence)
    if "search_index_evidence" in flags and confidence == "high":
        confidence = "medium"
    if "limited_evidence" in flags and confidence == "high":
        confidence = "medium"
    return confidence


def build_uncertainty_note(flags: Iterable[str]) -> str:
    parts = [FLAG_NOTES.get(flag, "") for flag in flags if FLAG_NOTES.get(flag)]
    return " ".join(parts[:2]).strip()


def annotate_conclusion(
    item: dict,
    supporting_findings: Iterable[Finding],
    reason: str,
    *,
    rule_id: Optional[str] = None,
    official_url: Optional[str] = None,
    extra_flags: Optional[Iterable[str]] = None,
    uncertainty_note: str = "",
    human_review_required: Optional[bool] = None,
    confidence_override: Optional[str] = None,
) -> dict:
    annotated = deepcopy(item)
    findings_list = dedupe_findings(supporting_findings)
    flags = infer_uncertainty_flags(findings_list)
    if extra_flags:
        extra = [flag for flag in extra_flags if flag]
        flags = [flag for flag in FLAG_PRIORITY if flag in set(flags).union(extra)]

    confidence = confidence_override or derive_confidence(findings_list, flags)
    if human_review_required is None:
        human_review_required = confidence != "high" or bool(flags)

    annotated["supporting_finding_ids"] = [f.finding_id for f in findings_list]
    annotated["supporting_sources"] = list(
        dict.fromkeys(finding_source_label(finding) for finding in findings_list)
    )
    annotated["reason"] = reason or summarize_support(findings_list)
    annotated["confidence"] = confidence
    annotated["uncertainty_flags"] = flags
    annotated["human_review_required"] = human_review_required
    if rule_id:
        annotated["rule_id"] = rule_id
    if official_url:
        annotated["official_url"] = official_url
    note = uncertainty_note or build_uncertainty_note(flags)
    if note:
        annotated["uncertainty_note"] = note
    return annotated


def _match_by_ref(finding: Finding, kind: str, value: str) -> bool:
    data = finding.data or {}
    normalized_value = _normalize_text(value)

    if kind == "breach":
        return (
            finding.finding_type == "breach"
            and normalized_value
            in {
                _normalize_text(data.get("breach_name")),
                _normalize_text(data.get("breach_source")),
            }
        )
    if kind == "account":
        return (
            finding.finding_type == "account_exists"
            and normalized_value
            in {
                _normalize_text(data.get("site")),
                _normalize_text(data.get("site_name")),
                _normalize_text(finding.source_url),
            }
        )
    if kind == "phone":
        return finding.input_used == "phone" and _normalize_text(finding.original_input) == normalized_value
    if kind == "document":
        return finding.finding_type == "document" and _normalize_text(finding.source_url) == normalized_value
    if kind == "domain":
        return _normalize_text(data.get("domain")) == normalized_value
    if kind == "email":
        return finding.input_used == "email" and _normalize_text(finding.original_input) == normalized_value
    if kind == "recovery":
        return normalized_value in {
            _normalize_text(data.get("site")),
            _normalize_text(data.get("site_name")),
        }
    return False


def resolve_supporting_findings(
    findings: Iterable[Finding], refs: Optional[Iterable[str]]
) -> list[Finding]:
    finding_list = list(findings)
    resolved: list[Finding] = []

    for ref in refs or []:
        if not ref:
            continue
        normalized_ref = _normalize_text(ref)
        matched: list[Finding] = []
        for finding in finding_list:
            data = finding.data or {}
            if normalized_ref == _normalize_text(finding.finding_id):
                matched.append(finding)
                continue
            if normalized_ref == _normalize_text(finding.source_url):
                matched.append(finding)
                continue
            if normalized_ref in {
                _normalize_text(data.get("listing_url")),
                _normalize_text(data.get("search_url")),
                _normalize_text(data.get("opt_out_url")),
            }:
                matched.append(finding)
                continue

            if ":" in ref:
                kind, value = ref.split(":", 1)
                if _match_by_ref(finding, kind.strip().lower(), value.strip()):
                    matched.append(finding)

        resolved.extend(matched)

    return dedupe_findings(resolved)


def privacy_relevant_findings(findings: Iterable[Finding], limit: int = 4) -> list[Finding]:
    relevant_types = {
        "data_broker_listing",
        "breach",
        "document",
        "phone_exposure",
        "leaked_credential",
        "marketing_data_sale",
    }
    relevant = [
        finding
        for finding in findings
        if finding.finding_type in relevant_types or finding.source == "google_search"
    ]
    if not relevant:
        relevant = list(findings)
    return top_findings(relevant, limit=limit)


def support_for_resource(resource_id: str, findings: Iterable[Finding]) -> list[Finding]:
    finding_list = list(findings)
    if resource_id == "google_removal":
        support = [f for f in finding_list if f.source == "google_search"]
    elif resource_id == "credit_freeze":
        support = [
            f
            for f in finding_list
            if f.finding_type in {"phone_exposure", "leaked_credential"}
            or (
                f.finding_type == "breach"
                and any(
                    keyword in _normalize_text(dc)
                    for dc in f.data.get("data_classes", [])
                    for keyword in ("password", "phone", "address", "social", "ssn", "driver", "dob")
                )
            )
            or (
                f.finding_type == "data_broker_listing"
                and f.severity in {"high", "critical"}
            )
        ]
    elif resource_id == "mfa":
        support = [
            f
            for f in finding_list
            if f.finding_type == "account_exists"
            or (
                f.finding_type == "breach"
                and any("password" in _normalize_text(dc) for dc in f.data.get("data_classes", []))
            )
        ]
    elif resource_id == "password_rotation":
        support = [
            f
            for f in finding_list
            if f.finding_type == "breach"
            and any("password" in _normalize_text(dc) for dc in f.data.get("data_classes", []))
        ]
    elif resource_id == "email_aliases":
        support = [f for f in finding_list if f.input_used == "email"] or [
            f for f in finding_list if f.finding_type in {"breach", "account_exists"}
        ]
    elif resource_id == "browser_privacy":
        support = [
            f
            for f in finding_list
            if f.finding_type == "data_broker_listing" or f.source == "google_search"
        ]
    elif resource_id == "data_broker_help":
        support = [f for f in finding_list if f.finding_type == "data_broker_listing"]
    elif resource_id == "periodic_rescan":
        support = list(finding_list)
    else:
        support = list(finding_list)

    return top_findings(support or finding_list, limit=4)


def annotate_actions(actions: list[dict], findings: list[Finding]) -> list[dict]:
    annotated_actions: list[dict] = []

    for index, action in enumerate(actions, start=1):
        supporting = resolve_supporting_findings(
            findings, action.get("addresses_findings", [])
        )
        if not supporting:
            supporting = privacy_relevant_findings(findings, limit=4)

        reason = summarize_support(supporting)
        category = str(action.get("category", "general")).strip() or "general"
        annotated_actions.append(
            annotate_conclusion(
                action,
                supporting,
                reason,
                rule_id=f"action_{category}_{index}",
                human_review_required=True if category == "legal" else None,
                extra_flags=["external_submission_required"]
                if category == "legal"
                else None,
            )
        )

    return annotated_actions


def annotate_kill_chains(chains: list[dict], findings: list[Finding]) -> list[dict]:
    annotated_chains: list[dict] = []

    for index, chain in enumerate(chains, start=1):
        supporting = resolve_supporting_findings(
            findings, chain.get("enabling_findings", [])
        )
        if not supporting:
            supporting = top_findings(findings, limit=4)

        reason = summarize_support(supporting)
        annotated_chains.append(
            annotate_conclusion(
                chain,
                supporting,
                reason,
                rule_id=f"kill_chain_{index}",
            )
        )

    return annotated_chains


def annotate_laws(
    laws: list[dict],
    findings: list[Finding],
    location_matched: bool,
) -> list[dict]:
    annotated_laws: list[dict] = []
    supporting = privacy_relevant_findings(findings, limit=4)

    for index, law in enumerate(laws, start=1):
        portal = law.get("complaint_portal") or {}
        reason_parts = [summarize_support(supporting)]
        if location_matched:
            reason_parts.append("The user's location matched a state-specific privacy law in the rule catalog.")
        else:
            reason_parts.append("No exact state match was available, so Leakipedia fell back to general privacy guidance.")

        extra_flags = ["external_submission_required"]
        if not location_matched:
            extra_flags.append("location_not_state_specific")

        annotated_laws.append(
            annotate_conclusion(
                law,
                supporting,
                " ".join(reason_parts),
                rule_id=law.get("rule_id") or f"law_rule_{index}",
                official_url=portal.get("url"),
                human_review_required=True,
                extra_flags=extra_flags,
            )
        )

    return annotated_laws


def annotate_privacy_resources(
    resources: list[dict], findings: list[Finding]
) -> list[dict]:
    annotated_resources: list[dict] = []

    for resource in resources:
        resource_id = str(resource.get("id") or resource.get("rule_id") or "resource")
        supporting = support_for_resource(resource_id, findings)
        reason = resource.get("reason") or summarize_support(supporting)
        extra_flags: list[str] = []
        confidence_override: Optional[str] = None

        if not resource.get("recommended"):
            extra_flags.append("generic_preventive_guidance")
            confidence_override = "low"
            if not resource.get("reason"):
                reason = (
                    "Included as preventive guidance because the scan still found public exposure and this step can reduce future risk."
                )

        official_url = ""
        links = resource.get("links") or []
        if links:
            first_link = links[0] or {}
            official_url = first_link.get("url", "")

        annotated_resources.append(
            annotate_conclusion(
                resource,
                supporting,
                reason,
                rule_id=resource.get("rule_id") or resource_id,
                official_url=official_url,
                extra_flags=extra_flags,
                human_review_required=False,
                confidence_override=confidence_override,
            )
        )

    return annotated_resources


def summarize_finding_for_decision(finding: Finding) -> str:
    label = finding_source_label(finding)
    if finding.finding_type == "breach":
        breach_name = finding.data.get("breach_name") or finding.data.get("breach_source") or label
        return f"{breach_name} exposed data tied to the scanned identity."
    if finding.finding_type == "data_broker_listing":
        return f"{label} appears to expose personal data in a broker or public-record listing."
    if finding.finding_type == "leaked_credential":
        return f"{label} found leaked-credential style evidence tied to the scanned identity."
    return f"{label} returned a {finding.finding_type.replace('_', ' ')} finding."


def build_decision_summary(
    findings: list[Finding],
    score_breakdown: ScoreBreakdown,
    kill_chains: list[dict],
    actions: list[dict],
    applicable_laws: list[dict],
) -> list[dict]:
    summary: list[dict] = []
    top_evidence = top_findings(findings, limit=3)

    if top_evidence:
        summary.append(
            annotate_conclusion(
                {
                    "type": "top_evidence",
                    "title": "Highest-risk exposure",
                    "summary": summarize_finding_for_decision(top_evidence[0]),
                },
                [top_evidence[0]],
                "This is the highest-severity evidence item in the report.",
            )
        )

    if kill_chains:
        chain = kill_chains[0]
        summary.append(
            annotate_conclusion(
                {
                    "type": "attack_path",
                    "title": "Most plausible attack path",
                    "summary": f"{chain.get('name', 'Attack path')} remains viable because the supporting findings can be chained together.",
                },
                resolve_supporting_findings(findings, chain.get("supporting_finding_ids", []))
                or resolve_supporting_findings(findings, chain.get("enabling_findings", []))
                or top_evidence,
                chain.get("reason") or "This attack path was generated from correlated findings in the report.",
                uncertainty_note=chain.get("uncertainty_note", ""),
                confidence_override=chain.get("confidence"),
                human_review_required=chain.get("human_review_required"),
                extra_flags=chain.get("uncertainty_flags", []),
            )
        )

    if applicable_laws:
        law = applicable_laws[0]
        summary.append(
            annotate_conclusion(
                {
                    "type": "law",
                    "title": "Triggered legal pathway",
                    "summary": f"{law.get('law', 'Applicable law')} is the complaint path mapped from the user's location and findings.",
                },
                resolve_supporting_findings(findings, law.get("supporting_finding_ids", []))
                or top_evidence,
                law.get("reason", "Leakipedia mapped this law from the user's location and privacy-relevant findings."),
                uncertainty_note=law.get("uncertainty_note", ""),
                confidence_override=law.get("confidence"),
                human_review_required=law.get("human_review_required"),
                extra_flags=law.get("uncertainty_flags", []),
            )
        )

    if actions:
        action = actions[0]
        summary.append(
            annotate_conclusion(
                {
                    "type": "next_step",
                    "title": "First next step",
                    "summary": action.get("action", "Review the first recommended remediation step."),
                },
                resolve_supporting_findings(findings, action.get("supporting_finding_ids", []))
                or top_evidence,
                action.get("reason", "This is the highest-priority remediation action generated from the scan."),
                uncertainty_note=action.get("uncertainty_note", ""),
                confidence_override=action.get("confidence"),
                human_review_required=action.get("human_review_required"),
                extra_flags=action.get("uncertainty_flags", []),
            )
        )

    if not summary:
        summary.append(
            annotate_conclusion(
                {
                    "type": "overview",
                    "title": "Scan completed",
                    "summary": f"Leakipedia produced a deterministic exposure score of {score_breakdown.total}/100.",
                },
                top_evidence,
                "The scan completed, but there were not enough findings to populate richer conclusion summaries.",
            )
        )

    return summary


def build_safety_boundaries(findings: list[Finding]) -> list[dict]:
    identity_note = (
        "Some broker-style findings contain conflicting person-level details, so identity-linked conclusions are flagged for human review."
        if has_identity_conflict(findings)
        else "Identity-linked conclusions require corroborating evidence before Leakipedia presents them as confirmed."
    )
    observed_sources = ", ".join(
        list(dict.fromkeys(finding_source_label(finding) for finding in top_findings(findings, limit=5)))
    )

    return [
        {
            "boundary_id": "evidence_only_guidance",
            "title": "Evidence-first recommendations",
            "will_do": "Query public and API-backed sources, preserve the evidence trail, and link official complaint or removal resources that match the findings.",
            "will_not_do": "Invent unsupported conclusions or hide which findings triggered a recommendation.",
            "details": "Every major conclusion on this page is tied back to supporting finding IDs and source labels.",
        },
        {
            "boundary_id": "human_review_external_submission",
            "title": "Human review for submissions",
            "will_do": "Generate complaint language, official portals, and remediation steps for the user to review.",
            "will_not_do": "Auto-submit regulator complaints, opt-out forms, or other external requests on the user's behalf.",
            "details": "Anything that leaves Leakipedia and reaches a third party remains a human decision.",
        },
        {
            "boundary_id": "no_bot_bypass",
            "title": "No bot-protection bypass",
            "will_do": "Use normal public and API-backed access paths when a source is available.",
            "will_not_do": "Bypass CAPTCHAs, login walls, or anti-bot protections to force data extraction.",
            "details": "If a source blocks access, Leakipedia records the limitation and defers to human review rather than escalating automatically.",
        },
        {
            "boundary_id": "identity_threshold",
            "title": "Identity thresholding",
            "will_do": "Treat high-confidence corroborated findings as stronger evidence and flag ambiguous identity-linked results as uncertain.",
            "will_not_do": "Claim a person-level match is confirmed when the evidence threshold is not met.",
            "details": identity_note,
        },
        {
            "boundary_id": "data_handling",
            "title": "Data handling and retention",
            "will_do": "Keep scan state in memory for the active scan ID and allow explicit export when the user chooses it.",
            "will_not_do": "Silently build a long-term dossier beyond the active scan unless the user explicitly exports the report.",
            "details": (
                "Identifiers may be sent to third-party sources used during the scan. "
                + (
                    f"Observed source labels in this run include {observed_sources}."
                    if observed_sources
                    else "This run did not surface any source labels to summarize."
                )
            ),
        },
    ]
