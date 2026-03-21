from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import anthropic
import whois

from specter.config import ANTHROPIC_API_KEY, CLAUDE_MODEL

TRACKER_SIGNATURES = {
    "meta_pixel": ("connect.facebook.net", "fbq("),
    "google_analytics": ("googletagmanager.com", "google-analytics.com", "gtag("),
    "tiktok_pixel": ("analytics.tiktok.com", "ttq.load"),
    "klaviyo": ("static.klaviyo.com", "_learnq"),
    "hotjar": ("static.hotjar.com", "hj("),
    "segment": ("cdn.segment.com", "analytics.load"),
}

BROKER_DATA = {
    "spokeo.com": "https://www.spokeo.com/optout",
    "whitepages.com": "https://www.whitepages.com/suppression_requests",
    "beenverified.com": "https://www.beenverified.com/f/optout/search",
    "truthfinder.com": "https://suppression.truthfinder.com",
    "peoplefinders.com": "https://www.peoplefinders.com/opt-out",
    "instantcheckmate.com": "https://www.instantcheckmate.com/opt-out",
    "intelius.com": "https://www.intelius.com/opt-out",
    "ussearch.com": "https://www.ussearch.com/opt-out/",
    "radaris.com": "https://radaris.com/control/privacy",
    "peekyou.com": "https://www.peekyou.com/about/contact/ccpa_optout/do_not_sell/",
    "peoplelooker.com": "https://www.peoplelooker.com/opt-out",
    "nuwber.com": "https://nuwber.com/removal/link",
    "rocketreach.co": "https://rocketreach.co/privacy?showOptOut=true",
    "fastpeoplesearch.com": "https://www.fastpeoplesearch.com/removal",
    "thatsthem.com": "https://thatsthem.com/optout",
    "clustrmaps.com": "https://clustrmaps.com/bl/opt-out",
    "addresses.com": "https://www.addresses.com/optout",
    "mylife.com": "https://www.mylife.com/ccpa/index.pubview",
    "privateeye.com": "https://www.privateeye.com/optout",
    "persopo.com": "https://persopo.com/opt-out",
}

TRUSTED_DOMAINS = {
    "irs.gov",
    "ssa.gov",
    "login.gov",
    "healthcare.gov",
    "bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "citi.com",
    "americanexpress.com",
    "capitalone.com",
    "fidelity.com",
    "vanguard.com",
}

SOCIAL_DOMAINS = {
    "instagram.com",
    "tiktok.com",
    "x.com",
    "twitter.com",
    "reddit.com",
    "facebook.com",
}

ATS_DOMAINS = {
    "greenhouse.io",
    "boards.greenhouse.io",
    "lever.co",
    "jobs.lever.co",
    "myworkdayjobs.com",
    "workday.com",
}

STATE_NOTES = {
    "CA": "In California, sharing cross-context behavioral tracking data can count as a sale or sharing under the CCPA/CPRA.",
    "TX": "In Texas, tracking still matters, but the sale analysis is narrower than California's default ad-tech framing.",
    "NY": "New York does not use California's sale language, but broad retention and weak disclosure still increase privacy risk.",
    "CO": "Colorado requires honoring universal opt-out signals for covered targeted advertising and sale contexts.",
    "CT": "Connecticut requires honoring opt-out preference signals for covered sale and targeted advertising uses.",
}

HONOR_GPC_STATES = {"CA", "CO", "CT", "NJ", "MT", "OR", "DE", "TX"}


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _matches_domain(hostname: str, candidates: set[str] | dict[str, str]) -> bool:
    return any(hostname == item or hostname.endswith(f".{item}") for item in candidates)


def _base_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def infer_data_types(fields: list[dict[str, Any]]) -> list[str]:
    detected: set[str] = set()
    for field in fields:
        blob = " ".join(
            str(field.get(key, ""))
            for key in ("name", "id", "placeholder", "label", "type", "autocomplete")
        ).lower()
        if re.search(r"\bemail\b", blob):
            detected.add("email")
        if re.search(r"\b(phone|tel|mobile)\b", blob):
            detected.add("phone")
        if re.search(r"\b(address|street|city|state|zip|postal)\b", blob):
            detected.add("address")
        if re.search(r"\b(ssn|social security|tax id|sin)\b", blob):
            detected.add("ssn")
        if re.search(r"\b(name|first name|last name|full name)\b", blob):
            detected.add("name")
        if re.search(r"\b(dob|birth|birthday)\b", blob):
            detected.add("birth_date")
        if re.search(r"\b(card|payment|cvv|security code)\b", blob):
            detected.add("payment")
        if re.search(r"\b(resume|linkedin|work history)\b", blob):
            detected.add("employment_history")
    return sorted(detected)


def detect_trackers(script_sources: list[str], html_excerpt: str) -> list[str]:
    haystacks = [item.lower() for item in script_sources if item]
    if html_excerpt:
        haystacks.append(html_excerpt.lower())

    found: list[str] = []
    for tracker, signatures in TRACKER_SIGNATURES.items():
        if any(signature.lower() in haystack for haystack in haystacks for signature in signatures):
            found.append(tracker)
    return found


def infer_dark_patterns(raw_patterns: list[str], html_excerpt: str) -> list[str]:
    patterns = list(raw_patterns or [])
    if re.search(r"\b\d{1,2}:\d{2}\b", html_excerpt or ""):
        patterns.append("countdown_timer")
    return sorted(set(patterns))


def classify_site_type(hostname: str, payload: dict[str, Any], trackers: list[str], domain_age_days: int | None) -> str:
    path = (urlparse(payload.get("url", "")).path or "").lower()
    title = str(payload.get("title", "")).lower()
    page_text = str(payload.get("page_text_excerpt", "")).lower()
    fields = payload.get("form_fields", [])
    data_types = infer_data_types(fields)

    if _matches_domain(hostname, BROKER_DATA):
        return "data_broker"
    if _matches_domain(hostname, TRUSTED_DOMAINS) or hostname.endswith(".gov"):
        return "trusted_government"
    if _matches_domain(hostname, SOCIAL_DOMAINS):
        return "social_media"
    if _matches_domain(hostname, ATS_DOMAINS) or "greenhouse" in page_text or "workday" in page_text:
        return "job_application"
    if any(token in path for token in ("/checkout", "/cart", "/payment")) or "checkout" in title:
        return "ecommerce"
    if "newsletter" in page_text or "start free trial" in page_text or "sign up for free" in page_text:
        return "signup_form"
    if "bank" in title or "insurance" in title or "routing number" in page_text:
        return "trusted_financial"
    if domain_age_days is not None and domain_age_days <= 14:
        return "sketchy"
    if trackers and data_types:
        return "commercial_form"
    return "general"


def build_legal_note(user_state: str, site_type: str, trackers: list[str]) -> str:
    if site_type == "data_broker":
        return "Known people-search and data broker sites are strong opt-out candidates because they aggregate and resell personal records."
    if trackers:
        return STATE_NOTES.get(
            user_state,
            "Ad-tech trackers can still expose behavioral data even where state law uses narrower sale terminology.",
        )
    return STATE_NOTES.get(
        user_state,
        "This page may still collect personal data, but the legal risk depends on retention, disclosure, and downstream sharing.",
    )


def score_analysis(site_type: str, data_types: list[str], trackers: list[str], dark_patterns: list[str], policy_exists: bool, domain_age_days: int | None) -> int:
    score = 8
    score += len(data_types) * 8
    score += len(trackers) * 9
    score += len(dark_patterns) * 12

    if not policy_exists:
        score += 18
    if site_type == "data_broker":
        score += 35
    elif site_type == "sketchy":
        score += 32
    elif site_type == "job_application":
        score += 16
    elif site_type == "social_media":
        score += 12
    elif site_type == "trusted_government":
        score -= 12
    elif site_type == "trusted_financial":
        score -= 8

    if domain_age_days is not None and domain_age_days <= 7:
        score += 18
    elif domain_age_days is not None and domain_age_days <= 30:
        score += 9

    return max(0, min(97, score))


def score_label(score: int) -> str:
    if score >= 75:
        return "High"
    if score >= 40:
        return "Moderate"
    return "Low"


def build_signals(site_type: str, data_types: list[str], trackers: list[str], policy_exists: bool, dark_patterns: list[str], domain_age_days: int | None, hostname: str, user_state: str) -> list[str]:
    signals: list[str] = []
    if data_types:
        signals.append(f"This page requests {', '.join(data_types[:4])} data.")
    if trackers:
        signals.append(f"This site shares data with {len(trackers)} major trackers: {', '.join(trackers[:4])}.")
    if not policy_exists:
        signals.append("No privacy policy link was detected on the page.")
    if dark_patterns:
        signals.append(f"Dark-pattern cues detected: {', '.join(dark_patterns[:3])}.")
    if domain_age_days is not None and domain_age_days <= 30:
        signals.append(f"This domain appears newly registered ({domain_age_days} days old).")
    if site_type == "data_broker":
        signals.append("This is a known data broker or people-search site.")
    if site_type == "job_application":
        signals.append("You may be submitting personal data to a third-party applicant tracking system.")
    if site_type == "social_media":
        signals.append("Profile settings can make contact details or discoverability visible by default.")
    if site_type in {"trusted_government", "trusted_financial"} and not trackers:
        signals.append("Trusted site profile with no major third-party trackers detected.")
    if trackers and user_state:
        signals.append(build_legal_note(user_state, site_type, trackers))
    if not signals:
        signals.append(f"No major privacy red flags were detected on {hostname}.")
    return signals


def build_steps(site_type: str, data_types: list[str], trackers: list[str], hostname: str) -> list[str]:
    steps = ["Share only the minimum personal information required for this task."]
    if "email" in data_types and site_type not in {"trusted_government", "trusted_financial"}:
        steps.append("Use a masked or secondary email if this service is not essential.")
    if trackers:
        steps.append("Check for a reject-all or ad-tech opt-out control before continuing.")
    if site_type == "data_broker":
        steps.append(f"Start the broker opt-out workflow for {hostname} before leaving the site.")
    if site_type == "job_application":
        steps.append("Log the application so you know where your resume and phone number were retained.")
    if site_type == "sketchy":
        steps.append("Do not submit personal information unless you independently verify the domain.")
    return steps[:4]


def heuristic_field_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    focused = payload.get("focused_field") or {}
    field_blob = " ".join(
        str(focused.get(key, "")) for key in ("name", "id", "placeholder", "label", "type", "autocomplete")
    ).lower()
    site_type = payload.get("site_type", "general")
    sensitive = bool(re.search(r"email|phone|address|ssn|social|birth|dob|resume|name|card|payment", field_blob))
    if site_type in {"job_application", "data_broker", "sketchy"} and focused:
        sensitive = True

    warning = "This field looks sensitive. Pause and verify how this site stores and shares the data."
    if site_type == "social_media":
        warning = "This profile field may affect discoverability or public visibility. Check account settings before saving."
    elif site_type == "job_application":
        warning = "You are about to submit personal data to a third-party hiring platform that may retain it for years."
    elif site_type == "data_broker":
        warning = "Do not provide extra personal details to a data broker unless it is required for an opt-out."
    elif site_type == "sketchy":
        warning = "Do not enter personal information on this site unless you verify it is legitimate."

    return {
        "field_is_sensitive": sensitive,
        "field_label": focused.get("label") or focused.get("name") or focused.get("type") or "field",
        "reason": "Heuristic fallback",
        "warning_message": warning,
        "visibility_risk": "medium" if site_type == "social_media" else "low",
        "confidence": "medium",
    }


async def analyze_sensitive_field(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload.get("focused_field"):
        return {
            "field_is_sensitive": False,
            "field_label": "",
            "reason": "No active field",
            "warning_message": "",
            "visibility_risk": "low",
            "confidence": "high",
        }

    if not ANTHROPIC_API_KEY:
        return heuristic_field_assessment(payload)

    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    prompt = {
        "task": "Decide whether a browser extension should auto-warn before the user types into the focused field.",
        "return_json_only": True,
        "focused_field": payload.get("focused_field"),
        "site_type": payload.get("site_type"),
        "url": payload.get("url"),
        "title": payload.get("title"),
        "trackers_detected": payload.get("trackers_detected"),
        "privacy_policy_exists": payload.get("privacy_policy_exists"),
        "dark_patterns_detected": payload.get("dark_patterns_detected"),
        "data_types_shared": payload.get("data_types_shared"),
        "user_state": payload.get("user_state"),
        "requirements": {
            "warn_on_sensitive_entry": True,
            "do_not_warn_on_routine_safe_government_or_bank_forms_without_adtech": True,
            "social_media_focus": "highlight discoverability or public-visibility defaults when relevant",
            "job_application_focus": "warn about ATS retention and third-party handling",
        },
        "schema": {
            "field_is_sensitive": "boolean",
            "field_label": "string",
            "reason": "string",
            "warning_message": "string",
            "visibility_risk": "low|medium|high",
            "confidence": "low|medium|high",
        },
    }

    try:
        response = await client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=350,
            system="You are a privacy browser assistant. Respond with only valid JSON.",
            messages=[{"role": "user", "content": json.dumps(prompt)}],
        )
        text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "field_is_sensitive" in parsed:
            return parsed
    except Exception:
        pass

    return heuristic_field_assessment(payload)


def lookup_domain_age_days(hostname: str) -> int | None:
    if not hostname or hostname in {"localhost", "127.0.0.1"}:
        return None
    try:
        result = whois.whois(hostname)
        created = result.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - created).days)
    except Exception:
        return None


async def build_extension_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    hostname = _base_domain(_hostname(payload.get("url", "")))
    user_state = (payload.get("user_state") or "CA").upper()
    form_fields = payload.get("form_fields") or []
    html_excerpt = payload.get("page_text_excerpt") or ""
    trackers = sorted(
        set(
            (payload.get("trackers_detected") or [])
            + detect_trackers(payload.get("script_sources") or [], html_excerpt)
        )
    )
    data_types = infer_data_types(form_fields)
    dark_patterns = infer_dark_patterns(payload.get("dark_patterns_detected") or [], html_excerpt)
    privacy_policy_exists = bool(payload.get("privacy_policy_exists"))
    domain_age_days = payload.get("domain_age_days")

    if domain_age_days is None:
        try:
            domain_age_days = await asyncio.wait_for(asyncio.to_thread(lookup_domain_age_days, hostname), timeout=2.5)
        except Exception:
            domain_age_days = None

    site_type = classify_site_type(hostname, payload, trackers, domain_age_days)
    legal_note = build_legal_note(user_state, site_type, trackers)
    score = score_analysis(site_type, data_types, trackers, dark_patterns, privacy_policy_exists, domain_age_days)
    label = score_label(score)
    broker_opt_out = BROKER_DATA.get(hostname)

    field_payload = {
        **payload,
        "site_type": site_type,
        "data_types_shared": data_types,
        "trackers_detected": trackers,
        "privacy_policy_exists": privacy_policy_exists,
        "dark_patterns_detected": dark_patterns,
        "user_state": user_state,
    }
    sensitive_field = await analyze_sensitive_field(field_payload)
    trusted_quiet = site_type in {"trusted_government", "trusted_financial"} and not trackers and not dark_patterns
    page_level_warning = site_type in {"data_broker", "sketchy"}
    field_level_warning = bool(
        payload.get("focused_field")
        and not trusted_quiet
        and sensitive_field.get("field_is_sensitive")
    )
    should_auto_warn = field_level_warning or bool(page_level_warning and not trusted_quiet)

    signals = build_signals(
        site_type,
        data_types,
        trackers,
        privacy_policy_exists,
        dark_patterns,
        domain_age_days,
        hostname,
        user_state,
    )
    if sensitive_field.get("field_is_sensitive") and sensitive_field.get("warning_message"):
        signals.insert(0, sensitive_field["warning_message"])

    steps = build_steps(site_type, data_types, trackers, hostname)
    if broker_opt_out:
        steps.insert(0, f"Open the broker opt-out page: {broker_opt_out}")

    gpc_enabled = bool(payload.get("gpc_enabled"))
    gpc_honored = None
    if gpc_enabled and user_state in HONOR_GPC_STATES:
        gpc_honored = not trackers if privacy_policy_exists else False

    public_visibility_risk = None
    if site_type == "social_media" and sensitive_field.get("field_is_sensitive"):
        public_visibility_risk = sensitive_field.get("visibility_risk", "medium")

    storage_record = {
        "site": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data_types_shared": data_types,
        "trackers_detected": trackers,
        "privacy_policy_exists": privacy_policy_exists,
        "domain_age_days": domain_age_days,
        "gpc_honored": gpc_honored,
        "user_state": user_state,
        "legal_note": legal_note,
    }
    should_log = bool(
        data_types
        or trackers
        or site_type in {"data_broker", "job_application", "sketchy", "social_media"}
        or sensitive_field.get("field_is_sensitive")
    )

    return {
        "domain": hostname or "Unknown domain",
        "siteType": site_type,
        "riskScore": score,
        "riskLabel": label,
        "signals": signals[:6],
        "steps": steps[:5],
        "trackersDetected": trackers,
        "dataTypesShared": data_types,
        "privacyPolicyExists": privacy_policy_exists,
        "domainAgeDays": domain_age_days,
        "gpcHonored": gpc_honored,
        "gpcEnabled": gpc_enabled,
        "userState": user_state,
        "legalNote": legal_note,
        "trustedSite": trusted_quiet,
        "shouldAutoWarn": should_auto_warn,
        "focusedField": sensitive_field,
        "publicVisibilityRisk": public_visibility_risk,
        "brokerOptOutUrl": broker_opt_out,
        "shouldLog": should_log,
        "storageRecord": storage_record,
    }
