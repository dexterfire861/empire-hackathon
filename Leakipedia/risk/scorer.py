from __future__ import annotations

from collections import Counter
from typing import Literal

from Leakipedia.agent.schemas import Finding, ScoreBreakdown, ScoreFactor

# ---------------------------------------------------------------------------
# Data‑type weights: how sensitive is this data ON ITS OWN?
# Things everyone has online (name, email) score zero.
# ---------------------------------------------------------------------------
DATA_TYPE_WEIGHTS: dict[str, int] = {
    "real_name": 0,
    "email": 0,
    "username": 0,
    "phone": 5,
    "home_address": 8,
    "dob": 6,
    "password": 12,
    "employer": 2,
    "relatives": 4,
    "financial_info": 15,
    "ssn_adjacent": 18,
    "gps_location": 10,
    "ip_address": 3,
}

MAX_INVENTORY_SCORE = 30
MAX_ATTACK_SCORE = 50
MAX_ACCESSIBILITY_SCORE = 20

# ---------------------------------------------------------------------------
# Attack surfaces: which combinations of data enable real harm?
# ---------------------------------------------------------------------------
ATTACK_SURFACES: dict[str, dict] = {
    "account_takeover": {
        "label": "Account takeover",
        "detail": "Leaked credentials combined with known accounts make password-stuffing or reset attacks viable.",
        "requires": {"email", "password"},
        "amplifiers": {"phone", "dob"},
        "base_score": 25,
        "amplified_score": 35,
    },
    "identity_theft": {
        "label": "Identity theft / fraud",
        "detail": "Enough personal details are exposed to impersonate you for financial or government applications.",
        "requires": {"real_name", "home_address", "dob"},
        "amplifiers": {"ssn_adjacent", "financial_info", "phone"},
        "base_score": 30,
        "amplified_score": 45,
    },
    "social_engineering": {
        "label": "Social engineering / phishing",
        "detail": "An attacker has enough context to craft a convincing, targeted phishing message.",
        "requires": {"real_name", "phone"},
        "amplifiers": {"employer", "relatives", "email"},
        "base_score": 15,
        "amplified_score": 25,
    },
    "doxxing_stalking": {
        "label": "Doxxing / stalking",
        "detail": "Physical location and identity details are publicly linkable, creating a personal safety risk.",
        "requires": {"real_name", "home_address"},
        "amplifiers": {"phone", "employer", "relatives", "gps_location"},
        "base_score": 20,
        "amplified_score": 35,
    },
    "sim_swap": {
        "label": "SIM-swap attack",
        "detail": "Phone number plus identity details may allow an attacker to port your number and bypass 2FA.",
        "requires": {"phone", "real_name"},
        "amplifiers": {"home_address", "dob", "password"},
        "base_score": 15,
        "amplified_score": 25,
    },
    "credential_stuffing": {
        "label": "Credential stuffing across services",
        "detail": "A leaked password paired with a wide account footprint means many services may be compromised at once.",
        "requires": {"password"},
        "amplifiers": {"email", "username"},
        "base_score": 15,
        "amplified_score": 20,
        "min_accounts": 5,  # only triggers if 5+ accounts exist
    },
    "targeted_scam": {
        "label": "Targeted scam / vishing",
        "detail": "Phone number plus personal context enables convincing phone scams impersonating banks, government, or employers.",
        "requires": {"phone", "employer"},
        "amplifiers": {"real_name", "financial_info"},
        "base_score": 12,
        "amplified_score": 20,
    },
}


# ===================================================================
# Public API
# ===================================================================

def compute_exposure_score(findings: list[Finding]) -> int:
    return compute_exposure_score_breakdown(findings).total


def compute_exposure_score_breakdown(findings: list[Finding]) -> ScoreBreakdown:
    if not findings:
        return ScoreBreakdown(
            section_totals={"data_exposure": 0, "attack_surfaces": 0, "accessibility": 0},
            notes=["No findings were collected, so the exposure score remained 0."],
        )

    unique = _deduplicate_findings(findings)
    severity_counts = Counter(f.severity for f in unique)
    finding_type_counts = Counter(f.finding_type for f in unique)

    # Step 1: what sensitive data is actually exposed?
    inventory = _build_data_inventory(unique)
    inv_factors, inv_total = _score_inventory(inventory)

    # Step 2: which attack scenarios does this combination unlock?
    atk_factors, atk_total = _score_attack_surfaces(inventory, unique)

    # Step 3: how discoverable / accessible is the exposed data?
    acc_factors, acc_total = _score_accessibility(unique, finding_type_counts)

    factors = inv_factors + atk_factors + acc_factors
    raw_total = inv_total + atk_total + acc_total
    total = min(100, raw_total)

    notes: list[str] = []
    dup_count = len(findings) - len(unique)
    if dup_count > 0:
        notes.append(
            "Repeated hits for the same exposure were deduplicated before scoring."
        )
    if raw_total > 100:
        notes.append(
            f"Raw score reached {raw_total}; the final score was capped at 100."
        )

    return ScoreBreakdown(
        total=total,
        raw_total=raw_total,
        label=score_label(total),
        finding_count=len(findings),
        unique_finding_count=len(unique),
        duplicate_finding_count=dup_count,
        section_totals={
            "data_exposure": inv_total,
            "attack_surfaces": atk_total,
            "accessibility": acc_total,
        },
        severity_counts=_ordered_counts(
            severity_counts, ("critical", "high", "medium", "low", "info")
        ),
        finding_type_counts=_ordered_counts(
            finding_type_counts,
            (
                "leaked_credential",
                "breach",
                "phone_exposure",
                "document",
                "data_broker_listing",
                "account_exists",
                "domain_registration",
                "archived_page",
                "error",
            ),
        ),
        factors=factors,
        notes=notes,
        data_inventory=sorted(inventory),
    )


def score_label(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


# ===================================================================
# Step 1 — Data Exposure Inventory
# ===================================================================

def _build_data_inventory(findings: list[Finding]) -> set[str]:
    """Scan all findings and extract which sensitive data types are confirmed exposed."""
    inventory: set[str] = set()

    for f in findings:
        data = f.data or {}

        # --- Breaches ---
        if f.finding_type == "breach":
            data_classes = [str(dc).lower() for dc in data.get("data_classes", [])]
            if any("password" in dc or "credential" in dc for dc in data_classes):
                inventory.add("password")
            if any("phone" in dc for dc in data_classes):
                inventory.add("phone")
            if any("date of birth" in dc or "dob" in dc for dc in data_classes):
                inventory.add("dob")
            if any("address" in dc for dc in data_classes):
                inventory.add("home_address")
            if any("name" in dc for dc in data_classes):
                inventory.add("real_name")
            if any("employer" in dc or "job" in dc or "occupation" in dc for dc in data_classes):
                inventory.add("employer")
            if any(
                "financial" in dc or "bank" in dc or "credit card" in dc or "income" in dc
                for dc in data_classes
            ):
                inventory.add("financial_info")
            if any("ip" in dc and "address" in dc for dc in data_classes):
                inventory.add("ip_address")
            # email and username from a breach are info-level, still tag them
            inventory.add("email")

        # --- Leaked credentials ---
        elif f.finding_type == "leaked_credential":
            inventory.add("password")
            inventory.add("email")
            if data.get("has_phone") or data.get("phone"):
                inventory.add("phone")

        # --- Data broker listings ---
        elif f.finding_type == "data_broker_listing":
            if data.get("has_address") or data.get("address") or data.get("addresses"):
                inventory.add("home_address")
            if data.get("has_phone") or data.get("phone") or data.get("phones"):
                inventory.add("phone")
            if data.get("has_relatives") or data.get("relatives"):
                inventory.add("relatives")
            if data.get("has_dob") or data.get("dob") or data.get("age"):
                inventory.add("dob")
            if data.get("has_email") or data.get("email") or data.get("emails"):
                inventory.add("email")
            if data.get("name") or data.get("full_name"):
                inventory.add("real_name")
            if data.get("employer") or data.get("occupation"):
                inventory.add("employer")

        # --- Phone exposure ---
        elif f.finding_type == "phone_exposure":
            inventory.add("phone")
            if data.get("owner_name") or data.get("caller_name"):
                inventory.add("real_name")

        # --- Documents with metadata ---
        elif f.finding_type == "document":
            if data.get("has_gps") or data.get("gps"):
                inventory.add("gps_location")
            if data.get("author"):
                inventory.add("real_name")
            if data.get("has_phone") or data.get("phone"):
                inventory.add("phone")
            if data.get("has_address") or data.get("address"):
                inventory.add("home_address")

        # --- Domain registration ---
        elif f.finding_type == "domain_registration":
            if f.severity in {"medium", "high", "critical"}:
                # non-redacted WHOIS means real info is exposed
                if data.get("registrant_name"):
                    inventory.add("real_name")
                if data.get("registrant_address") or data.get("registrant_city"):
                    inventory.add("home_address")
                if data.get("registrant_phone"):
                    inventory.add("phone")
                if data.get("registrant_email"):
                    inventory.add("email")

        # --- Account exists (social media / platforms) ---
        elif f.finding_type == "account_exists":
            # The account existing is not a risk by itself.
            # Only flag data that is EXPOSED ON the profile.
            inventory.add("username")
            if data.get("has_email_visible") or data.get("email_visible"):
                inventory.add("email")
            if data.get("has_phone_visible") or data.get("phone_visible"):
                inventory.add("phone")
            if data.get("real_name") or data.get("display_name"):
                inventory.add("real_name")
            if data.get("employer") or data.get("bio_employer"):
                inventory.add("employer")
            if data.get("location") or data.get("bio_location"):
                # general "New York, NY" is not home_address level
                # only flag if it looks like a specific address
                pass

    return inventory


def _score_inventory(inventory: set[str]) -> tuple[list[ScoreFactor], int]:
    """Score based on what types of sensitive data are confirmed exposed."""
    factors: list[ScoreFactor] = []
    total = 0

    scored_types: list[tuple[str, int]] = []
    for dtype in sorted(inventory):
        weight = DATA_TYPE_WEIGHTS.get(dtype, 0)
        if weight > 0:
            scored_types.append((dtype, weight))
            total += weight

    # Cap the inventory bucket
    total = min(total, MAX_INVENTORY_SCORE)

    if scored_types:
        type_list = ", ".join(f"{dtype} (+{w})" for dtype, w in scored_types)
        factors.append(ScoreFactor(
            category="data_exposure",
            label="Sensitive data types confirmed exposed",
            points=total,
            detail=f"Exposed data types: {type_list}. "
                   f"Common data like name, email, and username are not penalized.",
        ))
    else:
        factors.append(ScoreFactor(
            category="data_exposure",
            label="No sensitive data types detected beyond name/email/username",
            points=0,
            detail="Only standard identifiers (name, email, username) were found. "
                   "These carry no score because they are expected to be public.",
        ))

    return factors, total


# ===================================================================
# Step 2 — Attack Surface Scoring
# ===================================================================

def _score_attack_surfaces(
    inventory: set[str], findings: list[Finding]
) -> tuple[list[ScoreFactor], int]:
    """Check which real-world attack scenarios are unlocked by the data combination."""
    factors: list[ScoreFactor] = []
    candidates: list[tuple[int, str, ScoreFactor]] = []

    account_count = sum(1 for f in findings if f.finding_type == "account_exists")

    for surface_id, surface in ATTACK_SURFACES.items():
        required: set[str] = surface["requires"]
        amplifiers: set[str] = surface.get("amplifiers", set())

        # Check if minimum required data is present
        if not required.issubset(inventory):
            continue

        # Some surfaces require additional context
        min_accounts = surface.get("min_accounts", 0)
        if min_accounts > 0 and account_count < min_accounts:
            continue

        # Determine if any amplifiers are present
        active_amplifiers = amplifiers & inventory
        if active_amplifiers:
            points = surface["amplified_score"]
            amp_detail = f" Amplified by: {', '.join(sorted(active_amplifiers))}."
        else:
            points = surface["base_score"]
            amp_detail = ""

        factor = ScoreFactor(
            category="attack_surfaces",
            label=surface["label"],
            points=points,
            detail=f"{surface['detail']}"
                   f" Required data present: {', '.join(sorted(required))}."
                   f"{amp_detail}",
        )
        candidates.append((points, surface_id, factor))

    # Take the top attack surfaces without massively double-counting.
    # Sort by points descending, take top 3.
    candidates.sort(key=lambda x: x[0], reverse=True)
    total = 0
    selected_count = 0

    for points, surface_id, factor in candidates:
        if selected_count >= 3:
            break
        # Diminishing returns: 2nd surface scores at 60%, 3rd at 30%
        if selected_count == 0:
            adjusted = points
        elif selected_count == 1:
            adjusted = int(points * 0.6)
        else:
            adjusted = int(points * 0.3)

        adjusted = min(adjusted, MAX_ATTACK_SCORE - total)
        if adjusted <= 0:
            break

        factor = ScoreFactor(
            category="attack_surfaces",
            label=factor.label,
            points=adjusted,
            detail=factor.detail + (
                f" (Reduced from {points} due to overlapping risk.)"
                if adjusted < points else ""
            ),
        )
        factors.append(factor)
        total += adjusted
        selected_count += 1

    if not factors:
        factors.append(ScoreFactor(
            category="attack_surfaces",
            label="No viable attack scenarios identified",
            points=0,
            detail="The combination of exposed data does not unlock any common "
                   "attack patterns (account takeover, identity theft, etc.).",
        ))

    return factors, total


# ===================================================================
# Step 3 — Accessibility Modifier
# ===================================================================

def _score_accessibility(
    findings: list[Finding], finding_type_counts: Counter[str]
) -> tuple[list[ScoreFactor], int]:
    """How easy is it to discover the exposed data?"""
    factors: list[ScoreFactor] = []
    total = 0

    # Data broker listings = very discoverable (anyone can search these)
    broker_count = finding_type_counts.get("data_broker_listing", 0)
    if broker_count >= 5:
        total += _add_factor(factors, "accessibility",
            "Data widely available on broker sites",
            8,
            f"Found on {broker_count} data broker sites — anyone can look this up.",
        )
    elif broker_count >= 2:
        total += _add_factor(factors, "accessibility",
            "Data available on multiple broker sites",
            4,
            f"Found on {broker_count} data broker site(s).",
        )

    # Breached credentials in well-known dumps
    breach_count = finding_type_counts.get("breach", 0) + finding_type_counts.get("leaked_credential", 0)
    if breach_count >= 5:
        total += _add_factor(factors, "accessibility",
            "Credentials in multiple breach databases",
            6,
            f"Appeared in {breach_count} breach or credential leak sources — "
            "attackers likely already have this data.",
        )
    elif breach_count >= 2:
        total += _add_factor(factors, "accessibility",
            "Credentials in breach databases",
            3,
            f"Appeared in {breach_count} breach or credential leak source(s).",
        )

    # Publicly indexed documents containing personal data
    doc_count = finding_type_counts.get("document", 0)
    if doc_count >= 3:
        total += _add_factor(factors, "accessibility",
            "Personal data in publicly indexed documents",
            4,
            f"{doc_count} documents containing personal data were found via search engines.",
        )
    elif doc_count >= 1:
        total += _add_factor(factors, "accessibility",
            "Document with personal data found online",
            2,
            f"{doc_count} document(s) containing personal data found via search engines.",
        )

    total = min(total, MAX_ACCESSIBILITY_SCORE)
    return factors, total


# ===================================================================
# Helpers
# ===================================================================

def _add_factor(
    factors: list[ScoreFactor],
    category: Literal["data_exposure", "attack_surfaces", "accessibility"],
    label: str,
    points: int,
    detail: str,
) -> int:
    if points <= 0:
        return 0
    factors.append(ScoreFactor(category=category, label=label, points=points, detail=detail))
    return points


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for f in findings:
        key = _finding_key(f)
        current = deduped.get(key)
        if current is None or _is_higher_risk(f, current):
            deduped[key] = f
    return list(deduped.values())


def _finding_key(f: Finding) -> str:
    data = f.data or {}
    marker = ""
    if f.finding_type == "breach":
        marker = str(data.get("breach_name") or data.get("service") or data.get("breach_source") or "").strip().lower()
    elif f.finding_type == "leaked_credential":
        marker = str(data.get("breach_source") or data.get("service") or "").strip().lower()
    elif f.finding_type == "data_broker_listing":
        marker = str(data.get("broker_name") or "").strip().lower()
    elif f.finding_type == "domain_registration":
        marker = str(data.get("domain") or data.get("matched_domain") or "").strip().lower()

    source_url = str(f.source_url or "").strip().lower()
    original_input = str(f.original_input or "").strip().lower()
    return "::".join(part for part in (f.finding_type, marker, source_url, original_input) if part)


def _is_higher_risk(candidate: Finding, current: Finding) -> bool:
    cs = SEVERITY_RANK.get(candidate.severity, 0)
    cu = SEVERITY_RANK.get(current.severity, 0)
    if cs != cu:
        return cs > cu
    cc = CONFIDENCE_RANK.get(candidate.confidence, 0)
    co = CONFIDENCE_RANK.get(current.confidence, 0)
    if cc != co:
        return cc > co
    return len(candidate.leads_to) > len(current.leads_to)


def _ordered_counts(counts: Counter[str], preferred_order: tuple[str, ...]) -> dict[str, int]:
    ordered: dict[str, int] = {}
    for key in preferred_order:
        value = counts.get(key, 0)
        if value > 0:
            ordered[key] = value
    for key in sorted(counts):
        if key not in ordered and counts[key] > 0:
            ordered[key] = counts[key]
    return ordered